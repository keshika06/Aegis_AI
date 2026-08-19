"""Stage 1 — Application Discovery.

Maps the target's attack surface before anything is attacked. Every fact is
labelled with how it was established, because claiming to have "discovered"
something that was actually assumed is how a scanner starts lying to its user.
"""

from __future__ import annotations

from typing import Any

import httpx

from aegisai.models.enums import DiscoveryConfidence, Stage
from aegisai.models.scan import Profile
from aegisai.pipeline.base import ScanContext, StageResult

TEXT_KEY_CANDIDATES = ("message", "prompt", "query", "text", "content", "input")
DEFAULT_TEXT_KEY = "message"

COMMON_PATHS = ("/health", "/info", "/chat", "/v1/chat/completions", "/api/chat", "/generate")


def _resolve_schema(schema: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    """Follow a single $ref into components/schemas."""
    ref = schema.get("$ref")
    if not ref or not ref.startswith("#/components/schemas/"):
        return schema
    name = ref.rsplit("/", 1)[-1]
    return spec.get("components", {}).get("schemas", {}).get(name, {})


def resolve_text_key(properties: dict[str, Any] | None) -> tuple[str | None, str]:
    """Decide which body key carries the prompt text.

    Returns (key, confidence). The fallback is the important part: a target whose
    handler takes a raw request body publishes no schema at all, and refusing to
    guess there means every probe fails before it is ever sent. A known schema
    that simply has no text-shaped field is a different case — that is not a chat
    surface, and returns None.
    """
    if properties is None:
        return DEFAULT_TEXT_KEY, DiscoveryConfidence.INFERRED
    for candidate in TEXT_KEY_CANDIDATES:
        if candidate in properties:
            return candidate, DiscoveryConfidence.OBSERVED
    return None, DiscoveryConfidence.UNKNOWN


class DiscoveryStage:
    stage = Stage.DISCOVERY

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    def run(self, ctx: ScanContext) -> StageResult:
        base = ctx.target_url.rstrip("/")
        spec = self._fetch_openapi(base)
        endpoints = self._from_openapi(spec) if spec else self._probe_common_paths(base)

        chat_surfaces = [e for e in endpoints if e.get("is_chat_surface")]
        profile = Profile(
            scan_id=ctx.scan_id,
            target_url=base,
            endpoints=endpoints,
            capabilities={
                "llm": bool(chat_surfaces),
                "rag": DiscoveryConfidence.UNKNOWN,
                "agent_tools": DiscoveryConfidence.UNKNOWN,
                "discovery_method": "openapi" if spec else "path_probe",
            },
            auth_model={"scheme": DiscoveryConfidence.UNKNOWN},
            surface_graph=self._build_graph(base, endpoints),
        )
        ctx.session.add(profile)
        ctx.session.flush()
        ctx.profile = profile

        return StageResult(
            ok=bool(endpoints),
            summary=(
                f"{len(endpoints)} endpoint(s), {len(chat_surfaces)} chat surface(s)"
                f" via {'OpenAPI' if spec else 'path probe'}"
            ),
            counts={"endpoints": len(endpoints), "chat_surfaces": len(chat_surfaces)},
        )

    def _fetch_openapi(self, base: str) -> dict[str, Any] | None:
        for path in ("/openapi.json", "/swagger.json"):
            try:
                res = httpx.get(f"{base}{path}", timeout=self.timeout)
                if res.status_code == 200:
                    data = res.json()
                    if isinstance(data, dict) and "paths" in data:
                        return data
            except Exception:  # noqa: BLE001 - absence of a spec is normal, not an error
                continue
        return None

    def _from_openapi(self, spec: dict[str, Any]) -> list[dict[str, Any]]:
        endpoints: list[dict[str, Any]] = []
        for path, methods in (spec.get("paths") or {}).items():
            for method, operation in (methods or {}).items():
                if method.upper() not in {"GET", "POST", "PUT", "PATCH"}:
                    continue

                properties: dict[str, Any] | None = None
                body = (operation or {}).get("requestBody", {})
                content = body.get("content", {}).get("application/json", {})
                if schema := content.get("schema"):
                    resolved = _resolve_schema(schema, spec)
                    properties = resolved.get("properties", {})

                text_key, confidence = (
                    resolve_text_key(properties)
                    if method.upper() == "POST"
                    else (None, DiscoveryConfidence.UNKNOWN)
                )
                endpoints.append(
                    {
                        "path": path,
                        "method": method.upper(),
                        "summary": (operation or {}).get("summary"),
                        "confidence": DiscoveryConfidence.OBSERVED,
                        "text_key": text_key,
                        "text_key_confidence": confidence,
                        "is_chat_surface": bool(text_key),
                    }
                )
        return endpoints

    def _probe_common_paths(self, base: str) -> list[dict[str, Any]]:
        """No spec published: fall back to probing, and say so in the labels."""
        endpoints: list[dict[str, Any]] = []
        for path in COMMON_PATHS:
            try:
                res = httpx.get(f"{base}{path}", timeout=self.timeout)
            except Exception:  # noqa: BLE001
                continue
            if res.status_code == 404:
                continue
            # 405 means the path exists but rejects GET - almost always a POST endpoint.
            is_post_only = res.status_code == 405
            text_key, confidence = (
                resolve_text_key(None) if is_post_only else (None, DiscoveryConfidence.UNKNOWN)
            )
            endpoints.append(
                {
                    "path": path,
                    "method": "POST" if is_post_only else "GET",
                    "summary": None,
                    "confidence": DiscoveryConfidence.OBSERVED,
                    "text_key": text_key,
                    "text_key_confidence": confidence,
                    "is_chat_surface": bool(text_key),
                }
            )
        return endpoints

    def _build_graph(self, base: str, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
        import networkx as nx

        graph = nx.DiGraph()
        graph.add_node(base, kind="target")
        for endpoint in endpoints:
            node = f"{endpoint['method']} {endpoint['path']}"
            graph.add_node(node, kind="endpoint", chat_surface=endpoint["is_chat_surface"])
            graph.add_edge(base, node)
        return nx.node_link_data(graph, edges="edges")
