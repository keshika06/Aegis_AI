"""HTTP transport to the target.

The adapter never raises for a target-side failure. A refused connection or a
timeout is a *result* — it becomes verdict ERROR — not an exception that aborts
the scan. AegisAI is measuring what the target does, and "it fell over" is data.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx


@dataclass
class ProbeRequest:
    url: str
    json_body: dict
    method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 30.0


@dataclass
class ProbeResponse:
    status_code: int | None
    headers: dict[str, str]
    body: str
    latency_ms: float
    error: str | None = None
    """Set only for transport failures, where status_code is None."""

    @property
    def transport_failed(self) -> bool:
        return self.error is not None


class TargetAdapter:
    """Sends one probe and reports what came back."""

    def __init__(self, timeout: float = 30.0) -> None:
        self.timeout = timeout

    def send(self, req: ProbeRequest) -> ProbeResponse:
        started = time.perf_counter()
        try:
            response = httpx.request(
                req.method,
                req.url,
                json=req.json_body,
                headers=req.headers or None,
                timeout=req.timeout or self.timeout,
            )
        except Exception as exc:  # noqa: BLE001 - every transport failure is one signal
            return ProbeResponse(
                status_code=None,
                headers={},
                body="",
                latency_ms=(time.perf_counter() - started) * 1000,
                error=f"{type(exc).__name__}: {exc}",
            )

        return ProbeResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            body=response.text,
            latency_ms=(time.perf_counter() - started) * 1000,
        )
