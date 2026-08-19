"""HTML report rendering.

Renders from the same payload the JSON report serialises, so the two formats
cannot drift: a section missing from one is missing from both, visibly.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from aegisai import __version__
from aegisai.knowledge_base.library import owasp_name

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        # Findings embed attacker-controlled text; escaping is what keeps a
        # report about injection from itself being an injection vector.
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def enrich(payload: dict[str, Any]) -> dict[str, Any]:
    """Add the derived views the template needs, without changing the JSON shape."""
    data = dict(payload)

    risk_by_finding = {r["finding_id"]: r for r in data.get("risk_scores", [])}
    findings = []
    for finding in data.get("findings", []):
        item = dict(finding)
        item["owasp_name"] = owasp_name(finding.get("owasp_tag"))
        item["risk"] = risk_by_finding.get(finding.get("finding_id"))
        findings.append(item)
    # Confirmed first: a reader should not have to scroll past suspicions.
    order = {"CONFIRMED": 0, "LIKELY": 1, "SUSPECTED": 2}
    data["findings"] = sorted(findings, key=lambda f: order.get(f.get("verdict", ""), 9))

    mapping: dict[str, dict[str, Any]] = {}
    for finding in data["findings"]:
        tag = finding.get("owasp_tag")
        if not tag:
            continue
        entry = mapping.setdefault(tag, {"name": owasp_name(tag) or "—", "count": 0})
        entry["count"] += 1
    data["owasp_mapping"] = dict(sorted(mapping.items()))

    data["mitigations"] = sorted({f["mitigation"] for f in data["findings"] if f.get("mitigation")})
    data["runtime_events"] = dict(Counter(data.get("runtime_event_types", [])))
    data.setdefault("violations", [])
    data.setdefault("regression_tests", [])
    data.setdefault("attack_chains", [])
    data.setdefault("risk_scores", [])
    data["version"] = __version__
    return data


def render(payload: dict[str, Any]) -> str:
    return _environment().get_template("report.html.j2").render(**enrich(payload))


def write(payload: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(payload), encoding="utf-8")
    return path
