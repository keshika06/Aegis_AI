"""Stage 10 — Reporting.

Phase 1 emits JSON only. The HTML report in Phase 6 renders from this same
payload, so both formats stay a single source of truth by construction.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from aegisai.models.analysis import AttackChain, Report, RiskScore
from aegisai.models.attack import AttackCase, AttackVariant
from aegisai.models.enums import FindingVerdict, Stage
from aegisai.models.execution import ControlEvaluation
from aegisai.models.finding import Evidence, Finding
from aegisai.models.policy import Violation
from aegisai.models.regression import RegressionTest
from aegisai.models.runtime import RuntimeEvent
from aegisai.pipeline.base import ScanContext, StageResult
from aegisai.pipeline.orchestrator import metrics as evasion_metrics
from aegisai.pipeline.reporting import html as html_report

MAX_BODY_EXCERPT = 2000
"""Responses are truncated in the report; the full body stays in the database."""


def build_payload(ctx: ScanContext) -> dict:
    session = ctx.session

    evaluations = list(
        session.scalars(select(ControlEvaluation).where(ControlEvaluation.scan_id == ctx.scan_id))
    )
    findings = list(session.scalars(select(Finding).where(Finding.scan_id == ctx.scan_id)))
    evidence = list(session.scalars(select(Evidence).where(Evidence.scan_id == ctx.scan_id)))
    cases = {
        c.id: c
        for c in session.scalars(select(AttackCase).where(AttackCase.scan_id == ctx.scan_id))
    }
    variants = {
        v.id: v
        for v in session.scalars(select(AttackVariant).where(AttackVariant.scan_id == ctx.scan_id))
    }

    evidence_by_finding: dict[str, list[Evidence]] = {}
    for item in evidence:
        evidence_by_finding.setdefault(item.finding_id or "", []).append(item)

    verdict_counts = {v.value: 0 for v in FindingVerdict}
    for finding in findings:
        verdict_counts[finding.verdict] = verdict_counts.get(finding.verdict, 0) + 1

    control_counts: dict[str, int] = {}
    for evaluation in evaluations:
        control_counts[evaluation.verdict] = control_counts.get(evaluation.verdict, 0) + 1

    return {
        "schema": "aegisai.report.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "scan_id": ctx.scan_id,
        "target": {"id": ctx.target_id, "url": ctx.target_url},
        "summary": {
            "attack_cases": len(cases),
            "probes_sent": len(evaluations),
            "control_results": control_counts,
            "findings": verdict_counts,
        },
        "guardrail_evasion": evasion_metrics.compute(session, ctx.scan_id).as_dict(),
        "target_profile": {
            "endpoints": (ctx.profile.endpoints if ctx.profile else []),
            "capabilities": (ctx.profile.capabilities if ctx.profile else {}),
        },
        "attack_cases": [
            {
                "id": case.id,
                "owasp_tag": case.owasp_tag,
                "category": case.category,
                "intent": case.original_intent,
                "payload": case.payload,
                "target_surface_element": case.target_surface_element,
            }
            for case in cases.values()
        ],
        "control_results": [
            {
                "id": e.id,
                "variant_id": e.variant_id,
                "verdict": e.verdict,
                "reason": e.verdict_reason,
                "status_code": e.status_code,
                "latency_ms": round(e.latency_ms, 1) if e.latency_ms else None,
                "response_excerpt": (e.response_body or "")[:MAX_BODY_EXCERPT],
                "error": e.error,
            }
            for e in evaluations
        ],
        "runtime_event_types": [
            e.event_type
            for e in session.scalars(
                select(RuntimeEvent).where(RuntimeEvent.scan_id == ctx.scan_id)
            )
        ],
        "violations": [
            {
                "boundary": v.boundary,
                "rule": v.rule,
                "expected": v.expected,
                "observed": v.observed,
                "severity": (v.detail or {}).get("severity"),
            }
            for v in session.scalars(select(Violation).where(Violation.scan_id == ctx.scan_id))
        ],
        "regression_tests": [
            {
                "id": t.id,
                "status": t.status,
                "owasp_tag": t.owasp_tag,
                "transformation": t.transformation,
                "attempt_count": t.attempt_count,
                "max_attempts": t.max_attempts,
            }
            for t in session.scalars(
                select(RegressionTest).where(RegressionTest.target_id == ctx.target_id)
            )
        ],
        "attack_chains": [
            {
                "chain_id": c.id,
                "title": c.title,
                "finding_ids": c.finding_ids,
                "owasp_tags": c.owasp_tags,
                "severity": c.severity,
                "graph": c.graph,
            }
            for c in session.scalars(select(AttackChain).where(AttackChain.scan_id == ctx.scan_id))
        ],
        "risk_scores": [
            {
                "finding_id": r.finding_id,
                "score": r.score,
                "risk_level": r.risk_level,
                "factors": r.factors,
                "weights": r.weights,
                "explanation": r.explanation,
            }
            for r in session.scalars(select(RiskScore).where(RiskScore.scan_id == ctx.scan_id))
        ],
        "findings": [
            {
                "finding_id": f.id,
                "verdict": f.verdict,
                "title": f.title,
                "description": f.description,
                "owasp_tag": f.owasp_tag,
                "confidence": f.confidence,
                "mitigation": f.mitigation,
                "attack_payload": (
                    variants[f.variant_id].payload if f.variant_id in variants else None
                ),
                "evidence": [
                    {
                        "evidence_id": ev.id,
                        "evidence_type": ev.evidence_type,
                        "deterministic": ev.deterministic,
                        "confidence_contribution": ev.confidence_contribution,
                        "summary": ev.summary,
                        "content": ev.content,
                    }
                    for ev in evidence_by_finding.get(f.id, [])
                ],
            }
            for f in findings
        ],
    }


class ReportingStage:
    stage = Stage.REPORTING

    def run(self, ctx: ScanContext) -> StageResult:
        payload = build_payload(ctx)

        reports_dir = Path(ctx.config.reports_dir)
        reports_dir.mkdir(parents=True, exist_ok=True)
        path = reports_dir / f"{ctx.scan_id}.json"
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

        ctx.session.add(
            Report(scan_id=ctx.scan_id, format="json", path=str(path), summary=payload["summary"])
        )

        html_path = reports_dir / f"{ctx.scan_id}.html"
        html_report.write(payload, html_path)
        ctx.session.add(
            Report(
                scan_id=ctx.scan_id,
                format="html",
                path=str(html_path),
                summary=payload["summary"],
            )
        )
        ctx.session.flush()

        return StageResult(
            ok=True, summary=f"wrote {path.name} and {html_path.name}", counts={"reports": 2}
        )
