"""Export a real scan into the shape the React dashboard consumes.

The dashboard was written against mock data for a fictional run. This maps a
genuine scan onto those same shapes so the UI shows what actually happened.

Where the dashboard expects something AegisAI does not measure, this module does
*not* invent it. Two cases matter:

* **Named security controls.** The mock lists things like "Prompt Guardrail" and
  "RAG Isolation" with effectiveness percentages. AegisAI is a black-box
  evaluator — it never learns what controls a target has, only how the target
  responded. So this reports per-transformation-family results instead, which is
  what was actually measured, and labels them as such.
* **SHAP values.** The mock shows a SHAP explainability panel. AegisAI runs no
  such model. Its risk score *is* a weighted linear combination, so each factor's
  real contribution (weight x value) is exported under its own name. That is a
  true decomposition, not a fabricated one.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegisai.knowledge_base.library import load_owasp_taxonomy, owasp_name
from aegisai.models.analysis import AttackChain, RiskScore
from aegisai.models.attack import AttackCase, AttackVariant
from aegisai.models.enums import ControlVerdict, FindingVerdict, RegressionStatus
from aegisai.models.execution import ControlEvaluation
from aegisai.models.finding import Evidence, Finding
from aegisai.models.policy import Violation
from aegisai.models.regression import RegressionTest
from aegisai.models.runtime import RuntimeEvent
from aegisai.models.scan import Profile, Scan
from aegisai.models.target import Target
from aegisai.pipeline.orchestrator import metrics as evasion_metrics

SEVERITY_BY_LEVEL = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}

VERDICT_LABEL = {
    ControlVerdict.ACCEPTED: "ACCEPTED",
    ControlVerdict.REJECTED: "REJECTED",
    ControlVerdict.REFUSED: "REFUSED",
    ControlVerdict.ERROR: "ERROR",
}

OUTCOME_COLOURS = {
    "ACCEPTED": "#ef4444",
    "REJECTED": "#22c55e",
    "REFUSED": "#3b82f6",
    "ERROR": "#eab308",
}


def _pct(value: float | None) -> int:
    """Risk scores are 0-10; the dashboard renders 0-100."""
    return int(round((value or 0) * 10))


def _short(identifier: str | None, prefix: str) -> str:
    """Turn scan-78f674d46ed2 into something readable in a table cell."""
    if not identifier:
        return "—"
    tail = identifier.split("-")[-1][:6].upper()
    return f"{prefix}-{tail}"


def _time(value: datetime | None) -> str:
    return value.strftime("%H:%M:%S") if value else "—"


def build(session: Session, scan_id: str) -> dict[str, Any]:
    """Assemble every dataset the dashboard imports, from one scan."""
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise ValueError(f"Unknown scan: {scan_id}")
    target = session.get(Target, scan.target_id) if scan.target_id else None
    profile = session.scalar(select(Profile).where(Profile.scan_id == scan_id))

    findings = list(session.scalars(select(Finding).where(Finding.scan_id == scan_id)))
    evidence = list(session.scalars(select(Evidence).where(Evidence.scan_id == scan_id)))
    evaluations = list(
        session.scalars(select(ControlEvaluation).where(ControlEvaluation.scan_id == scan_id))
    )
    risks = {
        r.finding_id: r
        for r in session.scalars(select(RiskScore).where(RiskScore.scan_id == scan_id))
    }
    chains = list(session.scalars(select(AttackChain).where(AttackChain.scan_id == scan_id)))
    events = list(session.scalars(select(RuntimeEvent).where(RuntimeEvent.scan_id == scan_id)))
    violations = list(session.scalars(select(Violation).where(Violation.scan_id == scan_id)))
    variants = {
        v.id: v
        for v in session.scalars(select(AttackVariant).where(AttackVariant.scan_id == scan_id))
    }
    cases = {
        c.id: c for c in session.scalars(select(AttackCase).where(AttackCase.scan_id == scan_id))
    }
    metrics = evasion_metrics.compute(session, scan_id)

    evidence_by_finding: dict[str, list[Evidence]] = {}
    for item in evidence:
        evidence_by_finding.setdefault(item.finding_id or "", []).append(item)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        risk = risks.get(finding.id)
        if risk:
            severity_counts[risk.risk_level] = severity_counts.get(risk.risk_level, 0) + 1

    top_risk = max((r.score for r in risks.values()), default=0.0)
    confirmed = [f for f in findings if f.verdict == FindingVerdict.CONFIRMED]

    return {
        "meta": {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "source": "aegisai",
            "scan_id": scan_id,
        },
        "run": _run(
            session,
            scan,
            target,
            findings,
            confirmed,
            severity_counts,
            top_risk,
            metrics,
            chains,
            evidence,
            cases,
        ),
        "riskRuns": _risk_runs(session, scan),
        "owaspCategories": _owasp(findings, risks, evidence_by_finding, chains),
        "findings": _findings(findings, risks, evidence_by_finding, variants, cases),
        "finding_detail": _detail(
            findings, risks, evidence_by_finding, variants, cases, violations
        ),
        "attackChainNodes": _chain_nodes(chains, findings, risks),
        "attackTimeline": _timeline(events),
        "riskComponents": _risk_components(risks),
        "factorContributions": _contributions(risks),
        "evidenceItems": _evidence(evidence, findings),
        "controlResults": _control_results(metrics),
        "outcomeDistribution": _outcomes(evaluations),
        "regression": _regression(session, scan, target),
        "recommendedActions": _actions(findings),
        "targetProfile": {
            "url": target.url if target else "—",
            "type": target.target_type if target else "—",
            "endpoints": (profile.endpoints if profile else []) or [],
        },
    }


def _previous_scan(session: Session, scan: Scan) -> Scan | None:
    """The scan immediately before this one, against the same target."""
    if not scan.target_id or not scan.created_at:
        return None
    return session.scalar(
        select(Scan)
        .where(
            Scan.target_id == scan.target_id,
            Scan.created_at < scan.created_at,
            Scan.id != scan.id,
        )
        .order_by(Scan.created_at.desc())
    )


def _top_risk_of(session: Session, scan_id: str) -> float:
    scores = session.scalars(select(RiskScore.score).where(RiskScore.scan_id == scan_id))
    return max(scores, default=0.0)


def _run(
    session, scan, target, findings, confirmed, severity, top_risk, metrics, chains, evidence, cases
) -> dict:
    # Attack success is confirmed objectives over objectives attempted — a rate
    # over probes would flatter the result, since one objective can be probed a
    # dozen ways.
    attempted = len(cases) or 1
    success_rate = int(round(len(confirmed) / attempted * 100))

    previous = _previous_scan(session, scan)
    previous_risk = _pct(_top_risk_of(session, previous.id)) if previous else None
    previous_confirmed = (
        len(
            [
                f
                for f in session.scalars(select(Finding).where(Finding.scan_id == previous.id))
                if f.verdict == FindingVerdict.CONFIRMED
            ]
        )
        if previous
        else None
    )
    previous_cases = (
        len(list(session.scalars(select(AttackCase).where(AttackCase.scan_id == previous.id))))
        if previous
        else 0
    )
    previous_rate = (
        int(round(previous_confirmed / (previous_cases or 1) * 100))
        if previous_confirmed is not None
        else None
    )

    # Confidence of the evidence actually relied upon. Averaging in the weak
    # signals would understate how solid the confirmed findings are.
    deterministic = [e for e in evidence if e.deterministic]
    confidence = (
        int(
            round(
                sum(e.confidence_contribution or 0 for e in deterministic)
                / len(deterministic)
                * 100
            )
        )
        if deterministic
        else None
    )

    return {
        # None where there is genuinely no prior scan to compare against; the UI
        # renders a dash rather than inventing a baseline.
        "previousRisk": previous_risk,
        "attackSuccessRate": success_rate,
        "attackSuccessDelta": (success_rate - previous_rate) if previous_rate is not None else None,
        "evidenceConfidence": confidence,
        "id": _short(scan.id, "RUN"),
        "scanId": scan.id,
        "target": target.url if target else "unknown",
        "targetType": target.target_type if target else "—",
        "status": scan.status.title() if scan.status else "Unknown",
        "risk": _pct(top_risk),
        "severity": (
            "CRITICAL"
            if severity.get("CRITICAL")
            else "HIGH"
            if severity.get("HIGH")
            else "MEDIUM"
            if severity.get("MEDIUM")
            else "LOW"
        ),
        "date": scan.created_at.strftime("%b %d, %Y") if scan.created_at else "—",
        "time": scan.created_at.strftime("%H:%M:%S") if scan.created_at else "—",
        "totalFindings": len(findings),
        "confirmed": len(confirmed),
        "critical": severity.get("CRITICAL", 0),
        "high": severity.get("HIGH", 0),
        "medium": severity.get("MEDIUM", 0),
        "low": severity.get("LOW", 0),
        "owaspAffected": len({f.owasp_tag for f in findings if f.owasp_tag}),
        "owaspTotal": len(load_owasp_taxonomy()) or 10,
        "guardrailEvasion": int(round(metrics.guardrail_evasion_rate * 100)),
        "refusalAfterAcceptance": int(round(metrics.refusal_after_acceptance_rate * 100)),
        "attackChains": len(chains),
        # Zero rejections means no control was observed at all — a different
        # result from a control holding, and the UI says so rather than
        # implying a perfect score.
        "baseRejectedCases": metrics.base_rejected_cases,
    }


def _risk_runs(session: Session, scan: Scan) -> list[dict]:
    """Recent scans of the same target, oldest first, for the trend chart."""
    history = list(
        session.scalars(
            select(Scan)
            .where(Scan.target_id == scan.target_id)
            .order_by(Scan.created_at.desc())
            .limit(8)
        )
    )
    rows = []
    for item in reversed(history):
        scores = list(session.scalars(select(RiskScore).where(RiskScore.scan_id == item.id)))
        findings = list(session.scalars(select(Finding).where(Finding.scan_id == item.id)))
        rows.append(
            {
                "run": _short(item.id, "RUN"),
                "risk": _pct(max((s.score for s in scores), default=0.0)),
                "critical": sum(1 for s in scores if s.risk_level == "CRITICAL"),
                "high": sum(1 for s in scores if s.risk_level == "HIGH"),
                "confirmed": sum(1 for f in findings if f.verdict == FindingVerdict.CONFIRMED),
                "findings": len(findings),
            }
        )
    return rows


def _owasp(findings, risks, evidence_by_finding, chains) -> list[dict]:
    taxonomy = load_owasp_taxonomy()
    by_tag: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.owasp_tag:
            by_tag.setdefault(finding.owasp_tag, []).append(finding)

    chain_tags: dict[str, int] = {}
    for chain in chains:
        for tag in chain.owasp_tags or []:
            chain_tags[tag] = chain_tags.get(tag, 0) + 1

    rows = []
    for tag in sorted(taxonomy):
        group = by_tag.get(tag, [])
        scores = [risks[f.id].score for f in group if f.id in risks]
        rows.append(
            {
                "id": tag,
                "name": taxonomy[tag].get("name", tag),
                "severity": (
                    max(
                        (risks[f.id].risk_level for f in group if f.id in risks),
                        key=lambda level: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(level),
                        default="LOW",
                    )
                    if scores
                    else "LOW"
                ),
                "findings": len(group),
                "risk": _pct(max(scores, default=0.0)),
                "evidence": sum(len(evidence_by_finding.get(f.id, [])) for f in group),
                "chains": chain_tags.get(tag, 0),
                "status": "OPEN" if group else "CLEAR",
            }
        )
    return rows


def _findings(findings, risks, evidence_by_finding, variants, cases) -> list[dict]:
    rows = []
    for finding in findings:
        risk = risks.get(finding.id)
        variant = variants.get(finding.variant_id or "")
        case = cases.get(variant.attack_case_id) if variant else None
        rows.append(
            {
                "id": _short(finding.id, "F"),
                "findingId": finding.id,
                "title": finding.title,
                "owasp": finding.owasp_tag or "—",
                "severity": risk.risk_level if risk else "LOW",
                "risk": _pct(risk.score if risk else 0),
                "confidence": int(round((finding.confidence or 0) * 100)),
                "verdict": finding.verdict,
                "attackType": (case.category if case else "—").replace("_", " ").title(),
                "transformation": variant.transformation if variant else "none",
                "evidence": len(evidence_by_finding.get(finding.id, [])),
                "status": "OPEN",
                "lastSeen": (
                    finding.created_at.strftime("%Y-%m-%d %H:%M") if finding.created_at else "—"
                ),
            }
        )
    return sorted(rows, key=lambda r: r["risk"], reverse=True)


def _detail(findings, risks, evidence_by_finding, variants, cases, violations) -> dict:
    """The single highest-risk finding, for the detail page."""
    if not findings:
        return {}
    top = max(findings, key=lambda f: risks[f.id].score if f.id in risks else 0)
    risk = risks.get(top.id)
    variant = variants.get(top.variant_id or "")
    case = cases.get(variant.attack_case_id) if variant else None
    related = [v for v in violations if v.variant_id == top.variant_id]

    return {
        "id": _short(top.id, "F"),
        "findingId": top.id,
        "title": top.title,
        "owasp": top.owasp_tag or "—",
        "owaspName": owasp_name(top.owasp_tag) or "—",
        "severity": risk.risk_level if risk else "LOW",
        "risk": _pct(risk.score if risk else 0),
        "confidence": int(round((top.confidence or 0) * 100)),
        "verdict": top.verdict,
        "description": top.description,
        "mitigation": top.mitigation,
        "payload": variant.payload if variant else "—",
        "transformation": variant.transformation if variant else "none",
        "intent": case.original_intent if case else "—",
        "violations": [
            {"boundary": v.boundary, "expected": v.expected, "observed": v.observed}
            for v in related
        ],
        "evidence": [
            {
                "id": _short(e.id, "EV"),
                "type": e.evidence_type,
                "deterministic": bool(e.deterministic),
                "summary": e.summary,
            }
            for e in evidence_by_finding.get(top.id, [])
        ],
    }


def _chain_nodes(chains, findings, risks) -> list[dict]:
    """Flatten the highest-severity chain's graph into ordered nodes."""
    if not chains:
        return []
    chain = max(chains, key=lambda c: c.severity or 0)
    graph = chain.graph or {}
    nodes = []
    for node in graph.get("nodes", []):
        kind = node.get("kind", "")
        nodes.append(
            {
                "id": node.get("id"),
                "name": str(node.get("label", node.get("id"))).replace("_", " ").title(),
                "kind": kind,
                "status": {
                    "intent": "OBSERVED",
                    "representation": "OBSERVED",
                    "control_decision": (
                        "BYPASSED" if "ACCEPTED" in str(node.get("label", "")) else "BLOCKED"
                    ),
                    "finding": "SUCCESS",
                    "evidence": "OBSERVED",
                }.get(kind, "OBSERVED"),
                "risk": _pct((chain.severity or 0) * 10),
                "deterministic": bool(node.get("deterministic")),
            }
        )
    return nodes


def _timeline(events) -> list[dict]:
    return [
        {
            "time": _time(e.created_at),
            "label": e.event_type.replace("_", " ").title(),
            "detail": (e.payload or {}).get("tool") or (e.payload or {}).get("model") or "",
            "node": e.variant_id or "—",
        }
        for e in events[:40]
    ]


def _risk_components(risks) -> list[dict]:
    """Factors of the highest-scoring finding, with their real weights."""
    if not risks:
        return []
    top = max(risks.values(), key=lambda r: r.score)
    rows = []
    for name, value in (top.factors or {}).items():
        established = isinstance(value, (int, float))
        rows.append(
            {
                "label": name.replace("_", " ").title(),
                "score": int(round(float(value) * 100)) if established else None,
                "weight": int(round((top.weights or {}).get(name, 0) * 100)),
                "established": established,
                "explain": (
                    f"Contributes {(top.weights or {}).get(name, 0):.0%} of the composite."
                    if established
                    # An unmeasured factor is excluded from the weighting rather
                    # than counted as zero risk.
                    else "Not established for this finding; excluded from the score."
                ),
            }
        )
    return rows


def _contributions(risks) -> dict:
    """Real per-factor contribution to the composite score.

    The risk model is a weighted linear combination, so weight x value *is* each
    factor's contribution — a true decomposition rather than an approximation of
    one from a model that was never run.
    """
    if not risks:
        return {"features": [], "base": 0, "final": 0}

    top = max(risks.values(), key=lambda r: r.score)
    established = {
        k: float(v) for k, v in (top.factors or {}).items() if isinstance(v, (int, float))
    }
    weights = top.weights or {}
    total_weight = sum(weights.get(k, 0) for k in established) or 1.0

    features = [
        {
            "feature": name,
            "value": f"{value:.2f}",
            "contribution": round((weights.get(name, 0) / total_weight) * value * 10, 2),
            "direction": "up" if value >= 0.5 else "down",
            "explain": f"weight {weights.get(name, 0):.2f}, value {value:.2f}",
        }
        for name, value in sorted(
            established.items(), key=lambda kv: weights.get(kv[0], 0) * kv[1], reverse=True
        )
    ]
    return {
        "features": features,
        "base": 0,
        "final": top.score,
        "unestablished": [
            k for k, v in (top.factors or {}).items() if not isinstance(v, (int, float))
        ],
    }


def _evidence(evidence, findings) -> list[dict]:
    titles = {f.id: f.title for f in findings}
    return [
        {
            "id": _short(e.id, "EV"),
            "type": e.evidence_type.replace("_", " ").title(),
            "deterministic": bool(e.deterministic),
            "source": e.source_stage or "—",
            "finding": titles.get(e.finding_id or "", "—")[:48],
            "confidence": int(round((e.confidence_contribution or 0) * 100)),
            "summary": e.summary or "",
            "timestamp": _time(e.created_at),
        }
        for e in evidence
    ]


def _control_results(metrics) -> list[dict]:
    """Per-transformation-family results.

    Deliberately *not* a list of named controls like "Prompt Guardrail":
    AegisAI never learns what controls a target implements, only how the target
    responded to each representation. Reporting invented control names would
    claim knowledge the scanner does not have.
    """
    return [
        {
            "family": stat.family,
            "name": stat.family.replace("_", " ").title(),
            "tested": stat.total,
            "accepted": stat.accepted,
            "rejected": stat.rejected,
            "refused": stat.refused,
            "errored": stat.errored,
            "acceptanceRate": round(stat.acceptance_rate * 100, 1),
            "evadedBaseRejection": stat.evaded,
        }
        for stat in metrics.families.values()
    ]


def _outcomes(evaluations) -> list[dict]:
    counts: dict[str, int] = {}
    for evaluation in evaluations:
        label = VERDICT_LABEL.get(evaluation.verdict, evaluation.verdict)
        counts[label] = counts.get(label, 0) + 1
    return [
        {"name": name, "value": value, "color": OUTCOME_COLOURS.get(name, "#64748b")}
        for name, value in sorted(counts.items(), key=lambda kv: -kv[1])
    ]


def _regression(session: Session, scan: Scan, target) -> dict:
    tests = list(
        session.scalars(select(RegressionTest).where(RegressionTest.target_id == scan.target_id))
    )
    by_status: dict[str, int] = {}
    for test in tests:
        by_status[test.status] = by_status.get(test.status, 0) + 1

    regressed = by_status.get(RegressionStatus.REGRESSED, 0) + by_status.get(
        RegressionStatus.EXHAUSTED, 0
    )

    previous = _previous_scan(session, scan)
    # Tests whose origin finding came from this scan are new; everything else
    # was carried in from an earlier run.
    this_scan_findings = {
        f.id for f in session.scalars(select(Finding).where(Finding.scan_id == scan.id))
    }
    newly_created = sum(1 for t in tests if t.origin_finding_id in this_scan_findings)

    # The family with the highest acceptance rate is where remediation buys the
    # most, so it leads. Derived from measurement, not a curated wish list.
    metrics = evasion_metrics.compute(session, scan.id)
    next_focus = [
        stat.family
        for stat in sorted(metrics.families.values(), key=lambda s: s.acceptance_rate, reverse=True)
    ][:3]

    worst_tag = None
    tag_counts: dict[str, int] = {}
    for test in tests:
        if test.owasp_tag and test.status in (
            RegressionStatus.REGRESSED,
            RegressionStatus.EXHAUSTED,
        ):
            tag_counts[test.owasp_tag] = tag_counts.get(test.owasp_tag, 0) + 1
    if tag_counts:
        worst_tag = max(tag_counts, key=lambda k: tag_counts[k])

    return {
        "total": len(tests),
        "active": by_status.get(RegressionStatus.ACTIVE, 0),
        "resolved": by_status.get(RegressionStatus.RESOLVED, 0),
        "regressed": regressed,
        "prevRun": _short(previous.id, "RUN") if previous else None,
        "currentRun": _short(scan.id, "RUN"),
        "fixed": by_status.get(RegressionStatus.RESOLVED, 0),
        "new": newly_created,
        "regressions": regressed,
        "riskPrev": _pct(_top_risk_of(session, previous.id)) if previous else None,
        "riskCurrent": _pct(_top_risk_of(session, scan.id)),
        "nextFocus": next_focus,
        "detail": (
            {
                "category": f"{worst_tag} {owasp_name(worst_tag) or ''}".strip(),
                "prev": _pct(_top_risk_of(session, previous.id)) if previous else None,
                "current": _pct(_top_risk_of(session, scan.id)),
            }
            if worst_tag
            else None
        ),
        "status": "REGRESSED" if regressed else ("CLEAN" if tests else "NONE"),
        "target": target.url if target else "—",
        "tests": [
            {
                "id": _short(t.id, "REG"),
                "status": t.status,
                "owasp": t.owasp_tag or "—",
                "transformation": t.transformation,
                "attempts": f"{t.attempt_count or 0}/{t.max_attempts or 3}",
            }
            for t in tests
        ],
    }


def _actions(findings) -> list[str]:
    """Mitigations from real findings, de-duplicated, highest verdict first."""
    seen: dict[str, None] = {}
    for finding in sorted(
        findings, key=lambda f: 0 if f.verdict == FindingVerdict.CONFIRMED else 1
    ):
        if finding.mitigation:
            seen.setdefault(finding.mitigation, None)
    return list(seen)
