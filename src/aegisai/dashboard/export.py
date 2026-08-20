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
from aegisai.models.enums import ControlVerdict, FindingVerdict, RegressionStatus, RiskLevel
from aegisai.models.execution import ControlEvaluation
from aegisai.models.finding import Evidence, Finding
from aegisai.models.policy import Violation
from aegisai.models.regression import RegressionTest
from aegisai.models.runtime import RuntimeEvent
from aegisai.models.scan import Profile, Scan
from aegisai.models.target import Target
from aegisai.pipeline.orchestrator import metrics as evasion_metrics
from aegisai.pipeline.risk.scoring import (
    IMPACT_WEIGHTS,
    LIKELIHOOD_WEIGHTS,
    RISK_MODEL_VERSION,
    THRESHOLDS,
    posture,
)

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

    posture_score = _posture_of(session, scan_id)
    confirmed = [f for f in findings if f.verdict == FindingVerdict.CONFIRMED]
    details = _details(findings, risks, evidence_by_finding, variants, cases, violations)

    return {
        "meta": {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "source": "aegisai",
            "scan_id": scan_id,
            # When the scan itself ran, which is not when it was exported. A
            # dashboard showing a three-hour-old scan should say so.
            "scan_completed_at": (
                scan.completed_at.isoformat(timespec="seconds") if scan.completed_at else None
            ),
            # The newest scan in the database at export time. If this is not
            # scan_id, the file is already behind and the UI says so rather than
            # presenting stale numbers as current.
            "latest_scan_id": session.scalar(
                select(Scan.id).order_by(Scan.created_at.desc()).limit(1)
            ),
        },
        "run": _run(
            session,
            scan,
            target,
            findings,
            confirmed,
            severity_counts,
            posture_score,
            metrics,
            chains,
            evidence,
        ),
        "riskRuns": _risk_runs(session, scan),
        "owaspCategories": _owasp(
            findings, risks, evidence_by_finding, chains, _previous_owasp_tags(session, scan)
        ),
        "findings": _findings(findings, risks, evidence_by_finding, variants, cases),
        "findingDetails": details,
        "finding_detail": _top_detail(details, findings, risks),
        "attackChainNodes": _chain_nodes(chains, findings, risks),
        "attackChains": _chains(
            chains,
            findings,
            risks,
            variants,
            cases,
            {e.id: e for e in evaluations},
            evidence_by_finding,
            violations,
            events,
        ),
        "attackTimeline": _timeline(events, variants),
        "chainSummary": _chain_summary(
            _chains(
                chains,
                findings,
                risks,
                variants,
                cases,
                {e.id: e for e in evaluations},
                evidence_by_finding,
                violations,
                events,
            )
        ),
        "riskComponents": _risk_components(risks),
        "factorContributions": _contributions(risks),
        "evidenceItems": _evidence(
            evidence,
            findings,
            variants,
            {e.id: e for e in evaluations},
            violations,
        ),
        "controlResults": _control_results(metrics),
        "attackScenarios": _scenarios(
            findings, risks, variants, cases, {e.id: e for e in evaluations}, violations, events
        ),
        "outcomeDistribution": _outcomes(evaluations),
        "regression": _regression(session, scan, target),
        "recommendedActions": _actions(findings),
        "targetProfile": {
            "url": target.url if target else "—",
            "type": target.target_type if target else "—",
            "endpoints": (profile.endpoints if profile else []) or [],
        },
    }


def _is_comparable(session: Session, scan_id: str) -> bool:
    """Whether this scan's scores came from the risk model in force today.

    A score from an older model is a different measurement. Putting one on the
    same trend line as a current score would show a change in the formula as a
    change in the target's security — reporting an improvement that never
    happened.
    """
    versions = set(
        session.scalars(select(RiskScore.model_version).where(RiskScore.scan_id == scan_id))
    )
    return bool(versions) and versions == {RISK_MODEL_VERSION}


def _previous_scan(session: Session, scan: Scan) -> Scan | None:
    """The most recent earlier scan of this target that is comparable to it.

    Skips scans scored under a superseded risk model rather than silently
    comparing against them.
    """
    if not scan.target_id or not scan.created_at:
        return None
    candidates = session.scalars(
        select(Scan)
        .where(
            Scan.target_id == scan.target_id,
            Scan.created_at < scan.created_at,
            Scan.id != scan.id,
        )
        .order_by(Scan.created_at.desc())
    )
    for candidate in candidates:
        if _is_comparable(session, candidate.id):
            return candidate
    return None


def _best_score_per_objective(session: Session, scan_id: str) -> dict[str, float]:
    """The highest score each attack objective reached in this scan.

    Keyed by attack case, so twelve representations of one weakness collapse to
    the one weakness they all probe. Findings that cannot be traced back to a
    case keep their own key rather than being dropped — an unattributed finding
    is still a finding.
    """
    case_by_variant = {
        v.id: v.attack_case_id
        for v in session.scalars(select(AttackVariant).where(AttackVariant.scan_id == scan_id))
    }
    variant_by_finding = {
        f.id: f.variant_id
        for f in session.scalars(select(Finding).where(Finding.scan_id == scan_id))
    }

    best: dict[str, float] = {}
    for risk in session.scalars(select(RiskScore).where(RiskScore.scan_id == scan_id)):
        variant_id = variant_by_finding.get(risk.finding_id or "")
        key = case_by_variant.get(variant_id or "") or f"unattributed:{risk.finding_id}"
        best[key] = max(best.get(key, 0.0), risk.score)
    return best


def _posture_of(session: Session, scan_id: str) -> int:
    """The 0-100 posture score for a scan."""
    return posture(_best_score_per_objective(session, scan_id)).score


def _band(posture_score: int) -> str:
    """The risk level a 0-100 posture score falls in.

    Uses the same thresholds as a finding's score, so "72/100" and the label
    beside it cannot disagree.
    """
    for threshold, level in THRESHOLDS:
        if posture_score >= threshold * 10:
            return level.value
    return RiskLevel.LOW.value


def _confirmed_objectives(session: Session, scan_id: str) -> int:
    """Distinct attack objectives that produced at least one confirmed finding.

    Counting confirmed *findings* here instead reported 130 successes against 27
    objectives — 481%, because one objective probed a dozen ways yields a dozen
    findings. A success rate that can exceed 100% is not a rate.
    """
    case_by_variant = {
        v.id: v.attack_case_id
        for v in session.scalars(select(AttackVariant).where(AttackVariant.scan_id == scan_id))
    }
    cases: set[str] = set()
    for finding in session.scalars(select(Finding).where(Finding.scan_id == scan_id)):
        if finding.verdict != FindingVerdict.CONFIRMED:
            continue
        case_id = case_by_variant.get(finding.variant_id or "")
        cases.add(case_id or f"unattributed:{finding.id}")
    return len(cases)


def _success_rate(session: Session, scan_id: str) -> int | None:
    """Confirmed objectives over objectives attempted, as a percentage."""
    attempted = len(
        list(session.scalars(select(AttackCase.id).where(AttackCase.scan_id == scan_id)))
    )
    if not attempted:
        return None
    return int(round(_confirmed_objectives(session, scan_id) / attempted * 100))


def _run(
    session, scan, target, findings, confirmed, severity, posture_score, metrics, chains, evidence
) -> dict:
    success_rate = _success_rate(session, scan.id)

    previous = _previous_scan(session, scan)
    previous_risk = _posture_of(session, previous.id) if previous else None
    previous_rate = _success_rate(session, previous.id) if previous else None

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
        "attackSuccessDelta": (
            (success_rate - previous_rate)
            if previous_rate is not None and success_rate is not None
            else None
        ),
        "evidenceConfidence": confidence,
        "id": _short(scan.id, "RUN"),
        "scanId": scan.id,
        "target": target.url if target else "unknown",
        "targetType": target.target_type if target else "—",
        "status": scan.status.title() if scan.status else "Unknown",
        "risk": posture_score,
        # The band of the posture score itself, not of the worst single
        # finding. The gauge renders this label directly under that number, and
        # a label describing a different quantity than the figure it sits under
        # is how a reader ends up with the wrong impression of both.
        "severity": _band(posture_score),
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
    """Recent scans of the same target, oldest first, for the trend chart.

    Only scans scored by the current risk model appear. A superseded model's
    scores are real, but they are a different measurement, and a line through
    both would read as the target changing when only the formula did.
    """
    history = [
        item
        for item in session.scalars(
            select(Scan)
            .where(Scan.target_id == scan.target_id)
            .order_by(Scan.created_at.desc())
            .limit(16)
        )
        if _is_comparable(session, item.id)
    ][:8]
    rows = []
    for item in reversed(history):
        scores = list(session.scalars(select(RiskScore).where(RiskScore.scan_id == item.id)))
        findings = list(session.scalars(select(Finding).where(Finding.scan_id == item.id)))
        rows.append(
            {
                "run": _short(item.id, "RUN"),
                "risk": _posture_of(session, item.id),
                "critical": sum(1 for s in scores if s.risk_level == "CRITICAL"),
                "high": sum(1 for s in scores if s.risk_level == "HIGH"),
                "confirmed": sum(1 for f in findings if f.verdict == FindingVerdict.CONFIRMED),
                "findings": len(findings),
            }
        )
    return rows


def _previous_owasp_tags(session: Session, scan: Scan) -> set[str] | None:
    """OWASP tags seen in the previous scan of this target.

    None where there is no previous scan, which the UI has to distinguish from
    an empty set: "nothing was found before" and "we have never looked before"
    are different claims, and only one of them makes a category *new*.
    """
    previous = _previous_scan(session, scan)
    if previous is None:
        return None
    return {
        f.owasp_tag
        for f in session.scalars(select(Finding).where(Finding.scan_id == previous.id))
        if f.owasp_tag
    }


def _owasp(findings, risks, evidence_by_finding, chains, previous_tags) -> list[dict]:
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
                # None where there is no previous scan: without a baseline,
                # nothing can be called newly detected.
                "isNew": (bool(group) and tag not in previous_tags)
                if previous_tags is not None
                else None,
            }
        )
    return rows


def _axis_value(risk, axis_weights) -> float | None:
    """One axis of a stored risk score, recomputed from its recorded factors.

    None when nothing on the axis was established — the caller must not plot a
    point whose position it had to invent.
    """
    if risk is None:
        return None
    present = {
        k: float(v)
        for k, v in (risk.factors or {}).items()
        if k in axis_weights and isinstance(v, (int, float))
    }
    total = sum(axis_weights[k] for k in present)
    if not total:
        return None
    return round(sum(axis_weights[k] * v for k, v in present.items()) / total, 3)


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
                # The two axes the score multiplies, so an impact/likelihood
                # plot can show where a finding actually sits rather than
                # deriving one axis from the composite it already produced.
                "likelihood": _axis_value(risk, LIKELIHOOD_WEIGHTS),
                "impact": _axis_value(risk, IMPACT_WEIGHTS),
                "confidence": int(round((finding.confidence or 0) * 100)),
                "verdict": finding.verdict,
                # category is nullable, so a case without one must not be
                # treated as the string it is not.
                "attackType": ((case.category if case else None) or "—").replace("_", " ").title(),
                "transformation": variant.transformation if variant else "none",
                "evidence": len(evidence_by_finding.get(finding.id, [])),
                # No "status" field: AegisAI has no concept of a finding being
                # triaged or closed, so every row carried a constant "OPEN" that
                # looked like workflow state and tracked nothing. `verdict` is
                # the real, measured disposition.
                "lastSeen": (
                    finding.created_at.strftime("%Y-%m-%d %H:%M") if finding.created_at else "—"
                ),
            }
        )
    return sorted(rows, key=lambda r: r["risk"], reverse=True)


def _details(findings, risks, evidence_by_finding, variants, cases, violations) -> dict:
    """Full detail for every finding, keyed by the id the tables link to.

    Previously only the highest-scoring finding was exported, and the detail
    page merged it with whichever row the reader had clicked — so opening any
    other finding showed that finding's title above the top finding's payload,
    evidence and violations. Exporting every finding removes the mismatch
    instead of papering over it.
    """
    violations_by_variant: dict[str, list] = {}
    for violation in violations:
        violations_by_variant.setdefault(violation.variant_id or "", []).append(violation)

    out = {}
    for finding in findings:
        risk = risks.get(finding.id)
        variant = variants.get(finding.variant_id or "")
        case = cases.get(variant.attack_case_id) if variant else None
        factors = (risk.factors if risk else None) or {}
        weights = (risk.weights if risk else None) or {}

        out[_short(finding.id, "F")] = {
            "id": _short(finding.id, "F"),
            "findingId": finding.id,
            "title": finding.title,
            "owasp": finding.owasp_tag or "—",
            "owaspName": owasp_name(finding.owasp_tag) or "—",
            "severity": risk.risk_level if risk else "LOW",
            "risk": _pct(risk.score if risk else 0),
            "confidence": int(round((finding.confidence or 0) * 100)),
            "verdict": finding.verdict,
            "description": finding.description,
            "mitigation": finding.mitigation,
            "payload": variant.payload if variant else None,
            "transformation": variant.transformation if variant else "none",
            "intent": case.original_intent if case else None,
            "explanation": risk.explanation if risk else None,
            # The scored factors for *this* finding, so "why this is risky" is
            # this finding's arithmetic rather than the top finding's.
            "components": [
                {
                    "label": name.replace("_", " ").title(),
                    "axis": _axis_of(name),
                    "score": int(round(float(value) * 100)),
                    "weight": int(round(weights.get(name, 0) * 100)),
                }
                for name, value in factors.items()
                if isinstance(value, (int, float))
            ],
            "unestablished": [
                name.replace("_", " ")
                for name, value in factors.items()
                if not isinstance(value, (int, float))
            ],
            "violations": [
                {"boundary": v.boundary, "expected": v.expected, "observed": v.observed}
                for v in violations_by_variant.get(finding.variant_id or "", [])
            ],
            "evidence": [
                {
                    "id": _short(e.id, "EV"),
                    "type": e.evidence_type.replace("_", " ").title(),
                    "deterministic": bool(e.deterministic),
                    "summary": e.summary,
                    "timestamp": _time(e.created_at),
                }
                for e in evidence_by_finding.get(finding.id, [])
            ],
        }
    return out


def _top_detail(details, findings, risks) -> dict:
    """The highest-scoring finding, for pages that describe the worst case."""
    if not findings:
        return {}
    top = max(findings, key=lambda f: risks[f.id].score if f.id in risks else 0)
    return details.get(_short(top.id, "F"), {})


PHASE_OK = "ok"
"""A defence did its job at this phase."""
PHASE_FAILED = "failed"
"""A defence should have acted here and did not."""
PHASE_INFO = "info"
"""Something happened; it is neither a pass nor a failure on its own."""


def _chains(
    chains, findings, risks, variants, cases, evaluations, evidence_by_finding, violations, events
) -> list[dict]:
    """One attack chain as an ordered sequence of phases.

    The previous graph rendered raw enum values — "None", "Confirmed" — as node
    labels, which said nothing about what happened. This walks the attack the way
    a reader needs to follow it: what was wanted, how it was sent, what each
    defence did about it, what the application then did, and what proves it.
    """
    violations_by_variant: dict[str, list] = {}
    for violation in violations:
        violations_by_variant.setdefault(violation.variant_id or "", []).append(violation)

    events_by_variant: dict[str, list] = {}
    for event in events:
        events_by_variant.setdefault(event.variant_id or "", []).append(event)

    out = []
    for chain in sorted(chains, key=lambda c: c.severity or 0, reverse=True):
        chain_findings = [f for f in findings if f.id in (chain.finding_ids or [])]
        if not chain_findings:
            continue
        # The highest-scoring finding is the one worth narrating.
        finding = max(chain_findings, key=lambda f: risks[f.id].score if f.id in risks else 0)
        risk = risks.get(finding.id)
        variant = variants.get(finding.variant_id or "")
        case = cases.get(variant.attack_case_id) if variant else None
        evaluation = evaluations.get(finding.control_evaluation_id or "")
        variant_events = events_by_variant.get(finding.variant_id or "", [])
        chain_violations = violations_by_variant.get(finding.variant_id or "", [])
        chain_evidence = evidence_by_finding.get(finding.id, [])

        llm_events = [e for e in variant_events if e.event_type == "llm_io"]
        tool_events = [e for e in variant_events if e.event_type == "tool_call"]

        verdict = evaluation.verdict if evaluation else None
        control_failed = verdict == ControlVerdict.ACCEPTED

        phases = [
            {
                "n": 1,
                "name": "Objective",
                "status": PHASE_INFO,
                "headline": (case.original_intent if case else "unknown").replace("_", " "),
                "detail": (
                    f"The attacker's goal, expressed independently of wording. Tagged "
                    f"{finding.owasp_tag or 'unmapped'}"
                    f"{' · ' + (owasp_name(finding.owasp_tag) or '') if finding.owasp_tag else ''}."
                ),
                "data": None,
            },
            {
                "n": 2,
                "name": "Delivery",
                "status": PHASE_INFO,
                "headline": (
                    "Sent as written"
                    if not variant or variant.transformation == "none"
                    else f"Re-expressed using {variant.transformation}"
                ),
                "detail": (
                    "The objective reached the target in its original form — nothing had to be "
                    "disguised."
                    if not variant or variant.transformation == "none"
                    else "The same objective, represented differently to test whether the "
                    "target's controls generalise across form."
                ),
                "data": {"label": "Prompt sent", "text": variant.payload if variant else None},
            },
            {
                "n": 3,
                "name": "Target control",
                "status": PHASE_FAILED if control_failed else PHASE_OK,
                "headline": DEFENCE_OUTCOME.get(verdict, ("Unknown", ""))[0],
                "detail": DEFENCE_OUTCOME.get(verdict, ("", "No control decision recorded."))[1],
                "data": (
                    {
                        "label": "Recorded reason",
                        "text": evaluation.verdict_reason if evaluation else None,
                    }
                    if evaluation
                    else None
                ),
            },
            {
                "n": 4,
                "name": "Model behaviour",
                "status": PHASE_FAILED if llm_events else PHASE_INFO,
                "headline": (
                    "The model answered the injected instruction"
                    if llm_events
                    else "No model activity was observed"
                ),
                "detail": (
                    "The probe reached the model, which produced a response rather than declining."
                    if llm_events
                    else "The target exposed no telemetry for this probe."
                ),
                "data": (
                    {
                        "label": "Model output",
                        "text": (llm_events[0].payload or {}).get("output"),
                    }
                    if llm_events
                    else None
                ),
            },
            {
                "n": 5,
                "name": "Application behaviour",
                "status": PHASE_FAILED if tool_events else PHASE_OK,
                "headline": (
                    f"{len(tool_events)} privileged action(s) ran"
                    if tool_events
                    else "No privileged action was triggered"
                ),
                "detail": (
                    "The model's output was trusted as a command, so an injected instruction "
                    "became a real state change."
                    if tool_events
                    else "Nothing downstream acted on the model's output for this probe."
                ),
                "data": (
                    {
                        "label": "Tool invoked",
                        "text": "; ".join(
                            f"{(e.payload or {}).get('tool')}({(e.payload or {}).get('arguments')})"
                            for e in tool_events
                        ),
                    }
                    if tool_events
                    else None
                ),
            },
            {
                "n": 6,
                "name": "Policy check",
                "status": PHASE_FAILED if chain_violations else PHASE_OK,
                "headline": (
                    f"{len(chain_violations)} declared boundary crossed"
                    if chain_violations
                    else "No declared boundary was crossed"
                ),
                "detail": (
                    "Behaviour the target's own contract forbids, measured deterministically."
                    if chain_violations
                    else "Observed behaviour stayed inside the declared contract."
                ),
                "data": (
                    {
                        "label": "Violated",
                        "text": "; ".join(
                            f"{v.boundary} — observed: {v.observed}" for v in chain_violations
                        ),
                    }
                    if chain_violations
                    else None
                ),
            },
            {
                "n": 7,
                "name": "Evidence",
                "status": (
                    PHASE_FAILED if any(e.deterministic for e in chain_evidence) else PHASE_INFO
                ),
                "headline": (
                    f"{sum(1 for e in chain_evidence if e.deterministic)} deterministic proof(s)"
                    if any(e.deterministic for e in chain_evidence)
                    else "Supporting signals only"
                ),
                "detail": (
                    "Proof that a security boundary was crossed, independent of how the response "
                    "reads."
                    if any(e.deterministic for e in chain_evidence)
                    else "Nothing here can raise the finding above SUSPECTED on its own."
                ),
                "data": {
                    "label": "Collected",
                    "text": "; ".join(f"{e.evidence_type}: {e.summary}" for e in chain_evidence),
                },
            },
            {
                "n": 8,
                "name": "Outcome",
                "status": PHASE_FAILED
                if finding.verdict == FindingVerdict.CONFIRMED
                else PHASE_INFO,
                "headline": (
                    f"{finding.verdict}" + (f" · {risk.risk_level} {risk.score}/10" if risk else "")
                ),
                "detail": finding.mitigation or "",
                "data": None,
            },
        ]

        out.append(
            {
                "id": chain.id,
                "title": chain.title,
                "severity": chain.severity,
                "owasp": chain.owasp_tags or [],
                "verdict": finding.verdict,
                "risk": _pct(risk.score if risk else 0),
                "riskLevel": risk.risk_level if risk else "LOW",
                "findingId": finding.id,
                "findingTitle": finding.title,
                "failedPhases": sum(1 for p in phases if p["status"] == PHASE_FAILED),
                "phases": phases,
            }
        )
    return out


def _chain_summary(built_chains) -> dict:
    """Headline numbers for the worst chain.

    Pages previously hardcoded "86/100" and "Tool Invocation" here, which was
    invented — this derives both from the chain that actually scored highest.
    """
    if not built_chains:
        return {
            "risk": 0,
            "riskLevel": "LOW",
            "chains": 0,
            "worstPhase": None,
            "worstPhaseName": None,
            "breachedLayers": 0,
            "totalLayers": 4,
        }

    top = built_chains[0]
    # The last phase a defence failed at is how far the attack actually got.
    failed = [p for p in top["phases"] if p["status"] == "failed"]
    worst = failed[-1] if failed else None
    defence_phases = {3, 4, 5, 6}
    breached = sum(1 for p in top["phases"] if p["n"] in defence_phases and p["status"] == "failed")

    return {
        "risk": top["risk"],
        "riskLevel": top["riskLevel"],
        "chains": len(built_chains),
        "worstPhase": worst["n"] if worst else None,
        "worstPhaseName": worst["name"] if worst else None,
        "worstPhaseHeadline": worst["headline"] if worst else None,
        "breachedLayers": breached,
        "totalLayers": len(defence_phases),
        "title": top["findingTitle"],
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


EVENT_LABEL = {
    "llm_io": "Model answered",
    "tool_call": "Privileged action ran",
    # Keys are the emitted event_type verbatim. The earlier "retrieval"/"authz"
    # spellings never matched anything a target sends, so those rows fell back
    # to the title-cased type name.
    "rag_retrieval": "Documents retrieved",
    "authz_decision": "Authorization decision",
    "cross_tenant_retrieval": "Another tenant's document returned",
    "document_ingested": "Corpus written to",
}


def _timeline(events, variants) -> list[dict]:
    """Runtime events, told as what happened rather than as a type name.

    The previous version emitted forty rows reading "Llm Io" at an identical
    timestamp, which is noise. Each row now carries the probe that caused it and
    what actually happened, and privileged actions are marked so they stand out
    from ordinary traffic.
    """
    rows = []
    for event in events:
        payload = event.payload or {}
        variant = variants.get(event.variant_id or "")
        kind = event.event_type

        if kind == "tool_call":
            tool = payload.get("tool", "unknown")
            args = payload.get("arguments") or {}
            authorized = payload.get("authorized")
            detail = f"{tool}({', '.join(f'{k}={v}' for k, v in args.items())})"
            # The limit that was breached is named where the target reported one;
            # not every privileged action has a numeric ceiling to quote.
            limit = payload.get("max_authorized_percent") or payload.get("authorized_domain")
            note = (
                "within policy"
                if authorized
                else (f"EXCEEDS POLICY (allowed: {limit})" if limit else "NOT AUTHORIZED")
            )
        elif kind == "llm_io":
            detail = (payload.get("output") or "").strip().replace("\n", " ")[:140]
            note = payload.get("model", "")
        else:
            detail = str(payload)[:140]
            note = ""

        rows.append(
            {
                "time": _time(event.created_at),
                "label": EVENT_LABEL.get(kind, kind.replace("_", " ").title()),
                "kind": kind,
                "detail": detail,
                "note": note,
                "prompt": (variant.payload[:120] if variant else None),
                "critical": kind == "tool_call" and payload.get("authorized") is False,
            }
        )
    # Privileged actions first: they are the ones that changed state.
    return sorted(rows, key=lambda r: (not r["critical"], r["kind"] != "tool_call"))[:60]


def _axis_of(name: str) -> str:
    return "likelihood" if name in LIKELIHOOD_WEIGHTS else "impact"


def _risk_components(risks) -> list[dict]:
    """Factors of the highest-scoring finding, with their real weights."""
    if not risks:
        return []
    top = max(risks.values(), key=lambda r: r.score)
    rows = []
    for name, value in (top.factors or {}).items():
        established = isinstance(value, (int, float))
        axis = _axis_of(name)
        weight = (top.weights or {}).get(name, 0)
        rows.append(
            {
                "label": name.replace("_", " ").title(),
                "axis": axis,
                "score": int(round(float(value) * 100)) if established else None,
                "weight": int(round(weight * 100)),
                "established": established,
                "explain": (
                    f"{weight:.0%} of the {axis} axis."
                    if established
                    # An unmeasured factor is excluded from the weighting rather
                    # than counted as zero risk.
                    else "Not established for this finding; excluded from the score."
                ),
            }
        )
    return rows


def _contributions(risks) -> dict:
    """Real decomposition of the highest-scoring finding's composite.

    The model is `likelihood x impact x confidence`, so there is no single
    additive contribution per factor and presenting one would be a fabrication.
    What *is* true is that each factor is a weighted share of its own axis, and
    that the two axes multiply. This exports exactly that: per-factor shares
    within an axis, the two axis values, and the arithmetic that combines them.
    """
    if not risks:
        return {
            "features": [],
            "likelihood": None,
            "impact": None,
            "confidence": None,
            "final": 0,
            "unestablished": [],
            "arithmetic": None,
        }

    top = max(risks.values(), key=lambda r: r.score)
    factors = top.factors or {}
    weights = top.weights or {}
    established = {k: float(v) for k, v in factors.items() if isinstance(v, (int, float))}

    axes: dict[str, float | None] = {}
    for axis, axis_weights in (("likelihood", LIKELIHOOD_WEIGHTS), ("impact", IMPACT_WEIGHTS)):
        present = {k: v for k, v in established.items() if k in axis_weights}
        total = sum(axis_weights[k] for k in present)
        axes[axis] = (
            round(sum(axis_weights[k] * v for k, v in present.items()) / total, 3)
            if total
            else None
        )

    features = []
    for name, value in sorted(
        established.items(), key=lambda kv: weights.get(kv[0], 0) * kv[1], reverse=True
    ):
        axis = _axis_of(name)
        axis_weights = LIKELIHOOD_WEIGHTS if axis == "likelihood" else IMPACT_WEIGHTS
        present_total = sum(axis_weights[k] for k in established if k in axis_weights) or 1.0
        features.append(
            {
                "feature": name,
                "axis": axis,
                "value": round(value, 3),
                "weight": weights.get(name, 0),
                # Share of its own axis, which is what the arithmetic actually
                # does with it — not a share of the final score.
                "contribution": round((axis_weights[name] / present_total) * value, 3),
                "direction": "up" if value >= 0.5 else "down",
                "explain": f"{axis_weights[name] / present_total:.0%} of {axis}, value {value:.2f}",
            }
        )

    stored = top.axes or {}
    # Prefer what the scorer recorded. The axis values recomputed above are a
    # fallback for scores written before the column existed; the confidence
    # multiplier has no fallback, because dividing it back out of a rounded
    # composite yields a number close to it but not equal to it, and a
    # reconstruction must not be presented as a measurement.
    likelihood = _as_number(stored.get("likelihood"), axes["likelihood"])
    impact = _as_number(stored.get("impact"), axes["impact"])
    confidence = stored.get("confidence") if isinstance(stored.get("confidence"), float) else None

    parts = [
        f"{value:.2f} {name}"
        for name, value in (("likelihood", likelihood), ("impact", impact))
        if value is not None
    ]
    arithmetic = (
        " x ".join(parts)
        + (f" x {confidence:.2f} confidence" if confidence is not None else "")
        + f" = {top.score}/10"
        if parts
        else None
    )

    return {
        "features": features,
        "likelihood": likelihood,
        "impact": impact,
        "confidence": confidence,
        "final": top.score,
        "unestablished": [k for k, v in factors.items() if not isinstance(v, (int, float))],
        "arithmetic": arithmetic,
    }


def _as_number(stored, fallback):  # noqa: ANN001, ANN201
    """The stored axis value, or the recomputed one when it predates the column.

    An axis the scorer recorded as UNKNOWN comes back as that string, which is
    not a number and must not be rendered as one.
    """
    if isinstance(stored, (int, float)):
        return float(stored)
    if isinstance(stored, str):
        return None
    return fallback


DEFENCE_OUTCOME = {
    ControlVerdict.ACCEPTED: (
        "No control stopped it",
        "The probe reached the model untouched. Nothing in the target — no input filter, no "
        "moderation layer — rejected it.",
    ),
    ControlVerdict.REFUSED: (
        "Only the model pushed back",
        "No deployed control stopped the probe; the model itself declined. Alignment is not a "
        "security control and cannot be relied on as one.",
    ),
    ControlVerdict.REJECTED: (
        "A control rejected it",
        "Something in the target detected and rejected the probe before it reached the model.",
    ),
    ControlVerdict.ERROR: (
        "Inconclusive",
        "The target did not respond, so nothing can be concluded about its controls.",
    ),
}

WHY_IT_PROVES = {
    "canary": (
        "A synthetic token that exists only inside the model's privileged context was returned "
        "verbatim. Legitimate output has no path to it, so this is proof the boundary was crossed "
        "— not an inference from how the response reads."
    ),
    "policy_violation": (
        "Behaviour the target's own declared contract forbids was observed. The boundary was "
        "written by the target's owner and measured deterministically."
    ),
    "pii_detection": (
        "Sensitive data was returned in the response. Detected by pattern matching, so the finding "
        "does not depend on a model's opinion."
    ),
    "tool_log": "A privileged tool ran that this objective should never have been able to invoke.",
    "response_text": (
        "The wording suggests compliance, but nothing was proven. This is a supporting signal only "
        "and can never on its own raise a finding above SUSPECTED."
    ),
}


def _evidence(evidence, findings, variants, evaluations, violations) -> list[dict]:
    """Each evidence item, with the full causal chain that produced it.

    The point of this view is to answer three questions for every row: what was
    sent, what the target's defences did about it, and why the result counts as
    proof. Evidence without the prompt that caused it is not traceable.
    """
    by_finding = {f.id: f for f in findings}
    violations_by_variant: dict[str, list] = {}
    for violation in violations:
        violations_by_variant.setdefault(violation.variant_id or "", []).append(violation)

    rows = []
    for e in evidence:
        finding = by_finding.get(e.finding_id or "")
        variant = variants.get(finding.variant_id or "") if finding else None
        evaluation = evaluations.get(finding.control_evaluation_id or "") if finding else None
        verdict = evaluation.verdict if evaluation else None
        headline, explanation = DEFENCE_OUTCOME.get(
            verdict, ("Unknown", "No control decision recorded.")
        )

        rows.append(
            {
                "id": _short(e.id, "EV"),
                "evidenceId": e.id,
                "type": e.evidence_type.replace("_", " ").title(),
                "rawType": e.evidence_type,
                "deterministic": bool(e.deterministic),
                "finding": finding.title if finding else "—",
                "findingId": finding.id if finding else None,
                "verdict": finding.verdict if finding else None,
                "owasp": finding.owasp_tag if finding else None,
                "owaspName": owasp_name(finding.owasp_tag) if finding else None,
                "confidence": int(round((e.confidence_contribution or 0) * 100)),
                "summary": e.summary or "",
                "timestamp": _time(e.created_at),
                # What was actually sent to the target.
                "prompt": variant.payload if variant else None,
                "transformation": variant.transformation if variant else None,
                # What the target's defences did about it.
                "controlVerdict": verdict,
                "defenceHeadline": headline,
                "defenceExplain": explanation,
                "controlReason": evaluation.verdict_reason if evaluation else None,
                "statusCode": evaluation.status_code if evaluation else None,
                "latencyMs": round(evaluation.latency_ms, 1)
                if evaluation and evaluation.latency_ms
                else None,
                # What came back.
                "response": (evaluation.response_body or "")[:1200] if evaluation else None,
                # Why this counts as proof.
                "whyItProves": WHY_IT_PROVES.get(e.evidence_type, "Supporting signal."),
                "boundaries": [
                    {"boundary": v.boundary, "expected": v.expected, "observed": v.observed}
                    for v in violations_by_variant.get(finding.variant_id if finding else "", [])
                ],
                "content": e.content or {},
            }
        )
    # Deterministic proof first — that is what a reader needs to see.
    return sorted(rows, key=lambda r: (not r["deterministic"], -r["confidence"]))


def _scenarios(findings, risks, variants, cases, evaluations, violations, events) -> list[dict]:
    """One row per attack objective, with the remediation it actually earned.

    Grouped by attack case rather than by probe: twelve representations of one
    objective are one scenario to remediate, and listing each separately buries
    the point under near-identical rows.

    Remediation is unioned across the objective's findings, preserving order and
    dropping repeats, so a scenario whose probes crossed different boundaries
    carries guidance for each of them.
    """
    violations_by_variant: dict[str, list] = {}
    for violation in violations:
        violations_by_variant.setdefault(violation.variant_id or "", []).append(violation)

    events_by_variant: dict[str, list] = {}
    for event in events:
        events_by_variant.setdefault(event.variant_id or "", []).append(event)

    grouped: dict[str, list] = {}
    for finding in findings:
        variant = variants.get(finding.variant_id or "")
        key = variant.attack_case_id if variant else f"unattributed:{finding.id}"
        grouped.setdefault(key, []).append(finding)

    rows = []
    for case_id, group in grouped.items():
        case = cases.get(case_id)
        worst = max(group, key=lambda f: risks[f.id].score if f.id in risks else 0)
        risk = risks.get(worst.id)

        # Union the layered remediation across the objective's findings.
        merged: dict[str, list[str]] = {"mitigations": [], "preventive": [], "detection": []}
        summaries: list[str] = []
        for finding in group:
            block = (finding.extra or {}).get("remediation") or {}
            if summary := block.get("summary"):
                if summary not in summaries:
                    summaries.append(summary)
            for field in merged:
                for item in block.get(field) or []:
                    if item not in merged[field]:
                        merged[field].append(item)

        verdicts: dict[str, int] = {}
        boundaries: dict[str, None] = {}
        families: dict[str, None] = {}
        observed_events: dict[str, None] = {}
        for finding in group:
            evaluation = evaluations.get(finding.control_evaluation_id or "")
            if evaluation:
                label = VERDICT_LABEL.get(evaluation.verdict, evaluation.verdict)
                verdicts[label] = verdicts.get(label, 0) + 1
            variant = variants.get(finding.variant_id or "")
            if variant:
                families.setdefault(variant.transformation, None)
            for violation in violations_by_variant.get(finding.variant_id or "", []):
                boundaries.setdefault(violation.boundary, None)
            for event in events_by_variant.get(finding.variant_id or "", []):
                observed_events.setdefault(event.event_type, None)

        rows.append(
            {
                "id": _short(case_id, "SC"),
                "caseId": case_id,
                "title": worst.title,
                "objective": (case.original_intent if case else None),
                "category": (case.category if case else None),
                "owasp": worst.owasp_tag,
                "owaspName": owasp_name(worst.owasp_tag),
                "severity": risk.risk_level if risk else "LOW",
                "risk": _pct(risk.score if risk else 0),
                "verdict": worst.verdict,
                "probes": len(group),
                "outcomes": verdicts,
                "boundaries": list(boundaries),
                "transformations": list(families),
                "events": list(observed_events),
                "findingIds": [_short(f.id, "F") for f in group],
                "summary": summaries[0] if summaries else None,
                "mitigations": merged["mitigations"],
                "preventive": merged["preventive"],
                "detection": merged["detection"],
            }
        )
    return sorted(rows, key=lambda r: r["risk"], reverse=True)


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
        "riskPrev": _posture_of(session, previous.id) if previous else None,
        "riskCurrent": _posture_of(session, scan.id),
        "nextFocus": next_focus,
        "detail": (
            {
                "category": f"{worst_tag} {owasp_name(worst_tag) or ''}".strip(),
                "prev": _posture_of(session, previous.id) if previous else None,
                "current": _posture_of(session, scan.id),
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
