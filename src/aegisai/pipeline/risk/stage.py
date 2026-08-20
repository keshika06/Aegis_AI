"""Stage 9 — Risk Scoring."""

from __future__ import annotations

from sqlalchemy import select

from aegisai.models.analysis import RiskScore
from aegisai.models.attack import AttackVariant
from aegisai.models.enums import ControlVerdict, Stage
from aegisai.models.execution import ControlEvaluation
from aegisai.models.finding import Evidence, Finding
from aegisai.models.policy import Violation
from aegisai.models.runtime import RuntimeEvent
from aegisai.pipeline.base import ScanContext, StageResult
from aegisai.pipeline.risk.scoring import RISK_MODEL_VERSION, RiskInputs, score


class RiskStage:
    stage = Stage.RISK_SCORING

    def run(self, ctx: ScanContext) -> StageResult:
        findings = list(ctx.session.scalars(select(Finding).where(Finding.scan_id == ctx.scan_id)))
        if not findings:
            return StageResult(ok=True, summary="no findings to score", counts={})

        evidence_by_finding: dict[str, list[Evidence]] = {}
        for item in ctx.session.scalars(select(Evidence).where(Evidence.scan_id == ctx.scan_id)):
            evidence_by_finding.setdefault(item.finding_id or "", []).append(item)

        violations_by_variant: dict[str, list[Violation]] = {}
        for violation in ctx.session.scalars(
            select(Violation).where(Violation.scan_id == ctx.scan_id)
        ):
            violations_by_variant.setdefault(violation.variant_id or "", []).append(violation)

        events_by_variant: dict[str, set[str]] = {}
        for event in ctx.session.scalars(
            select(RuntimeEvent).where(RuntimeEvent.scan_id == ctx.scan_id)
        ):
            events_by_variant.setdefault(event.variant_id or "", set()).add(event.event_type)

        variants = {
            v.id: v
            for v in ctx.session.scalars(
                select(AttackVariant).where(AttackVariant.scan_id == ctx.scan_id)
            )
        }
        evaluations = {
            e.id: e
            for e in ctx.session.scalars(
                select(ControlEvaluation).where(ControlEvaluation.scan_id == ctx.scan_id)
            )
        }

        # Reproducibility is measured per objective, not per probe: how many of
        # the representations we sent for this attack case actually landed. One
        # objective probed twelve ways and landing twice is a very different
        # weakness from one that landed all twelve times, and the score has to
        # be able to say so.
        #
        # A probe the target never answered is excluded from the denominator. An
        # ERROR is not evidence that the objective failed, it is the absence of
        # evidence, and counting it as a failed attempt would understate how
        # reproducible the weakness is.
        answered_variants = {
            e.variant_id for e in evaluations.values() if e.verdict != ControlVerdict.ERROR
        }
        tried_per_case: dict[str, int] = {}
        for variant in variants.values():
            if variant.id in answered_variants:
                tried_per_case[variant.attack_case_id] = (
                    tried_per_case.get(variant.attack_case_id, 0) + 1
                )

        succeeded_per_case: dict[str, set[str]] = {}
        for finding in findings:
            variant = variants.get(finding.variant_id or "")
            if variant:
                succeeded_per_case.setdefault(variant.attack_case_id, set()).add(variant.id)

        counts: dict[str, int] = {}
        top = 0.0
        for finding in findings:
            variant = variants.get(finding.variant_id or "")
            evaluation = evaluations.get(finding.control_evaluation_id or "")
            violations = violations_by_variant.get(finding.variant_id or "", [])
            case_id = variant.attack_case_id if variant else None

            result = score(
                RiskInputs(
                    verdict=finding.verdict,
                    confidence=finding.confidence,
                    control_verdict=evaluation.verdict if evaluation else None,
                    transformation=variant.transformation if variant else None,
                    boundary_severities=[
                        str((v.detail or {}).get("severity", "medium")) for v in violations
                    ],
                    boundary_rules=[v.rule for v in violations if v.rule],
                    event_types=sorted(events_by_variant.get(finding.variant_id or "", set())),
                    evidence_types=[
                        e.evidence_type for e in evidence_by_finding.get(finding.id, [])
                    ],
                    variants_tried=tried_per_case.get(case_id) if case_id else None,
                    variants_succeeded=(
                        len(succeeded_per_case.get(case_id, set())) if case_id else None
                    ),
                )
            )

            ctx.session.add(
                RiskScore(
                    scan_id=ctx.scan_id,
                    finding_id=finding.id,
                    score=result.score,
                    risk_level=result.level,
                    model_version=RISK_MODEL_VERSION,
                    factors=result.factors,
                    weights=result.weights,
                    axes={
                        "likelihood": result.likelihood,
                        "impact": result.impact,
                        "confidence": result.confidence_multiplier,
                    },
                    explanation=result.explanation,
                )
            )
            counts[result.level.value] = counts.get(result.level.value, 0) + 1
            top = max(top, result.score)

        ctx.session.flush()

        detail = " · ".join(f"{n} {k}" for k, n in sorted(counts.items()))
        return StageResult(
            ok=True,
            summary=f"top score {top}/10 — {detail}",
            counts={**counts, "top_score": int(top)},
        )
