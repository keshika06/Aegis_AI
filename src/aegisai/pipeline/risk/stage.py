"""Stage 9 — Risk Scoring."""

from __future__ import annotations

from sqlalchemy import select

from aegisai.models.analysis import AttackChain, RiskScore
from aegisai.models.attack import AttackVariant
from aegisai.models.enums import Stage
from aegisai.models.execution import ControlEvaluation
from aegisai.models.finding import Evidence, Finding
from aegisai.models.policy import Violation
from aegisai.pipeline.base import ScanContext, StageResult
from aegisai.pipeline.risk.scoring import RiskInputs, score


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

        chain_severity_by_finding: dict[str, float] = {}
        for chain in ctx.session.scalars(
            select(AttackChain).where(AttackChain.scan_id == ctx.scan_id)
        ):
            for finding_id in chain.finding_ids or []:
                chain_severity_by_finding[finding_id] = chain.severity or 0.0

        counts: dict[str, int] = {}
        top = 0.0
        for finding in findings:
            variant = variants.get(finding.variant_id or "")
            evaluation = evaluations.get(finding.control_evaluation_id or "")
            violations = violations_by_variant.get(finding.variant_id or "", [])

            result = score(
                RiskInputs(
                    verdict=finding.verdict,
                    confidence=finding.confidence,
                    control_verdict=evaluation.verdict if evaluation else None,
                    transformation=variant.transformation if variant else None,
                    boundary_severities=[
                        str((v.detail or {}).get("severity", "medium")) for v in violations
                    ],
                    evidence_types=[
                        e.evidence_type for e in evidence_by_finding.get(finding.id, [])
                    ],
                    chain_severity=chain_severity_by_finding.get(finding.id),
                )
            )

            ctx.session.add(
                RiskScore(
                    scan_id=ctx.scan_id,
                    finding_id=finding.id,
                    score=result.score,
                    risk_level=result.level,
                    factors=result.factors,
                    weights=result.weights,
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
