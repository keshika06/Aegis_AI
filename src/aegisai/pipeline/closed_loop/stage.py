"""Stage 11 — Closed-Loop Replay & Adaptive Engine.

Two jobs, in order:

1. Turn every CONFIRMED finding from this scan into a stored regression test.
2. Replay any tests carried over from earlier scans of the same target, so a
   reintroduced weakness is caught rather than rediscovered from scratch.

This is what makes AegisAI get stricter over time instead of merely louder.
"""

from __future__ import annotations

from sqlalchemy import select

from aegisai.models.analysis import RiskScore
from aegisai.models.attack import AttackVariant
from aegisai.models.enums import (
    FindingVerdict,
    RegressionStatus,
    RegressionVerdict,
    Stage,
)
from aegisai.models.finding import Finding
from aegisai.models.policy import Violation
from aegisai.models.regression import RegressionTest
from aegisai.pipeline.base import ScanContext, StageResult
from aegisai.pipeline.closed_loop.engine import make_test, record_result, replay


class ClosedLoopStage:
    stage = Stage.CLOSED_LOOP

    def __init__(self, replay_existing: bool = True) -> None:
        self.replay_existing = replay_existing

    def run(self, ctx: ScanContext) -> StageResult:
        generated = self._generate(ctx)
        replayed, regressed = self._replay_prior(ctx) if self.replay_existing else (0, 0)

        parts = [f"{generated} regression test(s) stored"]
        if replayed:
            parts.append(f"{replayed} prior test(s) replayed, {regressed} still failing")
        return StageResult(
            ok=True,
            summary="; ".join(parts),
            counts={"generated": generated, "replayed": replayed, "regressed": regressed},
        )

    def _generate(self, ctx: ScanContext) -> int:
        confirmed = list(
            ctx.session.scalars(
                select(Finding).where(
                    Finding.scan_id == ctx.scan_id,
                    Finding.verdict == FindingVerdict.CONFIRMED,
                )
            )
        )
        if not confirmed:
            return 0

        variants = {
            v.id: v
            for v in ctx.session.scalars(
                select(AttackVariant).where(AttackVariant.scan_id == ctx.scan_id)
            )
        }
        violations_by_variant: dict[str, list[Violation]] = {}
        for violation in ctx.session.scalars(
            select(Violation).where(Violation.scan_id == ctx.scan_id)
        ):
            violations_by_variant.setdefault(violation.variant_id or "", []).append(violation)

        endpoints = (ctx.profile.endpoints if ctx.profile else None) or []
        surface = next((e for e in endpoints if e.get("is_chat_surface")), None)
        text_key = (surface or {}).get("text_key") or "message"
        path = (surface or {}).get("path") or "/chat"

        created = 0
        for finding in confirmed:
            # One test per confirmed finding, keyed by origin so a re-scan does
            # not accumulate duplicates of the same weakness.
            existing = ctx.session.scalar(
                select(RegressionTest).where(RegressionTest.origin_finding_id == finding.id)
            )
            if existing is not None:
                continue

            variant = variants.get(finding.variant_id or "")
            if variant is None:
                continue
            boundaries = violations_by_variant.get(finding.variant_id or "", [])

            ctx.session.add(
                make_test(
                    finding_id=finding.id,
                    target_id=ctx.target_id,
                    payload=variant.payload,
                    transformation=variant.transformation,
                    endpoint=path,
                    owasp_tag=finding.owasp_tag,
                    boundary=boundaries[0].boundary if boundaries else None,
                    max_attempts=ctx.config.scan.max_regression_attempts,
                    text_key=text_key,
                )
            )
            created += 1

        ctx.session.flush()
        return created

    def _replay_prior(self, ctx: ScanContext) -> tuple[int, int]:
        """Replay tests from earlier scans of this same target.

        Scoped to this target: replaying another target's tests would consume
        their lifecycle state and report failures against the wrong system.
        """
        prior = list(
            ctx.session.scalars(
                select(RegressionTest).where(
                    RegressionTest.target_id == ctx.target_id,
                    RegressionTest.status.in_(
                        [RegressionStatus.ACTIVE, RegressionStatus.REGRESSED]
                    ),
                )
            )
        )
        # Tests generated moments ago in this same scan have nothing to prove yet.
        this_scan_findings = {
            f.id for f in ctx.session.scalars(select(Finding).where(Finding.scan_id == ctx.scan_id))
        }
        prior = [t for t in prior if t.origin_finding_id not in this_scan_findings]
        if not prior:
            return 0, 0

        risk_by_finding = {
            r.finding_id: r.score
            for r in ctx.session.scalars(select(RiskScore).where(RiskScore.scan_id == ctx.scan_id))
        }

        regressed = 0
        replay_total = len(prior)
        for replay_index, test in enumerate(prior, start=1):
            ctx.report(
                f"replaying {replay_index}/{replay_total} · {test.owasp_tag or 'unmapped'}",
                transient=True,
            )
            outcome = replay(
                test,
                target_url=ctx.target_url,
                target_type=ctx.target_type,
                config=ctx.config,
            )
            record_result(
                ctx.session,
                test,
                outcome,
                scan_id=ctx.scan_id,
                risk_score=risk_by_finding.get(test.origin_finding_id),
            )
            if outcome.verdict == RegressionVerdict.REGRESSED:
                regressed += 1

        ctx.session.flush()
        return len(prior), regressed
