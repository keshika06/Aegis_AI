"""Stage 2B — Attack/Evasion Orchestrator.

Generates variations of each attack case that preserve its security objective
while changing how that objective is represented. The point is not to invent new
attacks: it is to measure whether the target's own controls generalise across
representation, encoding, framing, and conversation structure.

Every variation keeps a link to its parent case, which is what makes the
guardrail-evasion rate computable in Stage 9 — base rejected, variation
accepted, same objective.
"""

from __future__ import annotations

from sqlalchemy import select

from aegisai.llm.router import ProviderRouter
from aegisai.models.attack import AttackCase, AttackVariant
from aegisai.models.enums import Stage, TransformationFamily
from aegisai.pipeline.base import ScanContext, StageResult
from aegisai.pipeline.orchestrator.engines.native import DEFAULT_FAMILIES, NativeEngine

MAX_VARIANTS_PER_CASE = 8
"""Bounds the combinatorial blow-up: 19 cases x every family would be hundreds
of probes against a target the tester has to wait on."""


class EvasionStage:
    stage = Stage.EVASION_ORCHESTRATOR

    def __init__(
        self,
        engines: list | None = None,
        families: list[str] | None = None,
        per_case: int = MAX_VARIANTS_PER_CASE,
        use_llm: bool = True,
    ) -> None:
        self.engines = engines
        self.families = families
        self.per_case = per_case
        self.use_llm = use_llm

    def run(self, ctx: ScanContext) -> StageResult:
        families = self.families or ctx.families or list(DEFAULT_FAMILIES)

        router = ProviderRouter.from_config(ctx.config) if self.use_llm else None
        engines = self.engines or [
            NativeEngine(
                router=router,
                per_family=2,
                timeout=float(ctx.config.llm.timeout_seconds),
            )
        ]

        cases = list(
            ctx.session.scalars(select(AttackCase).where(AttackCase.scan_id == ctx.scan_id))
        )
        if not cases:
            return StageResult(ok=False, summary="no attack cases to vary", counts={})

        family_counts: dict[str, int] = {}
        created = 0

        for case in cases:
            produced = 0
            for engine in engines:
                if not engine.available():
                    continue
                for variation in engine.variations(case.payload, families):
                    if produced >= self.per_case:
                        break
                    ctx.session.add(
                        AttackVariant(
                            scan_id=ctx.scan_id,
                            attack_case_id=case.id,
                            transformation=variation.transformation,
                            engine=variation.engine,
                            payload=variation.payload,
                            conversation=variation.conversation,
                            extra={"note": variation.note, **variation.metadata},
                        )
                    )
                    family_counts[variation.transformation.value] = (
                        family_counts.get(variation.transformation.value, 0) + 1
                    )
                    produced += 1
                    created += 1

        ctx.session.flush()

        detail = ", ".join(f"{n} {f}" for f, n in sorted(family_counts.items()))
        return StageResult(
            ok=created > 0,
            summary=(
                f"{created} evasion variant(s) across {len(family_counts)} family(ies): {detail}"
            ),
            counts={"variants": created, **family_counts},
        )


ALL_FAMILIES = [
    TransformationFamily.ENCODING.value,
    TransformationFamily.SEMANTIC.value,
    TransformationFamily.CONTEXT.value,
    TransformationFamily.FRAGMENTATION.value,
    TransformationFamily.MUTATION.value,
]
