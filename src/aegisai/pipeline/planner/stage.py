"""Stage 2A — Attack Planner.

Selects attacks based on what Stage 1 actually discovered, so every case is
traceable to a specific surface element rather than being generic payload replay.

The OWASP-tagged library is the floor and always applies. LLM assistance adds
application-aware cases on top; when no model answers, planning continues on the
library alone and records that assistance was unavailable — degraded coverage is
reported, never silently passed off as a clean scan.
"""

from __future__ import annotations

from pathlib import Path

from aegisai.knowledge_base.library import AttackTemplate, select_for_target
from aegisai.llm.router import ProviderRouter
from aegisai.models.attack import AttackCase, AttackVariant
from aegisai.models.enums import AttackSource, Stage, TransformationFamily
from aegisai.pipeline.base import ScanContext, StageResult
from aegisai.pipeline.planner.llm_planner import propose_attacks


class PlannerStage:
    stage = Stage.ATTACK_PLANNER

    def __init__(
        self,
        library_dir: Path | None = None,
        router: ProviderRouter | None = None,
        use_llm: bool = True,
    ) -> None:
        self.library_dir = library_dir
        self.router = router
        self.use_llm = use_llm

    def run(self, ctx: ScanContext) -> StageResult:
        endpoints = (ctx.profile.endpoints if ctx.profile else None) or []
        chat_surfaces = [e for e in endpoints if e.get("is_chat_surface")]
        if not chat_surfaces:
            return StageResult(
                ok=False,
                summary="no chat surface discovered — nothing to attack",
                counts={"attack_cases": 0},
            )

        surface = chat_surfaces[0]
        templates = select_for_target(ctx.target_type, directory=self.library_dir)

        llm_templates: list[AttackTemplate] = []
        llm_error: str | None = None
        if self.use_llm:
            ctx.report("asking the model for additional attack cases", transient=True)
            router = self.router or ProviderRouter.from_config(ctx.config)
            llm_templates, llm_error = propose_attacks(
                router,
                target_url=ctx.target_url,
                target_type=ctx.target_type,
                endpoints=endpoints,
                covered_intents=[t.intent for t in templates],
                timeout=float(ctx.config.llm.timeout_seconds),
            )

        for template in [*templates, *llm_templates]:
            case = AttackCase(
                scan_id=ctx.scan_id,
                source=AttackSource.PLANNER,
                owasp_tag=template.owasp,
                category=template.category,
                original_intent=template.intent,
                payload=template.payload,
                target_surface_element=f"{surface['method']} {surface['path']}",
                target_endpoint=surface["path"],
                extra={
                    "library_id": template.id,
                    "evidence": template.evidence,
                    "origin": template.source,
                },
            )
            ctx.session.add(case)
            ctx.session.flush()

            # Every case gets a base variant with no transformation applied, so
            # execution has one uniform input. Stage 2B adds sibling variants
            # against the same case without a schema change.
            ctx.session.add(
                AttackVariant(
                    scan_id=ctx.scan_id,
                    attack_case_id=case.id,
                    transformation=TransformationFamily.NONE,
                    engine="native",
                    payload=case.payload,
                )
            )

        ctx.session.flush()
        total = len(templates) + len(llm_templates)

        if llm_error:
            assistance = "LLM unavailable — library only"
        elif llm_templates:
            assistance = f"+{len(llm_templates)} LLM-proposed"
        elif self.use_llm:
            assistance = "LLM returned no usable proposals"
        else:
            assistance = "library only"

        return StageResult(
            ok=total > 0,
            summary=(
                f"{total} attack case(s) targeting {surface['method']} {surface['path']}"
                f" ({assistance})"
            ),
            counts={
                "attack_cases": total,
                "library": len(templates),
                "llm_proposed": len(llm_templates),
            },
        )
