"""Stage 2A — Attack Planner.

Selects attacks from an OWASP-tagged library based on what Stage 1 actually
found, so every case is traceable to a specific surface element rather than
being generic payload replay.

Phase 1 uses static YAML. Phase 2 adds LLM-assisted planning on top — the
library stays the floor, so planning never depends on a model being reachable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from aegisai.models.attack import AttackCase, AttackVariant
from aegisai.models.enums import AttackSource, Stage, TransformationFamily
from aegisai.pipeline.base import ScanContext, StageResult

LIBRARY_DIR = Path(__file__).resolve().parents[2] / "knowledge_base" / "payloads"


def load_library(path: Path | None = None) -> list[dict[str, Any]]:
    source = path or (LIBRARY_DIR / "lab1.yaml")
    if not source.exists():
        return []
    data = yaml.safe_load(source.read_text(encoding="utf-8")) or []
    return [entry for entry in data if isinstance(entry, dict)]


class PlannerStage:
    stage = Stage.ATTACK_PLANNER

    def __init__(self, library_path: Path | None = None) -> None:
        self.library_path = library_path

    def run(self, ctx: ScanContext) -> StageResult:
        library = load_library(self.library_path)
        endpoints = (ctx.profile.endpoints if ctx.profile else None) or []
        chat_surfaces = [e for e in endpoints if e.get("is_chat_surface")]

        if not chat_surfaces:
            return StageResult(
                ok=False,
                summary="no chat surface discovered - nothing to attack",
                counts={"attack_cases": 0},
            )

        surface = chat_surfaces[0]
        created = 0
        for entry in library:
            case = AttackCase(
                scan_id=ctx.scan_id,
                source=AttackSource.PLANNER,
                owasp_tag=entry.get("owasp"),
                category=entry.get("category"),
                original_intent=entry.get("intent", "unspecified"),
                payload=entry["payload"],
                target_surface_element=f"{surface['method']} {surface['path']}",
                target_endpoint=surface["path"],
                extra={"library_id": entry.get("id"), "evidence": entry.get("evidence", "none")},
            )
            ctx.session.add(case)
            ctx.session.flush()

            # Every case gets a base variant with no transformation applied, so
            # execution has a single uniform input. Stage 2B later adds sibling
            # variants against the same case - no schema change needed.
            ctx.session.add(
                AttackVariant(
                    scan_id=ctx.scan_id,
                    attack_case_id=case.id,
                    transformation=TransformationFamily.NONE,
                    engine="native",
                    payload=case.payload,
                )
            )
            created += 1

        ctx.session.flush()
        return StageResult(
            ok=created > 0,
            summary=f"{created} attack case(s) targeting {surface['method']} {surface['path']}",
            counts={"attack_cases": created},
        )
