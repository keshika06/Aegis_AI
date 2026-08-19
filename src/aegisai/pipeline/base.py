"""Contracts every pipeline stage shares.

Frozen first, before any stage is written, so stages can be built in parallel
without colliding at integration time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from sqlalchemy.orm import Session

from aegisai.core.config import Config
from aegisai.models.enums import Stage
from aegisai.models.scan import Profile


@dataclass
class ScanContext:
    """Everything a stage needs, and the handoff between stages.

    `profile` is set by Stage 1 and read by every later stage — it is how
    discovery's findings reach the attack planner and the executor.
    """

    scan_id: str
    session: Session
    config: Config
    target_url: str
    target_id: str
    target_type: str = "llm"
    """Discovered shape of the target; selects which attack cases apply."""

    families: list[str] | None = None
    """Stage 2B transformation families to generate. None means the defaults."""

    profile: Profile | None = None


@dataclass
class StageResult:
    ok: bool
    summary: str
    """One line, shown live in the CLI as the stage completes."""

    counts: dict[str, int] = field(default_factory=dict)


class PipelineStage(Protocol):
    stage: Stage

    def run(self, ctx: ScanContext) -> StageResult: ...
