"""Contracts every pipeline stage shares.

Frozen first, before any stage is written, so stages can be built in parallel
without colliding at integration time.
"""

from __future__ import annotations

from collections.abc import Callable
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

    on_activity: Callable[[str, bool], None] | None = None
    """Sub-stage progress, for a caller that wants to render it live.

    A stage's `summary` is only produced once it finishes, so Stage 3/4 — which
    can run for twenty minutes — left the screen showing nothing at all. Long
    stages report what they are doing through this; short ones need not.
    """

    def report(self, message: str, *, transient: bool = False) -> None:
        """Report sub-stage progress, if anyone is listening.

        `transient` marks in-flight noise — "probe 8 of 143, sending" — which a
        spinner should show and a log should not. An outcome is not transient:
        it is the line someone scrolls back to find.
        """
        if self.on_activity is not None:
            self.on_activity(message, transient)


@dataclass
class StageResult:
    ok: bool
    summary: str
    """One line, shown live in the CLI as the stage completes."""

    counts: dict[str, int] = field(default_factory=dict)


class PipelineStage(Protocol):
    stage: Stage

    def run(self, ctx: ScanContext) -> StageResult: ...
