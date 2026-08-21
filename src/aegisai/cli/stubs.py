"""Placeholder for commands whose implementation lands in a later phase.

The command, its flags, and its help text exist from Phase 0 so the CLI contract
is reviewable up front — but an unimplemented command exits non-zero rather than
pretending to succeed, so no script ever mistakes a stub for a clean run.
"""

from __future__ import annotations

from typing import NoReturn

from aegisai.core.exceptions import AegisError


def planned(command: str, phase: str) -> NoReturn:
    raise AegisError(
        f"`{command}` is not implemented yet — planned for {phase}.",
        # Naming what *does* work matters more than naming what does not: the
        # previous hint still listed the Phase 0 four, long after the pipeline
        # landed, so it told a reader almost nothing works.
        hint=(
            "Everything else is implemented:  doctor · init · config · target · "
            "discover · scan run/list/status/report · findings · risk · chain · "
            "attack · regression · labs · dashboard"
        ),
    )
