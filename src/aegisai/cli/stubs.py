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
        hint="Implemented so far:  doctor, init, config, target",
    )
