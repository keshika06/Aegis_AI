"""Shared type for Stage 2B output.

A variation preserves the *security objective* of its parent attack case while
changing how that objective is expressed. That lineage is what makes guardrail
evasion measurable: if the base case was rejected and a variation was accepted,
the target's control does not generalise across representation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegisai.models.enums import TransformationFamily


@dataclass
class Variation:
    transformation: TransformationFamily
    payload: str
    """What is sent. For a multi-turn variation this is the final turn."""

    conversation: list[dict[str, str]] | None = None
    """Ordered turns, when the objective is split across a conversation."""

    engine: str = "native"
    note: str = ""
    """How this representation differs — shown in reports so a reader can see
    exactly which evasion technique the target failed to catch."""

    metadata: dict = field(default_factory=dict)

    @property
    def is_multi_turn(self) -> bool:
        return bool(self.conversation and len(self.conversation) > 1)
