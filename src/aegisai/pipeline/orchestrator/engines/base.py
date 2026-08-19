"""Attack engine contract.

One interface for the built-in transformation families and for external
red-teaming tools (garak, PyRIT, Promptfoo). Adapters live behind this so an
optional dependency being absent removes one engine's contribution rather than
breaking the scan.
"""

from __future__ import annotations

from typing import Protocol

from aegisai.pipeline.orchestrator.variations import Variation


class AttackEngine(Protocol):
    name: str

    def available(self) -> bool:
        """Whether this engine can run here. Must not raise."""
        ...

    def variations(self, payload: str, families: list[str] | None = None) -> list[Variation]:
        """Produce evasion variations of one payload. Must not raise."""
        ...
