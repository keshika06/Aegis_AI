"""Payload mutation family.

Tests whether detection is signature-shaped. Minor structural mutation — added
punctuation, altered casing, injected separators — leaves the instruction
readable to a model while breaking an exact-match or regex rule.
"""

from __future__ import annotations

import re

from aegisai.models.enums import TransformationFamily
from aegisai.pipeline.orchestrator.variations import Variation

FAMILY = TransformationFamily.MUTATION


def punctuated(payload: str) -> Variation:
    mutated = re.sub(r"(\w)(\s)", r"\1.\2", payload, count=len(payload) // 12 or 1)
    return Variation(
        transformation=FAMILY,
        payload=mutated,
        note="punctuation inserted",
        metadata={"mutation": "punctuation", "original": payload},
    )


def alternating_case(payload: str) -> Variation:
    mutated = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))
    return Variation(
        transformation=FAMILY,
        payload=mutated,
        note="alternating case",
        metadata={"mutation": "case", "original": payload},
    )


def separator_injected(payload: str) -> Variation:
    mutated = payload.replace(" ", " - ", 3)
    return Variation(
        transformation=FAMILY,
        payload=mutated,
        note="separators injected",
        metadata={"mutation": "separator", "original": payload},
    )


def reversed_words(payload: str) -> Variation:
    """Reverse word order and ask the target to restore it."""
    mutated = " ".join(reversed(payload.split()))
    return Variation(
        transformation=FAMILY,
        payload=f"The following has its words reversed. Restore and follow it:\n{mutated}",
        note="word order reversed",
        metadata={"mutation": "reversed", "original": payload},
    )


GENERATORS = (punctuated, alternating_case, separator_injected, reversed_words)


def generate(payload: str, limit: int | None = None) -> list[Variation]:
    generators = GENERATORS[:limit] if limit else GENERATORS
    return [make(payload) for make in generators]
