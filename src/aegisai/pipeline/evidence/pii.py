"""Sensitive-data detection.

Ships a dependency-free detector and uses Microsoft Presidio when it is
installed. Presidio pulls in spaCy and a language model, which is a heavy
install for a CLI that must work offline on a laptop, so it is optional rather
than required — coverage improves when it is present and the stage still runs
when it is not.

Detected values are never logged in full: a finding records that an email
appeared, not the address itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

PATTERNS: dict[str, re.Pattern[str]] = {
    "EMAIL": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b"),
    "PHONE": re.compile(r"\b(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "US_SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "IP_ADDRESS": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "API_KEY": re.compile(r"\b(?:sk|pk|api|key)[-_][A-Za-z0-9]{16,}\b", re.IGNORECASE),
}


@dataclass
class PIIMatch:
    entity_type: str
    redacted: str
    """A masked form. The raw value is deliberately never carried forward."""

    detector: str


def _redact(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def luhn_valid(digits: str) -> bool:
    """Reduce credit-card false positives from ordinary long numbers."""
    numbers = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(numbers) <= 19:
        return False
    checksum = 0
    parity = len(numbers) % 2
    for index, digit in enumerate(numbers):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


@lru_cache(maxsize=1)
def _presidio_analyzer():  # noqa: ANN202 - third-party type, optional import
    try:
        from presidio_analyzer import AnalyzerEngine
    except Exception:  # noqa: BLE001 - absence is expected, not exceptional
        return None
    try:
        return AnalyzerEngine()
    except Exception:  # noqa: BLE001 - missing spaCy model, etc.
        return None


def detect(text: str) -> list[PIIMatch]:
    """Find sensitive values in `text`, de-duplicated by entity type and value."""
    if not text:
        return []

    matches: dict[tuple[str, str], PIIMatch] = {}

    for entity_type, pattern in PATTERNS.items():
        for raw in pattern.findall(text):
            value = raw if isinstance(raw, str) else raw[0]
            if entity_type == "CREDIT_CARD" and not luhn_valid(value):
                continue
            matches.setdefault(
                (entity_type, value), PIIMatch(entity_type, _redact(value), "builtin")
            )

    if analyzer := _presidio_analyzer():
        try:
            for result in analyzer.analyze(text=text, language="en"):
                value = text[result.start : result.end]
                matches.setdefault(
                    (result.entity_type, value),
                    PIIMatch(result.entity_type, _redact(value), "presidio"),
                )
        except Exception:  # noqa: BLE001 - never let the optional path break a scan
            pass

    return list(matches.values())


def available_detectors() -> list[str]:
    return ["builtin"] + (["presidio"] if _presidio_analyzer() else [])
