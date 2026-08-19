"""Attack library and OWASP taxonomy loading.

The library is the *floor* for attack planning: it always applies, with or
without an LLM. LLM assistance in Stage 2A adds application-specific cases on
top, so planning quality degrades when no model is reachable but planning itself
never stops working.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

KB_DIR = Path(__file__).resolve().parent
PAYLOAD_DIR = KB_DIR / "payloads"
OWASP_FILE = KB_DIR / "owasp.yaml"

GENERIC_CAPABILITY = "llm"
"""Applies to any LLM-backed target, whatever its specific shape."""


@dataclass
class AttackTemplate:
    id: str
    owasp: str
    category: str
    intent: str
    payload: str
    evidence: str = "none"
    applies_to: list[str] = field(default_factory=lambda: [GENERIC_CAPABILITY])
    source: str = "library"

    @property
    def confirmable(self) -> bool:
        """Whether success could be proven deterministically, not just suspected."""
        return self.evidence == "canary"

    def matches(self, target_type: str) -> bool:
        return target_type in self.applies_to or GENERIC_CAPABILITY in self.applies_to


def _coerce(entry: dict[str, Any], source: str) -> AttackTemplate | None:
    if not entry.get("id") or not entry.get("payload"):
        return None
    return AttackTemplate(
        id=str(entry["id"]),
        owasp=str(entry.get("owasp", "")),
        category=str(entry.get("category", "uncategorised")),
        intent=str(entry.get("intent", "unspecified")),
        payload=str(entry["payload"]),
        evidence=str(entry.get("evidence", "none")),
        applies_to=list(entry.get("applies_to") or [GENERIC_CAPABILITY]),
        source=source,
    )


@lru_cache(maxsize=1)
def load_owasp_taxonomy() -> dict[str, dict[str, str]]:
    if not OWASP_FILE.exists():
        return {}
    return yaml.safe_load(OWASP_FILE.read_text(encoding="utf-8")) or {}


def owasp_name(tag: str | None) -> str | None:
    if not tag:
        return None
    entry = load_owasp_taxonomy().get(tag.upper())
    return entry.get("name") if entry else None


def load_library(directory: Path | None = None) -> list[AttackTemplate]:
    """Load every payload file, de-duplicated by id (first definition wins)."""
    source_dir = directory or PAYLOAD_DIR
    if not source_dir.exists():
        return []

    templates: dict[str, AttackTemplate] = {}
    for path in sorted(source_dir.glob("*.yaml")):
        entries = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            template = _coerce(entry, source=path.stem)
            if template and template.id not in templates:
                templates[template.id] = template
    return list(templates.values())


def select_for_target(
    target_type: str,
    *,
    directory: Path | None = None,
    categories: list[str] | None = None,
    owasp_tags: list[str] | None = None,
) -> list[AttackTemplate]:
    """Pick the cases meaningful against this target's discovered shape."""
    selected = [t for t in load_library(directory) if t.matches(target_type)]
    if categories:
        wanted = {c.lower() for c in categories}
        selected = [t for t in selected if t.category.lower() in wanted]
    if owasp_tags:
        tags = {t.upper() for t in owasp_tags}
        selected = [t for t in selected if t.owasp.upper() in tags]
    return selected
