"""Stage 6 — Expected vs Observed.

The contract is declarative and the comparison is a deterministic rule engine.
An LLM is never the authority for whether a boundary was crossed.
"""

from __future__ import annotations

from sqlalchemy import JSON, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aegisai.models.base import Base, TimestampMixin, new_id


class PolicyContract(Base, TimestampMixin):
    """A target's declared allowed behaviour, loaded from YAML."""

    __tablename__ = "policy_contracts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("pol"))
    contract_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    target_type: Mapped[str | None] = mapped_column(String(32))
    source_path: Mapped[str | None] = mapped_column(String(512))

    boundaries: Mapped[list | None] = mapped_column(JSON)
    """Named boundaries, e.g. must_not_leak_canary."""

    expected_behaviour: Mapped[dict | None] = mapped_column(JSON)
    raw: Mapped[dict | None] = mapped_column(JSON)


class Violation(Base, TimestampMixin):
    """A deterministic mismatch between contract and observed runtime behaviour."""

    __tablename__ = "violations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("vio"))
    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id"), nullable=False, index=True
    )
    variant_id: Mapped[str | None] = mapped_column(String(64), index=True)
    contract_id: Mapped[str | None] = mapped_column(String(128))

    boundary: Mapped[str] = mapped_column(String(128), nullable=False)
    expected: Mapped[str | None] = mapped_column(Text)
    observed: Mapped[str | None] = mapped_column(Text)
    rule: Mapped[str | None] = mapped_column(String(128))
    """Which deterministic rule fired, so the result can be re-derived."""

    detail: Mapped[dict | None] = mapped_column(JSON)
