"""Stages 8 and 9 — Attack Chain Builder and Risk Scoring."""

from __future__ import annotations

from sqlalchemy import JSON, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aegisai.models.base import Base, TimestampMixin, new_id


class AttackChain(Base, TimestampMixin):
    """Correlated path: intent -> control decision -> behaviour -> evidence -> impact."""

    __tablename__ = "attack_chains"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("chain"))
    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id"), nullable=False, index=True
    )

    title: Mapped[str | None] = mapped_column(String(255))
    finding_ids: Mapped[list | None] = mapped_column(JSON)
    graph: Mapped[dict | None] = mapped_column(JSON)
    """NetworkX node-link graph."""

    owasp_tags: Mapped[list | None] = mapped_column(JSON)
    severity: Mapped[float | None] = mapped_column(Float)


class RiskScore(Base, TimestampMixin):
    """Deterministic, explainable score.

    Every input factor is stored alongside the composite so a report can show the
    arithmetic rather than a bare number.
    """

    __tablename__ = "risk_scores"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("risk"))
    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id"), nullable=False, index=True
    )
    finding_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("findings.id"), index=True
    )

    score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    factors: Mapped[dict | None] = mapped_column(JSON)
    weights: Mapped[dict | None] = mapped_column(JSON)
    explanation: Mapped[str | None] = mapped_column(Text)


class Report(Base, TimestampMixin):
    """Stage 10 render record."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("rpt"))
    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id"), nullable=False, index=True
    )
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    summary: Mapped[dict | None] = mapped_column(JSON)
