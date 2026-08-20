"""Stages 8 and 9 — Attack Chain Builder and Risk Scoring."""

from __future__ import annotations

from sqlalchemy import JSON, Float, ForeignKey, Integer, String, Text
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
    model_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False, index=True)
    """Which risk model produced this score.

    Scores from different models are different measurements, so a trend must not
    put them on one line. 0 means the row predates versioning.
    """

    factors: Mapped[dict | None] = mapped_column(JSON)
    weights: Mapped[dict | None] = mapped_column(JSON)
    axes: Mapped[dict | None] = mapped_column(JSON)
    """The likelihood and impact the score was built from, and the confidence
    multiplier applied to their product.

    Stored rather than left to be re-derived from the composite: recovering the
    multiplier by dividing the rounded score back out returns a number close to
    the real one but not equal to it, and a report should not present a
    reconstruction as a measurement."""

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
