"""Stage 11 — Closed-Loop Replay & Adaptive Engine."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aegisai.models.base import Base, TimestampMixin, new_id, utcnow
from aegisai.models.enums import RegressionStatus


class RegressionTest(Base, TimestampMixin):
    """A CONFIRMED finding frozen into a replayable test.

    The exact payload and transformation are preserved: replaying an
    approximation would not prove the same weakness is gone.
    """

    __tablename__ = "regression_tests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("reg"))
    origin_finding_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("findings.id"), nullable=False, index=True
    )
    target_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("targets.id"), index=True)

    status: Mapped[str] = mapped_column(
        String(16), default=RegressionStatus.ACTIVE, nullable=False, index=True
    )
    matched_boundary: Mapped[str | None] = mapped_column(String(128))
    attack_payload: Mapped[str] = mapped_column(Text, nullable=False)
    transformation: Mapped[str | None] = mapped_column(String(32))
    target_endpoint: Mapped[str | None] = mapped_column(String(255))
    owasp_tag: Mapped[str | None] = mapped_column(String(32))

    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    """Bounds the adaptive loop. Replay is never `while not resolved`."""

    extra: Mapped[dict | None] = mapped_column(JSON)


class RegressionResult(Base, TimestampMixin):
    """One replay attempt. The ordered set of rows for a test is its run history."""

    __tablename__ = "regression_results"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("regres"))
    regression_test_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("regression_tests.id"), nullable=False, index=True
    )
    scan_id: Mapped[str | None] = mapped_column(String(64), index=True)

    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    """PASS / REGRESSED / INCONCLUSIVE, decided by Stage 7 evidence."""

    control_verdict: Mapped[str | None] = mapped_column(String(48))
    resulting_risk_score: Mapped[float | None] = mapped_column(Float)
    attempt_number: Mapped[int | None] = mapped_column(Integer)
    strategy_source: Mapped[str | None] = mapped_column(String(32))
    """ORIGINAL, ADAPTIVE, or ADVISOR_UNAVAILABLE."""

    evidence_summary: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[float | None] = mapped_column(Float)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    detail: Mapped[dict | None] = mapped_column(JSON)
