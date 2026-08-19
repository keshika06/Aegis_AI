"""Stage 5 — Runtime Observability.

A lightweight, OTEL-shaped event record. Kept deliberately generic so labs and
instrumented targets can emit the same schema without agreeing on a transport.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from aegisai.models.base import Base, TimestampMixin, new_id, utcnow


class RuntimeEvent(Base, TimestampMixin):
    __tablename__ = "runtime_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("evt"))
    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id"), nullable=False, index=True
    )
    variant_id: Mapped[str | None] = mapped_column(String(64), index=True)
    """The probe that triggered this event, when attributable."""

    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    source: Mapped[str] = mapped_column(String(64), default="target_adapter", nullable=False)
    payload: Mapped[dict | None] = mapped_column(JSON)
