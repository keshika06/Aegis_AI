"""Stage 3/4 — Target Execution.

The architecture diagram merges control evaluation and target dispatch into one
box, but the four-way outcome vocabulary is still recorded per probe: knowing
*which* layer stopped an attack is the point of the stage.
"""

from __future__ import annotations

from sqlalchemy import JSON, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aegisai.models.base import Base, TimestampMixin, new_id


class ControlEvaluation(Base, TimestampMixin):
    __tablename__ = "control_evaluations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("exec"))
    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id"), nullable=False, index=True
    )
    variant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("attack_variants.id"), nullable=False, index=True
    )

    verdict: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    """A ControlVerdict value: REJECTED / ACCEPTED / REFUSED / ERROR_TIMEOUT."""

    verdict_reason: Mapped[str | None] = mapped_column(Text)
    """Why the classifier chose that verdict — keeps the call auditable."""

    request_url: Mapped[str | None] = mapped_column(String(512))
    request_payload: Mapped[dict | list | None] = mapped_column(JSON)
    status_code: Mapped[int | None] = mapped_column(Integer)
    response_headers: Mapped[dict | None] = mapped_column(JSON)
    response_body: Mapped[str | None] = mapped_column(Text)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    error: Mapped[str | None] = mapped_column(Text)
