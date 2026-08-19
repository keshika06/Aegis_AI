"""Scan session and the Stage 1 application profile."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aegisai.models.base import Base, TimestampMixin, new_id
from aegisai.models.enums import ScanStatus


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("scan"))
    target_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("targets.id"), nullable=False, index=True
    )

    status: Mapped[str] = mapped_column(String(32), default=ScanStatus.PENDING, nullable=False)
    profile: Mapped[str] = mapped_column(String(32), default="standard", nullable=False)
    """Scan depth preset: quick | standard | deep."""

    current_stage: Mapped[str | None] = mapped_column(String(16))
    """Stage enum value, e.g. "3/4"."""

    stages_completed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_stages: Mapped[int] = mapped_column(Integer, default=11, nullable=False)
    message: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)

    engines: Mapped[dict | None] = mapped_column(JSON)
    """Attack engines requested for this scan (native, garak, pyrit, ...)."""

    config: Mapped[dict | None] = mapped_column(JSON)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Profile(Base, TimestampMixin):
    """Stage 1 output: attack surface graph plus security profile.

    Every entry in `endpoints` and `capabilities` carries a DiscoveryConfidence
    label so inferred facts are never reported as observed ones.
    """

    __tablename__ = "profiles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("prof"))
    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id"), nullable=False, index=True
    )
    target_url: Mapped[str] = mapped_column(String(512), nullable=False)

    endpoints: Mapped[list | None] = mapped_column(JSON)
    capabilities: Mapped[dict | None] = mapped_column(JSON)
    """Detected LLM / RAG / agent / tool surfaces."""

    auth_model: Mapped[dict | None] = mapped_column(JSON)
    surface_graph: Mapped[dict | None] = mapped_column(JSON)
    """NetworkX node-link representation of the attack surface graph."""
