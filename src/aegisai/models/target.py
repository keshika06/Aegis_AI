"""Target registry — the authorization boundary.

A row here is an explicit record that someone authorized testing against a URL.
`scan run` refuses anything without one.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aegisai.models.base import Base, TimestampMixin, new_id
from aegisai.models.enums import TargetType


class Target(Base, TimestampMixin):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("tgt"))
    url: Mapped[str] = mapped_column(String(512), nullable=False, unique=True, index=True)
    name: Mapped[str | None] = mapped_column(String(255))
    target_type: Mapped[str] = mapped_column(String(32), default=TargetType.LLM, nullable=False)

    authorized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    authorization_note: Mapped[str | None] = mapped_column(Text)
    """Free-text record of who authorized the test and under what agreement."""

    contract_id: Mapped[str | None] = mapped_column(String(128))
    """Expected-behaviour contract (Stage 6) governing this target."""

    api_key_env: Mapped[str | None] = mapped_column(String(128))
    """Name of the env var holding the target's API key.

    The key itself is never persisted.
    """
