"""Declarative base, ID generation, and shared column helpers."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    """Short, prefixed, human-quotable identifier, e.g. `scan-9f3a20b1c4d5`.

    The prefix makes IDs self-describing in logs and reports; 12 hex chars is
    ample for a single-installation scanner.
    """
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
