"""Stage 7 — Evidence Fusion & Impact."""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aegisai.models.base import Base, TimestampMixin, new_id
from aegisai.models.enums import FindingVerdict


class Finding(Base, TimestampMixin):
    """A fused verdict over one probe's evidence.

    CONFIRMED requires at least one deterministic evidence source; response text
    alone can never exceed SUSPECTED.
    """

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("fnd"))
    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id"), nullable=False, index=True
    )
    variant_id: Mapped[str | None] = mapped_column(String(64), index=True)
    control_evaluation_id: Mapped[str | None] = mapped_column(String(64))

    verdict: Mapped[str] = mapped_column(
        String(16), default=FindingVerdict.SUSPECTED, nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    owasp_tag: Mapped[str | None] = mapped_column(String(32), index=True)
    atlas_tag: Mapped[str | None] = mapped_column(String(64))
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    mitigation: Mapped[str | None] = mapped_column(Text)
    extra: Mapped[dict | None] = mapped_column(JSON)


class Evidence(Base, TimestampMixin):
    """One signal supporting a finding, weighted by how deterministic it is."""

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("evi"))
    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id"), nullable=False, index=True
    )
    finding_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("findings.id"), index=True
    )

    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source_stage: Mapped[str | None] = mapped_column(String(16))
    deterministic: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    """Whether this type can, alone, support CONFIRMED. Denormalized for reporting."""

    confidence_contribution: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    raw_reference: Mapped[str | None] = mapped_column(String(128))
    """Pointer to the underlying stored event/log row."""

    content: Mapped[dict | None] = mapped_column(JSON)
