"""Stage 2A attack cases and Stage 2B evasion variants."""

from __future__ import annotations

from sqlalchemy import JSON, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aegisai.models.base import Base, TimestampMixin, new_id
from aegisai.models.enums import AttackSource, TransformationFamily


class AttackCase(Base, TimestampMixin):
    """A security objective aimed at one discovered surface element."""

    __tablename__ = "attack_cases"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("atk"))
    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id"), nullable=False, index=True
    )

    source: Mapped[str] = mapped_column(String(8), default=AttackSource.PLANNER, nullable=False)
    owasp_tag: Mapped[str | None] = mapped_column(String(32), index=True)
    category: Mapped[str | None] = mapped_column(String(64))
    original_intent: Mapped[str] = mapped_column(Text, nullable=False)
    """The security objective under test, independent of any phrasing."""

    payload: Mapped[str] = mapped_column(Text, nullable=False)
    target_surface_element: Mapped[str | None] = mapped_column(String(255))
    """The discovered endpoint/tool/RAG component this case targets."""

    target_endpoint: Mapped[str | None] = mapped_column(String(255))
    extra: Mapped[dict | None] = mapped_column(JSON)


class AttackVariant(Base, TimestampMixin):
    """One transformation of an AttackCase, preserving its original intent.

    Lineage back to `attack_case_id` is what makes guardrail-evasion rates
    measurable: same objective, different representation.
    """

    __tablename__ = "attack_variants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("var"))
    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scans.id"), nullable=False, index=True
    )
    attack_case_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("attack_cases.id"), nullable=False, index=True
    )

    transformation: Mapped[str] = mapped_column(
        String(32), default=TransformationFamily.NONE, nullable=False
    )
    engine: Mapped[str] = mapped_column(String(32), default="native", nullable=False)
    """Which attack engine produced this variant: native, garak, pyrit, promptfoo."""

    payload: Mapped[str] = mapped_column(Text, nullable=False)
    conversation: Mapped[list | None] = mapped_column(JSON)
    """Ordered turns, when the variant is a multi-turn fragmentation."""

    extra: Mapped[dict | None] = mapped_column(JSON)
