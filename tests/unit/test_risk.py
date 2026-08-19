"""Stage 9 risk scoring, and Stage 7's PII detection."""

from __future__ import annotations

import pytest

from aegisai.models.enums import ControlVerdict, FindingVerdict, RiskLevel, TransformationFamily
from aegisai.pipeline.evidence.pii import detect, luhn_valid
from aegisai.pipeline.risk.scoring import UNKNOWN, WEIGHTS, RiskInputs, score


def _inputs(**overrides) -> RiskInputs:  # noqa: ANN003
    base = {
        "verdict": FindingVerdict.CONFIRMED,
        "confidence": 0.9,
        "control_verdict": ControlVerdict.ACCEPTED,
        "transformation": TransformationFamily.ENCODING.value,
        "boundary_severities": ["critical"],
        "evidence_types": ["canary"],
        "chain_severity": 0.9,
    }
    return RiskInputs(**{**base, **overrides})


class TestScoring:
    def test_worst_case_scores_critical(self) -> None:
        result = score(_inputs())

        assert result.level is RiskLevel.CRITICAL
        assert result.score >= 8.0

    def test_rejected_probe_scores_low(self) -> None:
        """A probe the control blocked is not a live exploit path."""
        result = score(
            _inputs(
                control_verdict=ControlVerdict.REJECTED,
                boundary_severities=["low"],
                evidence_types=["response_text"],
                confidence=0.2,
                chain_severity=0.3,
                verdict=FindingVerdict.SUSPECTED,
            )
        )

        assert result.level is RiskLevel.LOW

    def test_unestablished_factors_are_excluded_not_zeroed(self) -> None:
        """An unmeasured factor scored as zero is how a scanner talks itself
        into a reassuring answer."""
        partial = score(_inputs(control_verdict=None, boundary_severities=[], chain_severity=None))

        assert partial.factors["exploitability"] == UNKNOWN
        assert partial.factors["business_impact"] == UNKNOWN
        # Still scores highly on what *was* established (a retrieved canary).
        assert partial.score > 5.0

    def test_unconfirmed_findings_cannot_be_critical(self) -> None:
        """Suspicion must not present as a top-tier risk."""
        result = score(_inputs(verdict=FindingVerdict.SUSPECTED))

        assert result.level is not RiskLevel.CRITICAL
        assert "capped" in result.explanation

    def test_untransformed_payload_scores_lower_evasion(self) -> None:
        plain = score(_inputs(transformation=TransformationFamily.NONE.value))
        evaded = score(_inputs(transformation=TransformationFamily.ENCODING.value))

        assert plain.factors["control_evasion"] < evaded.factors["control_evasion"]

    def test_every_factor_is_reported_with_its_weight(self) -> None:
        result = score(_inputs())

        assert set(result.factors) == set(WEIGHTS)
        assert set(result.weights) == set(WEIGHTS)

    def test_scoring_is_deterministic(self) -> None:
        scores = {score(_inputs()).score for _ in range(5)}

        assert len(scores) == 1

    def test_no_established_factors_does_not_divide_by_zero(self) -> None:
        result = score(
            RiskInputs(verdict=FindingVerdict.SUSPECTED, confidence=0.0, control_verdict=None)
        )

        assert result.score >= 0.0
        assert result.level is RiskLevel.LOW


class TestPII:
    def test_detects_an_email(self) -> None:
        matches = detect("contact me at alice@example.com please")

        assert any(m.entity_type == "EMAIL" for m in matches)

    def test_raw_value_is_never_carried_forward(self) -> None:
        """Recording the raw value would recreate the exposure in the report."""
        matches = detect("alice@example.com")

        assert all("alice@example.com" not in m.redacted for m in matches)
        assert any("*" in m.redacted for m in matches)

    def test_clean_text_yields_nothing(self) -> None:
        assert detect("Our support hours are nine to five.") == []

    def test_empty_input_is_safe(self) -> None:
        assert detect("") == []

    @pytest.mark.parametrize(
        ("number", "valid"), [("4111111111111111", True), ("1234567890123456", False)]
    )
    def test_luhn_filters_credit_card_false_positives(self, number: str, valid: bool) -> None:
        assert luhn_valid(number) is valid

    def test_long_non_card_numbers_are_not_reported_as_cards(self) -> None:
        matches = detect("order reference 1234567890123456")

        assert not any(m.entity_type == "CREDIT_CARD" for m in matches)
