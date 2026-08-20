"""Stage 9 risk scoring, and Stage 7's PII detection."""

from __future__ import annotations

import pytest

from aegisai.models.enums import ControlVerdict, FindingVerdict, RiskLevel, TransformationFamily
from aegisai.pipeline.evidence.pii import detect, luhn_valid
from aegisai.pipeline.risk.scoring import (
    BLAST_EGRESS,
    COMPLEXITY_SCORES,
    EGRESS_RULES,
    PERSISTENT_RULES,
    SELF_RULES,
    SENSITIVITY_SCORES,
    UNKNOWN,
    WEIGHTS,
    RiskInputs,
    posture,
    score,
)


def _inputs(**overrides) -> RiskInputs:  # noqa: ANN003
    """The worst case Lab 2 actually produces: an unauthenticated plain-text
    prompt that returns another tenant's restricted document, every time."""
    base = {
        "verdict": FindingVerdict.CONFIRMED,
        "confidence": 0.95,
        "control_verdict": ControlVerdict.ACCEPTED,
        "transformation": TransformationFamily.NONE.value,
        "boundary_severities": ["critical"],
        "boundary_rules": ["response_must_not_match"],
        "event_types": ["cross_tenant_retrieval", "rag_retrieval"],
        "evidence_types": ["canary"],
        "variants_tried": 8,
        "variants_succeeded": 8,
    }
    return RiskInputs(**{**base, **overrides})


class TestScoring:
    def test_worst_case_scores_critical(self) -> None:
        result = score(_inputs())

        assert result.level is RiskLevel.CRITICAL
        assert result.score >= 7.5

    def test_nothing_reaches_a_perfect_score_without_earning_every_axis(self) -> None:
        """The old flat-mean model pinned every confirmed finding at ~9.9, which
        made the score useless for ranking. A finding has to max out likelihood
        *and* impact to approach 10."""
        result = score(_inputs())

        assert result.score < 10.0

    def test_rejected_probe_scores_low(self) -> None:
        """A probe the control blocked is not a live exploit path."""
        result = score(
            _inputs(
                control_verdict=ControlVerdict.REJECTED,
                boundary_severities=["low"],
                boundary_rules=["response_must_not_match"],
                event_types=[],
                evidence_types=["response_text"],
                confidence=0.2,
                variants_tried=8,
                variants_succeeded=1,
                verdict=FindingVerdict.SUSPECTED,
            )
        )

        assert result.level is RiskLevel.LOW

    def test_the_model_separates_findings_the_flat_mean_tied(self) -> None:
        """Two confirmed findings that the old model scored identically: a
        cross-tenant data breach, and a system prompt the model recited back to
        the caller who asked for it."""
        breach = score(_inputs())
        prompt_leak = score(
            _inputs(
                boundary_severities=["high"],
                boundary_rules=["response_must_not_match"],
                event_types=["llm_io"],
                evidence_types=["response_text"],
                variants_tried=8,
                variants_succeeded=2,
            )
        )

        assert breach.score - prompt_leak.score > 3.0

    def test_unestablished_factors_are_excluded_not_zeroed(self) -> None:
        """An unmeasured factor scored as zero is how a scanner talks itself
        into a reassuring answer."""
        partial = score(
            _inputs(
                control_verdict=None,
                boundary_severities=[],
                variants_tried=None,
                variants_succeeded=None,
            )
        )

        assert partial.factors["exploitability"] == UNKNOWN
        assert partial.factors["business_impact"] == UNKNOWN
        assert partial.factors["reproducibility"] == UNKNOWN
        # Still scores on what *was* established (a retrieved canary, reached
        # in plain text, that crossed a tenant boundary).
        assert partial.score > 5.0

    def test_one_measured_axis_reports_that_axis_rather_than_guessing(self) -> None:
        """With impact unmeasured there is no product to take. Assuming the
        missing axis would invent half the answer."""
        result = score(
            _inputs(boundary_severities=[], boundary_rules=[], event_types=[], evidence_types=[])
        )

        assert result.impact == UNKNOWN
        assert isinstance(result.likelihood, float)
        assert result.score > 0

    def test_unconfirmed_findings_cannot_be_critical(self) -> None:
        """Suspicion must not present as a top-tier risk."""
        result = score(_inputs(verdict=FindingVerdict.SUSPECTED))

        assert result.level is not RiskLevel.CRITICAL
        assert "capped" in result.explanation

    def test_a_payload_that_works_as_written_is_the_worst_case(self) -> None:
        """The previous model had this backwards, scoring an encoded payload
        above a plain one — rewarding the target for being harder to attack."""
        plain = score(_inputs(transformation=TransformationFamily.NONE.value))
        encoded = score(_inputs(transformation=TransformationFamily.ENCODING.value))

        assert plain.factors["attack_complexity"] > encoded.factors["attack_complexity"]
        assert plain.score > encoded.score

    def test_reproducibility_tracks_how_many_representations_landed(self) -> None:
        every_time = score(_inputs(variants_tried=8, variants_succeeded=8))
        lucky_once = score(_inputs(variants_tried=8, variants_succeeded=1))

        assert every_time.factors["reproducibility"] == 1.0
        assert lucky_once.factors["reproducibility"] < 0.2
        assert every_time.score > lucky_once.score

    def test_blast_radius_separates_persistent_change_from_own_session(self) -> None:
        planted = score(_inputs(event_types=["document_ingested"]))
        own_session = score(
            _inputs(boundary_rules=["response_must_not_match"], event_types=["llm_io"])
        )

        assert planted.factors["blast_radius"] > own_session.factors["blast_radius"]

    def test_weak_evidence_scales_the_score_down_rather_than_averaging_in(self) -> None:
        """Averaged in, weak evidence still leaves a high score when the other
        factors are high, which is precisely backwards."""
        certain = score(_inputs(confidence=1.0))
        shaky = score(_inputs(confidence=0.1))

        assert shaky.score < certain.score
        assert shaky.confidence_multiplier < certain.confidence_multiplier
        # But never to zero: a genuine finding recorded at low confidence is
        # still a finding.
        assert shaky.score > 0

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


class TestFactorVocabularies:
    """Every controlled vocabulary the model reads is mapped, so a new member
    cannot quietly fall through to a default nobody chose for it."""

    def test_every_transformation_family_has_a_complexity(self) -> None:
        assert {f.value for f in TransformationFamily} == set(COMPLEXITY_SCORES)

    def test_every_evidence_type_has_a_sensitivity(self) -> None:
        """api_log, db_log and callback are deterministic evidence the labs do
        not currently emit. Left unmapped they defaulted below a generic policy
        violation, ranking hard proof of a database read under a soft one."""
        from aegisai.models.enums import EvidenceType

        unmapped = {e.value for e in EvidenceType} - set(SENSITIVITY_SCORES)

        assert unmapped == set(), f"unmapped evidence types: {sorted(unmapped)}"


class TestBlastRadiusVocabulary:
    """The blast radius reads the rule engine's vocabulary, not one lab's
    boundary names, so it generalises to any target's contract."""

    def test_every_rule_kind_is_accounted_for(self) -> None:
        """A rule added to Stage 6 without a blast-radius classification would
        silently score as unmeasured impact."""
        from aegisai.pipeline.expected_observed.rules import RULES

        classified = PERSISTENT_RULES | EGRESS_RULES | SELF_RULES
        # `event_must_not_occur` is deliberately unclassified: the event it
        # names is what locates the blast radius, and it is read from
        # event_types instead.
        delegated_to_events = {"event_must_not_occur"}

        assert set(RULES) == classified | delegated_to_events

    def test_an_unclassifiable_crossing_is_unknown_not_assumed_harmless(self) -> None:
        result = score(_inputs(boundary_rules=["event_must_not_occur"], event_types=[]))

        assert result.factors["blast_radius"] == UNKNOWN

    def test_an_unauthorized_tool_call_outranks_a_disclosure(self) -> None:
        state_change = score(_inputs(boundary_rules=["tool_must_not_be_called"], event_types=[]))
        disclosure = score(_inputs(boundary_rules=["response_must_not_match"], event_types=[]))

        assert state_change.factors["blast_radius"] > disclosure.factors["blast_radius"]

    def test_an_out_of_policy_tool_argument_is_an_egress_channel(self) -> None:
        result = score(_inputs(boundary_rules=["tool_argument_must_match"], event_types=[]))

        assert result.factors["blast_radius"] == BLAST_EGRESS


class TestPosture:
    def test_one_severe_finding_no_longer_pins_the_headline_number(self) -> None:
        """Reporting the maximum alone read 99/100 for any scan containing one
        severe finding, and never moved again."""
        result = posture({"atk-1": 9.5, "atk-2": 3.0, "atk-3": 2.0})

        assert result.score < 95
        assert result.worst == 9.5

    def test_posture_is_never_better_than_the_worst_hole(self) -> None:
        result = posture({"atk-1": 8.0, "atk-2": 8.0, "atk-3": 8.0})

        assert result.score == 80

    def test_breadth_moves_the_number(self) -> None:
        """An application with one critical flaw must not score identically to
        one with thirty."""
        one = posture({"atk-1": 9.0, "atk-2": 1.0})
        many = posture({"atk-1": 9.0, "atk-2": 9.0})

        assert many.score > one.score

    def test_an_empty_scan_scores_zero_rather_than_erroring(self) -> None:
        result = posture({})

        assert result.score == 0
        assert result.objectives == 0

    def test_the_arithmetic_is_shown_not_asserted(self) -> None:
        result = posture({"atk-1": 9.0, "atk-2": 5.0})

        assert "worst" in result.explanation
        assert "9.00" in result.explanation


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
