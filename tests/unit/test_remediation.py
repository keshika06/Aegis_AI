"""Remediation derived from observed facts, not from a category lookup."""

from __future__ import annotations

from aegisai.knowledge_base.remediation import RemediationInputs, build
from aegisai.models.enums import ControlVerdict, RuntimeEventType, TransformationFamily


def _inputs(**overrides) -> RemediationInputs:  # noqa: ANN003
    base = {
        "rules": ["event_must_not_occur"],
        "boundaries": ["must_not_retrieve_across_tenants"],
        "event_types": [RuntimeEventType.CROSS_TENANT_RETRIEVAL.value],
        "control_verdict": ControlVerdict.ACCEPTED,
        "transformation": TransformationFamily.NONE.value,
        "evidence_types": ["canary"],
    }
    return RemediationInputs(**{**base, **overrides})


class TestRemediation:
    def test_scenarios_that_differ_get_different_guidance(self) -> None:
        """The whole point. The previous version chose between two fixed
        paragraphs on one `if`, so a 174-finding scan carried 2 mitigations."""
        breach = build(_inputs())
        tool_abuse = build(
            _inputs(
                rules=["tool_argument_must_match"],
                boundaries=["must_not_email_outside_authorized_domain"],
                event_types=[RuntimeEventType.TOOL_CALL.value],
                tools_called=["send_summary_email"],
                unauthorized_tools=["send_summary_email"],
                evidence_types=["tool_log"],
            )
        )

        assert breach.mitigations != tool_abuse.mitigations
        assert breach.summary != tool_abuse.summary
        assert breach.detection != tool_abuse.detection

    def test_guidance_names_what_was_actually_observed(self) -> None:
        """Advice that does not name the tool that ran is advice about a
        category, and a reader learns to skip it."""
        result = build(
            _inputs(
                rules=["tool_must_not_be_called"],
                event_types=[RuntimeEventType.TOOL_CALL.value],
                tools_called=["export_corpus"],
                unauthorized_tools=["export_corpus"],
            )
        )

        assert any("export_corpus" in m for m in result.mitigations)

    def test_the_event_rule_names_the_operation(self) -> None:
        """`event_must_not_occur` alone says only that something happened."""
        ingest = build(
            _inputs(
                boundaries=["must_not_accept_unauthenticated_ingestion"],
                event_types=[RuntimeEventType.DOCUMENT_INGESTED.value],
            )
        )

        assert "corpus" in ingest.summary.lower()
        assert ingest.summary != build(_inputs()).summary

    def test_a_refused_probe_says_alignment_is_not_a_control(self) -> None:
        refused = build(_inputs(control_verdict=ControlVerdict.REFUSED))

        assert any("alignment is not a security control" in p.lower() for p in refused.preventive)

    def test_a_transformation_recommends_normalisation(self) -> None:
        encoded = build(_inputs(transformation=TransformationFamily.ENCODING.value))
        plain = build(_inputs(transformation=TransformationFamily.NONE.value))

        assert any("encoding" in p for p in encoded.preventive)
        assert any("normalise" in p.lower() for p in encoded.preventive)
        # Plain text is the worse case and must not be described as sophisticated.
        assert any("exactly as written" in p for p in plain.preventive)

    def test_detection_follows_the_evidence_that_proved_it(self) -> None:
        canary = build(_inputs(evidence_types=["canary"]))
        pii = build(_inputs(evidence_types=["pii_detection"]))

        assert any("canary" in d.lower() for d in canary.detection)
        assert canary.detection != pii.detection

    def test_nothing_is_invented_when_no_boundary_broke(self) -> None:
        """A finding resting on evidence outside the contract must not be given
        contract-derived advice."""
        result = build(_inputs(rules=[], boundaries=[], event_types=[]))

        assert "no declared boundary" in result.summary.lower()

    def test_repeated_facts_do_not_repeat_guidance(self) -> None:
        result = build(
            _inputs(
                rules=["event_must_not_occur", "event_must_not_occur"],
                event_types=[RuntimeEventType.CROSS_TENANT_RETRIEVAL.value] * 3,
            )
        )

        assert len(result.mitigations) == len(set(result.mitigations))

    def test_derivation_is_deterministic(self) -> None:
        first, second = build(_inputs()), build(_inputs())

        assert first == second
