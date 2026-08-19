"""Stage 1 discovery and Stage 3/4 verdict classification."""

from __future__ import annotations

from aegisai.models.enums import ControlVerdict, DiscoveryConfidence
from aegisai.pipeline.discovery.stage import DEFAULT_TEXT_KEY, resolve_text_key
from aegisai.pipeline.execution.adapter import ProbeResponse
from aegisai.pipeline.execution.stage import classify


class TestTextKeyResolution:
    """Guards the bug that made a previous scanner report zero findings.

    A handler taking a raw request body publishes no schema, so schema-driven
    request building failed on every probe and the scan "succeeded" having never
    actually reached the target.
    """

    def test_falls_back_when_no_schema_is_published(self) -> None:
        key, confidence = resolve_text_key(None)

        assert key == DEFAULT_TEXT_KEY
        assert confidence == DiscoveryConfidence.INFERRED

    def test_uses_the_declared_key_when_a_schema_exists(self) -> None:
        key, confidence = resolve_text_key({"prompt": {"type": "string"}})

        assert key == "prompt"
        assert confidence == DiscoveryConfidence.OBSERVED

    def test_known_schema_without_a_text_field_is_not_a_chat_surface(self) -> None:
        """A tool endpoint must not be probed as if it took a prompt."""
        key, confidence = resolve_text_key({"function": {"type": "string"}})

        assert key is None
        assert confidence == DiscoveryConfidence.UNKNOWN

    def test_candidate_order_is_honoured(self) -> None:
        assert resolve_text_key({"text": {}, "message": {}})[0] == "message"


class TestClassify:
    @staticmethod
    def _response(status: int, body: str = "") -> ProbeResponse:
        return ProbeResponse(status_code=status, headers={}, body=body, latency_ms=1.0)

    def test_transport_failure_is_error_not_a_crash(self) -> None:
        response = ProbeResponse(
            status_code=None, headers={}, body="", latency_ms=30_000, error="ReadTimeout"
        )
        verdict, reason = classify(response)

        assert verdict is ControlVerdict.ERROR
        assert "ReadTimeout" in reason

    def test_4xx_is_the_target_control_rejecting(self) -> None:
        assert classify(self._response(403))[0] is ControlVerdict.REJECTED

    def test_5xx_is_error_not_rejection(self) -> None:
        assert classify(self._response(500))[0] is ControlVerdict.ERROR

    def test_refusal_language_is_the_llm_declining(self) -> None:
        response = self._response(200, '{"response":"I\'m sorry, I cannot help with that."}')

        assert classify(response)[0] is ControlVerdict.REFUSED

    def test_plain_answer_is_accepted(self) -> None:
        response = self._response(200, '{"response":"Our support hours are 9-5."}')

        assert classify(response)[0] is ControlVerdict.ACCEPTED

    def test_block_language_is_a_control_rejection(self) -> None:
        response = self._response(200, '{"error":"request rejected by policy"}')

        assert classify(response)[0] is ControlVerdict.REJECTED

    def test_every_verdict_carries_a_reason(self) -> None:
        """Classification must stay auditable, never an opaque judgement."""
        for response in (
            self._response(200, "hello"),
            self._response(403),
            ProbeResponse(None, {}, "", 1.0, error="boom"),
        ):
            assert classify(response)[1]
