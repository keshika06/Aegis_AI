"""LLM provider abstraction and the bounded fallback chain.

The rule under test throughout: an unreachable model degrades a scan. It never
hangs one, never aborts one, and never becomes a "clean" result.
"""

from __future__ import annotations

import pytest

from aegisai.llm.base import LLMRequest, LLMResponse
from aegisai.llm.router import UNAVAILABLE, ProviderRouter


class FakeProvider:
    """Records how many times it was called, so retry bounds are observable."""

    def __init__(self, name: str, *, ok: bool, text: str = "hello") -> None:
        self.name = name
        self.model = "fake-model"
        self._ok = ok
        self._text = text
        self.calls = 0

    def available(self) -> bool:
        return self._ok

    def generate(self, request: LLMRequest) -> LLMResponse:
        self.calls += 1
        if self._ok:
            return LLMResponse(text=self._text, provider=self.name, model=self.model)
        return LLMResponse.failed(self.name, self.model, "simulated failure")


def test_first_working_provider_wins() -> None:
    good = FakeProvider("good", ok=True)
    spare = FakeProvider("spare", ok=True)

    response = ProviderRouter([good, spare]).generate(LLMRequest(prompt="hi"))

    assert response.ok
    assert spare.calls == 0, "should not have tried the second provider"


def test_falls_through_to_the_next_provider() -> None:
    dead = FakeProvider("dead", ok=False)
    good = FakeProvider("good", ok=True)

    response = ProviderRouter([dead, good], max_retries=0).generate(LLMRequest(prompt="hi"))

    assert response.ok
    assert response.provider == "good"


def test_total_failure_returns_unavailable_instead_of_raising() -> None:
    """An LLM outage must be a result the caller handles, not an exception."""
    router = ProviderRouter([FakeProvider("dead", ok=False)], max_retries=0)

    response = router.generate(LLMRequest(prompt="hi"))

    assert not response.ok
    assert response.provider == UNAVAILABLE
    assert "simulated failure" in (response.error or "")


def test_retries_are_bounded() -> None:
    """Regression guard: never `while not ok: retry()`."""
    dead = FakeProvider("dead", ok=False)

    ProviderRouter([dead], max_retries=2).generate(LLMRequest(prompt="hi"))

    assert dead.calls == 3, "expected exactly max_retries + 1 attempts"


def test_no_providers_configured_is_not_a_crash() -> None:
    response = ProviderRouter([]).generate(LLMRequest(prompt="hi"))

    assert not response.ok
    assert response.provider == UNAVAILABLE


@pytest.mark.parametrize("retries", [0, 1, 3])
def test_attempt_count_matches_configuration(retries: int) -> None:
    dead = FakeProvider("dead", ok=False)

    ProviderRouter([dead], max_retries=retries).generate(LLMRequest(prompt="hi"))

    assert dead.calls == retries + 1
