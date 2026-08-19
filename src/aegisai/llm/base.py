"""LLM provider contract.

The abstraction exists so the pipeline never depends on a specific model, and —
more importantly — so it never depends on a model being *reachable*. Every
provider returns a response object; none of them raise. A dead provider is a
result the caller handles, not an exception that aborts a scan.

The LLM's role is proposing attacks and strategies. It is never the authority on
whether something is a vulnerability — that is Stage 7's deterministic evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class LLMRequest:
    prompt: str
    system: str | None = None
    temperature: float = 0.7
    max_tokens: int = 1024
    timeout: float = 60.0


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    ok: bool = True
    error: str | None = None

    @classmethod
    def failed(cls, provider: str, model: str, error: str) -> LLMResponse:
        return cls(text="", provider=provider, model=model, ok=False, error=error)


class LLMProvider(Protocol):
    name: str
    model: str

    def available(self) -> bool:
        """Cheap reachability probe. Must not raise."""
        ...

    def generate(self, request: LLMRequest) -> LLMResponse:
        """Produce a completion. Must not raise — failures come back ok=False."""
        ...
