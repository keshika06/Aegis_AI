"""Provider routing with a bounded fallback chain.

Two rules this module exists to enforce:

1. **Bounded.** Retries are capped. There is no `while not ok: retry()` — a
   previous build stalled a scan for two minutes per attempt when nothing in the
   chain was reachable.
2. **Never fatal.** When every provider fails, the caller gets `ok=False` and a
   trace of what was tried. LLM unavailability degrades a scan; it never fails
   one, and it never silently becomes a "safe" result.
"""

from __future__ import annotations

import logging

from aegisai.core.config import Config
from aegisai.llm.base import LLMProvider, LLMRequest, LLMResponse
from aegisai.llm.ollama import OllamaProvider

logger = logging.getLogger("aegisai.llm")

UNAVAILABLE = "LLM_UNAVAILABLE"


class ProviderRouter:
    """Tries each provider in order, at most `max_retries + 1` attempts each."""

    def __init__(self, providers: list[LLMProvider], max_retries: int = 1) -> None:
        self.providers = providers
        self.max_retries = max(0, max_retries)

    @classmethod
    def from_config(cls, config: Config) -> ProviderRouter:
        provider = OllamaProvider(
            base_url=config.llm.base_url,
            model=config.llm.model,
            timeout=float(config.llm.timeout_seconds),
        )
        return cls([provider], max_retries=config.llm.max_retries)

    def available(self) -> bool:
        return any(p.available() for p in self.providers)

    def generate(self, request: LLMRequest) -> LLMResponse:
        trace: list[str] = []

        for provider in self.providers:
            for attempt in range(self.max_retries + 1):
                response = provider.generate(request)
                if response.ok:
                    return response
                trace.append(
                    f"{provider.name}/{provider.model} attempt "
                    f"{attempt + 1}/{self.max_retries + 1}: {response.error}"
                )
                logger.warning("LLM provider %s failed: %s", provider.name, response.error)

        return LLMResponse.failed(UNAVAILABLE, UNAVAILABLE, "; ".join(trace) or "no providers")
