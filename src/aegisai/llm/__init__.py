"""LLM provider abstraction.

Used for attack planning (Stage 2A), evasion variation (Stage 2B), and adaptive
strategy (Stage 11). Never used to decide whether a finding is real — that rests
on deterministic evidence in Stage 7.
"""

from aegisai.llm.base import LLMProvider, LLMRequest, LLMResponse
from aegisai.llm.ollama import OllamaProvider
from aegisai.llm.router import UNAVAILABLE, ProviderRouter

__all__ = [
    "UNAVAILABLE",
    "LLMProvider",
    "LLMRequest",
    "LLMResponse",
    "OllamaProvider",
    "ProviderRouter",
]
