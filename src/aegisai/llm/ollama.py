"""Local Ollama provider.

Free, local inference — no API key, no per-token cost. Every call is bounded by
an explicit timeout: a stalled model must degrade the scan, never hang it.
"""

from __future__ import annotations

import httpx

from aegisai.llm.base import LLMRequest, LLMResponse


class OllamaProvider:
    name = "ollama"

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        model: str = "qwen2.5:0.5b",
        timeout: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def available(self) -> bool:
        try:
            return httpx.get(f"{self.base_url}/api/version", timeout=3.0).status_code == 200
        except Exception:  # noqa: BLE001 - unreachable is the answer, not an error
            return False

    def has_model(self) -> bool:
        """Whether the configured model is actually pulled.

        A reachable daemon missing the model fails at generate time otherwise,
        which is a confusing place to discover it.
        """
        try:
            res = httpx.get(f"{self.base_url}/api/tags", timeout=5.0)
            names = {m.get("name", "") for m in res.json().get("models", [])}
        except Exception:  # noqa: BLE001
            return False
        return self.model in names or f"{self.model}:latest" in names

    def generate(self, request: LLMRequest) -> LLMResponse:
        messages = []
        if request.system:
            messages.append({"role": "system", "content": request.system})
        messages.append({"role": "user", "content": request.prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": request.temperature,
                "num_predict": request.max_tokens,
            },
        }

        try:
            res = httpx.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=request.timeout or self.timeout,
            )
            res.raise_for_status()
            text = res.json().get("message", {}).get("content", "")
        except httpx.TimeoutException:
            return LLMResponse.failed(
                self.name, self.model, f"timed out after {request.timeout or self.timeout}s"
            )
        except Exception as exc:  # noqa: BLE001 - any failure degrades, never aborts
            return LLMResponse.failed(self.name, self.model, f"{type(exc).__name__}: {exc}")

        return LLMResponse(text=text, provider=self.name, model=self.model)
