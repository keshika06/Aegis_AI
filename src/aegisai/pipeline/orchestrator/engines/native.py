"""Built-in transformation engine.

Always available: everything except semantic paraphrase is deterministic and
dependency-free, so the evasion stage keeps working with no model and no
optional packages installed.
"""

from __future__ import annotations

from aegisai.llm.router import ProviderRouter
from aegisai.models.enums import TransformationFamily
from aegisai.pipeline.orchestrator.transformations import (
    context,
    encoding,
    fragmentation,
    mutation,
    semantic,
)
from aegisai.pipeline.orchestrator.variations import Variation

FAMILY_MODULES = {
    TransformationFamily.ENCODING.value: encoding,
    TransformationFamily.FRAGMENTATION.value: fragmentation,
    TransformationFamily.CONTEXT.value: context,
    TransformationFamily.MUTATION.value: mutation,
    TransformationFamily.SEMANTIC.value: semantic,
}

DEFAULT_FAMILIES = (
    TransformationFamily.ENCODING.value,
    TransformationFamily.CONTEXT.value,
    TransformationFamily.FRAGMENTATION.value,
    TransformationFamily.SEMANTIC.value,
)


class NativeEngine:
    name = "native"

    def __init__(
        self,
        router: ProviderRouter | None = None,
        per_family: int = 2,
        timeout: float = 60.0,
    ) -> None:
        self.router = router
        self.per_family = per_family
        self.timeout = timeout

    def available(self) -> bool:
        return True

    def variations(self, payload: str, families: list[str] | None = None) -> list[Variation]:
        selected = families or list(DEFAULT_FAMILIES)
        produced: list[Variation] = []

        for family in selected:
            module = FAMILY_MODULES.get(family)
            if module is None:
                continue
            try:
                if family == TransformationFamily.SEMANTIC.value:
                    produced.extend(
                        semantic.generate(
                            payload,
                            router=self.router,
                            limit=self.per_family,
                            timeout=self.timeout,
                        )
                    )
                else:
                    produced.extend(module.generate(payload, limit=self.per_family))
            except Exception:  # noqa: BLE001 - one broken family must not lose the rest
                continue

        return produced
