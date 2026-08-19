"""Stage 6 — Expected vs Observed.

Compares what the application actually did against a declarative contract of
what it is permitted to do. The comparison is deterministic and per-probe, so a
violation names the exact probe that caused it.

A violation here is the strongest evidence Stage 7 can receive short of a
canary: it is a boundary the target's owner declared, measured against
behaviour the target itself reported.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from sqlalchemy import select

from aegisai.models.enums import Stage
from aegisai.models.execution import ControlEvaluation
from aegisai.models.policy import PolicyContract, Violation
from aegisai.models.runtime import RuntimeEvent
from aegisai.pipeline.base import ScanContext, StageResult
from aegisai.pipeline.expected_observed.rules import Observation, evaluate

CONTRACT_DIRS = (
    Path("configs/expected-behaviour"),
    Path(__file__).resolve().parents[4] / "configs" / "expected-behaviour",
)


def find_contract(target_type: str, contract_id: str | None = None) -> dict | None:
    """Load a contract by id, else the first matching the target type."""
    for directory in CONTRACT_DIRS:
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.yaml")):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError:
                continue
            if not isinstance(data, dict):
                continue
            if contract_id and data.get("contract_id") == contract_id:
                return {**data, "_source": str(path)}
            if not contract_id and data.get("target_type") == target_type:
                return {**data, "_source": str(path)}
    return None


class ExpectedObservedStage:
    stage = Stage.EXPECTED_VS_OBSERVED

    def __init__(self, contract_id: str | None = None) -> None:
        self.contract_id = contract_id

    def run(self, ctx: ScanContext) -> StageResult:
        contract = find_contract(ctx.target_type, self.contract_id)
        if contract is None:
            return StageResult(
                ok=True,
                summary=f"no expected-behaviour contract for target type '{ctx.target_type}'",
                counts={"violations": 0},
            )

        boundaries = contract.get("boundaries") or []
        self._persist_contract(ctx, contract, boundaries)

        evaluations = list(
            ctx.session.scalars(
                select(ControlEvaluation).where(ControlEvaluation.scan_id == ctx.scan_id)
            )
        )
        events = list(
            ctx.session.scalars(select(RuntimeEvent).where(RuntimeEvent.scan_id == ctx.scan_id))
        )

        events_by_variant: dict[str, list[dict]] = {}
        for event in events:
            events_by_variant.setdefault(event.variant_id or "", []).append(
                {"event_type": event.event_type, "payload": event.payload or {}}
            )

        violated_boundaries: dict[str, int] = {}
        skipped: set[str] = set()
        total = 0

        for evaluation in evaluations:
            observation = Observation(
                response_body=evaluation.response_body or "",
                events=events_by_variant.get(evaluation.variant_id, []),
            )
            for boundary in boundaries:
                outcome = evaluate(boundary, observation)
                if outcome is None:
                    skipped.add(str(boundary.get("rule", "unknown")))
                    continue
                if not outcome.violated:
                    continue

                ctx.session.add(
                    Violation(
                        scan_id=ctx.scan_id,
                        variant_id=evaluation.variant_id,
                        contract_id=contract.get("contract_id"),
                        boundary=str(boundary.get("id", "unnamed")),
                        expected=outcome.expected,
                        observed=outcome.observed,
                        rule=str(boundary.get("rule")),
                        detail={
                            "severity": boundary.get("severity", "medium"),
                            "description": boundary.get("description"),
                            **(outcome.detail or {}),
                        },
                    )
                )
                key = str(boundary.get("id", "unnamed"))
                violated_boundaries[key] = violated_boundaries.get(key, 0) + 1
                total += 1

        ctx.session.flush()

        if total:
            detail = ", ".join(f"{k} x{n}" for k, n in sorted(violated_boundaries.items()))
            summary = f"{total} policy violation(s) across {len(violated_boundaries)}: {detail}"
        else:
            summary = f"no policy violations against '{contract.get('contract_id')}'"
        if skipped:
            summary += f" (skipped unknown rules: {', '.join(sorted(skipped))})"

        return StageResult(
            ok=True,
            summary=summary,
            counts={"violations": total, "boundaries_violated": len(violated_boundaries)},
        )

    def _persist_contract(self, ctx: ScanContext, contract: dict, boundaries: list) -> None:
        contract_id = contract.get("contract_id")
        existing = ctx.session.scalar(
            select(PolicyContract).where(PolicyContract.contract_id == contract_id)
        )
        if existing is not None:
            return
        ctx.session.add(
            PolicyContract(
                contract_id=str(contract_id),
                target_type=contract.get("target_type"),
                source_path=contract.get("_source"),
                boundaries=[b.get("id") for b in boundaries],
                raw={k: v for k, v in contract.items() if not k.startswith("_")},
            )
        )
        ctx.session.flush()
