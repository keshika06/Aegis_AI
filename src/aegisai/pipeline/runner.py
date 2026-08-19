"""Pipeline orchestration.

Runs the enabled stages in order, committing at every boundary so `scan status`
in another process sees real progress rather than a scan that appears frozen
until it finishes.

Phase 1 runs five of the eleven stages. Later phases insert their stages into
STAGES without touching this runner.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass

from sqlalchemy.orm import Session

from aegisai.core.config import Config
from aegisai.models.base import utcnow
from aegisai.models.enums import STAGE_LABELS, ScanStatus, Stage
from aegisai.models.scan import Scan
from aegisai.pipeline.attack_chain.stage import AttackChainStage
from aegisai.pipeline.base import ScanContext, StageResult
from aegisai.pipeline.closed_loop.stage import ClosedLoopStage
from aegisai.pipeline.discovery.stage import DiscoveryStage
from aegisai.pipeline.evidence.stage import EvidenceStage
from aegisai.pipeline.execution.stage import ExecutionStage
from aegisai.pipeline.expected_observed.stage import ExpectedObservedStage
from aegisai.pipeline.observability.stage import ObservabilityStage
from aegisai.pipeline.orchestrator.stage import EvasionStage
from aegisai.pipeline.planner.stage import PlannerStage
from aegisai.pipeline.reporting.stage import ReportingStage
from aegisai.pipeline.risk.stage import RiskStage

STAGES: list[Callable[[], object]] = [
    DiscoveryStage,
    PlannerStage,
    EvasionStage,
    ExecutionStage,
    ObservabilityStage,
    ExpectedObservedStage,
    EvidenceStage,
    AttackChainStage,
    RiskStage,
    ClosedLoopStage,
    ReportingStage,
]

TOTAL_PIPELINE_STAGES = 11
"""The full pipeline, not just the stages implemented so far.

Progress is reported against the real target so "5/11" stays honest.
"""


@dataclass
class StageProgress:
    stage: Stage
    label: str
    index: int
    total: int
    result: StageResult


def run_pipeline(
    *,
    scan_id: str,
    session: Session,
    config: Config,
    target_url: str,
    target_id: str,
    target_type: str = "llm",
    families: list[str] | None = None,
) -> Iterator[StageProgress]:
    """Execute the pipeline, yielding after each stage so callers can render live.

    A stage that raises marks the scan FAILED with the error recorded — a scan is
    never left stuck in RUNNING, which is what makes stale-scan recovery
    unnecessary.
    """
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise ValueError(f"Unknown scan: {scan_id}")

    scan.status = ScanStatus.RUNNING
    scan.started_at = utcnow()
    session.commit()

    ctx = ScanContext(
        scan_id=scan_id,
        session=session,
        config=config,
        target_url=target_url,
        target_id=target_id,
        target_type=target_type,
        families=families,
    )

    for index, stage_cls in enumerate(STAGES, start=1):
        stage = stage_cls()  # type: ignore[operator]
        try:
            result = stage.run(ctx)
        except Exception as exc:  # noqa: BLE001 - any stage failure ends the scan cleanly
            session.rollback()
            scan = session.get(Scan, scan_id)
            scan.status = ScanStatus.FAILED
            scan.current_stage = str(stage.stage)
            scan.error = f"{type(exc).__name__}: {exc}"
            scan.completed_at = utcnow()
            session.commit()
            raise

        scan = session.get(Scan, scan_id)
        scan.current_stage = str(stage.stage)
        scan.stages_completed = index
        scan.message = result.summary
        session.commit()

        yield StageProgress(
            stage=stage.stage,
            label=STAGE_LABELS[stage.stage],
            index=index,
            total=len(STAGES),
            result=result,
        )

        if not result.ok:
            # A stage reporting ok=False is a legitimate dead end (nothing to
            # attack), not a crash. Stop, but complete cleanly.
            break

    scan = session.get(Scan, scan_id)
    scan.status = ScanStatus.COMPLETED
    scan.completed_at = utcnow()
    session.commit()
