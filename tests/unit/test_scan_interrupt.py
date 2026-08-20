"""An interrupted scan must reach a terminal state.

Ctrl-C raises KeyboardInterrupt, which is a BaseException and not an Exception,
so the runner's failure handler never saw it. An interrupted scan stayed RUNNING
for ever and `scan list` went on reporting it as live — which is exactly what
the runner's docstring promises cannot happen.
"""

from __future__ import annotations

import pytest

from aegisai.core.config import load_config
from aegisai.core.db import create_db_engine, session_scope
from aegisai.models.enums import ScanStatus, Stage
from aegisai.models.scan import Scan
from aegisai.models.target import Target
from aegisai.pipeline import runner


class _Interrupting:
    stage = Stage.DISCOVERY

    def run(self, ctx):  # noqa: ANN001, ANN201
        raise KeyboardInterrupt


class _Failing:
    stage = Stage.DISCOVERY

    def run(self, ctx):  # noqa: ANN001, ANN201
        raise RuntimeError("boom")


def _status_after(monkeypatch: pytest.MonkeyPatch, stage_cls: type) -> str:
    """Drive one stage that dies, and report the scan's recorded status."""
    monkeypatch.setattr(runner, "STAGES", [stage_cls])
    cfg = load_config()
    with session_scope(create_db_engine(cfg)) as session:
        target = Target(url="http://127.0.0.1:1", target_type="chatbot", authorized=True)
        session.add(target)
        session.flush()
        scan = Scan(target_id=target.id, status=ScanStatus.PENDING)
        session.add(scan)
        session.flush()
        scan_id = scan.id
        session.commit()

        with pytest.raises(BaseException):  # noqa: B017 - both paths re-raise
            list(
                runner.run_pipeline(
                    scan_id=scan_id,
                    session=session,
                    config=cfg,
                    target_url=target.url,
                    target_id=target.id,
                )
            )

        session.expire_all()
        return session.get(Scan, scan_id).status


def test_interrupt_marks_the_scan_cancelled(monkeypatch: pytest.MonkeyPatch, initialized) -> None:
    assert _status_after(monkeypatch, _Interrupting) == ScanStatus.CANCELLED


def test_a_stage_failure_still_marks_the_scan_failed(
    monkeypatch: pytest.MonkeyPatch, initialized
) -> None:
    """The Exception path must keep its own status; the fix adds to it."""
    assert _status_after(monkeypatch, _Failing) == ScanStatus.FAILED


def test_an_interrupted_scan_is_never_left_running(
    monkeypatch: pytest.MonkeyPatch, initialized
) -> None:
    """The claim the runner's docstring makes, asserted rather than trusted."""
    assert _status_after(monkeypatch, _Interrupting) != ScanStatus.RUNNING
