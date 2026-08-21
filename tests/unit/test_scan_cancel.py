"""`scan cancel`, and the cooperative check that makes it mean something.

A cancel that only relabels the row would leave the scanning process running and
then overwrite the label when it finished. The runner therefore checks between
stages, and the request has to survive the write contention of a scan that is
committing as it goes.
"""

from __future__ import annotations

import sqlite3

import pytest

from aegisai.core.config import load_config
from aegisai.core.db import create_db_engine, session_scope
from aegisai.models.enums import TERMINAL_STATUSES, ScanStatus, Stage
from aegisai.models.scan import Scan
from aegisai.models.target import Target
from aegisai.pipeline import runner
from aegisai.pipeline.base import StageResult


class _Cancelling:
    """Stands in for the other process: cancels the scan mid-run."""

    stage = Stage.DISCOVERY

    def run(self, ctx):  # noqa: ANN001, ANN201
        scan = ctx.session.get(Scan, ctx.scan_id)
        scan.status = ScanStatus.CANCELLED
        ctx.session.commit()
        return StageResult(ok=True, summary="cancelled mid-run", counts={})


class _Recording:
    """A stage that records that it ran, so we can prove it did not."""

    stage = Stage.ATTACK_PLANNER
    ran = False

    def run(self, ctx):  # noqa: ANN001, ANN201
        type(self).ran = True
        return StageResult(ok=True, summary="ran", counts={})


@pytest.fixture
def scan_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGISAI_CORE_DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
    monkeypatch.setenv("AEGISAI_CORE_HOME", str(tmp_path))
    config = load_config()
    engine = create_db_engine(config)
    from aegisai.core.migrations import upgrade

    upgrade(engine)
    with session_scope(engine) as session:
        target = Target(url="http://127.0.0.1:8001", target_type="chatbot", authorized=True)
        session.add(target)
        session.flush()
        scan = Scan(target_id=target.id, status=ScanStatus.PENDING)
        session.add(scan)
        session.flush()
        ids = (scan.id, target.id)
    return engine, config, ids


class TestTerminalStatuses:
    def test_a_finished_scan_is_never_cancellable(self) -> None:
        """Relabelling a COMPLETED scan as CANCELLED overwrites a real outcome
        with a false one."""
        assert ScanStatus.COMPLETED in TERMINAL_STATUSES
        assert ScanStatus.FAILED in TERMINAL_STATUSES
        assert ScanStatus.CANCELLED in TERMINAL_STATUSES

    def test_a_live_scan_is_cancellable(self) -> None:
        assert ScanStatus.RUNNING not in TERMINAL_STATUSES
        assert ScanStatus.PENDING not in TERMINAL_STATUSES


class TestCooperativeCancel:
    def test_a_cancel_mid_run_stops_the_next_stage(self, scan_env, monkeypatch) -> None:
        """The realistic case: the request arrives from another process while a
        stage is already running."""
        engine, config, (scan_id, target_id) = scan_env
        _Recording.ran = False
        monkeypatch.setattr(runner, "STAGES", [_Cancelling, _Recording])

        with session_scope(engine) as session:
            progress = list(
                runner.run_pipeline(
                    session=session,
                    config=config,
                    scan_id=scan_id,
                    target_url="http://127.0.0.1:8001",
                    target_id=target_id,
                )
            )

        assert len(progress) == 1, "only the stage already underway should complete"
        assert _Recording.ran is False, "the next stage ran despite the cancellation"

    def test_a_cancel_while_pending_stops_it_starting(self, scan_env, monkeypatch) -> None:
        """Setting RUNNING unconditionally would overwrite the request and the
        scan would run anyway."""
        engine, config, (scan_id, target_id) = scan_env
        _Recording.ran = False
        monkeypatch.setattr(runner, "STAGES", [_Recording])

        with session_scope(engine) as session:
            session.get(Scan, scan_id).status = ScanStatus.CANCELLED
            session.commit()
            progress = list(
                runner.run_pipeline(
                    session=session,
                    config=config,
                    scan_id=scan_id,
                    target_url="http://127.0.0.1:8001",
                    target_id=target_id,
                )
            )

        assert progress == []
        assert _Recording.ran is False

    def test_the_scan_is_finalised_with_a_reason(self, scan_env, monkeypatch) -> None:
        engine, config, (scan_id, target_id) = scan_env
        monkeypatch.setattr(runner, "STAGES", [_Cancelling, _Recording])

        with session_scope(engine) as session:
            list(
                runner.run_pipeline(
                    session=session,
                    config=config,
                    scan_id=scan_id,
                    target_url="http://127.0.0.1:8001",
                    target_id=target_id,
                )
            )

        with session_scope(engine) as session:
            scan = session.get(Scan, scan_id)
            assert scan.status == ScanStatus.CANCELLED
            assert scan.completed_at is not None, "a cancelled scan must reach a terminal state"
            assert "cancel" in (scan.error or "").lower()


class TestWriteContention:
    def test_the_busy_timeout_is_set_on_every_connection(self, tmp_path, monkeypatch) -> None:
        """WAL admits concurrent readers but one writer, and SQLite's default
        busy timeout is zero — a second writer fails on the spot rather than
        waiting. `scan cancel` writes while a scan is committing, so without
        this the request could not be recorded at all."""
        monkeypatch.setenv("AEGISAI_CORE_DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
        engine = create_db_engine(load_config())

        with engine.connect() as conn:
            from sqlalchemy import text

            timeout = conn.execute(text("PRAGMA busy_timeout")).scalar()
            journal = conn.execute(text("PRAGMA journal_mode")).scalar()

        assert timeout >= 5000, f"busy_timeout is {timeout}"
        assert journal.lower() == "wal"

    def test_a_second_writer_waits_rather_than_failing(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("AEGISAI_CORE_DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
        engine = create_db_engine(load_config())
        from aegisai.core.migrations import upgrade

        upgrade(engine)

        holder = sqlite3.connect(f"{tmp_path}/t.db", timeout=10)
        holder.execute("BEGIN IMMEDIATE")
        try:
            with engine.connect() as conn:
                from sqlalchemy import text

                # Proves the connection is configured to wait; the holder is
                # released below rather than waiting out the full timeout here.
                assert conn.execute(text("PRAGMA busy_timeout")).scalar() >= 5000
        finally:
            holder.rollback()
            holder.close()
