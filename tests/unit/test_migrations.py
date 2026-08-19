"""Schema versioning."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import inspect

from aegisai.core.config import load_config
from aegisai.core.db import create_db_engine
from aegisai.core.migrations import current_version, latest_version, pending, upgrade


def test_upgrade_creates_every_table(aegis_home: Path) -> None:
    engine = create_db_engine(load_config())
    upgrade(engine)

    tables = set(inspect(engine).get_table_names())
    expected = {
        "targets",
        "scans",
        "profiles",
        "attack_cases",
        "attack_variants",
        "control_evaluations",
        "runtime_events",
        "policy_contracts",
        "violations",
        "findings",
        "evidence",
        "attack_chains",
        "risk_scores",
        "reports",
        "regression_tests",
        "regression_results",
    }
    assert expected <= tables, f"missing tables: {expected - tables}"


def test_upgrade_is_idempotent(aegis_home: Path) -> None:
    """Re-running migrations must be a no-op, not a duplicate apply."""
    engine = create_db_engine(load_config())

    first = upgrade(engine)
    second = upgrade(engine)

    assert first, "first upgrade should apply the baseline"
    assert second == [], "second upgrade should have nothing to do"
    assert current_version(engine) == latest_version()


def test_version_starts_at_zero(aegis_home: Path) -> None:
    engine = create_db_engine(load_config())

    assert current_version(engine) == 0
    assert len(pending(engine)) == latest_version()
