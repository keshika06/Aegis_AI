"""Schema versioning."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import inspect, text

from aegisai.core.config import load_config
from aegisai.core.db import create_db_engine
from aegisai.core.migrations import (
    MIGRATIONS,
    SCHEMA_VERSION_TABLE,
    _ensure_version_table,
    current_version,
    latest_version,
    pending,
    upgrade,
)


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


def test_risk_scores_record_which_model_produced_them(aegis_home: Path) -> None:
    """A score from a superseded model is a different measurement, so the row
    has to say which model made it."""
    engine = create_db_engine(load_config())
    upgrade(engine)

    columns = {c["name"] for c in inspect(engine).get_columns("risk_scores")}

    assert "model_version" in columns


def test_adding_the_version_column_preserves_existing_scores(aegis_home: Path) -> None:
    """A database holds real scan history; a migration must never drop it.

    The baseline migration is `create_all` over the current metadata, so a fresh
    database is already the newest shape and migration 2 no-ops on it. The
    migration exists for databases created before the column did, so this builds
    that older table shape explicitly rather than pretending create_all produces
    it.
    """
    engine = create_db_engine(load_config())
    with engine.begin() as conn:
        _ensure_version_table(conn)
        conn.execute(
            text(
                "CREATE TABLE risk_scores ("
                "  id VARCHAR(64) NOT NULL PRIMARY KEY,"
                "  scan_id VARCHAR(64) NOT NULL,"
                "  finding_id VARCHAR(64),"
                "  score FLOAT NOT NULL,"
                "  risk_level VARCHAR(16) NOT NULL,"
                "  factors JSON, weights JSON, explanation TEXT,"
                "  created_at DATETIME"
                ")"
            )
        )
        conn.execute(
            text(
                "INSERT INTO risk_scores (id, scan_id, finding_id, score, risk_level)"
                " VALUES ('risk-old', 'scan-old', 'fnd-old', 9.9, 'CRITICAL')"
            )
        )
        conn.execute(text(f"INSERT INTO {SCHEMA_VERSION_TABLE} (version) VALUES (1)"))

    upgrade(engine)

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT score, risk_level, model_version FROM risk_scores WHERE id = 'risk-old'")
        ).one()

    assert row[0] == 9.9
    assert row[1] == "CRITICAL"
    # 0 means "scored before versioning", which is what excludes it from trends.
    assert row[2] == 0


def test_the_version_migration_is_safe_to_re_run(aegis_home: Path) -> None:
    """Guarded by column_exists, so applying it twice is harmless."""
    engine = create_db_engine(load_config())
    upgrade(engine)

    with engine.begin() as conn:
        MIGRATIONS[1].apply(conn)

    columns = {c["name"] for c in inspect(engine).get_columns("risk_scores")}
    assert "model_version" in columns
