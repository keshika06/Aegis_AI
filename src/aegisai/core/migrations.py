"""Schema versioning.

Deliberately not Alembic: the schema is small and the runtime is a local CLI, so
a numbered list of idempotent steps is easier to audit than a migration graph.

The rules that matter:

* Never drop or recreate a table — a database holds real scan history.
* Adding a column to an existing table needs its own migration, guarded by
  `column_exists`; `create_all` will not alter a table that already exists.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import Connection, Engine, inspect, text

import aegisai.models  # noqa: F401  (registers every table on Base.metadata)
from aegisai.models.base import Base

SCHEMA_VERSION_TABLE = "aegisai_schema_version"


@dataclass(frozen=True)
class Migration:
    version: int
    description: str
    apply: Callable[[Connection], None]


def _create_baseline(conn: Connection) -> None:
    """v1 — every table currently declared on the metadata."""
    Base.metadata.create_all(conn)


def _add_risk_model_version(conn: Connection) -> None:
    """v2 — record which risk model produced each score.

    Existing rows keep 0, meaning "scored before versioning". They are real
    scores and are not discarded, but they were produced by a different model,
    so anything comparing scans across time has to exclude them rather than
    plot them alongside current ones.
    """
    if not column_exists(conn, "risk_scores", "model_version"):
        conn.execute(
            text("ALTER TABLE risk_scores ADD COLUMN model_version INTEGER NOT NULL DEFAULT 0")
        )


def _add_risk_axes(conn: Connection) -> None:
    """v3 — store the likelihood/impact/confidence a score was built from.

    Nullable: rows written before this column exists keep NULL, which readers
    treat as "not recorded" rather than as zeroes.
    """
    if not column_exists(conn, "risk_scores", "axes"):
        conn.execute(text("ALTER TABLE risk_scores ADD COLUMN axes JSON"))


MIGRATIONS: list[Migration] = [
    Migration(1, "baseline schema", _create_baseline),
    Migration(2, "record the risk model version on each score", _add_risk_model_version),
    Migration(3, "record the axes each risk score was built from", _add_risk_axes),
]


def column_exists(conn: Connection, table: str, column: str) -> bool:
    """Guard for additive migrations, so re-running one is harmless."""
    inspector = inspect(conn)
    if table not in inspector.get_table_names():
        return False
    return any(col["name"] == column for col in inspector.get_columns(table))


def _ensure_version_table(conn: Connection) -> None:
    conn.execute(
        text(
            f"CREATE TABLE IF NOT EXISTS {SCHEMA_VERSION_TABLE} ("
            "  version INTEGER NOT NULL,"
            "  applied_at TEXT NOT NULL DEFAULT (datetime('now'))"
            ")"
        )
    )


def current_version(engine: Engine) -> int:
    """Highest applied migration version; 0 means an empty database."""
    with engine.connect() as conn:
        _ensure_version_table(conn)
        conn.commit()
        row = conn.execute(
            text(f"SELECT COALESCE(MAX(version), 0) FROM {SCHEMA_VERSION_TABLE}")
        ).scalar_one()
        return int(row or 0)


def latest_version() -> int:
    return max((m.version for m in MIGRATIONS), default=0)


def pending(engine: Engine) -> list[Migration]:
    applied = current_version(engine)
    return [m for m in MIGRATIONS if m.version > applied]


def upgrade(engine: Engine) -> list[Migration]:
    """Apply every pending migration in order. Returns the ones applied."""
    to_apply = pending(engine)
    for migration in to_apply:
        with engine.begin() as conn:
            _ensure_version_table(conn)
            migration.apply(conn)
            conn.execute(
                text(f"INSERT INTO {SCHEMA_VERSION_TABLE} (version) VALUES (:v)"),
                {"v": migration.version},
            )
    return to_apply
