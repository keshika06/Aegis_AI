"""Database engine and session management."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from aegisai.core.config import Config


def _ensure_sqlite_parent(url: str) -> None:
    if url.startswith("sqlite:///"):
        path = Path(url.removeprefix("sqlite:///")).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)


def create_db_engine(cfg: Config) -> Engine:
    url = cfg.core.database_url
    if url.startswith("sqlite:///"):
        expanded = str(Path(url.removeprefix("sqlite:///")).expanduser())
        url = f"sqlite:///{expanded}"
    _ensure_sqlite_parent(url)

    engine = create_engine(url, future=True)

    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):  # type: ignore[no-untyped-def]
            cursor = dbapi_conn.cursor()
            # WAL keeps a long-running scan's writes from blocking concurrent reads
            # (`scan status` polling while `scan run` works).
            cursor.execute("PRAGMA journal_mode=WAL")
            # WAL admits concurrent readers but still allows only one writer, and
            # SQLite's default busy timeout is zero — a second writer fails on the
            # spot with "database is locked" rather than waiting. During a scan the
            # pipeline writes after every stage, so any concurrent write lands in
            # that window: `scan cancel` could not record its request, and
            # `target add` failed outright. Five seconds comfortably outlasts a
            # stage commit while still surfacing a genuine deadlock rather than
            # hanging on it.
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope(engine: Engine) -> Iterator[Session]:
    """Transactional session: commits on success, rolls back on error."""
    factory = session_factory(engine)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
