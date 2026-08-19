"""Diagnostics behaviour."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from aegisai.core.config import load_config
from aegisai.core.doctor import CheckStatus, check_database, run_checks, worst_status


def test_doctor_is_read_only_on_a_clean_machine(
    aegis_home: Path, run: Callable[..., int], capsys: pytest.CaptureFixture
) -> None:
    """`doctor` must not create anything it is only supposed to report on.

    Regression test: opening the SQLite engine to read the schema version used to
    create the home directory and an empty database file, which both mutated
    state the user did not ask to change and silently invalidated the
    "directories missing" warning printed just above it.
    """
    assert not aegis_home.exists()

    assert run("doctor") == 0

    assert not aegis_home.exists(), "doctor created the home directory"
    assert not (aegis_home / "aegisai.db").exists(), "doctor created a database file"


def test_doctor_reports_uninitialized_database_without_touching_disk(aegis_home: Path) -> None:
    cfg = load_config()
    result = check_database(cfg)

    assert result.status is CheckStatus.WARN
    assert "not initialized" in result.detail
    assert result.fixable
    assert not aegis_home.exists()


def test_doctor_passes_after_init(initialized: Path, run: Callable[..., int]) -> None:
    assert run("doctor") == 0
    assert worst_status(run_checks(load_config())) is not CheckStatus.FAIL


def test_doctor_json_output_is_parseable(
    initialized: Path, run: Callable[..., int], capsys: pytest.CaptureFixture
) -> None:
    assert run("doctor", "--json") == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["status"] in {"OK", "WARN", "FAIL"}
    assert {c["name"] for c in payload["checks"]} >= {"Python", "Config", "Database"}


def test_fix_creates_what_was_missing(aegis_home: Path, run: Callable[..., int]) -> None:
    assert run("doctor", "--fix") == 0
    assert aegis_home.exists()
    assert (aegis_home / "aegisai.db").exists()
