"""Shared fixtures.

Tests drive the real `main()` entry point rather than calling command functions
directly, so error rendering and the documented exit codes are covered too — the
contract users and CI actually depend on.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from aegisai.cli.main import main


@pytest.fixture
def aegis_home(tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point every AegisAI path at a throwaway directory.

    Without this a test run would read and write the developer's real
    ~/.aegisai, including their scan history.
    """
    home = Path(tmp_path) / "home"
    monkeypatch.setenv("AEGISAI_CONFIG", str(Path(tmp_path) / "config.toml"))
    monkeypatch.setenv("AEGISAI_CORE_HOME", str(home))
    monkeypatch.setenv("AEGISAI_CORE_DATABASE_URL", f"sqlite:///{home / 'aegisai.db'}")
    monkeypatch.setenv("AEGISAI_CORE_REPORTS_DIR", str(home / "reports"))
    return home


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch) -> Callable[..., int]:
    """Invoke the CLI exactly as the console script does; return the exit code."""

    def _run(*args: str) -> int:
        monkeypatch.setattr(sys, "argv", ["aegisai", *args])
        return main()

    return _run


@pytest.fixture
def initialized(aegis_home: Path, run: Callable[..., int]) -> Path:
    """An initialized installation: config written, schema migrated."""
    assert run("init") == 0
    return aegis_home
