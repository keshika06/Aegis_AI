"""The CLI surface itself: command tree, exit codes, and JSON output.

Phase 0 promises the whole command tree exists with real help text, so these
tests fail loudly if a group is dropped or renamed.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from aegisai.core.exit_codes import ExitCode

EXPECTED_GROUPS = [
    "doctor",
    "init",
    "discover",
    "serve",
    "target",
    "scan",
    "findings",
    "chain",
    "risk",
    "attack",
    "regression",
    "labs",
    "config",
]


def test_help_lists_every_command_group(
    aegis_home: Path, run: Callable[..., int], capsys: pytest.CaptureFixture
) -> None:
    assert run("--help") == 0
    out = capsys.readouterr().out

    missing = [name for name in EXPECTED_GROUPS if name not in out]
    assert not missing, f"missing from --help: {missing}"


@pytest.mark.parametrize("group", EXPECTED_GROUPS)
def test_every_group_has_help(
    group: str, aegis_home: Path, run: Callable[..., int], capsys: pytest.CaptureFixture
) -> None:
    assert run(group, "--help") == 0
    assert "Usage:" in capsys.readouterr().out


def test_version_flag(
    aegis_home: Path, run: Callable[..., int], capsys: pytest.CaptureFixture
) -> None:
    assert run("--version") == 0
    assert "aegisai" in capsys.readouterr().out


def test_unknown_option_is_a_usage_error(aegis_home: Path, run: Callable[..., int]) -> None:
    assert run("--definitely-not-a-flag") == ExitCode.USAGE


def test_unimplemented_command_exits_non_zero(initialized: Path, run: Callable[..., int]) -> None:
    """A stub must never look like a clean run to a script."""
    assert run("findings", "list", "scan-abc") == ExitCode.USAGE


def test_json_flag_works_after_the_subcommand(
    initialized: Path, run: Callable[..., int], capsys: pytest.CaptureFixture
) -> None:
    """Click resolves callback options only before the subcommand.

    Scripts naturally write `aegisai target list --json`, so read commands accept
    the flag locally as well as globally.
    """
    assert run("target", "list", "--json") == 0
    assert json.loads(capsys.readouterr().out) == []


def test_json_flag_works_before_the_subcommand(
    initialized: Path, run: Callable[..., int], capsys: pytest.CaptureFixture
) -> None:
    assert run("--json", "target", "list") == 0
    assert json.loads(capsys.readouterr().out) == []


def test_target_lifecycle_via_json(
    initialized: Path, run: Callable[..., int], capsys: pytest.CaptureFixture
) -> None:
    assert run("target", "add", "http://localhost:8001", "--authorize", "--json") == 0
    added = json.loads(capsys.readouterr().out)
    assert added["authorized"] is True
    assert added["url"] == "http://localhost:8001"

    assert run("target", "list", "--json") == 0
    listed = json.loads(capsys.readouterr().out)
    assert [t["id"] for t in listed] == [added["id"]]

    assert run("target", "show", added["id"], "--json") == 0
    assert json.loads(capsys.readouterr().out)["id"] == added["id"]


def test_api_key_is_never_persisted(
    initialized: Path, run: Callable[..., int], capsys: pytest.CaptureFixture
) -> None:
    """Only the *name* of the env var is stored, never a secret value."""
    assert (
        run(
            "target",
            "add",
            "http://localhost:8002",
            "--api-key-env",
            "TARGET_TOKEN",
            "--json",
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)

    assert payload["api_key_env"] == "TARGET_TOKEN"
    assert "api_key" not in payload


def test_scan_list_is_empty_but_successful(initialized: Path, run: Callable[..., int]) -> None:
    assert run("scan", "list", "--json") == 0
