"""The authorization gate — AegisAI's central safety boundary.

These are the highest-value tests in the suite: everything else is a feature, but
this is the rule that keeps the scanner from probing systems nobody authorized.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from aegisai.core.exit_codes import ExitCode


@pytest.fixture
def targets(initialized: Path, run: Callable[..., int]) -> None:
    assert run("target", "add", "http://localhost:9999", "--type", "rag") == 0
    assert run("target", "add", "http://localhost:8001", "--type", "chatbot", "--authorize") == 0


def test_scan_refuses_unregistered_target(targets: None, run: Callable[..., int]) -> None:
    assert run("scan", "run", "http://evil.example.com") == ExitCode.TARGET


def test_scan_refuses_registered_but_unauthorized_target(
    targets: None, run: Callable[..., int]
) -> None:
    assert run("scan", "run", "http://localhost:9999") == ExitCode.TARGET


def test_discover_is_behind_the_same_gate(targets: None, run: Callable[..., int]) -> None:
    """Discovery sends live requests, so it is not a way around authorization."""
    assert run("discover", "http://localhost:9999") == ExitCode.TARGET


def test_gate_runs_before_unimplemented_stages(targets: None, run: Callable[..., int]) -> None:
    """Regression test: the gate must not sit behind the not-implemented guard.

    `scan run` previously raised "not implemented" (exit 2) before checking
    authorization, so an unauthorized target produced a usage error and the
    safety boundary was never actually exercised.
    """
    unauthorized = run("scan", "run", "http://localhost:9999")
    authorized = run("scan", "run", "http://localhost:8001")

    assert unauthorized == ExitCode.TARGET
    assert authorized == ExitCode.USAGE, "authorized target should pass the gate and reach the stub"


def test_authorize_promotes_an_existing_target(targets: None, run: Callable[..., int]) -> None:
    assert run("scan", "run", "http://localhost:9999") == ExitCode.TARGET
    assert run("target", "authorize", "http://localhost:9999") == 0
    # Now past the gate; only the unimplemented pipeline stops it.
    assert run("scan", "run", "http://localhost:9999") == ExitCode.USAGE


def test_unauthorized_hint_names_the_authorize_command(
    targets: None, run: Callable[..., int], capsys: pytest.CaptureFixture
) -> None:
    """An already-registered target must not be told to `add` itself again."""
    run("scan", "run", "http://localhost:9999")
    output = capsys.readouterr()
    combined = output.out + output.err

    assert "target authorize" in combined
    assert "target add" not in combined
