"""The authorization gate — AegisAI's central safety boundary.

These are the highest-value tests in the suite: everything else is a feature, but
this is the rule that keeps the scanner from probing systems nobody authorized.

Targets here point at a port with nothing listening, so the gate can be tested
without the tests depending on a live lab.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from aegisai.core.exit_codes import ExitCode

UNAUTHORIZED = "http://127.0.0.1:59998"
AUTHORIZED = "http://127.0.0.1:59999"


@pytest.fixture
def targets(initialized: Path, run: Callable[..., int]) -> None:
    assert run("target", "add", UNAUTHORIZED, "--type", "rag") == 0
    assert run("target", "add", AUTHORIZED, "--type", "chatbot", "--authorize") == 0


def test_scan_refuses_unregistered_target(targets: None, run: Callable[..., int]) -> None:
    assert run("scan", "run", "http://evil.example.com") == ExitCode.TARGET


def test_scan_refuses_registered_but_unauthorized_target(
    targets: None, run: Callable[..., int]
) -> None:
    assert run("scan", "run", UNAUTHORIZED) == ExitCode.TARGET


def test_discover_is_behind_the_same_gate(targets: None, run: Callable[..., int]) -> None:
    """Discovery sends live requests, so it is not a way around authorization."""
    assert run("discover", UNAUTHORIZED) == ExitCode.TARGET


def test_gate_decides_before_the_pipeline_starts(targets: None, run: Callable[..., int]) -> None:
    """Regression test: the gate must be the first thing `scan run` evaluates.

    It previously sat behind the not-implemented guard, so an unauthorized target
    produced a usage error and the safety boundary was never exercised at all.
    An authorized target must get past the gate — whatever the pipeline then
    finds against an unreachable host is a separate question.
    """
    assert run("scan", "run", UNAUTHORIZED) == ExitCode.TARGET
    assert run("scan", "run", AUTHORIZED) != ExitCode.TARGET


def test_authorize_promotes_an_existing_target(targets: None, run: Callable[..., int]) -> None:
    assert run("scan", "run", UNAUTHORIZED) == ExitCode.TARGET
    assert run("target", "authorize", UNAUTHORIZED) == 0
    assert run("scan", "run", UNAUTHORIZED) != ExitCode.TARGET


def test_unauthorized_hint_names_the_authorize_command(
    targets: None, run: Callable[..., int], capsys: pytest.CaptureFixture
) -> None:
    """An already-registered target must not be told to `add` itself again."""
    run("scan", "run", UNAUTHORIZED)
    output = capsys.readouterr()
    combined = output.out + output.err

    assert "target authorize" in combined
    assert "target add" not in combined
