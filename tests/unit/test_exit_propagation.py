"""Exit codes raised via `typer.Exit` must reach the shell.

Regression test. With `standalone_mode=False`, Typer catches `typer.Exit`
internally and returns the code as the *return value* of `app()` rather than
raising it. `main()` originally discarded that return value, which silently
swallowed every deliberate non-zero exit — most importantly the exit-1 CI gate
that fires when a scan produces a CONFIRMED finding.
"""

from __future__ import annotations

import pytest

from aegisai.cli import main as main_module
from aegisai.core.exit_codes import ExitCode


def test_int_returned_by_the_app_becomes_the_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main_module, "app", lambda **_: int(ExitCode.FINDINGS))

    assert main_module.main() == ExitCode.FINDINGS


def test_none_return_means_a_clean_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main_module, "app", lambda **_: None)

    assert main_module.main() == ExitCode.OK


def test_typer_exit_is_still_honoured_if_it_does_propagate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Belt and braces: handle the raised form too, in case Typer changes."""
    import typer

    def _raise(**_: object) -> None:
        raise typer.Exit(int(ExitCode.ENVIRONMENT))

    monkeypatch.setattr(main_module, "app", _raise)

    assert main_module.main() == ExitCode.ENVIRONMENT


def test_aegis_error_maps_to_its_own_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisai.core.exceptions import UnauthorizedTargetError

    def _raise(**_: object) -> None:
        raise UnauthorizedTargetError("http://localhost:9999", "tgt-abc")

    monkeypatch.setattr(main_module, "app", _raise)

    assert main_module.main() == ExitCode.TARGET
