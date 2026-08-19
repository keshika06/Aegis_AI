"""`aegisai regression` — the closed loop, and the CI gate."""

from __future__ import annotations

import typer

from aegisai.cli.stubs import planned

app = typer.Typer(help="Replay confirmed findings as regression tests.")


@app.command("list")
def list_regressions(
    ctx: typer.Context,
    status: str | None = typer.Option(
        None, "--status", help="ACTIVE | RESOLVED | REGRESSED | EXHAUSTED"
    ),
) -> None:
    """List stored regression tests."""
    planned("regression list", "Phase 6 (closed loop)")


@app.command("run")
def run_regressions(
    ctx: typer.Context,
    target: str | None = typer.Option(None, "--target", help="Restrict to one target."),
    all_targets: bool = typer.Option(False, "--all", help="Replay every active test."),
    cycle: bool = typer.Option(
        False, "--cycle", help="Run the bounded adaptive cycle, not a single replay."
    ),
) -> None:
    """Replay regression tests. Exits 1 if any test REGRESSED, for CI gating."""
    planned("regression run", "Phase 6 (closed loop)")
