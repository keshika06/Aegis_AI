"""`aegisai labs` — lifecycle for the bundled intentionally-vulnerable labs.

The labs exist so the full pipeline can be demonstrated safely and repeatably.
They contain synthetic data and synthetic canaries only.
"""

from __future__ import annotations

import typer

from aegisai.cli.stubs import planned

app = typer.Typer(help="Start and stop the bundled vulnerable demo labs.")


@app.command("up")
def labs_up(
    ctx: typer.Context,
    lab: str = typer.Argument("all", help="lab1 | lab2 | lab3 | all"),
) -> None:
    """Start the vulnerable labs via Docker Compose."""
    planned("labs up", "Phase 1 (lab1) / Phase 7 (lab2, lab3)")


@app.command("down")
def labs_down(
    ctx: typer.Context,
    lab: str = typer.Argument("all", help="lab1 | lab2 | lab3 | all"),
) -> None:
    """Stop the vulnerable labs."""
    planned("labs down", "Phase 1")


@app.command("status")
def labs_status(ctx: typer.Context) -> None:
    """Show which labs are running and healthy."""
    planned("labs status", "Phase 1")
