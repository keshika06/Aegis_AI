"""`aegisai attack` — payload library, plans, and generated variants."""

from __future__ import annotations

import typer

from aegisai.cli.stubs import planned

app = typer.Typer(help="Browse the attack library and inspect generated attacks.")
library_app = typer.Typer(help="The OWASP-tagged payload library.")
app.add_typer(library_app, name="library")


@library_app.command("list")
def list_library(
    ctx: typer.Context,
    owasp: str | None = typer.Option(None, "--owasp", help="Filter by OWASP tag."),
    category: str | None = typer.Option(None, "--category", help="Filter by attack category."),
) -> None:
    """List payloads in the attack library."""
    planned("attack library list", "Phase 2 (planner)")


@app.command("plan")
def show_plan(
    ctx: typer.Context,
    scan_id: str = typer.Argument(..., help="Scan id."),
) -> None:
    """Show the Stage 2A attack plan for a scan."""
    planned("attack plan", "Phase 2 (planner)")


@app.command("variants")
def show_variants(
    ctx: typer.Context,
    attack_id: str = typer.Argument(..., help="Attack case id."),
) -> None:
    """Show the Stage 2B variants generated from one attack case."""
    planned("attack variants", "Phase 3 (evasion orchestrator)")
