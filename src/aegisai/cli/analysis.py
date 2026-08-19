"""`aegisai chain` and `aegisai risk` — Stage 8 and Stage 9 views."""

from __future__ import annotations

import typer

from aegisai.cli.stubs import planned

chain_app = typer.Typer(help="Attack-chain graphs correlating findings into exploit paths.")
risk_app = typer.Typer(help="Deterministic, explainable risk scores.")


@chain_app.command("show")
def show_chain(
    ctx: typer.Context,
    scan_id: str = typer.Argument(..., help="Scan id."),
    export: str | None = typer.Option(None, "--export", help="json | dot"),
) -> None:
    """Show the attack-chain graph for a scan."""
    planned("chain show", "Phase 5 (attack chain)")


@risk_app.command("show")
def show_risk(
    ctx: typer.Context,
    scan_id: str = typer.Argument(..., help="Scan id."),
) -> None:
    """Show risk scores with every contributing factor."""
    planned("risk show", "Phase 5 (risk scoring)")
