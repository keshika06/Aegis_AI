"""`aegisai findings` — inspect fused verdicts and their evidence."""

from __future__ import annotations

import typer

from aegisai.cli.stubs import planned

app = typer.Typer(help="Inspect findings and their supporting evidence.")


@app.command("list")
def list_findings(
    ctx: typer.Context,
    scan_id: str = typer.Argument(..., help="Scan id."),
    verdict: str | None = typer.Option(None, "--verdict", help="CONFIRMED | LIKELY | SUSPECTED"),
    owasp: str | None = typer.Option(None, "--owasp", help="Filter by OWASP tag, e.g. LLM01."),
) -> None:
    """List findings for a scan."""
    planned("findings list", "Phase 5 (evidence)")


@app.command("show")
def show_finding(
    ctx: typer.Context,
    finding_id: str = typer.Argument(..., help="Finding id."),
) -> None:
    """Show one finding with its full evidence trail."""
    planned("findings show", "Phase 5 (evidence)")
