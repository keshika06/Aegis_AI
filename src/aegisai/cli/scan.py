"""`aegisai scan` — run and inspect scans."""

from __future__ import annotations

import typer
from sqlalchemy import select

from aegisai.cli import output
from aegisai.cli.context import AppContext
from aegisai.cli.options import JSON_OPTION
from aegisai.cli.stubs import planned
from aegisai.cli.target import require_authorized
from aegisai.core.db import session_scope
from aegisai.models.scan import Scan
from aegisai.models.target import Target

app = typer.Typer(help="Run security scans and inspect their results.")


@app.command("run")
def run_scan(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Registered target id or URL."),
    profile: str = typer.Option("standard", "--profile", "-p", help="quick | standard | deep"),
    stages: str | None = typer.Option(
        None, "--stages", help="Comma-separated subset, e.g. 1,2A,2B. Default: all."
    ),
    engines: str = typer.Option(
        "native", "--engines", help="Attack engines: native,garak,pyrit,promptfoo"
    ),
    families: str | None = typer.Option(
        None, "--families", help="Stage 2B transformation families to include."
    ),
    fmt: str = typer.Option("html,json", "--format", help="Report formats to render."),
    out: str | None = typer.Option(None, "--out", help="Directory for rendered reports."),
) -> None:
    """Run the full 11-stage pipeline against an authorized target."""
    app_ctx: AppContext = ctx.obj

    # The authorization gate runs before anything else, including the
    # not-yet-implemented guard below: an unauthorized target must be refused as
    # unauthorized (exit 3) no matter how much of the pipeline exists yet.
    with session_scope(app_ctx.engine()) as session:
        require_authorized(session, target)

    planned("scan run", "Phase 1 (vertical slice)")


@app.command("status")
def scan_status(
    ctx: typer.Context,
    scan_id: str = typer.Argument(..., help="Scan id."),
    watch: bool = typer.Option(False, "--watch", "-w", help="Poll until the scan finishes."),
) -> None:
    """Show live stage and progress for a scan."""
    planned("scan status", "Phase 1")


@app.command("list")
def list_scans(
    ctx: typer.Context,
    target: str | None = typer.Option(None, "--target", help="Filter by target id or URL."),
    status: str | None = typer.Option(None, "--status", help="Filter by scan status."),
    limit: int = typer.Option(20, "--limit", help="Maximum rows to return."),
    json_: bool = JSON_OPTION,
) -> None:
    """List scans, newest first."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)

    with session_scope(app_ctx.engine()) as session:
        stmt = select(Scan, Target).join(Target, Scan.target_id == Target.id)
        if target:
            stmt = stmt.where((Target.id == target) | (Target.url == target))
        if status:
            stmt = stmt.where(Scan.status == status.upper())
        stmt = stmt.order_by(Scan.created_at.desc()).limit(limit)
        payload = [
            {
                "scan_id": scan.id,
                "target_url": tgt.url,
                "status": scan.status,
                "stage": scan.current_stage,
                "profile": scan.profile,
                "created_at": scan.created_at,
            }
            for scan, tgt in session.execute(stmt).all()
        ]

    def render() -> None:
        if not payload:
            output.empty_hint(
                app_ctx, "No scans recorded yet.", "Start one with:  aegisai scan run <target>"
            )
            return
        rows = [
            (
                row["scan_id"],
                row["target_url"],
                output.styled(row["status"]),
                row["stage"] or "-",
                str(row["created_at"])[:19],
            )
            for row in payload
        ]
        app_ctx.console.print(
            output.build_table(["SCAN", "TARGET", "STATUS", "STAGE", "CREATED"], rows)
        )

    output.emit(app_ctx, payload, render)


@app.command("cancel")
def cancel_scan(
    ctx: typer.Context,
    scan_id: str = typer.Argument(..., help="Scan id."),
) -> None:
    """Stop a running scan."""
    planned("scan cancel", "Phase 1")


@app.command("report")
def scan_report(
    ctx: typer.Context,
    scan_id: str = typer.Argument(..., help="Scan id."),
    fmt: str = typer.Option("html", "--format", help="html | json | pdf"),
    out: str | None = typer.Option(None, "--out", help="Output directory."),
) -> None:
    """Render (or re-render) the report for a scan."""
    planned("scan report", "Phase 6 (reporting)")
