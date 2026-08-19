"""`aegisai scan` — run and inspect scans."""

from __future__ import annotations

import json as jsonlib

import typer
from sqlalchemy import select

from aegisai.cli import output
from aegisai.cli.context import AppContext
from aegisai.cli.options import JSON_OPTION
from aegisai.cli.stubs import planned
from aegisai.cli.target import require_authorized
from aegisai.core.db import session_factory, session_scope
from aegisai.core.exceptions import NotFoundError
from aegisai.core.exit_codes import ExitCode
from aegisai.models.enums import FindingVerdict, ScanStatus
from aegisai.models.finding import Finding
from aegisai.models.scan import Scan
from aegisai.models.target import Target
from aegisai.pipeline.runner import TOTAL_PIPELINE_STAGES, run_pipeline

app = typer.Typer(help="Run security scans and inspect their results.")


@app.command("run")
def run_scan(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Registered target id or URL."),
    profile: str = typer.Option("standard", "--profile", "-p", help="quick | standard | deep"),
    engines: str = typer.Option(
        "native", "--engines", help="Attack engines: native,garak,pyrit,promptfoo"
    ),
    families: str | None = typer.Option(
        None,
        "--families",
        help="Stage 2B evasion families: encoding,semantic,context,fragmentation,mutation",
    ),
    fmt: str = typer.Option("json", "--format", help="Report formats to render."),
    json_: bool = JSON_OPTION,
) -> None:
    """Run the pipeline against an authorized target.

    Exits 1 when any CONFIRMED finding exists, so this can gate a CI build.
    """
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)
    engine = app_ctx.engine()
    family_list = [f.strip() for f in families.split(",") if f.strip()] if families else None

    # The authorization gate runs before anything else: an unauthorized target is
    # refused as unauthorized regardless of how much of the pipeline exists.
    with session_scope(engine) as session:
        target_row = require_authorized(session, target)
        target_url, target_id = target_row.url, target_row.id
        target_type = target_row.target_type

        scan = Scan(
            target_id=target_id,
            profile=profile,
            status=ScanStatus.PENDING,
            total_stages=TOTAL_PIPELINE_STAGES,
            engines={"requested": [e.strip() for e in engines.split(",") if e.strip()]},
            config={"format": fmt, "families": family_list},
        )
        session.add(scan)
        session.flush()
        scan_id = scan.id

    if not app_ctx.json_output:
        app_ctx.console.print(f"\n  [bold]AEGISAI[/bold]  {scan_id}  →  {target_url}\n")

    session = session_factory(engine)()
    try:
        for progress in run_pipeline(
            scan_id=scan_id,
            session=session,
            config=app_ctx.config,
            target_url=target_url,
            target_id=target_id,
            target_type=target_type,
            families=family_list,
        ):
            if not app_ctx.json_output and not app_ctx.quiet:
                mark = "[green]✓[/green]" if progress.result.ok else "[yellow]![/yellow]"
                app_ctx.console.print(
                    f"  [{progress.index}/{TOTAL_PIPELINE_STAGES}] "
                    f"{progress.label:<26} {mark}  [dim]{progress.result.summary}[/dim]"
                )
    finally:
        session.close()

    with session_scope(engine) as session:
        findings = list(session.scalars(select(Finding).where(Finding.scan_id == scan_id)))
        counts = {v.value: 0 for v in FindingVerdict}
        for finding in findings:
            counts[finding.verdict] = counts.get(finding.verdict, 0) + 1
        json_path = str(app_ctx.config.reports_dir / f"{scan_id}.json")
        html_path = str(app_ctx.config.reports_dir / f"{scan_id}.html")

    payload = {
        "scan_id": scan_id,
        "target": target_url,
        "findings": counts,
        "report": json_path,
        "report_html": html_path,
    }

    def render() -> None:
        app_ctx.console.print()
        confirmed = counts.get(FindingVerdict.CONFIRMED, 0)
        headline = (
            f"[bold red]{confirmed} CONFIRMED[/bold red]"
            if confirmed
            else "[green]0 CONFIRMED[/green]"
        )
        app_ctx.console.print(
            f"  {headline} · {counts.get(FindingVerdict.LIKELY, 0)} LIKELY "
            f"· {counts.get(FindingVerdict.SUSPECTED, 0)} SUSPECTED"
        )
        # The HTML report is what a person actually opens, so it leads and comes
        # with a copy-pasteable command — the full path is easy to mistype.
        app_ctx.console.print(f"\n  [bold]report[/bold]     open {html_path}")
        app_ctx.console.print(f"  [dim]json       {json_path}[/dim]")
        # The dashboard is the surface people actually demo, so it belongs in the
        # summary rather than needing to be discovered in the docs.
        app_ctx.console.print("  [bold]dashboard[/bold]  aegisai dashboard serve")
        app_ctx.console.print(f"  [dim]details    aegisai findings list {scan_id}[/dim]\n")

    output.emit(app_ctx, payload, render)

    if counts.get(FindingVerdict.CONFIRMED, 0) > 0:
        raise typer.Exit(int(ExitCode.FINDINGS))


@app.command("status")
def scan_status(
    ctx: typer.Context,
    scan_id: str = typer.Argument(..., help="Scan id."),
    json_: bool = JSON_OPTION,
) -> None:
    """Show stage and progress for a scan."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)

    with session_scope(app_ctx.engine()) as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError(
                f"No scan with id '{scan_id}'.", hint="List scans with:  aegisai scan list"
            )
        payload = {
            "scan_id": scan.id,
            "status": scan.status,
            "stage": scan.current_stage,
            "stages_completed": scan.stages_completed,
            "total_stages": scan.total_stages,
            "message": scan.message,
            "error": scan.error,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
        }

    def render() -> None:
        for key, value in payload.items():
            if value is not None:
                app_ctx.console.print(f"  [dim]{key:<18}[/dim] {value}")

    output.emit(app_ctx, payload, render)


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
    planned("scan cancel", "Phase 2")


@app.command("report")
def scan_report(
    ctx: typer.Context,
    scan_id: str | None = typer.Argument(None, help="Scan id. Omit to use the most recent scan."),
    fmt: str = typer.Option("json", "--format", help="json | html"),
    open_: bool = typer.Option(False, "--open", help="Open the report in your browser."),
) -> None:
    """Print or open the stored report for a scan."""
    app_ctx: AppContext = ctx.obj

    if fmt not in {"json", "html"}:
        planned(f"scan report --format {fmt}", "a later phase")

    # Reaching for the newest scan is what people mean when they omit the id,
    # and it saves copying a 12-character hex string off the previous screen.
    if scan_id is None:
        with session_scope(app_ctx.engine()) as session:
            latest = session.scalar(select(Scan).order_by(Scan.created_at.desc()))
            if latest is None:
                raise NotFoundError(
                    "No scans recorded yet.",
                    hint="Run one with:  aegisai scan run <target>",
                )
            scan_id = latest.id

    path = app_ctx.config.reports_dir / f"{scan_id}.{fmt}"
    if not path.exists():
        raise NotFoundError(
            f"No {fmt.upper()} report for '{scan_id}'.",
            hint=f"Expected it at {path}. Run:  aegisai scan run <target>",
        )

    if open_:
        import subprocess
        import sys

        opener = {"darwin": "open", "win32": "start"}.get(sys.platform, "xdg-open")
        subprocess.run([opener, str(path)], check=False)
        output.success(app_ctx, f"opened {path}")
        return

    if fmt == "html":
        # Printing 30 KB of markup into a terminal helps nobody.
        output.success(app_ctx, str(path))
        app_ctx.console.print(
            f"  [dim]view it with:  aegisai scan report {scan_id} --format html --open[/dim]"
        )
        return

    app_ctx.console.print_json(jsonlib.dumps(jsonlib.loads(path.read_text(encoding="utf-8"))))
