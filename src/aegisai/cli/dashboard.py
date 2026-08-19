"""`aegisai dashboard` — put a real scan into the web dashboard."""

from __future__ import annotations

import json as jsonlib
import shutil
import subprocess
from pathlib import Path

import typer
from sqlalchemy import select

from aegisai.cli import output
from aegisai.cli.context import AppContext
from aegisai.cli.options import JSON_OPTION
from aegisai.core.db import session_scope
from aegisai.core.exceptions import AegisError, NotFoundError
from aegisai.dashboard.export import build
from aegisai.models.scan import Scan

app = typer.Typer(help="Export scan results to the web dashboard.")

FRONTEND_DIR = Path(__file__).resolve().parents[3] / "frontend"
DATA_FILE = FRONTEND_DIR / "src" / "data" / "scanData.json"


def _resolve_scan(session, scan_id: str | None) -> str:
    """Fall back to the most recent scan, which is what people mean."""
    if scan_id:
        if session.get(Scan, scan_id) is None:
            raise NotFoundError(
                f"No scan with id '{scan_id}'.", hint="List scans with:  aegisai scan list"
            )
        return scan_id

    latest = session.scalar(select(Scan).order_by(Scan.created_at.desc()))
    if latest is None:
        raise NotFoundError(
            "No scans recorded yet.", hint="Run one with:  aegisai scan run <target>"
        )
    return latest.id


@app.command("export")
def export_scan(
    ctx: typer.Context,
    scan_id: str | None = typer.Argument(None, help="Scan id. Omit for the most recent."),
    out: Path | None = typer.Option(None, "--out", help="Where to write the JSON."),
    json_: bool = JSON_OPTION,
) -> None:
    """Write a scan's results into the dashboard's data file."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)

    with session_scope(app_ctx.engine()) as session:
        resolved = _resolve_scan(session, scan_id)
        data = build(session, resolved)

    destination = out or DATA_FILE
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(jsonlib.dumps(data, indent=2, default=str), encoding="utf-8")

    summary = {
        "scan_id": resolved,
        "path": str(destination),
        "findings": data["run"]["totalFindings"],
        "confirmed": data["run"]["confirmed"],
        "risk": data["run"]["risk"],
    }

    def render() -> None:
        output.success(app_ctx, f"exported {resolved} → {destination}")
        app_ctx.console.print(
            f"  [dim]{summary['findings']} findings · {summary['confirmed']} confirmed "
            f"· top risk {summary['risk']}/100[/dim]"
        )
        app_ctx.console.print("  [dim]view it with:  aegisai dashboard serve[/dim]")

    output.emit(app_ctx, summary, render)


@app.command("serve")
def serve_dashboard(
    ctx: typer.Context,
    scan_id: str | None = typer.Argument(None, help="Scan id. Omit for the most recent."),
    port: int = typer.Option(5173, "--port", help="Port for the dev server."),
    no_export: bool = typer.Option(
        False, "--no-export", help="Use the data already exported instead of refreshing it."
    ),
) -> None:
    """Export a scan and start the dashboard dev server."""
    app_ctx: AppContext = ctx.obj

    if not FRONTEND_DIR.exists():
        raise AegisError(
            f"Frontend not found at {FRONTEND_DIR}.",
            hint="It ships in the repo under frontend/.",
        )

    if not no_export:
        with session_scope(app_ctx.engine()) as session:
            resolved = _resolve_scan(session, scan_id)
            data = build(session, resolved)
        DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        DATA_FILE.write_text(jsonlib.dumps(data, indent=2, default=str), encoding="utf-8")
        output.success(app_ctx, f"exported {resolved} ({data['run']['totalFindings']} findings)")

    npm = shutil.which("npm")
    if npm is None:
        raise AegisError(
            "npm is not installed, so the dev server cannot start.",
            hint=f"Install Node.js, then:  cd {FRONTEND_DIR} && npm install && npm run dev",
        )

    if not (FRONTEND_DIR / "node_modules").exists():
        output.warn(app_ctx, "installing frontend dependencies (first run only)…")
        result = subprocess.run([npm, "install"], cwd=FRONTEND_DIR, check=False)
        if result.returncode != 0:
            raise AegisError("npm install failed.", hint="Run it manually to see the error.")

    app_ctx.console.print(f"\n  [bold]Dashboard[/bold]  http://localhost:{port}")
    app_ctx.console.print("  [dim]Ctrl-C to stop[/dim]\n")
    subprocess.run([npm, "run", "dev", "--", "--port", str(port)], cwd=FRONTEND_DIR, check=False)
