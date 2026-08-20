"""`aegisai dashboard` — put a real scan into the web dashboard."""

from __future__ import annotations

import json as jsonlib
import shutil
import socket
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


def _port_is_free(port: int) -> bool:
    """True only if every address `localhost` resolves to accepts a bind.

    Checking IPv4 alone is not enough: Vite's dev server binds `[::1]`, so an
    IPv4-only probe reports a busy port as free and we advertise a URL nothing
    is serving.
    """
    try:
        candidates = socket.getaddrinfo("localhost", port, type=socket.SOCK_STREAM)
    except socket.gaierror:  # pragma: no cover - localhost always resolves
        candidates = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", port))]

    for family, socktype, proto, _canon, sockaddr in candidates:
        # No SO_REUSEADDR: this is an availability probe, and the option exists
        # to make binds succeed that otherwise would not.
        with socket.socket(family, socktype, proto) as probe:
            try:
                probe.bind(sockaddr)
            except OSError:
                return False
    return True


def _resolve_port(requested: int, *, span: int = 20) -> int:
    """Return the first free port at or after `requested`.

    Vite falls back to the next free port on its own, but silently and *after*
    we have already printed a URL -- so the address AegisAI advertises is the
    one it asked for, not the one that ends up serving. Binding the choice here
    means the printed URL is the real one, and `--strictPort` turns any
    remaining drift into a loud failure instead of a wrong link.
    """
    for candidate in range(requested, requested + span):
        if _port_is_free(candidate):
            return candidate
    raise AegisError(
        f"No free port between {requested} and {requested + span - 1}.",
        hint="Free one, or pick another with:  aegisai dashboard serve --port <n>",
    )


DASHBOARD_MARKER = "package.json"
"""What proves a candidate directory is really the dashboard source."""


def _find_frontend() -> Path | None:
    """Locate the dashboard source, which ships in the repo, not in the wheel.

    Identified by its package.json rather than by the directory merely existing.
    The previous version counted directories up from __file__, which is correct
    only for a source checkout: installed non-editable, `parents[3]` lands inside
    the virtualenv. Exporting then created that path via `mkdir(parents=True)`,
    so the "frontend not found" guard passed on every later run and npm was
    handed a directory with no package.json — an error that named npm rather
    than the actual problem.
    """
    candidates = [
        # Source checkout: src/aegisai/cli/dashboard.py -> repo root.
        Path(__file__).resolve().parents[3] / "frontend",
        # Installed non-editable, but invoked from the repo.
        Path.cwd() / "frontend",
        Path.cwd(),
    ]
    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if (candidate / DASHBOARD_MARKER).is_file():
            return candidate
    return None


FRONTEND_DIR = _find_frontend()
DATA_FILE = (
    FRONTEND_DIR / "src" / "data" / "scanData.json" if FRONTEND_DIR else Path("scanData.json")
)


def _require_frontend() -> Path:
    if FRONTEND_DIR is None:
        raise AegisError(
            "The dashboard's frontend was not found.",
            hint=(
                "It ships in the repo under frontend/ and is not part of the installed "
                "package. Run this from a checkout of the repository, or point at the "
                "data file directly with:  aegisai dashboard export --out <path>"
            ),
        )
    return FRONTEND_DIR


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

    if out is None:
        _require_frontend()
        destination = DATA_FILE
    else:
        destination = out
    # Only an explicitly requested path may bring its parent into being. Creating
    # the default one is what silently manufactured a frontend inside the venv.
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

    frontend = _require_frontend()

    if not no_export:
        with session_scope(app_ctx.engine()) as session:
            resolved = _resolve_scan(session, scan_id)
            data = build(session, resolved)
        DATA_FILE.write_text(jsonlib.dumps(data, indent=2, default=str), encoding="utf-8")
        output.success(app_ctx, f"exported {resolved} ({data['run']['totalFindings']} findings)")

    npm = shutil.which("npm")
    if npm is None:
        raise AegisError(
            "npm is not installed, so the dev server cannot start.",
            hint=f"Install Node.js, then:  cd {frontend} && npm install && npm run dev",
        )

    if not (frontend / "node_modules").exists():
        output.warn(app_ctx, "installing frontend dependencies (first run only)…")
        result = subprocess.run([npm, "install"], cwd=frontend, check=False)
        if result.returncode != 0:
            raise AegisError("npm install failed.", hint="Run it manually to see the error.")

    bound = _resolve_port(port)
    if bound != port:
        output.warn(app_ctx, f"port {port} is in use — using {bound} instead")

    app_ctx.console.print(f"\n  [bold]Dashboard[/bold]  http://localhost:{bound}")
    app_ctx.console.print("  [dim]Ctrl-C to stop[/dim]\n")
    subprocess.run(
        [npm, "run", "dev", "--", "--port", str(bound), "--strictPort"],
        cwd=frontend,
        check=False,
    )
