"""AegisAI command-line entry point.

Command shape is `aegisai <noun> <verb>`, so the surface stays predictable as
stages land. Global behaviour (`--json`, `--quiet`, config path) is resolved once
in the callback and carried on the Typer context.
"""

from __future__ import annotations

from pathlib import Path

import typer

from aegisai import __version__
from aegisai.cli import (
    analysis,
    attack,
    config_cmd,
    dashboard,
    doctor,
    findings,
    labs,
    regression,
    scan,
    target,
)
from aegisai.cli.context import AppContext
from aegisai.cli.options import JSON_OPTION
from aegisai.cli.output import render_error
from aegisai.cli.stubs import planned
from aegisai.cli.target import require_authorized
from aegisai.core.db import session_scope
from aegisai.core.exceptions import AegisError
from aegisai.core.exit_codes import ExitCode

app = typer.Typer(
    name="aegisai",
    help=(
        "AegisAI - AI application security validation platform.\n\n"
        "Discovers an AI application's attack surface, probes it with OWASP-mapped "
        "attacks and evasion variants, records what the target's own controls did, "
        "and proves impact with deterministic evidence.\n\n"
        "Scanning requires an explicitly authorized target:  aegisai target add <url> --authorize"
    ),
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)

app.add_typer(target.app, name="target")
app.add_typer(scan.app, name="scan")
app.add_typer(findings.app, name="findings")
app.add_typer(analysis.chain_app, name="chain")
app.add_typer(analysis.risk_app, name="risk")
app.add_typer(attack.app, name="attack")
app.add_typer(regression.app, name="regression")
app.add_typer(labs.app, name="labs")
app.add_typer(config_cmd.app, name="config")
app.add_typer(dashboard.app, name="dashboard")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"aegisai {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    ctx: typer.Context,
    config: Path | None = typer.Option(
        None, "--config", help="Path to config.toml.", envvar="AEGISAI_CONFIG"
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-essential output."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show diagnostic detail."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colour."),
    assume_yes: bool = typer.Option(
        False, "--yes", "-y", help="Assume yes for confirmation prompts."
    ),
    version: bool = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    ctx.obj = AppContext.build(
        config_path=config,
        json_output=json_output,
        quiet=quiet,
        verbose=verbose,
        no_color=no_color,
        assume_yes=assume_yes,
    )


@app.command("doctor")
def doctor_command(
    ctx: typer.Context,
    fix: bool = typer.Option(False, "--fix", help="Apply the fixes that are safe to automate."),
    json_: bool = JSON_OPTION,
) -> None:
    """Check that everything AegisAI depends on is present and healthy."""
    ctx.obj.apply_json(json_)
    code = doctor.run_doctor(ctx.obj, apply_fixes=fix)
    if code is not ExitCode.OK:
        raise typer.Exit(int(code))


@app.command("init")
def init_command(
    ctx: typer.Context,
    force: bool = typer.Option(False, "--force", help="Overwrite an existing config file."),
    llm_model: str | None = typer.Option(
        None, "--llm-model", help="Local model to use, e.g. qwen2.5:0.5b"
    ),
    json_: bool = JSON_OPTION,
) -> None:
    """Create the config file, working directories, and database schema."""
    ctx.obj.apply_json(json_)
    code = doctor.run_init(ctx.obj, force=force, llm_model=llm_model)
    if code is not ExitCode.OK:
        raise typer.Exit(int(code))


@app.command("discover")
def discover_command(
    ctx: typer.Context,
    target_ref: str = typer.Argument(..., help="Registered target id or URL."),
    json_: bool = JSON_OPTION,
) -> None:
    """Run Stage 1 only: map a target's attack surface without scanning it."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)

    from aegisai.cli import output
    from aegisai.models.enums import ScanStatus
    from aegisai.models.scan import Scan
    from aegisai.pipeline.base import ScanContext
    from aegisai.pipeline.discovery.stage import DiscoveryStage

    engine = app_ctx.engine()
    with session_scope(engine) as session:
        # Discovery sends live requests to the target, so it sits behind the same
        # authorization gate as a full scan.
        target_row = require_authorized(session, target_ref)

        # Recorded as a scan so the profile is persisted and inspectable, rather
        # than being printed once and lost.
        scan = Scan(target_id=target_row.id, profile="discovery-only", status=ScanStatus.RUNNING)
        session.add(scan)
        session.flush()

        scan_ctx = ScanContext(
            scan_id=scan.id,
            session=session,
            config=app_ctx.config,
            target_url=target_row.url,
            target_id=target_row.id,
            target_type=target_row.target_type,
        )
        result = DiscoveryStage().run(scan_ctx)

        scan.status = ScanStatus.COMPLETED
        scan.current_stage = "1"
        scan.stages_completed = 1
        scan.message = result.summary
        payload = {
            "scan_id": scan.id,
            "target_url": target_row.url,
            "summary": result.summary,
            "endpoints": scan_ctx.profile.endpoints if scan_ctx.profile else [],
            "capabilities": scan_ctx.profile.capabilities if scan_ctx.profile else {},
        }

    def render() -> None:
        app_ctx.console.print(
            f"\n  [bold]{payload['target_url']}[/bold]  [dim]{payload['summary']}[/dim]\n"
        )
        rows = [
            (
                e["method"],
                e["path"],
                e.get("text_key") or "-",
                e.get("text_key_confidence") or e.get("confidence", "-"),
                "[green]chat[/green]" if e.get("is_chat_surface") else "",
            )
            for e in payload["endpoints"]
        ]
        app_ctx.console.print(
            output.build_table(["METHOD", "PATH", "TEXT KEY", "CONFIDENCE", "SURFACE"], rows)
        )

    output.emit(app_ctx, payload, render)


@app.command("serve")
def serve_command(
    ctx: typer.Context,
    port: int = typer.Option(8000, "--port", help="Port to bind."),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code changes."),
) -> None:
    """Serve the REST API that the dashboard and CLI both consume."""
    planned("serve", "Phase 8 (optional surfaces)")


class _Unmatchable(Exception):
    """Never raised. Stands in when a vendored exception type cannot be located."""


def _vendored(name: str) -> type[BaseException]:
    """Resolve one of Click's exception classes as Typer vendors them.

    Typer bundles Click under `typer._click`, so the exceptions it raises are not
    the classes a top-level `click` install would provide — depending on `click`
    directly would produce `except` clauses that silently never match. Walking
    Typer's own public exports keeps us on the classes actually raised.
    """
    for cls in typer.BadParameter.__mro__:
        if cls.__name__ == name:
            return cls
    return _Unmatchable  # pragma: no cover - Typer restructured its exceptions


_ClickException = _vendored("ClickException")


def main() -> int:
    """Console-script entry point.

    Runs with Click's standalone mode off so AegisError can be rendered with its
    remediation hint and mapped to the documented exit code, instead of surfacing
    as a traceback.
    """
    try:
        # With standalone_mode off, Typer catches `typer.Exit` itself and hands
        # the code back as the return value rather than raising it. Ignoring
        # this return silently swallows every deliberate non-zero exit --
        # including the CONFIRMED-findings CI gate.
        result = app(standalone_mode=False)
        return result if isinstance(result, int) else int(ExitCode.OK)
    except AegisError as exc:
        render_error(None, exc)
        return int(exc.exit_code)
    except typer.Exit as exc:
        return int(exc.exit_code)
    except typer.Abort:
        typer.echo("Aborted.", err=True)
        return 130
    except _ClickException as exc:  # usage errors: unknown option, missing argument
        exc.show()
        return int(ExitCode.USAGE)
    except KeyboardInterrupt:
        typer.echo("Interrupted.", err=True)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
