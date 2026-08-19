"""`aegisai doctor` and `aegisai init`."""

from __future__ import annotations

from aegisai.cli import output
from aegisai.cli.context import AppContext
from aegisai.core import doctor as diagnostics
from aegisai.core.config import default_config_path, write_config
from aegisai.core.doctor import CheckStatus
from aegisai.core.exceptions import ConfigError
from aegisai.core.exit_codes import ExitCode

STATUS_MARK = {
    CheckStatus.OK: "[green]✓[/green]",
    CheckStatus.WARN: "[yellow]![/yellow]",
    CheckStatus.FAIL: "[red]✗[/red]",
}


def run_doctor(ctx: AppContext, apply_fixes: bool = False) -> ExitCode:
    results = diagnostics.run_checks(ctx.config)
    applied: list[str] = []

    if apply_fixes:
        for result in results:
            if result.fix is not None and result.status is not CheckStatus.OK:
                try:
                    applied.append(f"{result.name}: {result.fix()}")
                except Exception as exc:  # noqa: BLE001 - report, don't abort remaining fixes
                    applied.append(f"{result.name}: fix failed ({exc})")
        # Re-run so the reported state reflects the fixes, not the state before them.
        results = diagnostics.run_checks(ctx.config)

    overall = diagnostics.worst_status(results)
    payload = {
        "status": str(overall),
        "checks": [r.to_dict() for r in results],
        "fixes_applied": applied,
    }

    def render() -> None:
        for result in results:
            mark = STATUS_MARK[result.status]
            ctx.console.print(f"{mark} [bold]{result.name}[/bold]  {result.detail}")
            if result.hint and result.status is not CheckStatus.OK:
                ctx.console.print(f"    [dim]{result.hint}[/dim]")
        if applied:
            ctx.console.print()
            for line in applied:
                ctx.console.print(f"  [green]fixed[/green] {line}")
        ctx.console.print()
        if overall is CheckStatus.OK:
            ctx.console.print("[green]All checks passed. Ready to scan.[/green]")
        elif overall is CheckStatus.WARN:
            fixable = any(r.fixable and r.status is not CheckStatus.OK for r in results)
            ctx.console.print("[yellow]Usable, with warnings above.[/yellow]")
            if fixable and not apply_fixes:
                ctx.console.print(
                    "[dim]Some of these are auto-fixable:  aegisai doctor --fix[/dim]"
                )
        else:
            ctx.console.print("[red]Blocking problems found. Resolve the ✗ items above.[/red]")

    output.emit(ctx, payload, render)
    return ExitCode.ENVIRONMENT if overall is CheckStatus.FAIL else ExitCode.OK


def run_init(ctx: AppContext, force: bool = False, llm_model: str | None = None) -> ExitCode:
    """Create the config file, the working directories, and the database schema."""
    from aegisai.core.migrations import latest_version, upgrade

    path = ctx.config.path or default_config_path()
    steps: list[str] = []

    if llm_model:
        ctx.config.llm.model = llm_model

    if path.exists() and not force and llm_model is None:
        steps.append(f"config already present at {path}")
    else:
        if path.exists() and not force and llm_model is not None:
            raise ConfigError(
                f"Config already exists at {path}.",
                hint=(
                    "Change one value with `aegisai config set`, "
                    "or overwrite it with `aegisai init --force`."
                ),
            )
        write_config(ctx.config, path)
        steps.append(f"wrote config to {path}")

    for directory in (ctx.config.home_dir, ctx.config.reports_dir):
        if not directory.exists():
            directory.mkdir(parents=True, exist_ok=True)
            steps.append(f"created {directory}")

    migrations = upgrade(ctx.engine())
    if migrations:
        steps.append(f"applied {len(migrations)} migration(s) -> schema v{latest_version()}")
    else:
        steps.append(f"database already at schema v{latest_version()}")

    payload = {"config_path": str(path), "steps": steps}

    def render() -> None:
        for step in steps:
            ctx.console.print(f"[green]✓[/green] {step}")
        ctx.console.print()
        ctx.console.print("[dim]Next:  aegisai doctor[/dim]")

    output.emit(ctx, payload, render)
    return ExitCode.OK
