"""Output rendering.

Every read command supports `--json`, so a human-readable renderer and a
machine-readable payload are always produced from the same call site — the two
cannot drift.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Any

from rich.table import Table

from aegisai.cli.context import AppContext
from aegisai.core.exceptions import AegisError

VERDICT_STYLES = {
    "CONFIRMED": "bold red",
    "LIKELY": "yellow",
    "SUSPECTED": "dim",
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "PASS": "green",
    "REGRESSED": "bold red",
    "INCONCLUSIVE": "yellow",
    "OK": "green",
    "WARN": "yellow",
    "FAIL": "bold red",
}


def emit(ctx: AppContext, payload: Any, render: Callable[[], None]) -> None:
    """Print `payload` as JSON under --json, otherwise run the rich renderer."""
    if ctx.json_output:
        ctx.console.print_json(json.dumps(payload, default=str))
        return
    if not ctx.quiet:
        render()


def info(ctx: AppContext, message: str) -> None:
    if not ctx.quiet and not ctx.json_output:
        ctx.console.print(message)


def success(ctx: AppContext, message: str) -> None:
    info(ctx, f"[green]✓[/green] {message}")


def warn(ctx: AppContext, message: str) -> None:
    if not ctx.json_output:
        ctx.err_console.print(f"[yellow]![/yellow] {message}")


def render_error(ctx: AppContext | None, exc: AegisError) -> None:
    """Render an error plus its remediation hint.

    The hint is the point: an error should always name the next command to run.
    """
    console = ctx.err_console if ctx else None
    if console is None:
        from rich.console import Console

        console = Console(stderr=True)
    console.print(f"[bold red]✗[/bold red] {exc.message}")
    if exc.hint:
        console.print(f"  [dim]{exc.hint}[/dim]")


def styled(value: str) -> str:
    style = VERDICT_STYLES.get(value.upper())
    return f"[{style}]{value}[/{style}]" if style else value


def build_table(
    columns: Sequence[str],
    rows: Sequence[Sequence[Any]],
    *,
    title: str | None = None,
) -> Table:
    table = Table(title=title, header_style="dim", box=None, pad_edge=False)
    for column in columns:
        table.add_column(column)
    for row in rows:
        table.add_row(*(str(cell) if cell is not None else "-" for cell in row))
    return table


def empty_hint(ctx: AppContext, message: str, hint: str | None = None) -> None:
    """An empty result set is information, not silence."""
    if ctx.json_output:
        return
    ctx.console.print(f"[dim]{message}[/dim]")
    if hint:
        ctx.console.print(f"  [dim]{hint}[/dim]")
