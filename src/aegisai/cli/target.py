"""`aegisai target` — the authorization registry.

This is the safety boundary for the whole tool: a scan may only run against a URL
someone deliberately registered and authorized. Nothing else in the CLI is
allowed to bypass it.
"""

from __future__ import annotations

import typer
from sqlalchemy import select

from aegisai.cli import output
from aegisai.cli.context import AppContext
from aegisai.cli.options import JSON_OPTION
from aegisai.core.db import session_scope
from aegisai.core.exceptions import AegisError, TargetNotRegisteredError
from aegisai.core.exit_codes import ExitCode
from aegisai.models.base import utcnow
from aegisai.models.enums import TargetType
from aegisai.models.target import Target

app = typer.Typer(help="Register and manage authorized scan targets.")


def _to_dict(target: Target) -> dict:
    return {
        "id": target.id,
        "url": target.url,
        "name": target.name,
        "type": target.target_type,
        "authorized": target.authorized,
        "authorized_at": target.authorized_at,
        "contract_id": target.contract_id,
        "api_key_env": target.api_key_env,
        "authorization_note": target.authorization_note,
        "created_at": target.created_at,
    }


def resolve_target(session, identifier: str) -> Target:
    """Look a target up by id or exact URL.

    Raises TargetNotRegisteredError (exit 3), not a generic usage error: anything
    wrong with the target resolves to the same documented exit code.
    """
    target = session.get(Target, identifier)
    if target is None:
        target = session.scalar(select(Target).where(Target.url == identifier))
    if target is None:
        raise TargetNotRegisteredError(identifier)
    return target


@app.command("add")
def add_target(
    ctx: typer.Context,
    url: str = typer.Argument(..., help="Base URL of the target application."),
    target_type: str = typer.Option(
        "llm", "--type", "-t", help="llm | chatbot | rag | agent | api"
    ),
    name: str | None = typer.Option(None, "--name", "-n", help="Human-readable label."),
    authorize: bool = typer.Option(
        False, "--authorize", help="Record explicit authorization to scan this target."
    ),
    note: str | None = typer.Option(
        None, "--note", help="Who authorized the test, and under what agreement."
    ),
    contract: str | None = typer.Option(
        None, "--contract", help="Expected-behaviour contract id for Stage 6."
    ),
    api_key_env: str | None = typer.Option(
        None,
        "--api-key-env",
        help="Env var holding the target's API key. The key itself is never stored.",
    ),
    json_: bool = JSON_OPTION,
) -> None:
    """Register a target. Add --authorize to permit scanning it."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)

    try:
        TargetType(target_type)
    except ValueError as exc:
        valid = ", ".join(t.value for t in TargetType)
        raise AegisError(
            f"Unknown target type '{target_type}'.", hint=f"Valid types: {valid}"
        ) from exc

    with session_scope(app_ctx.engine()) as session:
        existing = session.scalar(select(Target).where(Target.url == url))
        if existing is not None:
            raise AegisError(
                f"Target already registered as {existing.id}.",
                hint=f"Inspect it with:  aegisai target show {existing.id}",
            )

        target = Target(
            url=url,
            name=name,
            target_type=target_type,
            authorized=authorize,
            authorized_at=utcnow() if authorize else None,
            authorization_note=note,
            contract_id=contract,
            api_key_env=api_key_env,
        )
        session.add(target)
        session.flush()
        payload = _to_dict(target)

    def render() -> None:
        state = (
            "[green]authorized[/green]"
            if payload["authorized"]
            else "[yellow]registered, NOT authorized[/yellow]"
        )
        output.success(app_ctx, f"{payload['id']}  {payload['url']}  ({payload['type']}) — {state}")
        if not payload["authorized"]:
            app_ctx.console.print(
                f"  [dim]Authorize before scanning:  aegisai target authorize {payload['id']}[/dim]"
            )

    output.emit(app_ctx, payload, render)


@app.command("authorize")
def authorize_target(
    ctx: typer.Context,
    identifier: str = typer.Argument(..., help="Target id or URL."),
    note: str | None = typer.Option(
        None, "--note", help="Who authorized it, and under what agreement."
    ),
    json_: bool = JSON_OPTION,
) -> None:
    """Record authorization for an already-registered target."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)
    with session_scope(app_ctx.engine()) as session:
        target = resolve_target(session, identifier)
        target.authorized = True
        target.authorized_at = utcnow()
        if note:
            target.authorization_note = note
        session.flush()
        payload = _to_dict(target)

    output.emit(
        app_ctx,
        payload,
        lambda: output.success(app_ctx, f"{payload['id']} authorized for scanning."),
    )


@app.command("list")
def list_targets(ctx: typer.Context, json_: bool = JSON_OPTION) -> None:
    """List every registered target."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)
    with session_scope(app_ctx.engine()) as session:
        targets = list(session.scalars(select(Target).order_by(Target.created_at.desc())))
        payload = [_to_dict(t) for t in targets]

    def render() -> None:
        if not payload:
            output.empty_hint(
                app_ctx,
                "No targets registered.",
                'Add one with:  aegisai target add "http://localhost:8001" --authorize',
            )
            return
        rows = [
            (
                t["id"],
                t["url"],
                t["type"],
                "[green]yes[/green]" if t["authorized"] else "[yellow]no[/yellow]",
                t["name"] or "-",
            )
            for t in payload
        ]
        app_ctx.console.print(output.build_table(["ID", "URL", "TYPE", "AUTHORIZED", "NAME"], rows))

    output.emit(app_ctx, payload, render)


@app.command("show")
def show_target(
    ctx: typer.Context,
    identifier: str = typer.Argument(..., help="Target id or URL."),
    json_: bool = JSON_OPTION,
) -> None:
    """Show one target in full."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)
    with session_scope(app_ctx.engine()) as session:
        payload = _to_dict(resolve_target(session, identifier))

    def render() -> None:
        for key, value in payload.items():
            app_ctx.console.print(f"  [dim]{key:<20}[/dim] {value if value is not None else '-'}")

    output.emit(app_ctx, payload, render)


@app.command("remove")
def remove_target(
    ctx: typer.Context,
    identifier: str = typer.Argument(..., help="Target id or URL."),
) -> None:
    """Remove a target from the registry."""
    app_ctx: AppContext = ctx.obj
    with session_scope(app_ctx.engine()) as session:
        target = resolve_target(session, identifier)
        target_id, target_url = target.id, target.url
        if not app_ctx.assume_yes and not app_ctx.json_output:
            typer.confirm(f"Remove {target_id} ({target_url})?", abort=True)
        session.delete(target)

    output.emit(
        app_ctx,
        {"removed": target_id},
        lambda: output.success(app_ctx, f"Removed {target_id} ({target_url})."),
    )


def require_authorized(session, identifier: str) -> Target:
    """Resolve a target and refuse it unless authorization was recorded.

    Every scan path must call this. There is no override flag by design.
    """
    from aegisai.core.exceptions import UnauthorizedTargetError

    target = resolve_target(session, identifier)
    if not target.authorized:
        raise UnauthorizedTargetError(target.url, target.id)
    return target


__all__ = ["app", "require_authorized", "resolve_target", "ExitCode"]
