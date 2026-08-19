"""`aegisai config` — inspect and edit configuration."""

from __future__ import annotations

from dataclasses import asdict, fields

import typer

from aegisai.cli import output
from aegisai.cli.context import AppContext
from aegisai.cli.options import JSON_OPTION
from aegisai.core.config import _SECTIONS, default_config_path, write_config
from aegisai.core.exceptions import ConfigError

app = typer.Typer(help="View and change AegisAI configuration.")


def _split_key(key: str) -> tuple[str, str]:
    if "." not in key:
        raise ConfigError(
            f"Config keys are '<section>.<name>', got '{key}'.",
            hint="See available keys with:  aegisai config show",
        )
    section, name = key.split(".", 1)
    if section not in _SECTIONS:
        valid = ", ".join(_SECTIONS)
        raise ConfigError(f"Unknown config section '{section}'.", hint=f"Sections: {valid}")
    if not any(f.name == name for f in fields(_SECTIONS[section])):
        valid = ", ".join(f.name for f in fields(_SECTIONS[section]))
        raise ConfigError(f"Unknown key '{name}' in [{section}].", hint=f"Keys: {valid}")
    return section, name


@app.command("show")
def show_config(ctx: typer.Context, json_: bool = JSON_OPTION) -> None:
    """Show the effective configuration, after file and env overrides."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)
    data = {name: asdict(getattr(app_ctx.config, name)) for name in _SECTIONS}
    payload = {"path": str(app_ctx.config.path) if app_ctx.config.path else None, **data}

    def render() -> None:
        source = app_ctx.config.path or f"{default_config_path()} (not created; using defaults)"
        app_ctx.console.print(f"[dim]source:[/dim] {source}\n")
        for section, values in data.items():
            app_ctx.console.print(f"[bold]{section}[/bold]")
            for key, value in values.items():
                app_ctx.console.print(f"  [dim]{key:<24}[/dim] {value}")
            app_ctx.console.print()

    output.emit(app_ctx, payload, render)


@app.command("get")
def get_config(
    ctx: typer.Context,
    key: str = typer.Argument(..., help="Config key, e.g. llm.model"),
    json_: bool = JSON_OPTION,
) -> None:
    """Read one config value."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)
    section, name = _split_key(key)
    value = getattr(getattr(app_ctx.config, section), name)
    output.emit(app_ctx, {key: value}, lambda: app_ctx.console.print(str(value)))


@app.command("set")
def set_config(
    ctx: typer.Context,
    key: str = typer.Argument(..., help="Config key, e.g. llm.model"),
    value: str = typer.Argument(..., help="New value."),
) -> None:
    """Write one config value to the config file."""
    app_ctx: AppContext = ctx.obj
    section, name = _split_key(key)
    section_obj = getattr(app_ctx.config, section)

    field_type = next(f.type for f in fields(type(section_obj)) if f.name == name)
    try:
        # dataclass field types arrive as strings under `from __future__ import annotations`.
        if field_type in (int, "int"):
            coerced: object = int(value)
        elif field_type in (bool, "bool"):
            coerced = value.strip().lower() in {"1", "true", "yes", "on"}
        else:
            coerced = value
    except ValueError as exc:
        raise ConfigError(f"'{value}' is not valid for {key} ({field_type}).") from exc

    setattr(section_obj, name, coerced)
    path = app_ctx.config.path or default_config_path()
    write_config(app_ctx.config, path)

    output.emit(
        app_ctx,
        {key: coerced, "path": str(path)},
        lambda: output.success(app_ctx, f"{key} = {coerced}   [dim]({path})[/dim]"),
    )


@app.command("path")
def config_path(ctx: typer.Context, json_: bool = JSON_OPTION) -> None:
    """Print the config file path."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)
    path = app_ctx.config.path or default_config_path()
    output.emit(app_ctx, {"path": str(path)}, lambda: app_ctx.console.print(str(path)))
