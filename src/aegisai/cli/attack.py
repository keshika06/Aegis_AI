"""`aegisai attack` — payload library, plans, and generated variants."""

from __future__ import annotations

import typer
from sqlalchemy import select

from aegisai.cli import output
from aegisai.cli.context import AppContext
from aegisai.cli.options import JSON_OPTION
from aegisai.core.db import session_scope
from aegisai.knowledge_base.library import load_library, owasp_name
from aegisai.models.attack import AttackCase, AttackVariant

app = typer.Typer(help="Browse the attack library and inspect generated attacks.")
library_app = typer.Typer(help="The OWASP-tagged payload library.")
app.add_typer(library_app, name="library")


@library_app.command("list")
def list_library(
    ctx: typer.Context,
    owasp: str | None = typer.Option(None, "--owasp", help="Filter by OWASP tag, e.g. LLM01."),
    category: str | None = typer.Option(None, "--category", help="Filter by attack category."),
    target_type: str | None = typer.Option(
        None, "--type", help="Only cases applicable to this target type."
    ),
    json_: bool = JSON_OPTION,
) -> None:
    """List payloads in the attack library."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)

    templates = load_library()
    if owasp:
        templates = [t for t in templates if t.owasp.upper() == owasp.upper()]
    if category:
        templates = [t for t in templates if t.category.lower() == category.lower()]
    if target_type:
        templates = [t for t in templates if t.matches(target_type)]

    payload = [
        {
            "id": t.id,
            "owasp": t.owasp,
            "owasp_name": owasp_name(t.owasp),
            "category": t.category,
            "intent": t.intent,
            "evidence": t.evidence,
            "confirmable": t.confirmable,
            "applies_to": t.applies_to,
            "payload": t.payload,
        }
        for t in templates
    ]

    def render() -> None:
        if not payload:
            output.empty_hint(app_ctx, "No library entries match those filters.")
            return
        rows = [
            (
                t["id"],
                t["owasp"],
                t["category"],
                t["intent"],
                "[green]yes[/green]" if t["confirmable"] else "[dim]no[/dim]",
            )
            for t in payload
        ]
        app_ctx.console.print(
            output.build_table(["ID", "OWASP", "CATEGORY", "INTENT", "CONFIRMABLE"], rows)
        )
        confirmable = sum(1 for t in payload if t["confirmable"])
        app_ctx.console.print(
            f"\n  [dim]{len(payload)} case(s); {confirmable} can be confirmed "
            f"deterministically[/dim]"
        )

    output.emit(app_ctx, payload, render)


@app.command("plan")
def show_plan(
    ctx: typer.Context,
    scan_id: str = typer.Argument(..., help="Scan id."),
    json_: bool = JSON_OPTION,
) -> None:
    """Show the Stage 2A attack plan for a scan."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)

    with session_scope(app_ctx.engine()) as session:
        cases = list(
            session.scalars(
                select(AttackCase)
                .where(AttackCase.scan_id == scan_id)
                .order_by(AttackCase.created_at)
            )
        )
        payload = [
            {
                "attack_id": c.id,
                "owasp": c.owasp_tag,
                "category": c.category,
                "intent": c.original_intent,
                "origin": (c.extra or {}).get("origin", "library"),
                "target": c.target_surface_element,
                "payload": c.payload,
            }
            for c in cases
        ]

    def render() -> None:
        if not payload:
            output.empty_hint(
                app_ctx, f"No attack plan for {scan_id}.", "Run:  aegisai scan run <target>"
            )
            return
        rows = [
            (c["attack_id"], c["owasp"], c["category"], c["intent"], c["origin"]) for c in payload
        ]
        app_ctx.console.print(
            output.build_table(["ATTACK", "OWASP", "CATEGORY", "INTENT", "ORIGIN"], rows)
        )
        llm = sum(1 for c in payload if c["origin"] == "llm")
        app_ctx.console.print(
            f"\n  [dim]{len(payload)} case(s): {len(payload) - llm} from library, "
            f"{llm} LLM-proposed[/dim]"
        )

    output.emit(app_ctx, payload, render)


@app.command("variants")
def show_variants(
    ctx: typer.Context,
    attack_id: str = typer.Argument(..., help="Attack case id."),
    json_: bool = JSON_OPTION,
) -> None:
    """Show the variants generated from one attack case."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)

    with session_scope(app_ctx.engine()) as session:
        variants = list(
            session.scalars(select(AttackVariant).where(AttackVariant.attack_case_id == attack_id))
        )
        payload = [
            {
                "variant_id": v.id,
                "transformation": v.transformation,
                "engine": v.engine,
                "payload": v.payload,
            }
            for v in variants
        ]

    def render() -> None:
        if not payload:
            output.empty_hint(app_ctx, f"No variants for attack case {attack_id}.")
            return
        rows = [
            (v["variant_id"], v["transformation"], v["engine"], v["payload"][:60]) for v in payload
        ]
        app_ctx.console.print(
            output.build_table(["VARIANT", "TRANSFORMATION", "ENGINE", "PAYLOAD"], rows)
        )
        if all(v["transformation"] == "none" for v in payload):
            app_ctx.console.print(
                "\n  [dim]Only base variants so far — evasion families land in Phase 3.[/dim]"
            )

    output.emit(app_ctx, payload, render)


@app.command("engines")
def list_engines(ctx: typer.Context, json_: bool = JSON_OPTION) -> None:
    """Show which attack engines are available."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)

    payload = [
        {"engine": "native", "available": True, "description": "Built-in OWASP-tagged library"},
        {"engine": "garak", "available": False, "description": "NVIDIA garak (Phase 3)"},
        {"engine": "pyrit", "available": False, "description": "Microsoft PyRIT (Phase 3)"},
        {"engine": "promptfoo", "available": False, "description": "Promptfoo (Phase 3)"},
    ]

    def render() -> None:
        rows = [
            (
                e["engine"],
                "[green]yes[/green]" if e["available"] else "[dim]not yet[/dim]",
                e["description"],
            )
            for e in payload
        ]
        app_ctx.console.print(output.build_table(["ENGINE", "AVAILABLE", "DESCRIPTION"], rows))

    output.emit(app_ctx, payload, render)
