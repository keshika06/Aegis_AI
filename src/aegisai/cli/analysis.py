"""`aegisai chain` and `aegisai risk` — Stage 8 and Stage 9 views."""

from __future__ import annotations

import json as jsonlib

import typer
from sqlalchemy import select

from aegisai.cli import output
from aegisai.cli.context import AppContext
from aegisai.cli.options import JSON_OPTION
from aegisai.core.db import session_scope
from aegisai.knowledge_base.library import owasp_name
from aegisai.models.analysis import AttackChain, RiskScore
from aegisai.models.finding import Finding

chain_app = typer.Typer(help="Attack-chain graphs correlating findings into exploit paths.")
risk_app = typer.Typer(help="Deterministic, explainable risk scores.")

KIND_MARKS = {
    "intent": "◆",
    "representation": "▸",
    "control_decision": "◈",
    "finding": "●",
    "evidence": "✓",
}


@chain_app.command("show")
def show_chain(
    ctx: typer.Context,
    scan_id: str = typer.Argument(..., help="Scan id."),
    export: str | None = typer.Option(None, "--export", help="json | dot"),
    json_: bool = JSON_OPTION,
) -> None:
    """Show the attack-chain graphs for a scan."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)

    with session_scope(app_ctx.engine()) as session:
        chains = list(
            session.scalars(
                select(AttackChain)
                .where(AttackChain.scan_id == scan_id)
                .order_by(AttackChain.severity.desc())
            )
        )
        payload = [
            {
                "chain_id": c.id,
                "title": c.title,
                "severity": c.severity,
                "owasp_tags": c.owasp_tags or [],
                "finding_ids": c.finding_ids or [],
                "graph": c.graph,
            }
            for c in chains
        ]

    if export == "json":
        app_ctx.console.print_json(jsonlib.dumps(payload, default=str))
        return
    if export == "dot":
        app_ctx.console.print(_to_dot(payload))
        return

    def render() -> None:
        if not payload:
            output.empty_hint(
                app_ctx, f"No attack chains for {scan_id}.", "Run:  aegisai scan run <target>"
            )
            return
        for chain in payload:
            tags = (
                ", ".join(f"{t} ({owasp_name(t) or '?'})" for t in chain["owasp_tags"])
                or "unmapped"
            )
            app_ctx.console.print(
                f"\n  [bold]{chain['title']}[/bold]  "
                f"[dim]severity {chain['severity']} · {tags}[/dim]"
            )
            for line in _ascii_path(chain["graph"]):
                app_ctx.console.print(f"    {line}")
        app_ctx.console.print()

    output.emit(app_ctx, payload, render)


def _ascii_path(graph: dict | None) -> list[str]:
    """Render the graph as an indented path, deepest chain first."""
    if not graph:
        return ["(no graph)"]
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    lines: list[str] = []
    for node in graph.get("nodes", []):
        kind = node.get("kind", "")
        mark = KIND_MARKS.get(kind, "·")
        label = node.get("label", node.get("id"))
        extra = ""
        if kind == "finding":
            extra = f"  {node.get('title', '')}"
        elif kind == "evidence" and node.get("deterministic"):
            extra = "  [deterministic]"
        indent = "  " * list(KIND_MARKS).index(kind) if kind in KIND_MARKS else ""
        lines.append(f"{indent}{mark} {label}{extra}")
    return lines or [f"({len(nodes)} nodes)"]


def _to_dot(payload: list[dict]) -> str:
    lines = ["digraph attack_chains {", '  rankdir="LR";']
    for chain in payload:
        graph = chain.get("graph") or {}
        for node in graph.get("nodes", []):
            label = str(node.get("label", node.get("id"))).replace('"', "'")
            lines.append(f'  "{node["id"]}" [label="{label}"];')
        for edge in graph.get("edges", graph.get("links", [])):
            label = str(edge.get("label", "")).replace('"', "'")
            lines.append(f'  "{edge["source"]}" -> "{edge["target"]}" [label="{label}"];')
    lines.append("}")
    return "\n".join(lines)


@risk_app.command("show")
def show_risk(
    ctx: typer.Context,
    scan_id: str = typer.Argument(..., help="Scan id."),
    json_: bool = JSON_OPTION,
) -> None:
    """Show risk scores with every contributing factor."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)

    with session_scope(app_ctx.engine()) as session:
        rows = list(
            session.scalars(
                select(RiskScore)
                .where(RiskScore.scan_id == scan_id)
                .order_by(RiskScore.score.desc())
            )
        )
        titles = {
            f.id: f.title
            for f in session.scalars(select(Finding).where(Finding.scan_id == scan_id))
        }
        payload = [
            {
                "finding_id": r.finding_id,
                "title": titles.get(r.finding_id or "", "?"),
                "score": r.score,
                "risk_level": r.risk_level,
                "factors": r.factors,
                "weights": r.weights,
                "explanation": r.explanation,
            }
            for r in rows
        ]

    def render() -> None:
        if not payload:
            output.empty_hint(app_ctx, f"No risk scores for {scan_id}.")
            return
        table_rows = [
            (
                r["finding_id"],
                output.styled(r["risk_level"]),
                f"{r['score']:.2f}",
                r["title"][:46],
            )
            for r in payload
        ]
        app_ctx.console.print(
            output.build_table(["FINDING", "LEVEL", "SCORE", "TITLE"], table_rows)
        )

        top = payload[0]
        app_ctx.console.print(
            f"\n  [bold]Top finding factors[/bold]  [dim]{top['title'][:50]}[/dim]"
        )
        for name, value in (top["factors"] or {}).items():
            weight = (top["weights"] or {}).get(name, 0)
            shown = f"{value:.2f}" if isinstance(value, (int, float)) else str(value)
            app_ctx.console.print(
                f"    [dim]{name:<22}[/dim] {shown:<26} [dim]weight {weight}[/dim]"
            )
        app_ctx.console.print(f"\n  [dim]{top['explanation']}[/dim]\n")

    output.emit(app_ctx, payload, render)
