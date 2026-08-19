"""`aegisai findings` — inspect fused verdicts and their evidence."""

from __future__ import annotations

import typer
from sqlalchemy import select

from aegisai.cli import output
from aegisai.cli.context import AppContext
from aegisai.cli.options import JSON_OPTION
from aegisai.core.db import session_scope
from aegisai.core.exceptions import NotFoundError
from aegisai.models.attack import AttackVariant
from aegisai.models.execution import ControlEvaluation
from aegisai.models.finding import Evidence, Finding

app = typer.Typer(help="Inspect findings and their supporting evidence.")


def _evidence_payload(session, finding_id: str) -> list[dict]:
    rows = session.scalars(select(Evidence).where(Evidence.finding_id == finding_id))
    return [
        {
            "evidence_id": e.id,
            "evidence_type": e.evidence_type,
            "deterministic": e.deterministic,
            "confidence_contribution": e.confidence_contribution,
            "summary": e.summary,
            "content": e.content,
        }
        for e in rows
    ]


@app.command("list")
def list_findings(
    ctx: typer.Context,
    scan_id: str = typer.Argument(..., help="Scan id."),
    verdict: str | None = typer.Option(None, "--verdict", help="CONFIRMED | LIKELY | SUSPECTED"),
    owasp: str | None = typer.Option(None, "--owasp", help="Filter by OWASP tag, e.g. LLM01."),
    json_: bool = JSON_OPTION,
) -> None:
    """List findings for a scan."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)

    with session_scope(app_ctx.engine()) as session:
        stmt = select(Finding).where(Finding.scan_id == scan_id)
        if verdict:
            stmt = stmt.where(Finding.verdict == verdict.upper())
        if owasp:
            stmt = stmt.where(Finding.owasp_tag == owasp.upper())
        findings = list(session.scalars(stmt.order_by(Finding.created_at)))
        payload = [
            {
                "finding_id": f.id,
                "verdict": f.verdict,
                "title": f.title,
                "owasp_tag": f.owasp_tag,
                "confidence": f.confidence,
                "evidence": _evidence_payload(session, f.id),
            }
            for f in findings
        ]

    def render() -> None:
        if not payload:
            output.empty_hint(app_ctx, f"No findings for {scan_id} matching those filters.")
            return
        rows = [
            (
                f["finding_id"],
                output.styled(f["verdict"]),
                f["owasp_tag"] or "-",
                f"{f['confidence']:.2f}",
                f["title"],
            )
            for f in payload
        ]
        app_ctx.console.print(
            output.build_table(["FINDING", "VERDICT", "OWASP", "CONF", "TITLE"], rows)
        )
        app_ctx.console.print(
            f"\n  [dim]Full evidence:  aegisai findings show {payload[0]['finding_id']}[/dim]"
        )

    output.emit(app_ctx, payload, render)


@app.command("show")
def show_finding(
    ctx: typer.Context,
    finding_id: str = typer.Argument(..., help="Finding id."),
    json_: bool = JSON_OPTION,
) -> None:
    """Show one finding with its full evidence trail."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)

    with session_scope(app_ctx.engine()) as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise NotFoundError(
                f"No finding with id '{finding_id}'.",
                hint="List findings with:  aegisai findings list <scan-id>",
            )
        variant = session.get(AttackVariant, finding.variant_id) if finding.variant_id else None
        evaluation = (
            session.get(ControlEvaluation, finding.control_evaluation_id)
            if finding.control_evaluation_id
            else None
        )
        payload = {
            "finding_id": finding.id,
            "scan_id": finding.scan_id,
            "verdict": finding.verdict,
            "title": finding.title,
            "description": finding.description,
            "owasp_tag": finding.owasp_tag,
            "confidence": finding.confidence,
            "mitigation": finding.mitigation,
            "attack_payload": variant.payload if variant else None,
            "control_verdict": evaluation.verdict if evaluation else None,
            "control_reason": evaluation.verdict_reason if evaluation else None,
            "response_excerpt": (evaluation.response_body or "")[:1000] if evaluation else None,
            "evidence": _evidence_payload(session, finding.id),
        }

    def render() -> None:
        c = app_ctx.console
        c.print(f"\n  [bold]{payload['title']}[/bold]")
        c.print(
            f"  {output.styled(payload['verdict'])}  ·  {payload['owasp_tag'] or '-'}  "
            f"·  confidence {payload['confidence']:.2f}\n"
        )
        c.print(f"  [dim]probe sent[/dim]      {payload['attack_payload']}")
        c.print(f"  [dim]target control[/dim]  {payload['control_verdict']}")
        c.print(f"  [dim]reason[/dim]          {payload['control_reason']}\n")
        c.print("  [bold]Evidence[/bold]")
        for item in payload["evidence"]:
            kind = "deterministic" if item["deterministic"] else "supporting"
            c.print(f"    [{kind}] {item['evidence_type']} — {item['summary']}")
        c.print(f"\n  [bold]Mitigation[/bold]\n  {payload['mitigation']}\n")

    output.emit(app_ctx, payload, render)
