"""`aegisai regression` — the closed loop, and the CI gate."""

from __future__ import annotations

import typer
from sqlalchemy import select

from aegisai.cli import output
from aegisai.cli.context import AppContext
from aegisai.cli.options import JSON_OPTION
from aegisai.cli.target import resolve_target
from aegisai.core.db import session_scope
from aegisai.core.exit_codes import ExitCode
from aegisai.models.enums import RegressionStatus, RegressionVerdict
from aegisai.models.regression import RegressionResult, RegressionTest
from aegisai.pipeline.closed_loop.engine import record_result, replay

app = typer.Typer(help="Replay confirmed findings as regression tests.")


@app.command("list")
def list_regressions(
    ctx: typer.Context,
    status: str | None = typer.Option(
        None, "--status", help="ACTIVE | RESOLVED | REGRESSED | EXHAUSTED"
    ),
    json_: bool = JSON_OPTION,
) -> None:
    """List stored regression tests."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)

    with session_scope(app_ctx.engine()) as session:
        stmt = select(RegressionTest)
        if status:
            stmt = stmt.where(RegressionTest.status == status.upper())
        tests = list(session.scalars(stmt.order_by(RegressionTest.created_at.desc())))
        payload = [
            {
                "id": t.id,
                "status": t.status,
                "owasp_tag": t.owasp_tag,
                "transformation": t.transformation,
                "boundary": t.matched_boundary,
                "attempts": f"{t.attempt_count}/{t.max_attempts}",
                "origin_finding_id": t.origin_finding_id,
                "payload": t.attack_payload,
            }
            for t in tests
        ]

    def render() -> None:
        if not payload:
            output.empty_hint(
                app_ctx,
                "No regression tests stored.",
                "They are created from CONFIRMED findings:  aegisai scan run <target>",
            )
            return
        rows = [
            (
                t["id"],
                output.styled(t["status"]),
                t["owasp_tag"] or "-",
                t["transformation"],
                t["attempts"],
            )
            for t in payload
        ]
        app_ctx.console.print(
            output.build_table(["TEST", "STATUS", "OWASP", "TRANSFORMATION", "ATTEMPTS"], rows)
        )

    output.emit(app_ctx, payload, render)


@app.command("run")
def run_regressions(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Registered target id or URL."),
    all_targets: bool = typer.Option(
        False, "--all", help="Replay every active test, not just this target's."
    ),
    json_: bool = JSON_OPTION,
) -> None:
    """Replay stored regression tests. Exits 1 if any REGRESSED, for CI gating."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)

    with session_scope(app_ctx.engine()) as session:
        target_row = resolve_target(session, target)

        stmt = select(RegressionTest).where(
            RegressionTest.status.in_([RegressionStatus.ACTIVE, RegressionStatus.REGRESSED])
        )
        if not all_targets:
            # Scoped by default: replaying another target's tests would consume
            # their lifecycle state and report failures against the wrong system.
            stmt = stmt.where(RegressionTest.target_id == target_row.id)
        tests = list(session.scalars(stmt))

        results = []
        for test in tests:
            outcome = replay(
                test,
                target_url=target_row.url,
                target_type=target_row.target_type,
                config=app_ctx.config,
            )
            record_result(session, test, outcome)
            results.append(
                {
                    "test_id": test.id,
                    "verdict": outcome.verdict,
                    "status": test.status,
                    "control_verdict": outcome.control_verdict,
                    "evidence": outcome.evidence_summary,
                    "duration_ms": round(outcome.duration_ms, 1),
                }
            )

    regressed = sum(1 for r in results if r["verdict"] == RegressionVerdict.REGRESSED)

    def render() -> None:
        if not results:
            output.empty_hint(app_ctx, f"No active regression tests for {target_row.url}.")
            return
        for item in results:
            app_ctx.console.print(
                f"  {output.styled(item['verdict']):<24} {item['test_id']}  "
                f"[dim]{item['evidence']}[/dim]"
            )
        app_ctx.console.print(
            f"\n  {len(results)} replayed · [bold]{regressed} still failing[/bold]\n"
        )

    output.emit(app_ctx, results, render)

    if regressed:
        raise typer.Exit(int(ExitCode.FINDINGS))


@app.command("history")
def regression_history(
    ctx: typer.Context,
    test_id: str = typer.Argument(..., help="Regression test id."),
    json_: bool = JSON_OPTION,
) -> None:
    """Show every replay attempt for one test."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)

    with session_scope(app_ctx.engine()) as session:
        rows = list(
            session.scalars(
                select(RegressionResult)
                .where(RegressionResult.regression_test_id == test_id)
                .order_by(RegressionResult.executed_at)
            )
        )
        payload = [
            {
                "attempt": r.attempt_number,
                "verdict": r.verdict,
                "strategy": r.strategy_source,
                "evidence": r.evidence_summary,
                "executed_at": r.executed_at,
            }
            for r in rows
        ]

    def render() -> None:
        if not payload:
            output.empty_hint(app_ctx, f"No replay history for {test_id}.")
            return
        rows_out = [
            (
                r["attempt"],
                output.styled(r["verdict"]),
                r["strategy"] or "-",
                (r["evidence"] or "")[:52],
            )
            for r in payload
        ]
        app_ctx.console.print(
            output.build_table(["ATTEMPT", "VERDICT", "STRATEGY", "EVIDENCE"], rows_out)
        )

    output.emit(app_ctx, payload, render)
