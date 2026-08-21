"""`aegisai labs` — lifecycle for the bundled intentionally-vulnerable labs.

The labs exist so the full pipeline can be demonstrated safely and repeatably.
They contain synthetic data and synthetic canaries only, and bind to localhost.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import httpx
import typer

from aegisai.cli import output
from aegisai.cli.context import AppContext
from aegisai.cli.options import JSON_OPTION
from aegisai.core.exceptions import AegisError, EnvironmentError_

app = typer.Typer(help="Start and stop the bundled demo labs.")

LABS = {
    "lab1": {
        "port": 8001,
        "description": "Vulnerable LLM chatbot",
        # The type to register the target as. It is not bookkeeping: it selects
        # which attack cases the planner draws and which expected-behaviour
        # contract Stage 6 loads, so registering a lab as the wrong type makes
        # it scan clean for the wrong reason. Surfaced here so the right value
        # is in front of whoever is about to register it.
        "target_type": "chatbot",
    },
    "lab2": {
        "port": 8002,
        "description": "Vulnerable RAG knowledge assistant",
        "target_type": "rag",
    },
    "lab3": {
        "port": 8003,
        # The control case. Same application as lab1, built properly, so a scan
        # of both is a comparison rather than two unrelated results.
        "description": "Defended chatbot (control case)",
        "target_type": "chatbot",
    },
}


def _compose_file(ctx: AppContext) -> Path:
    path = Path(ctx.config.labs.compose_file)
    if not path.is_absolute():
        # Resolve relative to the repo root (src/aegisai/cli/labs.py -> repo root).
        path = Path(__file__).resolve().parents[3] / path
    if not path.exists():
        raise AegisError(
            f"Lab compose file not found: {path}",
            hint="Set it with:  aegisai config set labs.compose_file <path>",
        )
    return path


def _compose(ctx: AppContext, *args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["docker", "compose", "-f", str(_compose_file(ctx)), *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except FileNotFoundError as exc:
        raise EnvironmentError_("Docker is not installed or not on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise EnvironmentError_("Docker Compose timed out after 300s.") from exc


def _healthy(port: int, timeout: float = 2.0) -> bool:
    try:
        return httpx.get(f"http://127.0.0.1:{port}/health", timeout=timeout).status_code == 200
    except Exception:  # noqa: BLE001 - unreachable is simply "not healthy"
        return False


def _wait_healthy(port: int, attempts: int = 30) -> bool:
    import time

    for _ in range(attempts):
        if _healthy(port):
            return True
        time.sleep(1)
    return False


def _selected(lab: str) -> list[str]:
    if lab == "all":
        return list(LABS)
    if lab not in LABS:
        raise AegisError(f"Unknown lab '{lab}'.", hint=f"Available: {', '.join(LABS)} (or 'all')")
    return [lab]


@app.command("up")
def labs_up(
    ctx: typer.Context,
    lab: str = typer.Argument("all", help="lab1 | lab2 | lab3 | all"),
    json_: bool = JSON_OPTION,
) -> None:
    """Start the vulnerable labs and wait until they actually answer."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)
    names = _selected(lab)

    proc = _compose(app_ctx, "up", "-d", "--build", *names)
    if proc.returncode != 0:
        raise EnvironmentError_(
            f"docker compose up failed: {(proc.stderr or proc.stdout).strip()[:400]}",
            hint="Check the Docker daemon is running:  aegisai doctor",
        )

    # "Started" must mean "answering", not "container created".
    results = [
        {"lab": name, "port": LABS[name]["port"], "healthy": _wait_healthy(LABS[name]["port"])}
        for name in names
    ]

    def render() -> None:
        for item in results:
            url = f"http://localhost:{item['port']}"
            if item["healthy"]:
                output.success(app_ctx, f"{item['lab']} healthy at {url}")
            else:
                output.warn(app_ctx, f"{item['lab']} started but not answering at {url}")

    output.emit(app_ctx, results, render)
    if not all(item["healthy"] for item in results):
        raise typer.Exit(4)


@app.command("down")
def labs_down(
    ctx: typer.Context,
    lab: str = typer.Argument("all", help="lab1 | lab2 | lab3 | all"),
    json_: bool = JSON_OPTION,
) -> None:
    """Stop the vulnerable labs."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)
    args = ["down"] if lab == "all" else ["stop", *_selected(lab)]
    proc = _compose(app_ctx, *args)
    if proc.returncode != 0:
        raise EnvironmentError_(f"docker compose failed: {(proc.stderr or '').strip()[:400]}")

    output.emit(
        app_ctx,
        {"stopped": _selected(lab)},
        lambda: output.success(app_ctx, f"stopped: {', '.join(_selected(lab))}"),
    )


@app.command("status")
def labs_status(ctx: typer.Context, json_: bool = JSON_OPTION) -> None:
    """Show which labs are running and healthy."""
    app_ctx: AppContext = ctx.obj
    app_ctx.apply_json(json_)
    payload = [
        {
            "lab": name,
            "port": meta["port"],
            "description": meta["description"],
            "target_type": meta["target_type"],
            "healthy": _healthy(meta["port"]),
            "url": f"http://localhost:{meta['port']}",
        }
        for name, meta in LABS.items()
    ]

    def render() -> None:
        rows = [
            (
                item["lab"],
                item["description"],
                item["url"],
                item["target_type"],
                "[green]healthy[/green]" if item["healthy"] else "[dim]stopped[/dim]",
            )
            for item in payload
        ]
        app_ctx.console.print(
            output.build_table(["LAB", "DESCRIPTION", "URL", "TYPE", "STATE"], rows)
        )

        # Scanning a lab takes two commands and one easily-wrong flag. Printing
        # them for whichever labs are actually answering removes the guesswork
        # about which target type goes with which lab.
        running = [item for item in payload if item["healthy"]]
        if running:
            app_ctx.console.print("\n[dim]To scan:[/dim]")
            for item in running:
                app_ctx.console.print(
                    f"  [dim]aegisai target add {item['url']} "
                    f"--type {item['target_type']} --authorize[/dim]"
                )
                app_ctx.console.print(f"  [dim]aegisai scan run {item['url']}[/dim]")

    output.emit(app_ctx, payload, render)
