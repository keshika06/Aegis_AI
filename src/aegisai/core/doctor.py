"""Environment diagnostics.

`aegisai doctor` is the first command anyone runs and the first one they are
pointed at when something breaks, so each check reports *what* is wrong and the
command that fixes it. Checks never raise: a failed check is data.

Severity: FAIL blocks scanning (exit 4); WARN degrades a capability but leaves
the pipeline runnable.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

import httpx

from aegisai.core.config import Config, default_config_path, write_config

MIN_PYTHON = (3, 11)


class CheckStatus(StrEnum):
    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    detail: str
    hint: str | None = None
    fix: Callable[[], str] | None = field(default=None, repr=False)
    """Applied by `doctor --fix`; returns a description of what it did."""

    @property
    def fixable(self) -> bool:
        return self.fix is not None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": str(self.status),
            "detail": self.detail,
            "hint": self.hint,
            "fixable": self.fixable,
        }


def check_python() -> CheckResult:
    version = ".".join(str(p) for p in sys.version_info[:3])
    if sys.version_info[:2] < MIN_PYTHON:
        required = ".".join(str(p) for p in MIN_PYTHON)
        return CheckResult(
            "Python",
            CheckStatus.FAIL,
            f"{version} (requires >= {required})",
            hint=f"Install Python {required} or newer and recreate the virtualenv.",
        )
    return CheckResult("Python", CheckStatus.OK, version)


def check_config(cfg: Config) -> CheckResult:
    path = cfg.path or default_config_path()
    if cfg.path is None:

        def _fix() -> str:
            written = write_config(cfg, path)
            return f"wrote default config to {written}"

        return CheckResult(
            "Config",
            CheckStatus.WARN,
            f"no config file; using defaults (would live at {path})",
            hint="Create it with:  aegisai init",
            fix=_fix,
        )
    return CheckResult("Config", CheckStatus.OK, str(path))


def check_directories(cfg: Config) -> CheckResult:
    missing = [d for d in (cfg.home_dir, cfg.reports_dir) if not d.exists()]
    if not missing:
        return CheckResult("Directories", CheckStatus.OK, str(cfg.home_dir))

    def _fix() -> str:
        for directory in missing:
            directory.mkdir(parents=True, exist_ok=True)
        return f"created {', '.join(str(d) for d in missing)}"

    return CheckResult(
        "Directories",
        CheckStatus.WARN,
        f"missing: {', '.join(str(d) for d in missing)}",
        hint="Create them with:  aegisai doctor --fix",
        fix=_fix,
    )


def check_database(cfg: Config) -> CheckResult:
    """Report schema state without touching the filesystem.

    Diagnostics must stay read-only: opening a SQLite engine would create the
    directory and an empty database file, which both mutates state the user did
    not ask to change and silently invalidates the directory check above it.
    """
    from aegisai.core.migrations import current_version, latest_version, upgrade

    latest = latest_version()

    def _fix() -> str:
        from aegisai.core.db import create_db_engine

        migrations = upgrade(create_db_engine(cfg))
        return f"applied {len(migrations)} migration(s), now at schema v{latest}"

    db_path = cfg.database_path
    if db_path is not None and not db_path.exists():
        return CheckResult(
            "Database",
            CheckStatus.WARN,
            f"not initialized (no database at {db_path})",
            hint="Create it with:  aegisai init",
            fix=_fix,
        )

    from aegisai.core.db import create_db_engine

    try:
        applied = current_version(create_db_engine(cfg))
    except Exception as exc:  # noqa: BLE001 - a broken DB must not crash diagnostics
        return CheckResult(
            "Database",
            CheckStatus.FAIL,
            f"cannot open {cfg.core.database_url}: {exc}",
            hint="Check the database_url in your config, then:  aegisai init",
        )

    if applied == latest:
        return CheckResult(
            "Database", CheckStatus.OK, f"schema v{applied} ({cfg.core.database_url})"
        )

    return CheckResult(
        "Database",
        CheckStatus.WARN,
        f"schema v{applied}, latest is v{latest}",
        hint="Apply migrations with:  aegisai init",
        fix=_fix,
    )


def check_ollama(cfg: Config) -> CheckResult:
    """Reachability and whether the configured model is actually pulled.

    A reachable daemon that lacks the model still fails at scan time, so both are
    checked here rather than discovering it mid-pipeline.
    """
    base = cfg.llm.base_url.rstrip("/")
    try:
        version = httpx.get(f"{base}/api/version", timeout=3.0).json().get("version", "unknown")
    except Exception:  # noqa: BLE001 - any transport failure is the same signal
        return CheckResult(
            "Ollama",
            CheckStatus.WARN,
            f"unreachable at {base}",
            hint="Start it with:  ollama serve   (LLM-assisted stages will be skipped without it)",
        )

    try:
        tags = httpx.get(f"{base}/api/tags", timeout=5.0).json().get("models", [])
        names = {m.get("name", "") for m in tags}
    except Exception:  # noqa: BLE001
        names = set()

    wanted = cfg.llm.model
    if names and wanted not in names and f"{wanted}:latest" not in names:
        return CheckResult(
            "Ollama",
            CheckStatus.WARN,
            f"v{version} up, but model '{wanted}' is not pulled",
            hint=f"Pull it with:  ollama pull {wanted}",
        )
    return CheckResult("Ollama", CheckStatus.OK, f"v{version} ({wanted})")


def check_docker() -> CheckResult:
    """Docker is only needed to run the bundled vulnerable labs, so never FAIL."""
    if shutil.which("docker") is None:
        return CheckResult(
            "Docker",
            CheckStatus.WARN,
            "not installed",
            hint="Needed only for `aegisai labs`; external targets scan fine without it.",
        )
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return CheckResult("Docker", CheckStatus.WARN, f"could not query daemon: {exc}")

    if proc.returncode != 0:
        return CheckResult(
            "Docker",
            CheckStatus.WARN,
            "installed, daemon not responding",
            hint="Start Docker Desktop (or the docker service) to use `aegisai labs`.",
        )
    return CheckResult("Docker", CheckStatus.OK, f"daemon v{proc.stdout.strip()}")


def check_disk(cfg: Config) -> CheckResult:
    probe: Path = cfg.home_dir if cfg.home_dir.exists() else Path.home()
    usage = shutil.disk_usage(probe)
    free_gb = usage.free / 1024**3
    if free_gb < 1:
        return CheckResult(
            "Disk",
            CheckStatus.WARN,
            f"{free_gb:.1f} GB free",
            hint="Reports and scan history need room.",
        )
    return CheckResult("Disk", CheckStatus.OK, f"{free_gb:.1f} GB free")


def run_checks(cfg: Config) -> list[CheckResult]:
    return [
        check_python(),
        check_config(cfg),
        check_directories(cfg),
        check_database(cfg),
        check_ollama(cfg),
        check_docker(),
        check_disk(cfg),
    ]


def worst_status(results: list[CheckResult]) -> CheckStatus:
    if any(r.status is CheckStatus.FAIL for r in results):
        return CheckStatus.FAIL
    if any(r.status is CheckStatus.WARN for r in results):
        return CheckStatus.WARN
    return CheckStatus.OK
