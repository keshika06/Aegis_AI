"""Configuration loading.

Precedence, lowest to highest: built-in defaults, then `config.toml`, then
`AEGISAI_*` environment variables. Reading uses stdlib `tomllib`; writing uses a
small local serializer so config stays a plain, hand-editable file with no extra
dependency.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from aegisai.core.exceptions import ConfigError

DEFAULT_HOME = Path.home() / ".aegisai"
ENV_PREFIX = "AEGISAI_"


def default_config_path() -> Path:
    if env := os.environ.get(f"{ENV_PREFIX}CONFIG"):
        return Path(env).expanduser()
    return DEFAULT_HOME / "config.toml"


@dataclass
class CoreConfig:
    home: str = str(DEFAULT_HOME)
    database_url: str = f"sqlite:///{DEFAULT_HOME / 'aegisai.db'}"
    reports_dir: str = str(DEFAULT_HOME / "reports")


@dataclass
class LLMConfig:
    provider: str = "ollama"
    base_url: str = "http://127.0.0.1:11434"
    model: str = "qwen2.5:0.5b"
    timeout_seconds: int = 60
    max_retries: int = 1


@dataclass
class ScanConfig:
    default_profile: str = "standard"
    target_timeout_seconds: int = 30
    max_regression_attempts: int = 3


@dataclass
class LabsConfig:
    compose_file: str = "docker/docker-compose.labs.yml"


@dataclass
class Config:
    core: CoreConfig = field(default_factory=CoreConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    labs: LabsConfig = field(default_factory=LabsConfig)

    path: Path | None = None
    """Where this config was loaded from; None when using pure defaults."""

    @property
    def home_dir(self) -> Path:
        return Path(self.core.home).expanduser()

    @property
    def reports_dir(self) -> Path:
        return Path(self.core.reports_dir).expanduser()

    @property
    def database_path(self) -> Path | None:
        """Filesystem path backing a sqlite URL, or None for other backends."""
        url = self.core.database_url
        if not url.startswith("sqlite:///"):
            return None
        return Path(url.removeprefix("sqlite:///")).expanduser()


_SECTIONS = {"core": CoreConfig, "llm": LLMConfig, "scan": ScanConfig, "labs": LabsConfig}


def _coerce(value: str, target_type: type | str) -> object:
    """Convert an env-var string to the field's declared type.

    `from __future__ import annotations` makes dataclass field types arrive as
    strings ("int"), not classes, so both spellings have to be matched — missing
    this silently stored numeric settings as strings.
    """
    if target_type in (int, "int"):
        return int(value)
    if target_type in (bool, "bool"):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return value


def load_config(path: Path | None = None) -> Config:
    """Load config from `path` (or the default location), then apply env overrides.

    A missing file is not an error — defaults are usable, and `aegisai init`
    writes the file when the user wants to customize.
    """
    path = path or default_config_path()
    cfg = Config()

    if path.exists():
        try:
            with path.open("rb") as fh:
                raw = tomllib.load(fh)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(
                f"Could not read config at {path}: {exc}",
                hint="Fix the file, or regenerate it with:  aegisai init --force",
            ) from exc

        for section_name, section_cls in _SECTIONS.items():
            section_data = raw.get(section_name) or {}
            if not isinstance(section_data, dict):
                raise ConfigError(f"Config section [{section_name}] must be a table.")
            known = {f.name: f.type for f in fields(section_cls)}
            current = getattr(cfg, section_name)
            for key, value in section_data.items():
                if key in known:
                    setattr(current, key, value)
        cfg.path = path

    _apply_env_overrides(cfg)
    return cfg


def _apply_env_overrides(cfg: Config) -> None:
    """Apply AEGISAI_<SECTION>_<KEY> overrides (e.g. AEGISAI_LLM_MODEL)."""
    for section_name, section_cls in _SECTIONS.items():
        section = getattr(cfg, section_name)
        for f in fields(section_cls):
            env_key = f"{ENV_PREFIX}{section_name.upper()}_{f.name.upper()}"
            if (raw := os.environ.get(env_key)) is not None:
                try:
                    setattr(section, f.name, _coerce(raw, f.type))
                except ValueError as exc:
                    raise ConfigError(f"Invalid value for {env_key}: {raw!r}") from exc


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_config(cfg: Config) -> str:
    lines = [
        "# AegisAI configuration",
        "# Every value can be overridden with AEGISAI_<SECTION>_<KEY> env vars,",
        "# e.g. AEGISAI_LLM_MODEL=llama3.2:3b",
        "",
    ]
    data = asdict(cfg)
    for section_name in _SECTIONS:
        lines.append(f"[{section_name}]")
        for key, value in data[section_name].items():
            lines.append(f"{key} = {_toml_value(value)}")
        lines.append("")
    return "\n".join(lines)


def write_config(cfg: Config, path: Path) -> Path:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_config(cfg), encoding="utf-8")
    cfg.path = path
    return path
