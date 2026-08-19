"""Configuration loading, precedence, and round-tripping."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisai.core.config import Config, load_config, render_config, write_config
from aegisai.core.exceptions import ConfigError


def test_defaults_load_without_a_file(aegis_home: Path) -> None:
    cfg = load_config()

    assert cfg.path is None
    assert cfg.llm.provider == "ollama"
    assert cfg.scan.default_profile == "standard"


def test_written_config_round_trips(tmp_path: Path, aegis_home: Path) -> None:
    cfg = Config()
    cfg.llm.model = "llama3.2:3b"
    cfg.scan.target_timeout_seconds = 45
    path = tmp_path / "config.toml"

    write_config(cfg, path)
    reloaded = load_config(path)

    assert reloaded.llm.model == "llama3.2:3b"
    assert reloaded.scan.target_timeout_seconds == 45
    assert isinstance(reloaded.scan.target_timeout_seconds, int)


def test_env_overrides_beat_the_file(
    tmp_path: Path, aegis_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = Config()
    cfg.llm.model = "from-file"
    path = tmp_path / "config.toml"
    write_config(cfg, path)

    monkeypatch.setenv("AEGISAI_LLM_MODEL", "from-env")

    assert load_config(path).llm.model == "from-env"


def test_int_env_override_is_coerced(aegis_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGISAI_LLM_TIMEOUT_SECONDS", "120")

    assert load_config().llm.timeout_seconds == 120


def test_malformed_config_reports_the_path(tmp_path: Path, aegis_home: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("this is not = valid = toml [[[", encoding="utf-8")

    with pytest.raises(ConfigError) as exc:
        load_config(path)

    assert str(path) in exc.value.message
    assert exc.value.hint


def test_rendered_config_is_valid_toml(aegis_home: Path) -> None:
    import tomllib

    parsed = tomllib.loads(render_config(Config()))

    assert {"core", "llm", "scan", "labs"} <= parsed.keys()
