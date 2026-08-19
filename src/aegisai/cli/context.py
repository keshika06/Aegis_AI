"""Per-invocation CLI state, carried on the Typer context object."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from sqlalchemy import Engine

from aegisai.core.config import Config, load_config


@dataclass
class AppContext:
    config: Config
    json_output: bool = False
    quiet: bool = False
    verbose: bool = False
    assume_yes: bool = False
    console: Console = field(default_factory=Console)
    err_console: Console = field(default_factory=lambda: Console(stderr=True))

    _engine: Engine | None = field(default=None, repr=False)

    @classmethod
    def build(
        cls,
        config_path: Path | None = None,
        *,
        json_output: bool = False,
        quiet: bool = False,
        verbose: bool = False,
        no_color: bool = False,
        assume_yes: bool = False,
    ) -> AppContext:
        return cls(
            config=load_config(config_path),
            json_output=json_output,
            quiet=quiet,
            verbose=verbose,
            assume_yes=assume_yes,
            console=Console(no_color=no_color, soft_wrap=False),
            err_console=Console(stderr=True, no_color=no_color),
        )

    def apply_json(self, flag: bool) -> None:
        """Honour a subcommand-level `--json`.

        Only ever turns JSON on: a global `--json` must not be cancelled by a
        subcommand that simply left its local flag at the default.
        """
        if flag:
            self.json_output = True

    def engine(self) -> Engine:
        """Lazily built so commands that never touch the DB stay fast."""
        if self._engine is None:
            from aegisai.core.db import create_db_engine

            self._engine = create_db_engine(self.config)
        return self._engine
