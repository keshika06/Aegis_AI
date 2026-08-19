"""Reusable option definitions.

Click resolves callback-level options only *before* the subcommand
(`aegisai --json target list`), but the natural way to script a read command is
to put the flag last (`aegisai target list --json`). Read commands therefore
accept `--json` locally as well, and both spellings mean the same thing.
"""

from __future__ import annotations

import typer

JSON_OPTION = typer.Option(False, "--json", help="Emit machine-readable JSON.")
