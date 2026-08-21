"""The CLI banner, and the four conditions that must suppress it.

A banner is decoration, but suppressing it is correctness: printed at the wrong
moment it corrupts a JSON document, pollutes a redirected file, or wraps into
noise on a narrow terminal.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from aegisai import __version__
from aegisai.cli import output
from aegisai.cli.context import AppContext


def _ctx(*, width: int = 100, terminal: bool = True, **kwargs) -> AppContext:
    ctx = AppContext.build(**kwargs)
    ctx.console = Console(
        file=io.StringIO(),
        width=width,
        force_terminal=terminal,
        no_color=True,
        legacy_windows=False,
    )
    return ctx


def _rendered(ctx: AppContext) -> str:
    return ctx.console.file.getvalue()


class TestBannerIsShown:
    def test_a_plain_terminal_gets_the_banner(self) -> None:
        ctx = _ctx()
        output.show_banner(ctx)

        assert "AEGISAI" in _rendered(ctx).replace(" ", "") or "█" in _rendered(ctx)
        assert output.TAGLINE in _rendered(ctx)

    def test_the_version_is_read_not_restated(self) -> None:
        """A literal would drift from pyproject.toml the first time either is
        bumped alone, and a banner advertising the wrong version is a small lie
        told confidently."""
        ctx = _ctx()
        output.show_banner(ctx)

        assert f"v{__version__}" in _rendered(ctx)

    def test_a_subtitle_is_included_when_given(self) -> None:
        ctx = _ctx()
        output.show_banner(ctx, "scan-abc123  →  http://127.0.0.1:8001")

        assert "scan-abc123" in _rendered(ctx)


class TestBannerIsSuppressed:
    def test_json_mode_prints_nothing(self) -> None:
        """A banner ahead of a JSON document makes the document unparseable,
        which would break every `| jq` in the README."""
        ctx = _ctx(json_output=True)
        output.show_banner(ctx)

        assert _rendered(ctx) == ""

    def test_a_non_terminal_prints_nothing(self) -> None:
        """`aegisai target list > out.txt` should contain the list, nothing else."""
        ctx = _ctx(terminal=False)
        output.show_banner(ctx)

        assert _rendered(ctx) == ""

    def test_quiet_prints_nothing(self) -> None:
        ctx = _ctx(quiet=True)
        output.show_banner(ctx)

        assert _rendered(ctx) == ""

    def test_a_narrow_terminal_falls_back_to_a_wordmark(self) -> None:
        """The art is 47 columns; below that it wraps into noise."""
        ctx = _ctx(width=40)
        output.show_banner(ctx)
        rendered = _rendered(ctx)

        assert "AEGISAI" in rendered
        assert "█" not in rendered


class TestBannerArt:
    def test_every_row_is_the_same_width(self) -> None:
        """A ragged row is immediately visible and looks broken."""
        rows = output.BANNER_ART.strip("\n").split("\n")

        assert len({len(r) for r in rows}) == 1, {len(r) for r in rows}

    def test_the_art_fits_the_declared_fallback_threshold(self) -> None:
        """The width check in show_banner has to match the art it guards."""
        widest = max(len(r) for r in output.BANNER_ART.strip("\n").split("\n"))

        assert widest < 52


class TestScanOrdering:
    def test_scan_applies_json_before_it_would_print_a_banner(self) -> None:
        """`--json` is resolved per-command, so a banner printed before
        apply_json would escape the suppression and corrupt the output."""
        import inspect

        from aegisai.cli import scan

        source = inspect.getsource(scan.run_scan)

        assert source.index("apply_json") < source.index("show_banner")


@pytest.mark.parametrize("flag", ["json_output", "quiet"])
def test_suppression_flags_are_honoured_independently(flag: str) -> None:
    ctx = _ctx(**{flag: True})
    output.show_banner(ctx, "subtitle that must not appear")

    assert _rendered(ctx) == ""
