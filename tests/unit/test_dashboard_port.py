"""Port resolution for `aegisai dashboard serve`.

The dev server prints its URL before Vite starts, so the port must be settled
*before* anything is announced. These tests pin the two ways that went wrong:
advertising a port already in use, and probing only IPv4 when Vite listens on
IPv6.
"""

from __future__ import annotations

import socket

import pytest

from aegisai.cli.dashboard import _port_is_free, _resolve_port
from aegisai.core.exceptions import AegisError


def _listen(family: int, host: str) -> socket.socket:
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.bind((host, 0))
    sock.listen(1)
    return sock


def test_free_port_is_reported_free() -> None:
    with _listen(socket.AF_INET, "127.0.0.1") as sock:
        port = sock.getsockname()[1]
    # Closed again, so the port is genuinely available.
    assert _port_is_free(port) is True


def test_ipv6_listener_is_detected() -> None:
    """The regression: Vite binds [::1], so an IPv4-only probe saw it as free."""
    if not socket.has_ipv6:  # pragma: no cover - IPv6 is present on CI and macOS
        pytest.skip("no IPv6 on this host")
    with _listen(socket.AF_INET6, "::1") as sock:
        port = sock.getsockname()[1]
        assert _port_is_free(port) is False


def test_ipv4_listener_is_detected() -> None:
    with _listen(socket.AF_INET, "127.0.0.1") as sock:
        port = sock.getsockname()[1]
        assert _port_is_free(port) is False


def test_resolve_skips_a_busy_port() -> None:
    with _listen(socket.AF_INET, "127.0.0.1") as sock:
        busy = sock.getsockname()[1]
        assert _resolve_port(busy) > busy


def test_resolve_gives_up_loudly_rather_than_guessing() -> None:
    with _listen(socket.AF_INET, "127.0.0.1") as sock:
        busy = sock.getsockname()[1]
        with pytest.raises(AegisError):
            _resolve_port(busy, span=1)
