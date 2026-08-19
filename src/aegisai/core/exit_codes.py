"""Process exit codes.

These are part of the CLI's public contract: CI pipelines branch on them, so the
numbers must not be reassigned once released.
"""

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    """Clean run, nothing actionable found."""

    FINDINGS = 1
    """A CONFIRMED finding or a REGRESSED regression test exists. CI should fail."""

    USAGE = 2
    """Bad invocation or invalid configuration."""

    TARGET = 3
    """Target unreachable, unregistered, or not authorized."""

    ENVIRONMENT = 4
    """A required dependency is missing or unhealthy. Run `aegisai doctor`."""
