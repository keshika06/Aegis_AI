"""Exception hierarchy.

Every error carries the exit code it should produce and, where possible, a `hint`
naming the command that fixes it. The CLI renders the hint directly, so an error
never dead-ends the user.
"""

from aegisai.core.exit_codes import ExitCode


class AegisError(Exception):
    """Base for all expected (non-crash) failures."""

    exit_code: ExitCode = ExitCode.USAGE

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


class ConfigError(AegisError):
    exit_code = ExitCode.USAGE


class TargetError(AegisError):
    """Target missing, unreachable, or not authorized for testing."""

    exit_code = ExitCode.TARGET


class UnauthorizedTargetError(TargetError):
    """Refused because the target is registered but not authorized.

    This is a safety boundary, not a permission prompt: no flag overrides it.
    """

    def __init__(self, url: str, target_id: str | None = None) -> None:
        # The target already exists in the registry by the time this is raised,
        # so the fix is `authorize`, never `add`.
        ref = target_id or url
        super().__init__(
            f"Target is registered but not authorized for scanning: {url}",
            hint=f"Authorize it with:  aegisai target authorize {ref}",
        )


class TargetNotRegisteredError(TargetError):
    """No registry entry matches the given id or URL."""

    def __init__(self, identifier: str) -> None:
        super().__init__(
            f"No registered target matches '{identifier}'.",
            hint=(
                f'Register it with:  aegisai target add "{identifier}" --authorize\n'
                "  See what is registered:  aegisai target list"
            ),
        )


class EnvironmentError_(AegisError):
    """A required external dependency is missing or unhealthy."""

    exit_code = ExitCode.ENVIRONMENT

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message, hint or "Run:  aegisai doctor")


class NotFoundError(AegisError):
    exit_code = ExitCode.USAGE
