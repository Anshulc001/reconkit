"""Exception types for reconkit (docs/06_CODE_STYLE.md section 6)."""

from __future__ import annotations

from typing import ClassVar


class ScopeError(Exception):
    """The target, host or scope file failed the scope gate (exit code 3)."""

    exit_code: ClassVar[int] = 3


class ToolNotInstalled(Exception):
    """No usable tool is available for the stage (exit code 4).

    Intentionally never raised. A tool that is absent at selection time is
    recorded as `skipped (not installed)` and the stage continues (docs/09
    selection rules), while exit code 4 is derived in `Engine._exit_code` from
    "no selected tool ran at all". The name stays in the vocabulary that
    docs/06 section 6 defines for adapters, but a skip must not raise it: doing
    so would turn a normal "not installed" into a stage failure.
    """

    exit_code: ClassVar[int] = 4


class ToolFailed(Exception):
    """A tool ran but failed; the run is partial (exit code 5)."""

    exit_code: ClassVar[int] = 5


class ToolTimeout(Exception):
    """A tool exceeded its timeout; the run is partial (exit code 5)."""

    exit_code: ClassVar[int] = 5


class ParseError(Exception):
    """Tool output could not be parsed (exit code 1)."""

    exit_code: ClassVar[int] = 1


class ConfigError(Exception):
    """Configuration or CLI values are invalid (exit code 2)."""

    exit_code: ClassVar[int] = 2
