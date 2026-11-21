"""Per-scan logging: a persistent file plus colored milestone lines.

Every scan writes ``<results_dir>/logs/<target>/<UTC stamp>.log``. The file
always receives every message; the terminal receives the scan milestones only,
so the existing Rich tables and progress lines keep their shape
(docs/02_CLI_UX.md section 5). Messages are redacted with the same
``core.store.redact`` helper as every other text reconkit writes, so a token in
a tool name or error can never reach the log.

This module is output, not orchestration: it imports no engine, adapter, scope
or CLI code, and child processes never use it.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.text import Text

from reconkit.core.store import redact
from reconkit.ui import make_console

SUCCESS = 25
logging.addLevelName(SUCCESS, "SUCCESS")

LEVELS: tuple[str, ...] = ("DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR")
_LEVEL_NUMBERS: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "SUCCESS": SUCCESS,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
}
_PATTERN = re.compile(r"^(DEBUG|INFO|SUCCESS|WARNING|ERROR)$")

_STYLES: dict[str, str] = {
    "DEBUG": "grey50",
    "INFO": "cyan",
    "SUCCESS": "green",
    "WARNING": "yellow",
    "ERROR": "bold red",
}
_FILE_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

_lock = threading.Lock()


def normalize_level(level: str) -> str:
    """Validate the configured level; an unknown value falls back to INFO."""

    candidate = level.strip().upper()
    return candidate if _PATTERN.fullmatch(candidate) else "INFO"


def log_directory(results_root: Path | str, target: str) -> Path:
    """The target's log folder: ``<results_dir>/logs/<target>/``."""

    if not target or not _SAFE_NAME.fullmatch(target):
        raise ValueError(f"unsafe log target {target!r}")
    directory = Path(results_root) / "logs" / target
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def scan_log_path(results_root: Path | str, target: str, run_at: datetime) -> Path:
    """A unique log file for one scan, never overwriting an earlier run.

    The stamp matches the report folder's UTC stamp; two runs in the same
    second get ``-2``, ``-3``, ... so evidence from one run is never lost.
    """

    directory = log_directory(results_root, target)
    stamp = run_at.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    candidate = directory / f"{stamp}.log"
    suffix = 2
    while candidate.exists():
        candidate = directory / f"{stamp}-{suffix}.log"
        suffix += 1
    return candidate


class ScanLog:
    """One scan's logger: a file handler and optional colored console lines."""

    def __init__(
        self,
        path: Path,
        *,
        level: str = "INFO",
        console: Console | None = None,
        console_enabled: bool = True,
    ) -> None:
        self.path = Path(path)
        self.level = normalize_level(level)
        self.console = console if console is not None else make_console()
        self.console_enabled = console_enabled
        self._logger = logging.getLogger(f"reconkit.scan.{self.path.stem}.{id(self)}")
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False
        handler = logging.FileHandler(self.path, mode="w", encoding="utf-8")
        handler.setLevel(_LEVEL_NUMBERS[self.level])
        formatter = logging.Formatter(_FILE_FORMAT, datefmt=_DATE_FORMAT)
        formatter.converter = time.gmtime  # the file records UTC, like the DB
        handler.setFormatter(formatter)
        self._logger.addHandler(handler)
        self._handler = handler

    def _emit(self, level: str, message: str, *, console: bool) -> None:
        clean = redact(str(message))
        with _lock:
            self._logger.log(_LEVEL_NUMBERS[level], clean)
        if not (console and self.console_enabled):
            return
        if LEVELS.index(level) < LEVELS.index(self.level):
            return
        stamp = datetime.now(UTC).astimezone().strftime("%H:%M:%S")
        line = Text()
        line.append(f"[{stamp}] ", style="grey50")
        line.append(f"[{level}] ", style=_STYLES[level])
        line.append(clean)
        self.console.print(line)

    def debug(self, message: str, *, console: bool = False) -> None:
        self._emit("DEBUG", message, console=console)

    def info(self, message: str, *, console: bool = True) -> None:
        self._emit("INFO", message, console=console)

    def success(self, message: str, *, console: bool = True) -> None:
        self._emit("SUCCESS", message, console=console)

    def warning(self, message: str, *, console: bool = True) -> None:
        self._emit("WARNING", message, console=console)

    def error(self, message: str, *, console: bool = True) -> None:
        self._emit("ERROR", message, console=console)

    def close(self) -> None:
        """Flush and detach the file handler; safe to call more than once."""

        with _lock:
            handler = getattr(self, "_handler", None)
            if handler is None:
                return
            self._handler = None  # type: ignore[assignment]
        handler.flush()
        handler.close()
        self._logger.removeHandler(handler)


def open_scan_log(
    results_root: Path | str,
    target: str,
    run_at: datetime,
    *,
    level: str = "INFO",
    console: Console | None = None,
    console_enabled: bool = True,
) -> ScanLog:
    """Build the log for one target's scan (docs/02 section 5)."""

    return ScanLog(
        scan_log_path(results_root, target, run_at),
        level=level,
        console=console,
        console_enabled=console_enabled,
    )
