"""Per-target workspace files under workspaces/<domain> (docs/03_ARCHITECTURE.md).

Every raw tool output is redacted with `store.redact()` before it touches disk.
Paths are limited to the documented stage directories and one plain filename;
writes go to a temporary file in the same directory and are then replaced
atomically, so a crash never leaves a partial result behind.
"""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Iterable
from contextlib import suppress
from pathlib import Path

from reconkit.core.runner import MAX_OUTPUT_BYTES, validate_target
from reconkit.core.store import redact

STAGES: tuple[str, ...] = ("subs", "live", "ports", "urls", "tech", "meta")
DIR_MODE = 0o700
FILE_MODE = 0o600
_NAME_LIMIT = 128

_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
    }
)


def _reserved(stem: str) -> bool:
    """Windows reserves device names even with an extension (CON.txt)."""
    return stem.split(".")[0].upper() in _RESERVED_NAMES


def _chmod(path: Path, mode: int) -> None:
    """Best effort: Windows only honours a subset of POSIX modes."""
    with suppress(OSError):
        path.chmod(mode)


def cap_bytes(text: str, max_bytes: int) -> str:
    """Cut `text` to at most `max_bytes` UTF-8 bytes (docs/03 section 5).

    A multi-byte character split by the cut is dropped instead of being written
    as a broken sequence. The output is capped, never silently emptied.
    """
    if max_bytes <= 0:
        raise ValueError("max_bytes must be > 0")
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", "ignore")


class Workspace:
    """The workspace for one validated target domain."""

    def __init__(self, root: Path | str, target: str, *, secrets: Iterable[str] = ()) -> None:
        self.root = Path(root)
        self.target = validate_target(target)
        if _reserved(self.target.split(".")[0]):
            raise ValueError(f"target directory is reserved on Windows: {self.target!r}")
        self.secrets = tuple(secrets)
        self.directory = self.root / self.target

    @classmethod
    def create(cls, root: Path | str, target: str, *, secrets: Iterable[str] = ()) -> Workspace:
        """Create (or reuse) the workspace and its six stage directories."""
        workspace = cls(root, target, secrets=secrets)
        workspace.ensure()
        return workspace

    def ensure(self) -> None:
        """Create the documented layout; safe to call repeatedly."""
        self.root.mkdir(parents=True, exist_ok=True)
        self.directory.mkdir(exist_ok=True)
        _chmod(self.directory, DIR_MODE)
        for stage in STAGES:
            stage_dir = self.directory / stage
            stage_dir.mkdir(exist_ok=True)
            _chmod(stage_dir, DIR_MODE)

    def path(self, stage: str, filename: str) -> Path:
        """Return a path only for a documented stage and a safe plain filename."""
        if stage not in STAGES:
            raise ValueError(f"unknown workspace stage: {stage!r}")
        if not isinstance(filename, str):
            raise TypeError("workspace filename must be a string")
        if not _NAME_RE.fullmatch(filename):
            raise ValueError(f"unsafe workspace filename: {filename!r}")
        if len(filename) > _NAME_LIMIT:
            raise ValueError(f"workspace filename is longer than {_NAME_LIMIT} characters")
        if filename.endswith(".") or _reserved(filename):
            raise ValueError(f"unsafe workspace filename: {filename!r}")

        stage_dir = self.directory / stage
        destination = stage_dir / filename
        if destination.parent != stage_dir:
            raise ValueError(f"unsafe workspace filename: {filename!r}")

        # Defence in depth against a stage directory replaced by a symlink.
        root = self.directory.resolve()
        if not stage_dir.resolve().is_relative_to(root):
            raise ValueError(f"workspace stage escapes the target directory: {stage!r}")
        if destination.resolve().parent != stage_dir.resolve():
            raise ValueError(f"unsafe workspace filename: {filename!r}")
        return destination

    def write(
        self,
        stage: str,
        filename: str,
        text: str,
        *,
        secrets: Iterable[str] | None = None,
        max_bytes: int = MAX_OUTPUT_BYTES,
    ) -> Path:
        """Redact, cap, then atomically write one raw output file."""
        if not isinstance(text, str):
            raise TypeError("workspace content must be a string")
        destination = self.path(stage, filename)
        destination.parent.mkdir(parents=True, exist_ok=True)
        _chmod(destination.parent, DIR_MODE)

        values = self.secrets if secrets is None else tuple(secrets)
        cleaned = cap_bytes(redact(text, values), max_bytes)

        fd, temp_name = tempfile.mkstemp(
            prefix=".reconkit-", suffix=".part", dir=destination.parent
        )
        temp = Path(temp_name)
        handle = None
        try:
            handle = os.fdopen(fd, "w", encoding="utf-8", newline="")
            with handle:
                handle.write(cleaned)
                handle.flush()
                os.fsync(handle.fileno())
            _chmod(temp, FILE_MODE)
            os.replace(temp, destination)
        except BaseException:
            if handle is None:
                with suppress(OSError):
                    os.close(fd)
            temp.unlink(missing_ok=True)
            raise
        return destination
