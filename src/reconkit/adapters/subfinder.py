"""subfinder binary adapter (docs/09_TOOL_CONTRACTS.md).

Provider keys are file-based in subfinder. The adapter writes the allowed env
values into a provider-config.yaml (mode 0600) inside a per-run directory (mode
0700), passes that path with `-pc`, and removes the directory in a finally
block; key values never reach argv or a log. A directory left behind by a killed
run is removed at the start of a later run, and a live run's directory is
protected by pid liveness plus an age rule (docs/09, C-2).
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import yaml

from reconkit.adapters.base import BinaryAdapter, Finder, parse_subdomain_lines
from reconkit.core.runner import validate_target
from reconkit.errors import ToolFailed
from reconkit.models import Record, RunContext, Stage

PROVIDERS = {
    "CERTSPOTTER_API_KEY": "certspotter",
    "PDCP_API_KEY": "chaos",
    "GITHUB_TOKEN": "github",
    "VT_API_KEY": "virustotal",
}

PROVIDER_DIR_PREFIX = "reconkit-subfinder-"
PROVIDER_FILE_NAME = "provider-config.yaml"
PROVIDER_DIR_MODE = 0o700
PROVIDER_FILE_MODE = 0o600
STALE_AFTER_S = 900.0


def _pid_alive(pid: int) -> bool:
    """Best-effort liveness probe for a PID recorded in a directory name."""
    if pid <= 0:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def cleanup_stale_provider_dirs(root: Path | None = None, *, now: float | None = None) -> int:
    """Remove provider directories (and pre-12g files) left by killed runs (docs/09, C-2).

    Never raises. A directory whose pid is still alive is kept until its mtime is
    older than `STALE_AFTER_S`, so concurrent runs cannot delete each other's
    live config.
    """
    base = Path(tempfile.gettempdir()) if root is None else root
    clock = time.time() if now is None else now
    try:
        entries = list(base.iterdir())
    except OSError:
        return 0
    removed = 0
    for entry in entries:
        name = entry.name
        if not name.startswith(PROVIDER_DIR_PREFIX):
            continue
        try:
            age = clock - entry.stat().st_mtime
        except OSError:
            continue
        if entry.is_file():
            if name.endswith(".yaml") and age >= STALE_AFTER_S:
                try:
                    entry.unlink()
                except OSError:
                    continue
                removed += 1
            continue
        if not entry.is_dir() or entry.is_symlink():
            continue
        try:
            pid = int(name[len(PROVIDER_DIR_PREFIX) :].split("-", 1)[0])
        except ValueError:
            continue
        if pid == os.getpid():
            continue
        if _pid_alive(pid) and age < STALE_AFTER_S:
            continue
        shutil.rmtree(entry, ignore_errors=True)
        if not entry.exists():
            removed += 1
    return removed


class SubfinderAdapter(BinaryAdapter):
    name = "subfinder"
    stage = Stage.SUBS
    binary = "subfinder"
    version_args = ["-version"]
    identity_markers = ("current version", "subfinder")
    # subfinder < v2.6.4 prints only "[INF] Current Version: vX.Y.Z" and never
    # names itself (upstream commit c1757901af2fa61c4deb805e17a3e5b9aa7bd5d5,
    # 2023-10-30; first released in v2.6.4). Requiring both markers would report
    # a working pre-2024 install as "not installed", so this adapter keeps
    # any-match; the binary is already identified by its filename.
    identity_require_all = False
    needs_home = True

    def __init__(self, *, finder: Finder | None = None, fixtures_dir: Path | None = None) -> None:
        super().__init__(finder=finder, fixtures_dir=fixtures_dir)
        self._provider_config: Path | None = None

    @contextmanager
    def prepare(self, ctx: RunContext) -> Iterator[None]:
        cleanup_stale_provider_dirs()
        directory = self._write_provider_config(ctx)
        self._provider_config = None if directory is None else directory / PROVIDER_FILE_NAME
        try:
            yield
        finally:
            self._provider_config = None
            if directory is not None:
                shutil.rmtree(directory, ignore_errors=True)

    def _write_provider_config(self, ctx: RunContext) -> Path | None:
        """Create this run's 0700 directory and its 0600 config, or return None."""
        data = {provider: [ctx.env[env]] for env, provider in PROVIDERS.items() if ctx.env.get(env)}
        if not data:
            return None
        directory: Path | None = None
        fd = -1
        try:
            directory = Path(tempfile.mkdtemp(prefix=f"{PROVIDER_DIR_PREFIX}{os.getpid()}-"))
            os.chmod(directory, PROVIDER_DIR_MODE)
            fd = os.open(
                directory / PROVIDER_FILE_NAME,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                PROVIDER_FILE_MODE,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                yaml.safe_dump(data, handle)
        except (OSError, yaml.YAMLError):
            if fd >= 0:
                os.close(fd)
            if directory is not None:
                shutil.rmtree(directory, ignore_errors=True)
            raise ToolFailed("subfinder: cannot write provider config") from None
        return directory

    def build_command(self, ctx: RunContext) -> list[str]:
        try:
            target = validate_target(ctx.target)
        except (TypeError, ValueError):
            raise ToolFailed("subfinder: invalid target") from None
        # The child gets only the env keys passed in, so it has no PATH: launch the
        # path binary_path() resolved (docs/09 adapter contract), never the bare name.
        argv = [self.binary_path() or self.binary, "-d", target, "-silent", "-nc", "-duc"]
        if self._provider_config is not None:
            argv += ["-pc", str(self._provider_config)]
        return argv

    def parse_output(self, raw: str) -> list[Record]:
        return parse_subdomain_lines(raw, self.name)
