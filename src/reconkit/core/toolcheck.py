"""Resolve an installed tool and read its version (docs/10_TOOL_SOURCES.md).

This is the read-only half of the old installer: where a tool's binary is found
(`~/.reconkit/bin` first, then `PATH`) and how its version is probed. Nothing
here downloads, writes or installs anything; reconkit stopped installing tools
on 2026-11-17 (docs/MASTER_PLAN.md D4).

It takes a `ToolSpec`, not an install plan: tools.yaml is the only source of
tool metadata, and every tool - with or without an adapter - is probed the same
way.
"""

from __future__ import annotations

import re
import shutil
from collections.abc import Callable
from pathlib import Path

from reconkit.adapters.base import (
    binary_search_dirs,
    identity_probe_env,
    interpreter_bin_dirs,
    probe_with_retry,
)
from reconkit.adapters.registry import ToolSpec
from reconkit.core.runner import ExecResult, run_exec

VERSION_TIMEOUT_S = 10.0
Runner = Callable[..., ExecResult]


def installed_copy(spec: ToolSpec, directory: Path) -> Path | None:
    """The managed copy, else the first copy in any search directory, else None.

    The search order is `adapters.base.binary_search_dirs()` - PATH, `$GOPATH/bin`
    and the standard install directories - so a tool installed by `go install`
    or `pipx` is found even when the shell that started reconkit never exported
    its directory (docs/10 section 3).
    """
    if spec.binary is None:
        return None
    managed = directory / spec.binary
    if managed.exists():
        return managed
    for search_dir in binary_search_dirs():
        candidate = search_dir / spec.binary
        if candidate.exists():
            return candidate
    found = shutil.which(spec.binary)
    if found is None:
        return None
    found_path = Path(found)
    if found_path.parent in interpreter_bin_dirs():
        return None
    return found_path


def installed_version(
    spec: ToolSpec,
    directory: Path,
    *,
    runner: Runner = run_exec,
    timeout: float = VERSION_TIMEOUT_S,
) -> str | None:
    """Return the installed version line, or None when the tool is not usable.

    `version_cmd`'s head names the program that reports the version and defaults
    to the resolved copy; a distro package with no version flag points it at its
    package manager (docs/10 section 3).

    A declared `version_regex` is a requirement, not a formatting hint: when the
    probe output does not match it, the copy is a namesake and counts as not
    installed. That is what keeps the Python `httpx` CLI from being reported as
    `httpx_tech` (2026-11-17, V-UNEXPECTED item 1).
    """
    copy = installed_copy(spec, directory)
    if copy is None:
        return None
    command = spec.version_cmd or []
    argv0 = str(copy)
    if command and command[0] != spec.binary:
        found = shutil.which(command[0])
        if found is None:
            return None
        argv0 = found
    if len(command) < 2:
        return argv0

    def probe() -> str | None:
        outcome = runner(
            [argv0, *command[1:]],
            timeout=timeout,
            # HOME and a PATH led by the copy's own directory, never the rest of
            # the parent environment (PIT-30/PIT-31, docs/10 section 3).
            env=identity_probe_env(argv0),
        )
        if outcome.timed_out or outcome.returncode is None:
            return None
        text = (outcome.stdout or outcome.stderr).strip()
        # Some tools print a valid banner and still exit nonzero (`masscan --version`
        # exits 1). Accept that only when the banner names the program; anything else
        # with a nonzero exit stays "not usable" (Part B audit, 2026-11-14).
        if outcome.returncode != 0 and (spec.binary or "").lower() not in text.lower():
            return None
        if spec.version_regex is not None:
            match = re.search(spec.version_regex, text)
            if match is None:
                return None
            return match.group(1) if match.groups() else match.group(0)
        return text.splitlines()[0] if text else str(copy)

    # Same retry the adapters use (D42): a transient failure here drops a tool
    # from the scan exactly as silently. A missing copy is not retried.
    return probe_with_retry(probe, ok=lambda version: version is not None)
