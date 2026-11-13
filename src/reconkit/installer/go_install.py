"""Install Go tools with go install (docs/10_TOOL_INSTALLER.md)."""

from __future__ import annotations

import os
import re
from pathlib import Path

from reconkit.core.runner import run_exec
from reconkit.errors import ConfigError, InstallError
from reconkit.installer.registry import InstallPlan
from reconkit.installer.verify import Runner, check_version

GO_TIMEOUT_S = 1800.0
SPEC_RE = re.compile(r"^[A-Za-z0-9._+/-]+(@[A-Za-z0-9._-]+)?$")
DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin"


def go_env(bin_dir: Path, *, home: Path | None = None, path: str | None = None) -> dict[str, str]:
    """HOME, GOBIN and PATH - nothing else from the parent environment."""
    base = Path.home() if home is None else home
    parent_path = path if path is not None else os.environ.get("PATH", "")
    return {"HOME": str(base), "GOBIN": str(bin_dir), "PATH": parent_path or DEFAULT_PATH}


def go_spec(plan: InstallPlan) -> str:
    """Return the validated `go install` package spec."""
    if plan.package is None:
        raise ConfigError(f"{plan.name}: go_install plan has no package")
    if not SPEC_RE.match(plan.package):
        raise ConfigError(f"{plan.name}: invalid go package {plan.package!r}")
    return plan.package


def go_argv(spec: str) -> list[str]:
    """`go install <spec>`, never a shell string."""
    return ["go", "install", spec]


def go_steps(plan: InstallPlan, bin_dir: Path) -> tuple[str, ...]:
    """What go install would do, shown before anything runs."""
    return (f"{plan.name}: go install {go_spec(plan)} -> {bin_dir / plan.binary}",)


def install_go(
    plan: InstallPlan,
    *,
    bin_dir: Path,
    runner: Runner = run_exec,
    dry_run: bool = False,
    env: dict[str, str] | None = None,
    timeout: float = GO_TIMEOUT_S,
) -> tuple[str, ...]:
    """Build one Go tool into bin_dir, then run its version check."""
    steps = go_steps(plan, bin_dir)
    if dry_run:
        return steps
    child_env = env if env is not None else go_env(bin_dir)
    outcome = runner(go_argv(go_spec(plan)), timeout=timeout, env=child_env)
    if outcome.timed_out:
        raise InstallError(f"{plan.name}: go install timed out after {timeout:.0f}s")
    if outcome.returncode != 0:
        raise InstallError(f"{plan.name}: go install failed (exit {outcome.returncode})")
    binary = bin_dir / plan.binary
    if not binary.exists():
        raise InstallError(f"{plan.name}: go install finished but {binary} was not created")
    check_version(binary, plan.version_args, name=plan.name, runner=runner, env=child_env)
    return steps
