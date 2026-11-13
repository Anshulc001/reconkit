"""Install Python tools with pipx (docs/10_TOOL_INSTALLER.md)."""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

from reconkit.core.runner import run_exec
from reconkit.errors import ConfigError, InstallError, InstallSkipped
from reconkit.installer import apt
from reconkit.installer.registry import InstallPlan
from reconkit.installer.verify import Runner, check_version

PIPX_TIMEOUT_S = 900.0
SPEC_RE = re.compile(
    r"^("
    r"git\+https://[A-Za-z0-9._/-]+"
    r"|[A-Za-z0-9._-]+(\[[A-Za-z0-9,._-]+\])?(==[A-Za-z0-9.]+)?"
    r")$"
)
DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin"
PREREQ = "pipx is required for {name}: sudo apt-get install -y pipx (sudo required)"
Confirm = apt.Confirm


def pipx_env(bin_dir: Path, *, home: Path | None = None, path: str | None = None) -> dict[str, str]:
    """HOME, PATH, PIPX_BIN_DIR and PIPX_HOME - nothing else."""
    base = Path.home() if home is None else home
    parent_path = path if path is not None else os.environ.get("PATH", "")
    return {
        "HOME": str(base),
        "PATH": parent_path or DEFAULT_PATH,
        "PIPX_BIN_DIR": str(bin_dir),
        "PIPX_HOME": str(base / ".local" / "pipx"),
    }


def pipx_spec(plan: InstallPlan) -> str:
    """Return the validated pipx spec (package, pinned or git+https URL)."""
    if plan.package is None:
        raise ConfigError(f"{plan.name}: pipx plan has no package")
    if not SPEC_RE.match(plan.package):
        raise ConfigError(f"{plan.name}: invalid pipx package {plan.package!r}")
    return plan.package


def pipx_argv(spec: str) -> list[str]:
    """`pipx install <spec>`, never a shell string."""
    return ["pipx", "install", spec]


def pipx_available() -> bool:
    """True when a `pipx` executable is already on PATH."""
    return shutil.which("pipx") is not None


def pipx_steps(plan: InstallPlan, bin_dir: Path, *, installed: bool) -> tuple[str, ...]:
    """Every step, with the sudo-bearing prerequisite kept separate."""
    steps: list[str] = []
    if not installed:
        steps.append(PREREQ.format(name=plan.name))
    steps.append(f"{plan.name}: pipx install {pipx_spec(plan)} -> {bin_dir / plan.binary}")
    return tuple(steps)


def install_pipx_tool(
    plan: InstallPlan,
    *,
    bin_dir: Path,
    confirm: Confirm,
    runner: Runner = run_exec,
    dry_run: bool = False,
    has_pipx: bool | None = None,
    env: dict[str, str] | None = None,
    timeout: float = PIPX_TIMEOUT_S,
) -> tuple[str, ...]:
    """Install pipx if needed, then the tool, with one confirmation per step."""
    installed = pipx_available() if has_pipx is None else has_pipx
    steps = pipx_steps(plan, bin_dir, installed=installed)
    if dry_run:
        return steps
    if not installed:
        apt.apt_install_package(
            "pipx",
            name=plan.name,
            message=steps[0],
            confirm=confirm,
            runner=runner,
        )
    install_step = f"{plan.name}: pipx install {pipx_spec(plan)}"
    if not confirm(f"{install_step} -> {bin_dir / plan.binary}"):
        raise InstallSkipped(f"{plan.name}: pipx install declined")
    child_env = env if env is not None else pipx_env(bin_dir)
    outcome = runner(pipx_argv(pipx_spec(plan)), timeout=timeout, env=child_env)
    if outcome.timed_out:
        raise InstallError(f"{plan.name}: pipx install timed out after {timeout:.0f}s")
    if outcome.returncode != 0:
        raise InstallError(f"{plan.name}: pipx install failed (exit {outcome.returncode})")
    binary = bin_dir / plan.binary
    if not binary.exists():
        raise InstallError(f"{plan.name}: pipx install finished but {binary} was not created")
    check_version(binary, plan.version_args, name=plan.name, runner=runner, env=child_env)
    return steps
