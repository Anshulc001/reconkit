"""The `apt` backend: the only place reconkit ever uses sudo (docs/10 3d)."""

from __future__ import annotations

import re
from collections.abc import Callable

from reconkit.core.runner import ExecResult, run_exec
from reconkit.errors import ConfigError, InstallError, InstallSkipped
from reconkit.installer.registry import InstallPlan
from reconkit.installer.verify import Runner, check_version

APT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
APT_TIMEOUT_S = 900.0
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
SUDO_HINT = "sudo needs a password: run `sudo -v` in this terminal and retry"
SUDO_DENIAL_MARKERS = ("a password is required", "no tty present", "askpass")
Confirm = Callable[[str], bool]


def apt_env() -> dict[str, str]:
    """The exact child environment for sudo/apt-get (docs/10 3d)."""
    return {"PATH": APT_PATH, "DEBIAN_FRONTEND": "noninteractive", "LC_ALL": "C"}


def package_name(plan: InstallPlan) -> str:
    """Return the validated apt package for a plan."""
    if plan.package is None:
        raise ConfigError(f"{plan.name}: apt plan has no package")
    if not PACKAGE_RE.match(plan.package):
        raise ConfigError(f"{plan.name}: invalid apt package name {plan.package!r}")
    return plan.package


def apt_argv(package: str) -> list[str]:
    """`sudo -n apt-get install -y <package>`; never a shell string."""
    if not PACKAGE_RE.match(package):
        raise ConfigError(f"invalid apt package name {package!r}")
    return ["sudo", "-n", "apt-get", "install", "-y", package]


def apt_steps(plan: InstallPlan) -> tuple[str, ...]:
    """What apt would do, shown before anything runs."""
    return (f"{plan.name}: sudo apt-get install -y {package_name(plan)} (sudo required)",)


def raise_for_apt(outcome: ExecResult, *, name: str, timeout: float) -> None:
    """Turn an apt failure into the right error type (skip vs failed)."""
    if outcome.timed_out:
        raise InstallError(f"{name}: apt-get timed out after {timeout:.0f}s")
    if outcome.returncode == 0:
        return
    text = f"{outcome.stderr}\n{outcome.stdout}".lower()
    if any(marker in text for marker in SUDO_DENIAL_MARKERS):
        raise InstallSkipped(f"{name}: {SUDO_HINT}")
    raise InstallError(f"{name}: apt-get failed (exit {outcome.returncode})")


def apt_install_package(
    package: str,
    *,
    name: str,
    message: str,
    confirm: Confirm,
    runner: Runner = run_exec,
    timeout: float = APT_TIMEOUT_S,
) -> None:
    """Ask, then run one apt install. A declined prompt starts no process."""
    if not confirm(message):
        raise InstallSkipped(f"{name}: declined {message}")
    outcome = runner(apt_argv(package), timeout=timeout, env=apt_env())
    raise_for_apt(outcome, name=name, timeout=timeout)


def install_apt(
    plan: InstallPlan,
    *,
    confirm: Confirm,
    runner: Runner = run_exec,
    dry_run: bool = False,
    timeout: float = APT_TIMEOUT_S,
) -> tuple[str, ...]:
    """Install one apt tool after confirmation, then run its version check."""
    steps = apt_steps(plan)
    if dry_run:
        return steps
    package = package_name(plan)
    apt_install_package(
        package,
        name=plan.name,
        message=steps[0],
        confirm=confirm,
        runner=runner,
        timeout=timeout,
    )
    check_version(
        plan.binary,
        plan.version_args,
        name=plan.name,
        runner=runner,
        env=apt_env(),
    )
    return steps
