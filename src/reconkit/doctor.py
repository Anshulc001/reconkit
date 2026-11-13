"""Environment and tool readiness checks (docs/10_TOOL_INSTALLER.md)."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values

from reconkit.adapters import ADAPTERS
from reconkit.adapters.registry import ToolSpec, load_system_packages, load_tools
from reconkit.config import DEFAULT_CONFIG_PATH, AppConfig
from reconkit.core.scope import DEFAULT_SCOPE_PATH
from reconkit.models import InstallStatus, Stage, Tier

MIN_PYTHON = (3, 11)
NO_BINARY = "n/a (no binary required)"
WRONG_PROGRAM = "wrong program"
MISSING = "missing"
YES = "yes"
IDENTITY_OK = "ok"
IDENTITY_NA = "n/a"
IDENTITY_FAILED = "failed"
DPKG_STATUS = Path("/var/lib/dpkg/status")
DPKG_INSTALLED = "install ok installed"


@dataclass(frozen=True)
class ToolCheck:
    """One tool row: what is on disk and whether it is the expected program."""

    name: str
    stage: Stage
    tier: Tier
    kind: str
    installed: str
    version: str
    path: str
    identity: str


@dataclass(frozen=True)
class StageCoverage:
    """Ready tools out of every tool the stage lists in tools.yaml."""

    stage: Stage
    ready: int
    total: int


@dataclass(frozen=True)
class PackageCheck:
    """One apt package: installed, missing, or unknown off Debian-family Linux."""

    package: str
    state: str


@dataclass(frozen=True)
class KeyCheck:
    """One optional API key by name only; values never leave `.env`."""

    tool: str
    env: str
    url: str
    adds: str
    set: bool


@dataclass(frozen=True)
class DoctorReport:
    """Everything doctor prints, computed without installing or scanning."""

    python_version: str
    python_ok: bool
    config_path: str
    config_ok: bool
    scope_path: str
    scope_found: bool
    db_path: str
    db_writable: bool
    tools: tuple[ToolCheck, ...]
    stages: tuple[StageCoverage, ...]
    packages: tuple[PackageCheck, ...]
    keys: tuple[KeyCheck, ...]
    missing: int
    warnings: tuple[str, ...]


def default_status(spec: ToolSpec) -> InstallStatus:
    """Ask the tool's adapter whether its binary is present and is the real one."""
    adapter = ADAPTERS.get(spec.name)
    if adapter is None:
        return InstallStatus(installed=False)
    return adapter().check_installed()


def installed_packages(path: Path | None = None) -> frozenset[str]:
    """Read the dpkg status database; an unreadable file means "unknown"."""
    file = DPKG_STATUS if path is None else path
    try:
        text = file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return frozenset()
    found: set[str] = set()
    for block in text.split("\n\n"):
        package: str | None = None
        status: str | None = None
        for line in block.splitlines():
            if line.startswith("Package: "):
                package = line[len("Package: ") :].strip()
            elif line.startswith("Status: "):
                status = line[len("Status: ") :].strip()
        if package is not None and status == DPKG_INSTALLED:
            found.add(package)
    return frozenset(found)


def db_writable(path: Path) -> bool:
    """Report whether the store could be created or written where it lives."""
    parent = path.parent if str(path.parent) else Path(".")
    if not parent.is_dir() or not os.access(parent, os.W_OK):
        return False
    return not path.exists() or os.access(path, os.W_OK)


def _env_keys(env: Mapping[str, str] | None, env_file: Path | None) -> dict[str, str]:
    if env is not None:
        return {key: value for key, value in env.items() if value}
    file = Path(".env") if env_file is None else Path(env_file)
    if not file.is_file():
        return {}
    values = dotenv_values(file)
    return {key: value for key, value in values.items() if value}


def _tool_check(
    spec: ToolSpec,
    status_of: Callable[[ToolSpec], InstallStatus],
) -> ToolCheck:
    if spec.kind != "binary":
        return ToolCheck(
            name=spec.name,
            stage=spec.stage,
            tier=spec.tier,
            kind=spec.kind,
            installed=YES,
            version=NO_BINARY,
            path=NO_BINARY,
            identity=IDENTITY_NA,
        )
    status = status_of(spec)
    if status.installed:
        return ToolCheck(
            name=spec.name,
            stage=spec.stage,
            tier=spec.tier,
            kind=spec.kind,
            installed=YES,
            version=status.version or "unknown",
            path=str(status.path) if status.path is not None else "-",
            identity=IDENTITY_OK,
        )
    if status.path is not None:
        return ToolCheck(
            name=spec.name,
            stage=spec.stage,
            tier=spec.tier,
            kind=spec.kind,
            installed=WRONG_PROGRAM,
            version="-",
            path=str(status.path),
            identity=IDENTITY_FAILED,
        )
    return ToolCheck(
        name=spec.name,
        stage=spec.stage,
        tier=spec.tier,
        kind=spec.kind,
        installed=MISSING,
        version="-",
        path="-",
        identity=IDENTITY_NA,
    )


def collect_report(
    *,
    config: AppConfig,
    config_path: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    env_file: Path | None = None,
    tools_path: Path | None = None,
    scope_path: Path | None = None,
    dpkg_status: Path | None = None,
    status_of: Callable[[ToolSpec], InstallStatus] | None = None,
    python_version: Sequence[int] | None = None,
) -> DoctorReport:
    """Build the doctor report. Reads files and version commands only."""
    specs = load_tools(tools_path)
    order = list(Stage)
    ordered = sorted(specs.values(), key=lambda spec: (order.index(spec.stage), spec.name))
    checker = status_of if status_of is not None else default_status
    tools = tuple(_tool_check(spec, checker) for spec in ordered)

    coverage: list[StageCoverage] = []
    for stage in order:
        in_stage = [check for check in tools if check.stage is stage]
        if in_stage:
            ready = sum(1 for check in in_stage if check.installed == YES)
            coverage.append(StageCoverage(stage=stage, ready=ready, total=len(in_stage)))

    packages = list(load_system_packages(tools_path))
    for spec in ordered:
        for package in spec.requires_apt:
            if package not in packages:
                packages.append(package)
    status_file = DPKG_STATUS if dpkg_status is None else dpkg_status
    known = status_file.is_file()
    installed = installed_packages(status_file)
    package_checks = tuple(
        PackageCheck(
            package=package,
            state="installed" if package in installed else ("missing" if known else "unknown"),
        )
        for package in packages
    )

    environment = _env_keys(env, env_file)
    keys = tuple(
        KeyCheck(
            tool=spec.name,
            env=key.env,
            url=key.url,
            adds=key.adds,
            set=bool(environment.get(key.env)),
        )
        for spec in ordered
        for key in spec.keys
    )

    missing = sum(1 for check in tools if check.installed != YES)
    warnings = [
        f"{check.name}: {check.path} is not the expected program; doctor ignores it. "
        "Install a known copy into the reconkit bin directory."
        for check in tools
        if check.installed == WRONG_PROGRAM
    ]

    current = tuple(python_version) if python_version is not None else tuple(sys.version_info[:3])
    scope_file = Path(scope_path) if scope_path is not None else DEFAULT_SCOPE_PATH
    config_file = Path(config_path) if config_path is not None else DEFAULT_CONFIG_PATH

    return DoctorReport(
        python_version=".".join(str(part) for part in current),
        python_ok=tuple(current[:2]) >= MIN_PYTHON,
        config_path=str(config_file),
        config_ok=True,
        scope_path=str(scope_file),
        scope_found=scope_file.is_file(),
        db_path=str(config.db_path),
        db_writable=db_writable(Path(config.db_path)),
        tools=tools,
        stages=tuple(coverage),
        packages=package_checks,
        keys=keys,
        missing=missing,
        warnings=tuple(warnings),
    )
