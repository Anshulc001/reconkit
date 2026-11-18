"""Environment and tool readiness checks (docs/10_TOOL_SOURCES.md)."""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values

from reconkit.adapters import ADAPTERS
from reconkit.adapters.registry import ToolSpec, load_system_packages, load_tools
from reconkit.config import DEFAULT_CONFIG_PATH, AppConfig, bin_dir
from reconkit.core.scope import DEFAULT_SCOPE_PATH
from reconkit.core.toolcheck import installed_copy, installed_version
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
    """One tool row: what is on disk and whether it is the expected program.

    There is no version field: the probe's string feeds the identity decision
    only and is never shown (2026-11-17, docs/MASTER_PLAN.md D6).
    """

    name: str
    stage: Stage
    tier: Tier
    kind: str
    installed: str
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
    # D36: the footer and `--json` must tell the same story, so both are
    # derived here instead of counting twice.
    installed: int = 0
    manual: tuple[str, ...] = ()
    # D35: gowitness needs a Chromium-family browser for the shots stage; doctor
    # reports it as its own row so "shots produced 0" is never a mystery.
    chromium: str = MISSING


def default_status(spec: ToolSpec) -> InstallStatus:
    """Adapter identity check first, else the tool's own binary probe.

    Most tools have no adapter (they are `phase: 3`), so asking adapters alone
    reported every one of them as missing even after a clean install. The
    fallback is the documented lookup: the managed copy first, then `PATH`, with
    `version_cmd` as the identity probe (docs/10 section 3).
    """
    adapter = ADAPTERS.get(spec.name)
    if adapter is not None:
        return adapter().check_installed()
    if spec.binary is None:
        return InstallStatus(installed=False)
    directory = bin_dir()
    copy = installed_copy(spec, directory)
    if copy is None:
        return InstallStatus(installed=False)
    version = installed_version(spec, directory)
    if version is None:
        return InstallStatus(installed=False, path=copy)
    return InstallStatus(installed=True, version=version, path=copy)


# gowitness 3.2.2 execs `google-chrome` itself; `chromium` alone is not enough
# (measured on this box: /usr/bin/chromium present, gowitness still reported
# `failed to initialize chrome context`). The row must answer "can shots work
# here", so it asks for the names gowitness actually launches (D35).
def manual_tools(specs: Mapping[str, ToolSpec]) -> tuple[str, ...]:
    """Tools the operator must place by hand (`manual: true`, D15/D36)."""
    return tuple(name for name, spec in sorted(specs.items()) if spec.manual)


BROWSER_NAMES = (
    "google-chrome",
    "google-chrome-stable",
    "chrome",
)


def browser_state(*, which: Callable[[str], str | None] | None = None) -> str:
    """`yes`/`missing`: can gowitness launch a browser on this box (D35)?"""
    lookup = which if which is not None else shutil.which
    return YES if any(lookup(name) for name in BROWSER_NAMES) else MISSING


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


def key_checks() -> tuple[KeyCheck, ...]:
    """Every documented key by name only, all reported missing (docs/05 6.1)."""
    return tuple(
        KeyCheck(tool=name, env=key.env, url=key.url, adds=key.adds, set=False)
        for name, spec in load_tools().items()
        for key in spec.keys
    )


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
            path=str(status.path),
            identity=IDENTITY_FAILED,
        )
    return ToolCheck(
        name=spec.name,
        stage=spec.stage,
        tier=spec.tier,
        kind=spec.kind,
        installed=MISSING,
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
    if status_of is not None:
        tools = tuple(_tool_check(spec, status_of) for spec in ordered)
    else:
        tools = tuple(_tool_check(spec, default_status) for spec in ordered)

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
    installed_count = sum(1 for check in tools if check.installed == YES)
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
        installed=installed_count,
        manual=manual_tools(specs),
        warnings=tuple(warnings),
        chromium=browser_state(),
    )
