"""Read install metadata from tools.yaml (docs/10_TOOL_INSTALLER.md)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from reconkit.adapters.registry import TOOLS_PATH, load_tools
from reconkit.errors import ConfigError

METHODS = ("github_release", "go_install", "apt", "pipx", "none")


@dataclass(frozen=True)
class InstallPlan:
    """One tool's install recipe, with its fallback resolved as a nested plan."""

    name: str
    method: str
    binary: str
    tier: str = "core"
    package: str | None = None
    repo: str | None = None
    asset_pattern: str | None = None
    checksums_pattern: str | None = None
    asset_name: str | None = None
    member: str | None = None
    verify_checksums: bool | None = None
    version: str = "latest"
    version_args: tuple[str, ...] = ()
    fallback: InstallPlan | None = None
    requires_apt: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()


def _text(value: Any, field: str, name: str, *, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ConfigError(f"tool {name!r} in tools.yaml has no install {field!r}")
        return None
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"tool {name!r} in tools.yaml has an invalid install {field!r}")
    return value.strip()


def _flag(value: Any, field: str, name: str) -> bool | None:
    """An optional install flag: absent means "use the config default"."""
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ConfigError(f"tool {name!r} in tools.yaml has an invalid install {field!r}")
    return value


def _names(value: Any, field: str, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ConfigError(f"tool {name!r} in tools.yaml has an invalid {field!r} list")
    return tuple(value)


def _package_with_version(package: str, version: str) -> str:
    """Pin a `go install` package, replacing a trailing `@latest` or `@x`."""
    if version == "latest":
        return package
    base, separator, _pinned = package.rpartition("@")
    if not separator:
        return f"{package}@{version}"
    return f"{base}@{version}"


def _plan(name: str, entry: Mapping[str, Any], version: str) -> InstallPlan:
    binary = _text(entry.get("binary"), "binary", name) or name
    tier = _text(entry.get("tier"), "tier", name) or "core"
    install = entry.get("install")
    requires_apt = _names(entry.get("requires_apt"), "requires_apt", name)
    requires = _names(entry.get("requires"), "requires", name)
    version_cmd = entry.get("version_cmd")
    version_args: tuple[str, ...] = ()
    if version_cmd is not None:
        if not isinstance(version_cmd, list) or not all(
            isinstance(part, str) for part in version_cmd
        ):
            raise ConfigError(f"tool {name!r} in tools.yaml has an invalid version_cmd")
        version_args = tuple(version_cmd[1:])
    if install is None:
        return InstallPlan(
            name=name,
            method="none",
            binary=binary,
            tier=tier,
            version_args=version_args,
            requires_apt=requires_apt,
            requires=requires,
        )
    if not isinstance(install, Mapping):
        raise ConfigError(f"tool {name!r} in tools.yaml has an invalid install block")
    method = _text(install.get("method"), "method", name, required=True)
    if method not in METHODS:
        raise ConfigError(
            f"tool {name!r} in tools.yaml has unknown install method {method!r}; "
            f"expected one of {', '.join(METHODS)}"
        )
    package = _text(install.get("package"), "package", name)
    repo = _text(install.get("repo"), "repo", name)
    if method in ("go_install", "apt", "pipx") and package is None:
        raise ConfigError(f"tool {name!r} in tools.yaml needs an install package for {method!r}")
    if method == "github_release" and repo is None:
        raise ConfigError(f"tool {name!r} in tools.yaml needs an install repo for 'github_release'")
    fallback_entry = install.get("fallback")
    if fallback_entry is not None and not isinstance(fallback_entry, Mapping):
        raise ConfigError(f"tool {name!r} in tools.yaml has an invalid install fallback")
    fallback = (
        _plan(name, {"binary": binary, "tier": tier, "install": dict(fallback_entry)}, version)
        if fallback_entry is not None
        else None
    )
    return InstallPlan(
        name=name,
        method=str(method),
        binary=binary,
        tier=tier,
        package=_package_with_version(package, version)
        if method == "go_install" and package
        else package,
        repo=repo,
        asset_pattern=_text(install.get("asset_pattern"), "asset_pattern", name),
        checksums_pattern=_text(install.get("checksums_pattern"), "checksums_pattern", name),
        asset_name=_text(install.get("name"), "name", name) or name,
        member=_text(install.get("member"), "member", name),
        verify_checksums=_flag(install.get("verify_checksums"), "verify_checksums", name),
        version=version,
        version_args=version_args,
        fallback=fallback,
        requires_apt=requires_apt,
        requires=requires,
    )


def _document(file: Path) -> dict[str, Any]:
    try:
        data: Any = yaml.safe_load(file.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {file}: {exc}") from None
    except yaml.YAMLError:
        raise ConfigError(f"{file} is not valid YAML") from None
    if not isinstance(data, dict) or not isinstance(data.get("tools"), dict):
        raise ConfigError(f"{file} has no tools mapping")
    return data


def load_plans(
    path: str | Path | None = None,
    *,
    versions: Mapping[str, str] | None = None,
) -> dict[str, InstallPlan]:
    """Build one plan per tool, applying `tool_versions` pins from config.yaml."""
    file = Path(path) if path is not None else TOOLS_PATH
    raw = _document(file)["tools"]
    specs = load_tools(file)
    pins = dict(versions or {})
    plans: dict[str, InstallPlan] = {}
    for name in specs:
        entry = raw.get(name)
        if not isinstance(entry, Mapping):
            raise ConfigError(f"tool {name!r} in {file} is not a mapping")
        version = pins.get(name, "latest")
        plan = _plan(name, entry, version)
        plans[name] = InstallPlan(
            name=plan.name,
            method=plan.method,
            binary=plan.binary,
            tier=plan.tier,
            package=plan.package,
            repo=plan.repo,
            asset_pattern=plan.asset_pattern,
            checksums_pattern=plan.checksums_pattern,
            asset_name=plan.asset_name,
            member=plan.member,
            verify_checksums=plan.verify_checksums,
            version=plan.version,
            version_args=plan.version_args,
            fallback=plan.fallback,
            requires_apt=specs[name].requires_apt,
            requires=plan.requires,
        )
    return plans


def plan_for(
    name: str,
    *,
    path: str | Path | None = None,
    versions: Mapping[str, str] | None = None,
) -> InstallPlan:
    """Look up one tool's plan; an unknown name is a ConfigError."""
    plan = load_plans(path, versions=versions).get(name)
    if plan is None:
        raise ConfigError(f"unknown tool {name!r}: it is not listed in tools.yaml")
    return plan


def bin_dir(home: Path | None = None) -> Path:
    """The managed binary directory: `~/.reconkit/bin` (docs/10 section 5)."""
    base = Path.home() if home is None else home
    return base / ".reconkit" / "bin"


def resolve_plan(plan: InstallPlan) -> tuple[InstallPlan, ...]:
    """Return the primary plan followed by every configured fallback."""
    chain: list[InstallPlan] = [plan]
    current = plan
    while current.fallback is not None:
        current = current.fallback
        chain.append(current)
    return tuple(chain)
