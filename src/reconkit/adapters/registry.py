"""Load tools.yaml and map tool names to adapter classes (docs/03 section 9)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit

import yaml

from reconkit.adapters import ADAPTERS
from reconkit.adapters.base import BaseToolAdapter
from reconkit.errors import ConfigError
from reconkit.models import Mode, Stage, Tier

TOOLS_PATH = Path(__file__).resolve().parents[3] / "tools.yaml"

Kind = Literal["http", "python", "binary"]
ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


@dataclass(frozen=True)
class ToolKey:
    """One optional API key: env name, sign-up URL and what it adds."""

    env: str
    url: str
    adds: str


@dataclass(frozen=True)
class ToolSpec:
    """One tools.yaml entry: the only source of tool metadata.

    `binary`/`version_cmd`/`version_regex` are what doctor probes (docs/10
    section 3); `source` is provenance only - where the upstream project lives -
    and is never executed, parsed into a command or read by any code.
    """

    name: str
    stage: Stage
    kind: Kind
    tier: Tier
    mode: Mode
    phase: int
    keys: tuple[ToolKey, ...] = ()
    requires_apt: tuple[str, ...] = ()
    binary: str | None = None
    version_cmd: list[str] | None = None
    version_regex: str | None = None
    source: str | None = None
    # Exploitation-class tools (sqlmap, dalfox, crlfuzz, ...). Never selected
    # automatically in any mode, `full` included; only an explicit `--tools`
    # naming runs one (docs/09, AGENTS "recon only").
    exploitation: bool = False
    # Tools that cannot run without root (masscan's raw sockets). Selected only
    # when the process is root; otherwise skipped with `requires root / sudo`.
    needs_root: bool = False
    # Deterministic WAF merge (docs/MASTER_PLAN.md D12): the stored `waf` keeps
    # the detection of the highest priority, so completion order and rerun order
    # cannot change it. 0 = the tool makes no claim (every tool but the four
    # WAF-capable ones).
    waf_priority: int = 0


def _document(file: Path) -> dict[str, Any]:
    """Read one YAML document, mapping every failure to ConfigError."""
    try:
        data: Any = yaml.safe_load(file.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {file}: {exc}") from None
    except yaml.YAMLError:
        raise ConfigError(f"{file} is not valid YAML") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{file} has no tools mapping")
    return data


def load_system_packages(path: str | Path | None = None) -> tuple[str, ...]:
    """Return the top-level `system_packages` list (docs/10 section 3)."""
    file = Path(path) if path is not None else TOOLS_PATH
    raw = _document(file).get("system_packages", [])
    if not isinstance(raw, list) or not all(isinstance(item, str) and item for item in raw):
        raise ConfigError(f"{file} has an invalid system_packages list")
    return tuple(raw)


def load_tools(path: str | Path | None = None) -> dict[str, ToolSpec]:
    """Read tools.yaml into ToolSpec objects, ignoring `x-` anchor holders."""
    file = Path(path) if path is not None else TOOLS_PATH
    data = _document(file)
    if not isinstance(data.get("tools"), dict):
        raise ConfigError(f"{file} has no tools mapping")
    specs: dict[str, ToolSpec] = {}
    for name, entry in data["tools"].items():
        if not isinstance(name, str) or not isinstance(entry, dict):
            raise ConfigError(f"{file}: every tool must be a named mapping")
        specs[name] = _spec(name, entry)
    return specs


def get_spec(name: str, *, path: str | Path | None = None) -> ToolSpec:
    """Look up one tool; unknown names are a ConfigError, never a silent skip."""
    spec = load_tools(path).get(name)
    if spec is None:
        raise ConfigError(f"unknown tool {name!r}: it is not listed in tools.yaml")
    return spec


def get_adapter(name: str, *, path: str | Path | None = None) -> type[BaseToolAdapter]:
    """Return the adapter class for a tool name, or raise ConfigError."""
    spec = get_spec(name, path=path)
    adapter = ADAPTERS.get(name)
    if adapter is None:
        raise ConfigError(
            f"tool {name!r} is listed in tools.yaml but has no adapter yet (phase {spec.phase})"
        )
    return adapter


def _spec(name: str, entry: dict[str, Any]) -> ToolSpec:
    if "needs_key" in entry:
        raise ConfigError(
            f"tool {name!r} in tools.yaml uses 'needs_key'; list the same env names under 'keys'"
        )
    try:
        stage = Stage(str(entry["stage"]))
        tier = Tier(str(entry["tier"]))
        mode = Mode(str(entry["mode"]))
    except KeyError as exc:
        raise ConfigError(f"tool {name!r} in tools.yaml is missing {exc.args[0]!r}") from None
    except ValueError as exc:
        raise ConfigError(f"tool {name!r} in tools.yaml: {exc}") from None
    kind = str(entry.get("kind", ""))
    if kind not in ("http", "python", "binary"):
        raise ConfigError(f"tool {name!r} in tools.yaml has invalid kind {kind!r}")
    phase = entry.get("phase", 3)
    if not isinstance(phase, int) or isinstance(phase, bool):
        raise ConfigError(f"tool {name!r} in tools.yaml has invalid phase {phase!r}")
    requires_apt = entry.get("requires_apt", [])
    if not isinstance(requires_apt, list) or not all(
        isinstance(item, str) and item for item in requires_apt
    ):
        raise ConfigError(f"tool {name!r} in tools.yaml has an invalid requires_apt list")
    return ToolSpec(
        name=name,
        stage=stage,
        kind=cast(Kind, kind),
        tier=tier,
        mode=mode,
        phase=phase,
        keys=_keys(name, entry),
        requires_apt=tuple(requires_apt),
        binary=_optional_text(name, entry, "binary"),
        version_cmd=_version_cmd(name, entry),
        version_regex=_version_regex(name, entry),
        source=_optional_text(name, entry, "source"),
        exploitation=_exploitation(name, entry),
        needs_root=_flag(name, entry, "needs_root"),
        waf_priority=_waf_priority(name, entry),
    )


def _flag(name: str, entry: dict[str, Any], field: str) -> bool:
    """An optional boolean registry flag; anything but a bool is a ConfigError."""
    value = entry.get(field, False)
    if not isinstance(value, bool):
        raise ConfigError(f"tool {name!r} in tools.yaml has an invalid {field!r}")
    return value


def _optional_text(name: str, entry: dict[str, Any], field: str) -> str | None:
    """An optional non-empty string field; a blank or non-string value is invalid."""
    value = entry.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"tool {name!r} in tools.yaml has an invalid {field!r}")
    return value.strip()


def _version_cmd(name: str, entry: dict[str, Any]) -> list[str] | None:
    raw = entry.get("version_cmd")
    if raw is None:
        return None
    if not isinstance(raw, list) or not all(isinstance(part, str) and part for part in raw):
        raise ConfigError(f"tool {name!r} in tools.yaml has an invalid version_cmd")
    return list(raw)


def _version_regex(name: str, entry: dict[str, Any]) -> str | None:
    """An optional version pattern; it must compile or the registry is invalid."""
    value = entry.get("version_regex")
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"tool {name!r} in tools.yaml has an invalid version_regex")
    try:
        re.compile(value)
    except re.error:
        raise ConfigError(f"tool {name!r} in tools.yaml has an invalid version_regex") from None
    return value.strip()


def _waf_priority(name: str, entry: dict[str, Any]) -> int:
    """Optional non-negative integer `waf_priority`; anything else is invalid."""
    value = entry.get("waf_priority", 0)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ConfigError(f"tool {name!r} in tools.yaml has an invalid waf_priority")
    return value


def _exploitation(name: str, entry: dict[str, Any]) -> bool:
    """Optional boolean `exploitation` marker; anything but a bool is invalid."""
    value = entry.get("exploitation")
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ConfigError(f"tool {name!r} in tools.yaml has an invalid exploitation flag")
    return value


def _keys(name: str, entry: dict[str, Any]) -> tuple[ToolKey, ...]:
    raw = entry.get("keys")
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError(f"tool {name!r} in tools.yaml: keys must be a list")
    keys: list[ToolKey] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ConfigError(f"tool {name!r} in tools.yaml: every keys entry must be a mapping")
        for field in ("env", "url", "adds"):
            value = item.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ConfigError(f"tool {name!r} in tools.yaml: keys entry is missing {field!r}")
        env = item["env"]
        url = item["url"]
        adds = item["adds"]
        if not ENV_NAME.fullmatch(env):
            raise ConfigError(
                f"tool {name!r} in tools.yaml: keys env {env!r} must match {ENV_NAME.pattern}"
            )
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.netloc:
            raise ConfigError(f"tool {name!r} in tools.yaml: keys url {url!r} must be https")
        keys.append(ToolKey(env=env, url=url, adds=adds))
    return tuple(keys)
