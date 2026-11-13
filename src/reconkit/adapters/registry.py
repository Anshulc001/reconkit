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
    """One tools.yaml entry: the only source of tool metadata."""

    name: str
    stage: Stage
    kind: Kind
    tier: Tier
    mode: Mode
    phase: int
    rate_flag: str | None = None
    keys: tuple[ToolKey, ...] = ()


def load_tools(path: str | Path | None = None) -> dict[str, ToolSpec]:
    """Read tools.yaml into ToolSpec objects, ignoring `x-` anchor holders."""
    file = Path(path) if path is not None else TOOLS_PATH
    try:
        data: Any = yaml.safe_load(file.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {file}: {exc}") from None
    except yaml.YAMLError:
        raise ConfigError(f"{file} is not valid YAML") from None
    if not isinstance(data, dict) or not isinstance(data.get("tools"), dict):
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


def rate_flags(*, path: str | Path | None = None) -> dict[str, str]:
    """tool -> rate_flag, ready for `Pacer(rate_flags=...)`."""
    return {
        name: spec.rate_flag
        for name, spec in load_tools(path).items()
        if spec.rate_flag is not None
    }


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
    rate_flag = entry.get("rate_flag")
    if rate_flag is not None and not isinstance(rate_flag, str):
        raise ConfigError(f"tool {name!r} in tools.yaml has a non-string rate_flag")
    return ToolSpec(
        name=name,
        stage=stage,
        kind=cast(Kind, kind),
        tier=tier,
        mode=mode,
        phase=phase,
        rate_flag=rate_flag,
        keys=_keys(name, entry),
    )


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
