"""Load config.yaml and merge CLI overrides (docs/03_ARCHITECTURE.md)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal, cast

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from reconkit.errors import ConfigError

SpeedName = Literal["slow", "normal", "fast"]
DEFAULT_CONFIG_PATH = Path("config.yaml")
_SPEED_NAMES = ("slow", "normal", "fast")


class PassiveSpeed(BaseModel):
    max_parallel_tools: int = Field(ge=1)
    tool_delay: tuple[float, float]
    requests_per_second: float = Field(gt=0)

    @model_validator(mode="after")
    def _validate_delay(self) -> PassiveSpeed:
        _check_delay(self.tool_delay, "passive.tool_delay")
        return self


class ActiveSpeed(BaseModel):
    max_parallel_tools: int = Field(ge=1)
    tool_delay: tuple[float, float]
    host_delay: tuple[float, float]
    requests_per_second: float = Field(gt=0)
    shuffle_hosts: bool
    shuffle_ports: bool
    nmap_timing: int = Field(ge=0, le=5)
    masscan_max_rate: int = Field(ge=1)

    @model_validator(mode="after")
    def _validate_delays(self) -> ActiveSpeed:
        _check_delay(self.tool_delay, "active.tool_delay")
        _check_delay(self.host_delay, "active.host_delay")
        return self


class SpeedSettings(BaseModel):
    passive: PassiveSpeed
    active: ActiveSpeed


class Speeds(BaseModel):
    slow: SpeedSettings
    normal: SpeedSettings
    fast: SpeedSettings


class Timeouts(BaseModel):
    default_phase: int = Field(gt=0)
    per_tool_default: int = Field(gt=0)
    subs: int = Field(gt=0)
    dns: int = Field(gt=0)
    live: int = Field(gt=0)
    ports: int = Field(gt=0)
    tech: int = Field(gt=0)
    urls: int = Field(gt=0)
    vulns: int = Field(gt=0)


class ConfidenceConfig(BaseModel):
    high_min_sources: int = Field(ge=1)
    medium_min_sources: int = Field(ge=1)


class WildcardCheck(BaseModel):
    enabled: bool
    probes: int = Field(ge=1)


class InstallConfig(BaseModel):
    dir: str
    verify_checksums: bool


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    workspace_dir: str
    db_path: str
    default_speed: SpeedName
    user_agent: str
    speeds: Speeds
    timeouts: Timeouts
    confidence: ConfidenceConfig
    wildcard_check: WildcardCheck
    tool_versions: dict[str, str] = Field(default_factory=dict)
    install: InstallConfig


class SpeedPreset(BaseModel):
    """Flattened preset handed to the Pacer for one run."""

    name: SpeedName
    passive_max_parallel_tools: int
    passive_tool_delay: tuple[float, float]
    passive_requests_per_second: float
    active_max_parallel_tools: int
    active_tool_delay: tuple[float, float]
    active_host_delay: tuple[float, float]
    active_requests_per_second: float
    shuffle_hosts: bool
    shuffle_ports: bool
    nmap_timing: int
    masscan_max_rate: int


def _check_delay(delay: tuple[float, float], label: str) -> None:
    low, high = delay
    if low < 0 or high < 0:
        raise ValueError(f"{label} must be >= 0")
    if low > high:
        raise ValueError(f"{label} min must be <= max")


def _settings(speeds: Speeds, name: SpeedName) -> SpeedSettings:
    if name == "slow":
        return speeds.slow
    if name == "normal":
        return speeds.normal
    return speeds.fast


def parse_delay(value: str) -> tuple[float, float]:
    """Parse a `MIN-MAX` delay override such as `5-20`."""
    parts = value.strip().split("-")
    if len(parts) != 2 or not all(part.strip() for part in parts):
        raise ConfigError(f"invalid delay {value!r}; expected MIN-MAX, for example 5-20")
    try:
        low, high = float(parts[0]), float(parts[1])
    except ValueError as exc:
        raise ConfigError(f"invalid delay {value!r}; expected numeric MIN-MAX") from exc
    if low < 0 or high < 0 or low > high:
        raise ConfigError(f"invalid delay {value!r}; require 0 <= MIN <= MAX")
    return low, high


def load_config(
    path: Path | str | None = None,
    *,
    speed: str | None = None,
    delay: str | None = None,
) -> AppConfig:
    """Load and validate config.yaml, applying --speed and --delay overrides."""
    config_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config file {config_path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {config_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"config file {config_path} must contain a mapping")
    try:
        config = AppConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"invalid config in {config_path}: {exc}") from exc

    if speed is not None:
        if speed not in _SPEED_NAMES:
            raise ConfigError(f"invalid speed {speed!r}; expected slow, normal or fast")
        config.default_speed = cast(SpeedName, speed)

    if delay is not None:
        low, high = parse_delay(delay)
        settings = _settings(config.speeds, config.default_speed)
        settings.passive.tool_delay = (low, high)
        settings.active.tool_delay = (low, high)

    return config


def resolve_speed(config: AppConfig, name: SpeedName | None = None) -> SpeedPreset:
    """Build the flattened preset for the selected speed."""
    speed_name = name if name is not None else config.default_speed
    settings = _settings(config.speeds, speed_name)
    return SpeedPreset(
        name=speed_name,
        passive_max_parallel_tools=settings.passive.max_parallel_tools,
        passive_tool_delay=settings.passive.tool_delay,
        passive_requests_per_second=settings.passive.requests_per_second,
        active_max_parallel_tools=settings.active.max_parallel_tools,
        active_tool_delay=settings.active.tool_delay,
        active_host_delay=settings.active.host_delay,
        active_requests_per_second=settings.active.requests_per_second,
        shuffle_hosts=settings.active.shuffle_hosts,
        shuffle_ports=settings.active.shuffle_ports,
        nmap_timing=settings.active.nmap_timing,
        masscan_max_rate=settings.active.masscan_max_rate,
    )
