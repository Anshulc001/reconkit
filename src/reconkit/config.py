"""Load config.yaml (docs/03_ARCHITECTURE.md).

There is no speed or delay setting: tools run at their own natural pace
(2026-11-17, docs/MASTER_PLAN.md D3).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from reconkit.errors import ConfigError

DEFAULT_CONFIG_PATH = Path("config.yaml")


def bin_dir(home: Path | None = None) -> Path:
    """The managed binary directory: `~/.reconkit/bin` (docs/10 section 3).

    Hard-coded on purpose: doctor's lookup and every adapter's binary resolution
    check this path first, and the value must not depend on which config file a
    command happened to load. The `install.dir` config key is accepted and
    ignored since the installer was removed (2026-11-17, MASTER_PLAN D4).
    """
    base = Path.home() if home is None else home
    return base / ".reconkit" / "bin"


class _StrictModel(BaseModel):
    """Reject unknown keys so a typo in config.yaml is an error, not a silent no-op."""

    model_config = ConfigDict(extra="forbid")


class Timeouts(_StrictModel):
    default_phase: int = Field(gt=0)
    per_tool_default: int = Field(gt=0)
    subs: int = Field(gt=0)
    dns: int = Field(gt=0)
    live: int = Field(gt=0)
    ports: int = Field(gt=0)
    tech: int = Field(gt=0)
    urls: int = Field(gt=0)
    vulns: int = Field(gt=0)


class ConfidenceConfig(_StrictModel):
    high_min_sources: int = Field(ge=1)
    medium_min_sources: int = Field(ge=1)


class UrlsConfig(_StrictModel):
    """Per-tool runtime bounds for the urls stage (docs/09 sections 4a2b/4a3).

    `urlfinder` gets a floor, an inactivity kill and a ceiling; `hakrawler` and
    `subjs` get a hard cap. The engine passes them down as
    `RunContext.limits`, so an adapter never reads this file itself.
    """

    urlfinder_min_s: int = Field(default=180, gt=0)
    urlfinder_max_s: int = Field(default=1800, gt=0)
    urlfinder_idle_s: int = Field(default=60, gt=0)
    hakrawler_max_s: int = Field(default=120, gt=0)
    subjs_max_s: int = Field(default=60, gt=0)


class UrlProbeConfig(_StrictModel):
    """Bounds for the engine-owned `url_probe` stage (D23, docs/09 section 5).

    `max_urls` bounds one pass (a bigger list is cut and the run says so),
    `batch_size` how many URLs are committed per transaction, `threads` the
    concurrent requests and `timeout_s` the per-request HTTP timeout.
    """

    max_urls: int = Field(default=5000, gt=0)
    batch_size: int = Field(default=200, gt=0)
    threads: int = Field(default=100, gt=0)
    timeout_s: int = Field(default=10, gt=0)


class WildcardCheck(_StrictModel):
    enabled: bool
    probes: int = Field(ge=1)


class InstallConfig(_StrictModel):
    dir: str
    verify_checksums: bool


class Webhook(_StrictModel):
    """Phase 3 notification settings; the URL itself comes from the environment."""

    enabled: bool
    only_on_new: bool


class AppConfig(_StrictModel):
    workspace_dir: str
    db_path: str
    # Saved reports for the interactive mode (docs/02 section 5). Defaulted so a
    # config file written before Part 13 keeps loading unchanged.
    results_dir: str = "results"
    user_agent: str
    timeouts: Timeouts
    # Defaulted so a config file written before this key existed still loads.
    urls: UrlsConfig = Field(default_factory=UrlsConfig)
    url_probe: UrlProbeConfig = Field(default_factory=UrlProbeConfig)
    confidence: ConfidenceConfig
    wildcard_check: WildcardCheck
    install: InstallConfig
    webhook: Webhook | None = None


def load_config(path: Path | str | None = None) -> AppConfig:
    """Load and validate config.yaml."""
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
        return AppConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"invalid config in {config_path}: {exc}") from exc
