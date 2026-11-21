"""Load config.yaml (docs/03_ARCHITECTURE.md).

There is no speed or delay setting: tools run at their own natural pace
(2026-11-17, docs/MASTER_PLAN.md D3).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

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
    url_probe: int = Field(default=600, gt=0)
    vulns: int = Field(gt=0)


class ConfidenceConfig(_StrictModel):
    high_min_sources: int = Field(ge=1)
    medium_min_sources: int = Field(ge=1)


class RuntimeClassConfig(_StrictModel):
    """One runtime class from `runtime_idle:` (D52, docs/09 section 4a2b).

    A class is a shape of tool, not a tool, and it now carries **one** number:
    how long the tool may stay silent before the engine assumes it is stuck.
    There is no runtime cap and no floor - a tool that keeps producing runs
    until it exits or the stage budget fires. A tool joins a class with one
    `class:` field in `tools.yaml`, and a single tool may override the window
    with `idle_s:` in its own row.
    """

    idle: float = Field(gt=0)

    @model_validator(mode="before")
    @classmethod
    def _bare_seconds(cls, value: object) -> object:
        """`crawler: 60` is the same class as `crawler: {idle: 60}` (D52).

        The window is the only field a class has, so a bare number in
        config.yaml is unambiguous and is what the file uses.
        """
        if isinstance(value, int | float) and not isinstance(value, bool):
            return {"idle": value}
        return value


# D52: generous windows, because the idle clock is "how long silent before we
# assume it is stuck", not "how long may it run". `archive` is the largest on
# purpose: gau and urlfinder compute for a while and then print in one block.
DEFAULT_RUNTIME_IDLE: dict[str, RuntimeClassConfig] = {
    "crawler": RuntimeClassConfig(idle=60),
    "scanner": RuntimeClassConfig(idle=120),
    "api": RuntimeClassConfig(idle=60),
    "archive": RuntimeClassConfig(idle=180),
}


class UrlProbeConfig(_StrictModel):
    """Bounds for the engine-owned `url_probe` stage (D23, docs/09 section 5).

    `max_urls` caps one pass; `0` means no cap (the default). When set, a bigger
    list is cut and the run says so. `batch_size` is how many finished results
    are committed per transaction (not a concurrency barrier), `threads` the
    concurrent requests and `timeout_s` the per-request HTTP timeout.
    """

    max_urls: int = Field(default=0, ge=0)
    batch_size: int = Field(default=200, gt=0)
    threads: int = Field(default=100, gt=0)
    timeout_s: int = Field(default=10, gt=0)


class ReportConfig(_StrictModel):
    """What one saved report directory contains (D62/D71, docs/02 section 5).

    `urls_max` caps the `urls_by_host` block across the whole report, not per
    host; `0` (the default since D71) means no cap. A cut is always stated in
    the report (`urls_shown` / `urls_truncated`). `emit_lists` writes the five
    top-level list files. `per_host_folders` writes `hosts/<hostname>/` for
    every host with at least one stored URL.
    """

    urls_max: int = Field(default=0, ge=0)
    per_host_folders: bool = True
    emit_lists: bool = True
    # 2026-11-21 (D107): `report.pdf` generation beside report.txt/report.json.
    # Defaulted so a config written before this flag keeps producing the PDF.
    pdf: bool = True
    # D72: extra query parameters that rank a URL down. The built-in list in
    # `ui.NOISE_PARAMS` always applies; this one only adds to it.
    noise_params: list[str] = Field(default_factory=list)


class LoggingConfig(_StrictModel):
    """Per-scan logging (D107, docs/02 section 5).

    `enabled` turns the persistent file on or off, `console` decides whether the
    milestone lines are also printed, and `level` is one of DEBUG, INFO,
    SUCCESS, WARNING or ERROR. An unknown level falls back to INFO in
    `reconkit.logs`; the value is never a secret.
    """

    enabled: bool = True
    console: bool = True
    level: str = "INFO"


class WildcardCheck(_StrictModel):
    enabled: bool
    probes: int = Field(ge=1)


class Webhook(_StrictModel):
    """Phase 3 notification settings; the URL itself comes from the environment."""

    enabled: bool
    only_on_new: bool


class AppConfig(_StrictModel):
    workspace_dir: str
    db_path: str
    # Saved reports (docs/02 section 5). Defaulted so a config file written
    # before Part 13 keeps loading unchanged.
    results_dir: str = "results"
    user_agent: str
    timeouts: Timeouts
    # D52: per-class idle windows. Defaulted, so a config written before this
    # block existed keeps loading with today's numbers.
    runtime_idle: dict[str, RuntimeClassConfig] = Field(
        default_factory=lambda: dict(DEFAULT_RUNTIME_IDLE)
    )
    url_probe: UrlProbeConfig = Field(default_factory=UrlProbeConfig)
    # D62: defaulted, so a config written before this block existed loads with
    # the documented 200-URL report cap.
    report: ReportConfig = Field(default_factory=ReportConfig)
    # D107: defaulted, so a config written before this block existed still logs.
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    confidence: ConfidenceConfig
    wildcard_check: WildcardCheck
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
