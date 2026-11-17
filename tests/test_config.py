"""Tests for config loading. Speed and delay settings were removed on 2026-11-17."""

from __future__ import annotations

from pathlib import Path

import pytest

from reconkit.config import AppConfig, load_config
from reconkit.errors import ConfigError

CONFIG = Path(__file__).resolve().parents[1] / "config.yaml"


def test_load_real_config() -> None:
    config = load_config(CONFIG)
    assert config.timeouts.ports > 0
    assert config.confidence.high_min_sources == 3
    assert config.results_dir
    assert config.user_agent


def test_config_has_no_speed_fields() -> None:
    """Speed control was removed (2026-11-17, MASTER_PLAN D3)."""
    config: AppConfig = load_config(CONFIG)
    assert not hasattr(config, "default_speed")
    assert not hasattr(config, "speeds")


def test_a_speeds_block_is_rejected(tmp_path: Path) -> None:
    """The removed keys are unknown now, and unknown keys are a config error."""
    text = CONFIG.read_text(encoding="utf-8").replace(
        "timeouts:", "default_speed: slow\nspeeds: {}\ntimeouts:", 1
    )
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_speed_and_delay_arguments_no_longer_exist() -> None:
    with pytest.raises(TypeError):
        load_config(CONFIG, **{"speed": "fast"})
    with pytest.raises(TypeError):
        load_config(CONFIG, **{"delay": "5-20"})


def test_webhook_block_loads() -> None:
    config = load_config(CONFIG)
    assert config.webhook is not None
    assert config.webhook.enabled is False
    assert config.webhook.only_on_new is True


def test_unknown_top_level_key_is_rejected(tmp_path: Path) -> None:
    # Append rather than string-replace: the real file's `tool_versions` value is
    # no longer the literal `{}` (2026-11-17 rustscan pin), and a test that
    # depends on one line's spelling silently stops testing the schema.
    text = CONFIG.read_text(encoding="utf-8") + "tool_delays: [1, 2]\n"
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_unknown_nested_key_is_rejected(tmp_path: Path) -> None:
    text = CONFIG.read_text(encoding="utf-8").replace(
        "high_min_sources: 3", "high_min_sources: 3\ntypo_key: 1"
    )
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_missing_config_file() -> None:
    with pytest.raises(ConfigError):
        load_config(CONFIG.parent / "missing-config.yaml")
