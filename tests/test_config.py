"""Tests for config loading and speed presets."""

from __future__ import annotations

from pathlib import Path

import pytest

from reconkit.config import load_config, resolve_speed
from reconkit.errors import ConfigError

CONFIG = Path(__file__).resolve().parents[1] / "config.yaml"


def test_load_real_config() -> None:
    config = load_config(CONFIG)
    assert config.default_speed == "slow"
    assert config.timeouts.ports > 0
    assert config.confidence.high_min_sources == 3
    preset = resolve_speed(config)
    assert preset.name == "slow"
    assert preset.passive_max_parallel_tools == 1
    assert preset.passive_tool_delay == (5.0, 30.0)


def test_speed_override() -> None:
    config = load_config(CONFIG, speed="fast")
    assert config.default_speed == "fast"
    preset = resolve_speed(config)
    assert preset.passive_max_parallel_tools == 99
    assert preset.shuffle_hosts is False


def test_invalid_speed_name() -> None:
    with pytest.raises(ConfigError):
        load_config(CONFIG, speed="turbo")


def test_delay_override_applies_to_active_and_passive() -> None:
    config = load_config(CONFIG, delay="7-9")
    preset = resolve_speed(config)
    assert preset.passive_tool_delay == (7.0, 9.0)
    assert preset.active_tool_delay == (7.0, 9.0)


@pytest.mark.parametrize("delay", ["9-5", "5", "a-b", "-1-5"])
def test_invalid_delay_override(delay: str) -> None:
    with pytest.raises(ConfigError):
        load_config(CONFIG, delay=delay)


def test_delay_range_in_file_is_rejected(tmp_path: Path) -> None:
    text = CONFIG.read_text(encoding="utf-8").replace("tool_delay: [5, 30]", "tool_delay: [30, 5]")
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_webhook_block_loads() -> None:
    config = load_config(CONFIG)
    assert config.webhook is not None
    assert config.webhook.enabled is False
    assert config.webhook.only_on_new is True


def test_unknown_top_level_key_is_rejected(tmp_path: Path) -> None:
    text = CONFIG.read_text(encoding="utf-8").replace(
        "default_speed: slow", "default_speed: slow\ntool_delays: [1, 2]"
    )
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
