"""Tests for config loading. Speed and delay settings were removed on 2026-11-17."""

from __future__ import annotations

from pathlib import Path

import pytest

from reconkit.config import AppConfig, bin_dir, load_config
from reconkit.errors import ConfigError

CONFIG = Path(__file__).resolve().parents[1] / "config.yaml"


def test_load_real_config() -> None:
    config = load_config(CONFIG)
    assert config.timeouts.ports > 0
    assert config.confidence.high_min_sources == 3
    assert config.results_dir
    assert config.user_agent


def test_runtime_idle_windows_load_from_the_real_config() -> None:
    """D52: `runtime_idle:` is the only runtime bound, and it holds windows."""
    config = load_config(CONFIG)
    assert config.runtime_idle["crawler"].idle == 60
    assert config.runtime_idle["scanner"].idle == 120
    assert config.runtime_idle["archive"].idle == 180
    assert config.runtime_idle["api"].idle == 60


@pytest.mark.parametrize("shape", ["bare", "nested"])
def test_a_runtime_idle_class_accepts_bare_or_nested_seconds(tmp_path: Path, shape: str) -> None:
    """`crawler: 60` and `crawler: {idle: 60}` are the same class (D52)."""
    import yaml

    raw = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    raw["runtime_idle"] = {"crawler": 45} if shape == "bare" else {"crawler": {"idle": 45}}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    assert load_config(path).runtime_idle["crawler"].idle == 45


def test_a_config_without_timeouts_url_probe_still_loads(tmp_path: Path) -> None:
    """D26 added the key; a config.yaml written before it must keep working."""
    import yaml

    legacy = tmp_path / "legacy.yaml"
    raw = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    raw["timeouts"].pop("url_probe")
    legacy.write_text(yaml.safe_dump(raw), encoding="utf-8")
    assert load_config(legacy).timeouts.url_probe == 600


def test_managed_bin_dir_has_one_source_of_truth(tmp_path: Path) -> None:
    """Moved from tests/test_install_cli.py:373 when `installer/` was deleted.

    `adapters.base.managed_bin_dir` (the first place a binary lookup looks) and
    `config.bin_dir` must stay the same path, and that path is `~/.reconkit/bin`.
    """
    from reconkit.adapters.base import managed_bin_dir

    assert managed_bin_dir() == bin_dir()
    assert managed_bin_dir() == Path.home() / ".reconkit" / "bin"
    assert bin_dir(tmp_path) == tmp_path / ".reconkit" / "bin"


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


def test_removed_install_block_is_rejected(tmp_path: Path) -> None:
    """D87: the old ignored `install:` block is now an unknown key."""
    text = CONFIG.read_text(encoding="utf-8") + (
        'install:\n  dir: "~/.reconkit/bin"\n  verify_checksums: true\n'
    )
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_unknown_top_level_key_is_rejected(tmp_path: Path) -> None:
    # Append rather than string-replace, so the test does not depend on one line's
    # spelling in the real file: a replace silently stops testing the schema.
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


def test_config_without_runtime_idle_still_loads(tmp_path: Path) -> None:
    """D52: a config.yaml written before `runtime_idle:` keeps working."""
    import yaml

    from reconkit.config import DEFAULT_RUNTIME_IDLE

    legacy = tmp_path / "legacy.yaml"
    raw = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    raw.pop("runtime_idle")
    legacy.write_text(yaml.safe_dump(raw), encoding="utf-8")
    loaded = load_config(legacy)
    assert {name: cfg.idle for name, cfg in loaded.runtime_idle.items()} == {
        name: cfg.idle for name, cfg in DEFAULT_RUNTIME_IDLE.items()
    }
