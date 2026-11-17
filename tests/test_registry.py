"""Registry tests: tools.yaml is the only source of tool metadata."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from reconkit.adapters.certspotter import CertspotterAdapter
from reconkit.adapters.crtsh import CrtshAdapter
from reconkit.adapters.hackertarget import HackertargetAdapter
from reconkit.adapters.otx import OtxAdapter
from reconkit.adapters.registry import (
    get_adapter,
    get_spec,
    load_system_packages,
    load_tools,
)
from reconkit.errors import ConfigError
from reconkit.models import Mode, Stage, Tier

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools.yaml"


def test_get_adapter_returns_the_registered_class() -> None:
    assert get_adapter("crtsh") is CrtshAdapter
    assert get_adapter("certspotter") is CertspotterAdapter
    assert get_adapter("otx") is OtxAdapter
    assert get_adapter("hackertarget") is HackertargetAdapter


def test_spec_exposes_stage_tier_mode_and_kind() -> None:
    spec = get_spec("crtsh")
    assert spec.stage is Stage.SUBS
    assert spec.tier is Tier.CORE
    assert spec.mode is Mode.PASSIVE
    assert spec.kind == "http"
    assert spec.phase == 2


def test_no_rate_flag_survives_in_tools_yaml() -> None:
    """2026-11-17: the pacer is gone, so the per-tool rate flag field is gone too."""
    data = yaml.safe_load(TOOLS.read_text(encoding="utf-8"))
    offenders = [name for name, entry in data["tools"].items() if "rate_flag" in entry]
    assert offenders == []
    assert not hasattr(get_spec("subfinder"), "rate_flag")


def test_keys_are_parsed() -> None:
    certspotter = get_spec("certspotter").keys
    assert [key.env for key in certspotter] == ["CERTSPOTTER_API_KEY"]
    assert certspotter[0].url == "https://sslmate.com/ct_search_api"
    assert "authenticates" in certspotter[0].adds
    assert "100 queries/hour" not in certspotter[0].adds
    assert [key.env for key in get_spec("otx").keys] == ["OTX_API_KEY"]
    assert [key.env for key in get_spec("assetfinder").keys] == ["VT_API_KEY"]
    assert [key.env for key in get_spec("chaos").keys] == ["PDCP_API_KEY"]
    assert [key.env for key in get_spec("github_subdomains").keys] == ["GITHUB_TOKEN"]
    assert [key.env for key in get_spec("urlscan").keys] == ["URLSCAN_API_KEY"]


def test_tools_yaml_has_no_legacy_needs_key() -> None:
    """Regression: PIT-19 needs_key stays removed; keys is the only source of truth."""
    data = yaml.safe_load(TOOLS.read_text(encoding="utf-8"))
    offenders = [name for name, entry in data["tools"].items() if "needs_key" in entry]
    assert offenders == [], f"needs_key is gone; move these env names to keys: {offenders}"


def test_legacy_needs_key_is_a_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "tools.yaml"
    bad.write_text(
        "tools:\n  weird: {stage: subs, kind: http, tier: core, mode: passive,"
        " needs_key: [SOME_KEY]}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="needs_key"):
        load_tools(bad)


def test_tool_without_keys_has_no_entries() -> None:
    assert get_spec("crtsh").keys == ()


@pytest.mark.parametrize(
    ("entry", "match"),
    [
        ("keys: [{env: lower_case, url: 'https://x.example', adds: a}]", "must match"),
        ("keys: [{env: OK_KEY, url: 'http://x.example', adds: a}]", "must be https"),
        ("keys: [{env: OK_KEY, url: 'https://' , adds: a}]", "must be https"),
        ("keys: [{env: OK_KEY, url: 'https://x.example'}]", "missing 'adds'"),
        ("keys: notalist", "keys must be a list"),
        ("keys: [nope]", "must be a mapping"),
    ],
)
def test_malformed_keys_raise_config_error(tmp_path: Path, entry: str, match: str) -> None:
    bad = tmp_path / "tools.yaml"
    bad.write_text(
        "tools:\n  weird: {stage: subs, kind: http, tier: core, mode: passive, " + entry + "}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match=match):
        load_tools(bad)


def test_every_key_env_is_in_env_example() -> None:
    example = (REPO / ".env.example").read_text(encoding="utf-8")
    names = {
        line.split("=", 1)[0].strip()
        for line in example.splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    }
    for spec in load_tools().values():
        for key in spec.keys:
            assert key.env in names, f"{key.env} missing from .env.example"


def test_unknown_tool_raises_config_error() -> None:
    with pytest.raises(ConfigError, match="unknown tool 'nope'"):
        get_adapter("nope")
    with pytest.raises(ConfigError, match="unknown tool 'nope'"):
        get_spec("nope")


def test_listed_tool_without_adapter_raises_config_error() -> None:
    # `urlscan` gained an adapter in wave 7; `dnsreaper` stays unadapted by D15.
    with pytest.raises(ConfigError, match="no adapter yet"):
        get_adapter("dnsreaper")


def test_invalid_yaml_is_a_config_error(tmp_path: Path) -> None:
    broken = tmp_path / "tools.yaml"
    broken.write_text("tools: [", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_tools(broken)


def test_missing_tools_mapping_is_a_config_error(tmp_path: Path) -> None:
    empty = tmp_path / "tools.yaml"
    empty.write_text("version: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="no tools mapping"):
        load_tools(empty)


def test_missing_required_field_is_a_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "tools.yaml"
    bad.write_text("tools:\n  weird: {stage: subs, kind: http}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="missing 'tier'"):
        load_tools(bad)


def test_bad_kind_is_a_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "tools.yaml"
    bad.write_text(
        "tools:\n  weird: {stage: subs, kind: magic, tier: core, mode: passive}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="invalid kind"):
        load_tools(bad)


def test_requires_apt_comes_from_tools_yaml() -> None:
    assert get_spec("naabu").requires_apt == ("libpcap-dev",)
    assert get_spec("crtsh").requires_apt == ()
    assert get_spec("nmap").requires_apt == ()


def test_load_system_packages_returns_the_top_level_list() -> None:
    data = yaml.safe_load(TOOLS.read_text(encoding="utf-8"))
    assert load_system_packages() == tuple(data["system_packages"])
    assert "jq" in load_system_packages()
    assert "dnsutils" not in load_system_packages()


def test_invalid_requires_apt_is_a_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "tools.yaml"
    bad.write_text(
        "tools:\n  weird: {stage: subs, kind: binary, tier: core, mode: passive,"
        " requires_apt: libpcap-dev}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_tools(bad)


def test_invalid_system_packages_is_a_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "tools.yaml"
    bad.write_text("system_packages: jq\ntools: {}\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_system_packages(bad)
