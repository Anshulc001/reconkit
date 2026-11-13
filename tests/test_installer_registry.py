"""Install-plan tests: tools.yaml is the only source of install metadata."""

from __future__ import annotations

from pathlib import Path

import pytest

from reconkit.adapters.registry import load_tools
from reconkit.errors import ConfigError
from reconkit.installer.registry import (
    METHODS,
    InstallPlan,
    load_plans,
    plan_for,
    resolve_plan,
)

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools.yaml"


def test_every_tool_gets_a_known_method_and_binary() -> None:
    plans = load_plans()
    assert set(plans) == set(load_tools())
    for plan in plans.values():
        assert plan.method in METHODS
        assert plan.binary


def test_github_release_plan_keeps_its_fallback() -> None:
    plan = plan_for("subfinder")
    assert plan.method == "github_release"
    assert plan.repo == "projectdiscovery/subfinder"
    assert plan.asset_pattern == "{name}_{version}_linux_{arch}.zip"
    assert plan.checksums_pattern == "{name}_{version}_checksums.txt"
    assert plan.asset_name == "subfinder"
    assert plan.version == "latest"
    assert plan.fallback is not None
    assert plan.fallback.method == "go_install"
    assert plan.fallback.package == "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    chain = resolve_plan(plan)
    assert [item.method for item in chain] == ["github_release", "go_install"]


def test_version_args_come_from_version_cmd() -> None:
    assert plan_for("subfinder").version_args == ("-version",)
    assert plan_for("nmap").version_args == ("--version",)
    assert plan_for("crtsh").version_args == ()


def test_requires_and_requires_apt_are_carried() -> None:
    assert plan_for("naabu").requires_apt == ("libpcap-dev",)
    assert plan_for("puredns").requires == ("massdns",)
    assert plan_for("crtsh").requires_apt == ()
    assert plan_for("crtsh").requires == ()


def test_tool_without_install_block_is_a_none_plan() -> None:
    plan = plan_for("httpx_tech")
    assert plan.method == "none"
    assert plan.binary == "httpx"
    assert plan.package is None


def test_version_pin_rewrites_the_go_package() -> None:
    plan = plan_for("subfinder", versions={"subfinder": "v2.6.0"})
    assert plan.version == "v2.6.0"
    assert plan.fallback is not None
    assert plan.fallback.package == "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.0"


def test_version_pin_applies_to_a_plain_go_package(tmp_path: Path) -> None:
    tools = tmp_path / "tools.yaml"
    tools.write_text(
        "tools:\n"
        "  beta: {stage: dns, kind: binary, tier: core, mode: passive, phase: 2,"
        ' binary: beta, install: {method: go_install, package: "example.com/beta/cmd/beta"}}\n',
        encoding="utf-8",
    )
    plan = plan_for("beta", path=tools, versions={"beta": "1.2.3"})
    assert plan.package == "example.com/beta/cmd/beta@1.2.3"


def test_unknown_method_is_a_config_error(tmp_path: Path) -> None:
    tools = tmp_path / "tools.yaml"
    tools.write_text(
        "tools:\n"
        "  beta: {stage: dns, kind: binary, tier: core, mode: passive, phase: 2,"
        " binary: beta, install: {method: curl_pipe_bash}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="unknown install method"):
        load_plans(tools)


def test_go_install_without_a_package_is_a_config_error(tmp_path: Path) -> None:
    tools = tmp_path / "tools.yaml"
    tools.write_text(
        "tools:\n"
        "  beta: {stage: dns, kind: binary, tier: core, mode: passive, phase: 2,"
        " binary: beta, install: {method: go_install}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="needs an install package"):
        load_plans(tools)


def test_github_release_without_a_repo_is_a_config_error(tmp_path: Path) -> None:
    tools = tmp_path / "tools.yaml"
    tools.write_text(
        "tools:\n"
        "  beta: {stage: dns, kind: binary, tier: core, mode: passive, phase: 2,"
        " binary: beta, install: {method: github_release}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="needs an install repo"):
        load_plans(tools)


def test_unknown_tool_is_a_config_error() -> None:
    with pytest.raises(ConfigError, match="unknown tool"):
        plan_for("nope")


def test_resolve_plan_without_fallback_is_one_step() -> None:
    plan = InstallPlan(name="crtsh", method="none", binary="crtsh")
    assert resolve_plan(plan) == (plan,)
