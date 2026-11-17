"""Install-plan tests: tools.yaml is the only source of install metadata."""

from __future__ import annotations

import re
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


def test_massdns_version_command_is_the_package_manager() -> None:
    plan = plan_for("massdns")
    assert plan.version_command == "dpkg-query"
    assert plan.version_args == ("-W", "-f=${Version}", "massdns")


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


def test_version_regex_is_parsed_from_the_registry() -> None:
    """12j: the pattern is per tool, from tools.yaml, and absent for the rest."""
    plans = load_plans()
    assert plans["katana"].version_regex == r"Current version: (v?\d+\.\d+\.\d+)"
    assert plans["nuclei"].version_regex == r"Nuclei Engine Version: (v?\d+\.\d+\.\d+)"
    assert plans["assetfinder"].version_regex is None


@pytest.mark.parametrize(
    ("tool", "banner", "expected"),
    [
        # Real banners captured on this box on 2026-11-17. The PD six print to
        # stderr, with ANSI around the [INF] tag; wafw00f uses stdout and wraps
        # the value itself.
        ("chaos", "[\x1b[34mINF\x1b[0m] Current Version: 0.5.2", "0.5.2"),
        ("dnsx", "[\x1b[34mINF\x1b[0m] Current Version: 1.3.1", "1.3.1"),
        ("httpx", "[\x1b[34mINF\x1b[0m] Current Version: v1.12.0", "v1.12.0"),
        ("tlsx", "[\x1b[34mINF\x1b[0m] Current version: v1.4.0", "v1.4.0"),
        ("naabu", "[\x1b[34mINF\x1b[0m] Current Version: 2.7.0", "2.7.0"),
        ("cdncheck", "[\x1b[34mINF\x1b[0m] Current version: v1.4.0", "v1.4.0"),
        (
            "wafw00f",
            "[+] The version of WAFW00F you have is \x1b[1;94mv2.4.2\x1b[0m",
            "v2.4.2",
        ),
    ],
)
def test_the_seven_version_patterns_extract_their_real_banner(
    tool: str, banner: str, expected: str
) -> None:
    """2026-11-17: the regex must yield the version, not the ASCII art."""
    pattern = plan_for(tool).version_regex
    assert pattern is not None
    match = re.search(pattern, banner)
    assert match is not None, f"{tool}: {pattern!r} did not match {banner!r}"
    assert match.group(1) == expected


def test_a_broken_version_regex_is_a_config_error(tmp_path: Path) -> None:
    """A pattern that cannot compile fails at load, not inside doctor."""
    tools = tmp_path / "tools.yaml"
    tools.write_text(
        "tools:\n"
        "  beta: {stage: dns, kind: binary, tier: core, mode: passive, phase: 2,"
        " binary: beta, version_regex: '(unclosed',"
        " install: {method: apt, package: beta}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="version_regex"):
        load_plans(tools)


def test_version_regex_survives_the_plan_copy(tmp_path: Path) -> None:
    """`load_plans` rebuilds each plan; the pattern must not be dropped there."""
    tools = tmp_path / "tools.yaml"
    tools.write_text(
        "tools:\n"
        "  beta: {stage: dns, kind: binary, tier: core, mode: passive, phase: 2,"
        " binary: beta, version_cmd: [beta, -version], version_regex: 'v\\d+',"
        " install: {method: apt, package: beta}}\n",
        encoding="utf-8",
    )
    assert load_plans(tools)["beta"].version_regex == r"v\d+"


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


def test_member_and_checksum_override_are_parsed_from_the_registry() -> None:
    chaos = plan_for("chaos")
    assert chaos.member == "chaos-client"
    assert chaos.verify_checksums is None
    assert plan_for("findomain").verify_checksums is False
    assert plan_for("dnsreaper").method == "none"
    assert plan_for("puredns").version_args == ("--version",)


def test_a_duplicate_plan_copy_keeps_the_override_fields(tmp_path: Path) -> None:
    path = tmp_path / "tools.yaml"
    path.write_text(
        "version: 1\ntools:\n  echo: {stage: subs, kind: binary, tier: core, mode: passive,\n"
        "         install: {method: github_release, repo: a/b, asset_pattern: x.zip,\n"
        "                   member: renamed, verify_checksums: false}}\n",
        encoding="utf-8",
    )
    plan = load_plans(path)["echo"]
    assert plan.member == "renamed"
    assert plan.verify_checksums is False
