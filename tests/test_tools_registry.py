"""Tool-registry tests: tools.yaml is the only source of tool metadata.

Moved from `tests/test_installer_registry.py` on 2026-11-17 when `installer/`
was deleted. The 22 tests here are the version-regex/probe set (b6697ff's
7 + 4 + 5) plus the version_cmd, massdns and requires_apt checks; each now
reads a `ToolSpec` instead of an `InstallPlan`. The 12 plan/method tests were
re-expressed as `source:` validation tests further down.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from reconkit.adapters.registry import get_spec, load_tools
from reconkit.core.runner import ExecResult
from reconkit.core.toolcheck import installed_copy, installed_version
from reconkit.errors import ConfigError

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools.yaml"


def test_version_cmd_comes_from_the_registry() -> None:
    specs = load_tools()
    assert specs["subfinder"].version_cmd == ["subfinder", "-version"]
    assert specs["nmap"].version_cmd == ["nmap", "--version"]
    assert specs["crtsh"].version_cmd is None


def test_massdns_version_command_is_the_package_manager() -> None:
    assert load_tools()["massdns"].version_cmd == [
        "dpkg-query",
        "-W",
        "-f=${Version}",
        "massdns",
    ]


def test_requires_apt_is_carried() -> None:
    specs = load_tools()
    assert specs["naabu"].requires_apt == ("libpcap-dev",)
    assert specs["crtsh"].requires_apt == ()


def test_version_regex_is_parsed_from_the_registry() -> None:
    """12j: the pattern is per tool, from tools.yaml, and absent for the rest."""
    specs = load_tools()
    assert specs["katana"].version_regex == r"Current version: (v?\d+\.\d+\.\d+)"
    assert specs["nuclei"].version_regex == r"Nuclei Engine Version: (v?\d+\.\d+\.\d+)"
    assert specs["assetfinder"].version_regex is None


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
    pattern = load_tools()[tool].version_regex
    assert pattern is not None
    match = re.search(pattern, banner)
    assert match is not None, f"{tool}: {pattern!r} did not match {banner!r}"
    assert match.group(1) == expected


@pytest.mark.parametrize(
    ("tool", "output", "expected"),
    [
        # Real probe output, 2026-11-17. smap and gospider print a multi-line
        # body after the version, so an anchored `^...$` pattern does not match
        # (found the hard way: doctor fell back to the first line).
        (
            "smap",
            "Smap 1.0.0-beta\nUsage: smap <targets here>\n  -i string\n",
            "1.0.0-beta",
        ),
        ("gospider", "Version: v1.1.6\n\n\nExamples:\n  gospider -s URL\n", "v1.1.6"),
        ("subjs", "subjs version: 1.0.1\n", "1.0.1"),
        ("urlfinder", "[\x1b[34mINF\x1b[0m] Current Version: v0.0.3\n", "v0.0.3"),
    ],
)
def test_the_four_probed_tools_extract_their_real_output(
    tool: str, output: str, expected: str
) -> None:
    """2026-11-17: these four report a version, so their identity probe reads it."""
    pattern = load_tools()[tool].version_regex
    assert pattern is not None
    match = re.search(pattern, output)
    assert match is not None, f"{tool}: {pattern!r} did not match {output!r}"
    assert match.group(1) == expected


@pytest.mark.parametrize(
    "tool", ["github_subdomains", "webanalyze", "waybackurls", "unfurl", "httprobe"]
)
def test_tools_without_a_version_flag_have_no_probe(tool: str) -> None:
    """Their real `-version` prints Go flag usage, so they stay presence-only.

    docs/10 documents this as intended; a `version_cmd` here would match
    `Usage of ...:` and prove nothing about identity (what httprobe used to do).
    """
    spec = load_tools()[tool]
    assert spec.version_cmd is None
    assert spec.version_regex is None


def test_a_broken_version_regex_is_a_config_error(tmp_path: Path) -> None:
    """A pattern that cannot compile fails at load, not inside doctor."""
    tools = tmp_path / "tools.yaml"
    tools.write_text(
        "tools:\n"
        "  beta: {stage: dns, kind: binary, tier: core, mode: passive, phase: 2,"
        " binary: beta, version_regex: '(unclosed', source: 'apt: beta'}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="version_regex"):
        load_tools(tools)


def test_every_binary_tool_has_a_non_empty_source() -> None:
    """Replaces `test_every_tool_gets_a_known_method_and_binary`.

    Old: every tool had an install method in the known set and a binary. New:
    reconkit installs nothing, so what a user needs is the source hint. Every
    binary tool must carry one; an HTTP/Python adapter has no tool to fetch.
    """
    specs = load_tools()
    assert len(specs) == 48
    for spec in specs.values():
        assert spec.binary or spec.kind != "binary", f"{spec.name}: binary tool with no binary"
        if spec.kind == "binary":
            assert spec.source, f"{spec.name}: binary tool with no source"
            assert spec.source.strip() == spec.source
        else:
            assert spec.source is None, f"{spec.name}: non-binary tool carries a source"


def test_a_release_source_names_its_repository() -> None:
    """Replaces `test_github_release_plan_keeps_its_fallback`.

    Old: a github_release plan carried its go_install fallback. New: the source
    string names the same repository, which is all a reader needs now.
    """
    specs = load_tools()
    assert "github.com/projectdiscovery/subfinder" in (specs["subfinder"].source or "")
    assert "github.com/projectdiscovery/nuclei" in (specs["nuclei"].source or "")
    assert "github.com/projectdiscovery/chaos-client" in (specs["chaos"].source or "")

    # These two used to cite their release pages. Kali packages both, so the
    # registry now installs them from the signed repository instead
    # (2026-11-18); the release page is the fallback named in `notes:`.
    assert specs["findomain"].source == "apt: findomain"
    assert specs["rustscan"].source == "apt: rustscan"


def test_a_shared_binary_tool_still_has_a_source() -> None:
    """Replaces `test_tool_without_install_block_is_a_none_plan`.

    `httpx_tech` had no install block, so it was a `none` plan. It is still a
    binary row that reuses `httpx`, and its source says so.
    """
    spec = load_tools()["httpx_tech"]
    assert spec.binary == "httpx"
    assert spec.source is not None
    assert "same binary as httpx" in spec.source
    # Changed 2026-11-17 (V-UNEXPECTED item 1): this row used to be
    # presence-only (`version_cmd is None`), which counted Python's httpx as
    # installed. It now carries its own probe; the regex requirement is pinned
    # by test_projectdiscovery_httpx_is_httpx_tech and by its Python twin.
    assert spec.version_cmd == ["httpx", "-version"]
    assert spec.version_regex is not None


def test_go_sources_are_pinned_to_nothing() -> None:
    """Replaces `test_version_pin_rewrites_the_go_package`.

    Old: a `tool_versions` pin rewrote `@latest` to `@<pin>` in a plan. New:
    nothing rewrites a source, so every Go source keeps whatever it names.
    """
    specs = load_tools()
    assert specs["assetfinder"].source == "go install github.com/tomnomnom/assetfinder@latest"
    assert specs["subfinder"].source is not None
    assert "@latest" in specs["subfinder"].source


def test_tools_yaml_carries_no_version_pin_field() -> None:
    """Replaces `test_version_pin_applies_to_a_plain_go_package`.

    A pin has no home anywhere: reconkit installs and pins nothing (2026-11-17),
    so the registry itself must not grow a `version:` or `tool_versions` key that
    looks like one.
    """
    import yaml

    data = yaml.safe_load(TOOLS.read_text(encoding="utf-8"))
    assert "tool_versions" not in data
    for name, entry in data["tools"].items():
        assert "version" not in entry, f"{name}: tools.yaml carries a version pin"


def test_an_empty_source_is_a_config_error(tmp_path: Path) -> None:
    """Replaces `test_unknown_method_is_a_config_error`.

    Old: an unknown install method raised. New: an install method no longer
    exists, so what can be malformed is the source hint itself.
    """
    tools = tmp_path / "tools.yaml"
    tools.write_text(
        "tools:\n"
        "  beta: {stage: dns, kind: binary, tier: core, mode: passive, phase: 2,"
        " binary: beta, source: ''}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="source"):
        load_tools(tools)


def test_a_non_string_source_is_a_config_error(tmp_path: Path) -> None:
    """Replaces `test_go_install_without_a_package_is_a_config_error`."""
    tools = tmp_path / "tools.yaml"
    tools.write_text(
        "tools:\n"
        "  beta: {stage: dns, kind: binary, tier: core, mode: passive, phase: 2,"
        " binary: beta, source: 3}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="source"):
        load_tools(tools)


def test_a_list_source_is_a_config_error(tmp_path: Path) -> None:
    """Replaces `test_github_release_without_a_repo_is_a_config_error`."""
    tools = tmp_path / "tools.yaml"
    tools.write_text(
        "tools:\n"
        "  beta: {stage: dns, kind: binary, tier: core, mode: passive, phase: 2,"
        " binary: beta, source: [a, b]}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="source"):
        load_tools(tools)


def test_an_unknown_tool_is_a_config_error() -> None:
    """Kept from the old file: an unknown name is still a ConfigError."""
    with pytest.raises(ConfigError, match="unknown tool"):
        get_spec("nope")


def test_a_builtin_adapter_has_no_source() -> None:
    """Replaces `test_resolve_plan_without_fallback_is_one_step`.

    A pure-Python or HTTP adapter has nothing to install, which is now expressed
    as an absent source rather than a one-step `none` plan.
    """
    specs = load_tools()
    for name in ("crtsh", "dnspython", "pyprobe", "pyscan"):
        assert specs[name].source is None
        assert specs[name].binary is None
        assert specs[name].version_cmd is None


def test_the_source_notes_are_preserved() -> None:
    """Replaces `test_member_and_checksum_override_are_parsed_from_the_registry`.

    The facts that used to live in plan fields (archive member, missing
    checksums, `--version` spelling) now live in the source note.
    """
    specs = load_tools()
    assert "chaos-client" in (specs["chaos"].source or "")
    assert "punk-security/dnsReaper" in (specs["dnsreaper"].source or "")
    assert "no PyPI package" in (specs["dnsreaper"].source or "")
    assert specs["puredns"].version_cmd == ["puredns", "--version"]


def test_a_source_survives_registry_loading(tmp_path: Path) -> None:
    """Replaces `test_a_duplicate_plan_copy_keeps_the_override_fields`."""
    path = tmp_path / "tools.yaml"
    path.write_text(
        "version: 1\ntools:\n  echo: {stage: subs, kind: binary, tier: core, mode: passive,\n"
        '         binary: echo, source: "apt: echo (provides echo)"}\n',
        encoding="utf-8",
    )
    assert load_tools(path)["echo"].source == "apt: echo (provides echo)"


def test_version_regex_survives_registry_loading(tmp_path: Path) -> None:
    """Changed from `test_version_regex_survives_the_plan_copy`.

    Old: asserted `load_plans` (which rebuilt each plan) kept the pattern. New:
    the registry copies the entry into a ToolSpec in one pass, so the test pins
    that the pattern reaches the ToolSpec intact.
    """
    tools = tmp_path / "tools.yaml"
    tools.write_text(
        "tools:\n"
        "  beta: {stage: dns, kind: binary, tier: core, mode: passive, phase: 2,"
        " binary: beta, version_cmd: [beta, -version], version_regex: 'v\\d+',"
        " source: 'apt: beta'}\n",
        encoding="utf-8",
    )
    assert load_tools(tools)["beta"].version_regex == r"v\d+"


def _probe(tmp_path: Path, tool: str, binary: str, outcome: ExecResult) -> str | None:
    """Run `installed_version` against a temp copy, with a fake probe result."""
    (tmp_path / binary).write_text("", encoding="utf-8")
    spec = load_tools()[tool]
    return installed_version(spec, tmp_path, runner=lambda argv, **kwargs: outcome)


def test_installed_copy_finds_a_binary_outside_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A tool installed by `go install` must be found without a PATH entry.

    `~/go/bin` and `~/.local/bin` are common on a real machine and often absent
    from a minimal PATH (sudo, cron); resolution must not depend on the shell
    that started reconkit (docs/10 section 3).
    """
    home = tmp_path / "home"
    target = home / "go" / "bin" / "findomain"
    target.parent.mkdir(parents=True)
    target.write_text("", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("GOPATH", raising=False)
    assert installed_copy(load_tools()["findomain"], tmp_path / "managed") == target


def test_the_python_httpx_cli_is_not_httpx_tech(tmp_path: Path) -> None:
    """V-UNEXPECTED item 1: the namesake must not count as installed.

    Real output of the Python `httpx` console script (2026-11-17): no
    `-version` flag, no ProjectDiscovery banner, exit 1. Before the regex-miss
    rule this text fell through to the first line and doctor said `yes`.
    """
    python_httpx = ExecResult(
        returncode=1,
        stdout="",
        stderr=(
            "The httpx command line client could not run because the required "
            "dependencies were not installed.\n"
            "Make sure you've installed everything with: pip install 'httpx[cli]'\n"
        ),
    )
    assert _probe(tmp_path, "httpx_tech", "httpx", python_httpx) is None


def test_projectdiscovery_httpx_is_httpx_tech(tmp_path: Path) -> None:
    """The real banner (stderr, ANSI around [INF]) yields the captured group."""
    pd_httpx = ExecResult(
        returncode=0,
        stdout="",
        stderr="\n[\x1b[34mINF\x1b[0m] Current Version: v1.12.0\n",
    )
    assert _probe(tmp_path, "httpx_tech", "httpx", pd_httpx) == "1.12.0"


def test_a_regex_miss_means_not_installed_for_any_tool(tmp_path: Path) -> None:
    """The rule is general, not special-cased to httpx_tech (chaos here)."""
    namesake = ExecResult(returncode=0, stdout="chaos 0.5.2\n", stderr="")
    assert _probe(tmp_path, "chaos", "chaos", namesake) is None


# ------------------------------------------------- exploitation flag (2026-11-17)

EXPLOITATION_TOOLS = {"sqlmap", "dalfox", "crlfuzz"}


def test_the_three_exploitation_tools_are_marked_and_intrusive() -> None:
    """docs/09: `exploitation: true` is what keeps a tool out of automatic runs."""
    specs = load_tools()
    for name in EXPLOITATION_TOOLS:
        assert specs[name].exploitation is True
        assert specs[name].tier.value == "intrusive"
    for name, spec in specs.items():
        if name not in EXPLOITATION_TOOLS:
            assert spec.exploitation is False


def test_an_invalid_exploitation_flag_is_a_config_error(tmp_path: Path) -> None:
    text = TOOLS.read_text(encoding="utf-8").replace(
        "binary: sqlmap, exploitation: true",
        'binary: sqlmap, exploitation: "yes"',
    )
    path = tmp_path / "tools.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid exploitation flag"):
        load_tools(path)


def test_waf_priorities_are_declared_in_the_registry() -> None:
    """D12: the WAF-capable tools carry their priority in tools.yaml."""
    specs = load_tools()
    assert specs["wafw00f"].waf_priority == 100
    assert specs["cdncheck"].waf_priority == 80
    assert specs["whatweb"].waf_priority == 50
    assert specs["httpx_tech"].waf_priority == 20
    # Everything else makes no WAF priority claim.
    assert specs["httpx"].waf_priority == 0
    assert specs["webanalyze"].waf_priority == 0


def test_a_non_integer_waf_priority_is_a_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "tools.yaml"
    bad.write_text(
        "tools:\n"
        "  wafw00f: {stage: tech, kind: binary, tier: core, mode: active,"
        " phase: 3, waf_priority: high}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="waf_priority"):
        load_tools(bad)


def test_a_negative_waf_priority_is_a_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "tools.yaml"
    bad.write_text(
        "tools:\n"
        "  wafw00f: {stage: tech, kind: binary, tier: core, mode: active,"
        " phase: 3, waf_priority: -1}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="waf_priority"):
        load_tools(bad)
