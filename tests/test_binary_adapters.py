"""Binary adapter tests: fake run_exec, synthetic fixtures, no installed tools."""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from reconkit.adapters import ADAPTERS
from reconkit.adapters import base as base_module
from reconkit.adapters import nikto as nikto_module
from reconkit.adapters import subfinder as subfinder_module
from reconkit.adapters.assetfinder import AssetfinderAdapter
from reconkit.adapters.base import BinaryAdapter
from reconkit.adapters.cdncheck import CdncheckAdapter
from reconkit.adapters.dnsreaper import DnsreaperAdapter
from reconkit.adapters.dnsx import DnsxAdapter
from reconkit.adapters.gau import GauAdapter
from reconkit.adapters.gospider import GospiderAdapter
from reconkit.adapters.hakrawler import HakrawlerAdapter
from reconkit.adapters.httprobe import HttprobeAdapter
from reconkit.adapters.httpx_tech import HttpxTechAdapter
from reconkit.adapters.httpx_tool import HttpxAdapter
from reconkit.adapters.katana import KatanaAdapter
from reconkit.adapters.naabu import NaabuAdapter
from reconkit.adapters.nuclei import NucleiAdapter
from reconkit.adapters.registry import get_spec, load_tools
from reconkit.adapters.subfinder import (
    PROVIDERS,
    STALE_AFTER_S,
    SubfinderAdapter,
    cleanup_stale_provider_dirs,
)
from reconkit.adapters.subjs import SubjsAdapter
from reconkit.adapters.subzy import SubzyAdapter
from reconkit.adapters.tlsx import TlsxAdapter
from reconkit.adapters.unfurl import UnfurlAdapter
from reconkit.adapters.urlfinder import UrlfinderAdapter
from reconkit.adapters.wafw00f import Wafw00fAdapter
from reconkit.adapters.waybackurls import WaybackurlsAdapter
from reconkit.adapters.webanalyze import WebanalyzeAdapter
from reconkit.adapters.whatweb import WhatwebAdapter
from reconkit.config import load_config
from reconkit.core.runner import ExecResult
from reconkit.core.store import Store
from reconkit.engine import Engine
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import (
    FindingRecord,
    HostState,
    HostStatusRecord,
    PortRecord,
    RunContext,
    SubdomainRecord,
    ToolLimits,
    ToolResult,
    ToolStatus,
    UrlRecord,
)

REPO = Path(__file__).resolve().parents[1]
CONFIG = REPO / "config.yaml"
FIXTURES = REPO / "tests" / "fixtures"
ADAPTER_DIR = REPO / "src" / "reconkit" / "adapters"


def make_ctx(
    *,
    hosts: list[str] | None = None,
    ports: list[int] | None = None,
    env: dict[str, str] | None = None,
    mock: bool = False,
    headers: dict[str, str] | None = None,
    user_agent: str | None = None,
    resolvers: Path | None = None,
    target: str = "example.com",
    timeout: float = 5.0,
) -> RunContext:
    return RunContext(
        target=target,
        hosts=hosts or [],
        ports=ports or [],
        timeout=timeout,
        workspace=REPO / "workspaces" / "example.com",
        mock=mock,
        env=env or {},
        headers=headers or {},
        user_agent=user_agent,
        resolvers=resolvers,
    )


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))
    return home


def outcome(
    stdout: str = "",
    stderr: str = "",
    returncode: int | None = 0,
    timed_out: bool = False,
    truncated: bool = False,
    idle_killed: bool = False,
    last_output_s: float = 0.0,
) -> ExecResult:
    return ExecResult(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        truncated=truncated,
        idle_killed=idle_killed,
        last_output_s=last_output_s,
    )


def fake_exec(
    monkeypatch: pytest.MonkeyPatch,
    result: ExecResult,
    on_call: Callable[[list[str], dict[str, object]], None] | None = None,
) -> list[tuple[list[str], dict[str, object]]]:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake(argv: list[str], **kwargs: object) -> ExecResult:
        calls.append((argv, kwargs))
        if on_call is not None:
            on_call(argv, kwargs)
        return result

    monkeypatch.setattr(base_module, "run_exec", fake)
    return calls


def fixture(*parts: str) -> str:
    return FIXTURES.joinpath(*parts).read_text(encoding="utf-8")


# --------------------------------------------------------------- registration


def test_binary_adapters_are_registered() -> None:
    assert ADAPTERS["subfinder"] is SubfinderAdapter
    assert ADAPTERS["assetfinder"] is AssetfinderAdapter
    assert ADAPTERS["httpx"] is HttpxAdapter
    assert ADAPTERS["naabu"] is NaabuAdapter
    assert ADAPTERS["dnsx"] is DnsxAdapter
    assert ADAPTERS["tlsx"] is TlsxAdapter
    assert ADAPTERS["katana"] is KatanaAdapter
    assert ADAPTERS["gau"] is GauAdapter
    assert ADAPTERS["httprobe"] is HttprobeAdapter
    assert ADAPTERS["webanalyze"] is WebanalyzeAdapter
    assert ADAPTERS["cdncheck"] is CdncheckAdapter
    assert ADAPTERS["waybackurls"] is WaybackurlsAdapter
    assert ADAPTERS["hakrawler"] is HakrawlerAdapter
    assert ADAPTERS["gospider"] is GospiderAdapter
    assert ADAPTERS["subjs"] is SubjsAdapter
    assert ADAPTERS["urlfinder"] is UrlfinderAdapter
    assert ADAPTERS["unfurl"] is UnfurlAdapter
    assert ADAPTERS["wafw00f"] is Wafw00fAdapter
    assert ADAPTERS["whatweb"] is WhatwebAdapter
    assert ADAPTERS["httpx_tech"] is HttpxTechAdapter
    assert ADAPTERS["nuclei"] is NucleiAdapter
    assert ADAPTERS["subzy"] is SubzyAdapter


# Binary tools whose invocation never touches $HOME, so neither the identity
# probe nor a scan needs to pass HOME to them. Every entry needs a reason that
# can be checked in this repo: an adapter that forgets `needs_home` writes its
# config beside the working directory (PIT-30), so the list stays short on purpose.
NO_HOME_NEEDED: dict[str, str] = {
    "assetfinder": (
        "build_command passes only --subs-only <domain>; no config path, and "
        "tools.yaml lists no keys for it"
    ),
    "httprobe": (
        "real `httprobe -h` lists only -c/-p/-s/-t/-v: no config file, no key, "
        "and hosts arrive on stdin"
    ),
    "waybackurls": (
        "real `waybackurls -h` lists only -dates/-get-versions/-no-subs: no "
        "config file, no key, and domains arrive on stdin"
    ),
    "hakrawler": (
        "real `hakrawler -version` prints the Go usage (exit 2) and it lists only "
        "crawl flags: no config file, no key, and URLs arrive on stdin"
    ),
    "gospider": (
        "real `gospider -h` lists only crawl flags and -o (an output folder we "
        "never pass): no config file is read and no key is used"
    ),
    "subjs": (
        "real `subjs -h` lists only -c/-i/-t/-ua/-version: no config file, no "
        "key, and URLs arrive on stdin"
    ),
    "unfurl": (
        "real `unfurl -h` lists only -u/-v: no config file, no key, and URLs arrive on stdin"
    ),
    "wafw00f": (
        "real `wafw00f --help` lists only -a/-f/-o/-i/-l/-p/-t/-v: no config "
        "path is read and no key is used"
    ),
    "whatweb": (
        "real `whatweb --help` lists only scan/log/plugin flags: no config path "
        "is read and no key is used"
    ),
    "nmap": (
        "real `nmap --help` reads no HOME config in the invocation we build "
        "(-sV -Pn -oX --open, no --datadir/-sC): no config path and no key"
    ),
    "rustscan": (
        "the adapter always passes -n/--no-config, so rustscan's config file is "
        "never read; no key is used"
    ),
    "smap": (
        "real `smap -h` lists only -iL/--nmap/--concurrency/output flags: it "
        "queries Shodan's public data, reads no HOME config and uses no key"
    ),
    "masscan": (
        "real `masscan --help` reads config only via -c (never passed); the "
        "adapter writes an -oL file and uses no key"
    ),
    "findomain": (
        "real `findomain -h` lists only target/output/database flags: no config "
        "file in HOME is read and no key is used"
    ),
    "github_subdomains": (
        "the tool reads its token from -t or GITHUB_TOKEN only; the adapter passes "
        "-d and -o, so no HOME config path is touched"
    ),
    "dig": (
        "the adapter passes only +noall +answer -f <hosts file>; dig reads no HOME "
        "config in that invocation and uses no key"
    ),
    "massdns": (
        "the adapter passes -r/-t/-o/-w and a hosts file; massdns reads no HOME "
        "config and uses no key"
    ),
    "nikto": (
        "the adapter passes -h/-nointeractive/-Format/-output; nikto's config and "
        "database come from its install prefix, not HOME, and no key is used"
    ),
}


def test_every_binary_adapter_declares_needs_home_or_is_allowlisted() -> None:
    """Guard: a new binary adapter that forgets needs_home would pollute the CWD."""
    binaries = {
        name: spec
        for name, spec in load_tools().items()
        if spec.kind == "binary" and name in ADAPTERS
    }
    offenders = sorted(
        name for name in binaries if not ADAPTERS[name].needs_home and name not in NO_HOME_NEEDED
    )
    assert offenders == [], (
        "binary adapters must set needs_home = True or be listed in NO_HOME_NEEDED "
        f"with a reason: {offenders}"
    )
    empty_reasons = sorted(name for name, reason in NO_HOME_NEEDED.items() if not reason.strip())
    assert empty_reasons == [], f"NO_HOME_NEEDED entries need a reason: {empty_reasons}"
    stale = sorted(set(NO_HOME_NEEDED) - set(binaries))
    assert stale == [], f"NO_HOME_NEEDED lists tools without a binary adapter: {stale}"


@pytest.mark.parametrize(
    ("cls", "tool"),
    [
        (SubfinderAdapter, "subfinder"),
        (AssetfinderAdapter, "assetfinder"),
        (HttpxAdapter, "httpx"),
        (NaabuAdapter, "naabu"),
    ],
)
def test_version_args_match_tools_yaml(cls: type[BinaryAdapter], tool: str) -> None:
    data = yaml.safe_load((REPO / "tools.yaml").read_text(encoding="utf-8"))
    assert cls.version_args == list(data["tools"][tool]["version_cmd"])[1:]


# ---------------------------------------------------------------- identity


def test_missing_binary_is_not_installed() -> None:
    status = SubfinderAdapter(finder=lambda _name: None).check_installed()
    assert status.installed is False
    assert status.path is None


def test_identity_probe_passes_home(monkeypatch: pytest.MonkeyPatch, isolated_home: Path) -> None:
    """PIT-30: an empty child env made ProjectDiscovery tools write into the CWD."""
    calls = fake_exec(monkeypatch, outcome("projectdiscovery.io\n[INF] Current Version: v2.17.0"))
    status = SubfinderAdapter(finder=lambda _name: "/usr/bin/subfinder").check_installed()
    assert status.installed is True
    assert calls[0][1]["env"]["HOME"] == str(isolated_home)


def test_identity_probe_gets_a_path_led_by_the_program(
    monkeypatch: pytest.MonkeyPatch, isolated_home: Path
) -> None:
    """PIT-31: a distro wrapper script needs PATH to run the helpers it calls.

    Kali's `/usr/bin/amass` is a `/bin/sh` script that execs its real binary and
    may call `id`/`sudo`; a probe env with only HOME is not enough everywhere.
    """
    calls = fake_exec(monkeypatch, outcome("projectdiscovery.io\nCurrent Version: v2.17.0"))
    SubfinderAdapter(finder=lambda _name: "/opt/tools/subfinder").check_installed()
    env = calls[0][1]["env"]
    assert env["HOME"] == str(isolated_home)
    assert env["PATH"].split(os.pathsep)[0] == "/opt/tools"
    assert len(env["PATH"].split(os.pathsep)) > 1


def test_a_binary_outside_path_is_found_in_a_standard_dir(
    monkeypatch: pytest.MonkeyPatch, isolated_home: Path
) -> None:
    """`go install`/`pipx` put tools in dirs a minimal PATH never exports.

    The tool must be found wherever this machine installed it, not only in
    `~/.reconkit/bin` or the shell's PATH (docs/10 section 3).
    """
    target = isolated_home / "go" / "bin" / "subfinder"
    target.parent.mkdir(parents=True)
    target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    target.chmod(0o755)
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("GOPATH", raising=False)
    fake_exec(monkeypatch, outcome("projectdiscovery.io\nCurrent Version: v2.17.0"))
    adapter = SubfinderAdapter()
    assert adapter.binary_path() == str(target)
    status = adapter.check_installed()
    assert status.installed is True
    assert status.path == target


def test_sudo_user_bin_dirs_are_searched(monkeypatch: pytest.MonkeyPatch) -> None:
    """`sudo reconkit` runs with HOME=/root; the tools belong to SUDO_USER."""
    import pwd

    user = pwd.getpwuid(os.getuid()).pw_name
    monkeypatch.setenv("SUDO_USER", user)
    monkeypatch.setattr(base_module, "running_as_root", lambda: True)
    dirs = base_module.binary_search_dirs()
    home = Path(pwd.getpwnam(user).pw_dir)
    assert home / ".local" / "bin" in dirs
    assert home / "go" / "bin" in dirs


def test_projectdiscovery_httpx_identity_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_exec(monkeypatch, outcome("projectdiscovery.io\n[INF] Current Version: v1.6.9"))
    status = HttpxAdapter(finder=lambda _name: "C:/tools/httpx").check_installed()
    assert status.installed is True
    assert status.version == "v1.6.9"
    assert status.path is not None


def test_python_httpx_cli_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: PIT-14 the Python httpx CLI is not ProjectDiscovery's httpx."""
    fake_exec(monkeypatch, outcome("0.28.1"))
    status = HttpxAdapter(finder=lambda _name: "C:/python/Scripts/httpx").check_installed()
    assert status.installed is False
    assert status.path is not None


def test_assetfinder_usage_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome("Usage: assetfinder [--subs-only] <domain>\n", returncode=0))
    status = AssetfinderAdapter(finder=lambda _name: "/usr/bin/assetfinder").check_installed()
    assert status.installed is True


def fake_exec_sequence(
    monkeypatch: pytest.MonkeyPatch, results: list[ExecResult]
) -> list[list[str]]:
    """`run_exec` that answers with `results` in order, repeating the last one."""
    calls: list[list[str]] = []

    def fake(argv: list[str], **_kwargs: object) -> ExecResult:
        calls.append(argv)
        return results[min(len(calls) - 1, len(results) - 1)]

    monkeypatch.setattr(base_module, "run_exec", fake)
    return calls


def test_a_transient_identity_failure_is_retried_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D42: one failed probe does not drop a working tool from every scan."""
    calls = fake_exec_sequence(
        monkeypatch,
        [
            outcome("cannot execute binary file", returncode=126),
            outcome("projectdiscovery.io\n[INF] Current Version: v2.17.0"),
        ],
    )
    status = SubfinderAdapter(finder=lambda _name: "/usr/bin/subfinder").check_installed()
    assert status.installed is True
    assert status.version == "v2.17.0"
    assert len(calls) == 2


def test_two_consecutive_identity_failures_still_mark_wrong_program(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The retry changes nothing when the first program really is a namesake."""
    calls = fake_exec_sequence(
        monkeypatch,
        [outcome("0.28.1", returncode=0), outcome("0.28.1", returncode=0)],
    )
    status = HttpxAdapter(finder=lambda _name: "C:/python/Scripts/httpx").check_installed()
    assert status.installed is False
    assert status.path is not None
    assert len(calls) == 2


def test_retry_does_not_fire_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = fake_exec_sequence(
        monkeypatch, [outcome("projectdiscovery.io\nCurrent Version: v1.6.9")]
    )
    status = HttpxAdapter(finder=lambda _name: "C:/tools/httpx").check_installed()
    assert status.installed is True
    assert len(calls) == 1


def test_doctor_and_engine_share_the_retry_helper() -> None:
    """One retry implementation: both probes call the same function (D42)."""
    from reconkit.core import toolcheck

    assert toolcheck.probe_with_retry is base_module.probe_with_retry
    assert "probe_with_retry" in inspect.getsource(BinaryAdapter.check_installed)
    assert "probe_with_retry" in inspect.getsource(toolcheck.installed_version)


@pytest.mark.parametrize(
    "banner",
    [
        "projectdiscovery.io\n",
        "[INF] Current Version: v1.0.0\n",
    ],
)
@pytest.mark.parametrize("cls", [HttpxAdapter, NaabuAdapter])
def test_projectdiscovery_identity_requires_every_marker(
    monkeypatch: pytest.MonkeyPatch, cls: type[BinaryAdapter], banner: str
) -> None:
    """One marker alone is not identity (docs/09: every marker must appear).

    Both banners are printed by other ProjectDiscovery tools too, so accepting
    either one alone is how the namesake check decays into a version-string
    check. Fix the marker list, never this assertion.
    """
    fake_exec(monkeypatch, outcome(banner))
    status = cls(finder=lambda _name: f"/usr/bin/{cls.binary}").check_installed()
    assert status.installed is False
    assert status.path is not None


def test_naabu_identity_accepts_real_version_banner(monkeypatch: pytest.MonkeyPatch) -> None:
    """The positive path had no test at all before identity became strict."""
    fake_exec(monkeypatch, outcome("projectdiscovery.io\n\n[INF] Current Version: 2.7.0\n"))
    status = NaabuAdapter(finder=lambda _name: "/usr/bin/naabu").check_installed()
    assert status.installed is True
    assert status.version == "2.7.0"


def test_subfinder_identity_accepts_pre_264_version_only_banner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: subfinder < v2.6.4 prints no name-bearing line.

    Upstream commit c175790 (2023-10-30) added "Subfinder Config Directory" to
    -version; the first release containing it is v2.6.4. Requiring every marker
    would make a working v2.6.3 install invisible to doctor and scans.
    """
    fake_exec(monkeypatch, outcome("[INF] Current Version: v2.6.3\n"))
    status = SubfinderAdapter(finder=lambda _name: "/usr/bin/subfinder").check_installed()
    assert status.installed is True
    assert status.version == "v2.6.3"


def test_identity_runner_error_is_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*_args: object, **_kwargs: object) -> ExecResult:
        raise RuntimeError("pipes")

    monkeypatch.setattr(base_module, "run_exec", explode)
    status = NaabuAdapter(finder=lambda _name: "/usr/bin/naabu").check_installed()
    assert status.installed is False
    assert status.path is not None


def test_identity_timeout_is_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome(timed_out=True, returncode=None))
    status = NaabuAdapter(finder=lambda _name: "/usr/bin/naabu").check_installed()
    assert status.installed is False


# ------------------------------------------------------------- build_command


def test_subfinder_command_has_no_rate_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """2026-11-17: the pacer is gone, so no `-rl` (or any rate flag) is passed."""
    adapter = SubfinderAdapter()
    argv = adapter.build_command(make_ctx())
    # argv[0] is whatever this machine resolves (managed dir, PATH or bare
    # name); pins the flags here and the resolution in the 11d-findings-e tests.
    assert Path(argv[0]).name == "subfinder"
    assert argv[1:] == ["-d", "example.com", "-silent", "-nc", "-duc"]
    assert "-rl" not in argv


def test_assetfinder_command() -> None:
    argv = AssetfinderAdapter().build_command(make_ctx())
    assert Path(argv[0]).name == "assetfinder"
    assert argv[1:] == ["--subs-only", "example.com"]


BINARY_STAND_INS = [(SubfinderAdapter, "subfinder"), (AssetfinderAdapter, "assetfinder")]


def _managed_stand_in(home: Path, binary: str, body: str) -> Path:
    target = home / ".reconkit" / "bin" / binary
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    target.chmod(0o755)
    return target


@pytest.mark.parametrize(("adapter_cls", "binary"), BINARY_STAND_INS)
def test_build_command_launches_the_resolved_managed_binary(
    adapter_cls: type[BinaryAdapter], binary: str, isolated_home: Path
) -> None:
    """Regression: 11d-findings-e.

    The child gets only the env keys that were passed in, so it has no PATH
    to resolve a bare name against. An explicit --tools run of an installed
    binary therefore failed with "not installed or not executable" while
    check_installed() reported it present. Launch the resolved path; do not
    widen the child env to fix this. Fix build_command, never this assertion.
    """
    target = _managed_stand_in(isolated_home, binary, "#!/bin/sh\nexit 0\n")
    adapter = adapter_cls()
    assert adapter.binary_path() == str(target)
    argv = adapter.build_command(make_ctx())
    assert Path(argv[0]).is_absolute()
    assert argv[0] == str(target)


ACTIVE_BINARY_STAND_INS = [(HttpxAdapter, "httpx"), (NaabuAdapter, "naabu")]


@pytest.mark.parametrize(("adapter_cls", "binary"), ACTIVE_BINARY_STAND_INS)
def test_active_binary_adapters_launch_the_resolved_managed_binary(
    adapter_cls: type[BinaryAdapter], binary: str, isolated_home: Path
) -> None:
    """Regression: 11c-A-1.

    The same defect as 11d-findings-e, missed by that fix: the live and ports
    adapters built argv[0] from the bare binary name while the engine gives the
    child no PATH, so an install that lives only in ~/.reconkit/bin reported
    "not installed or not executable" even though doctor showed it present.
    Fix build_command, never this assertion.
    """
    target = _managed_stand_in(isolated_home, binary, "#!/bin/sh\nexit 0\n")
    adapter = adapter_cls()
    assert adapter.binary_path() == str(target)
    argv = adapter.build_command(make_ctx(hosts=["www.example.com"], ports=[443]))
    assert Path(argv[0]).is_absolute()
    assert argv[0] == str(target)


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell stand-in")
@pytest.mark.parametrize(("adapter_cls", "binary"), BINARY_STAND_INS)
async def test_installed_binary_in_managed_dir_actually_runs(
    adapter_cls: type[BinaryAdapter], binary: str, isolated_home: Path
) -> None:
    """Regression: 11d-findings-e, end to end.

    The product contradicted itself: doctor said installed, the scan said
    "not installed". This runs the adapter for real against a stand-in in the
    managed directory - no monkeypatched run_exec, no network, no real tool -
    and requires it to launch. On the bare-name code the spawn fails, which is
    exactly the symptom. Fix build_command, never this test.
    """
    _managed_stand_in(isolated_home, binary, "#!/bin/sh\necho www.example.com\n")
    result = await adapter_cls().run(make_ctx())
    assert result.status is ToolStatus.OK
    assert [record.fqdn for record in result.records] == ["www.example.com"]


def test_httpx_command_dedupes_and_lowercases_hosts() -> None:
    argv = HttpxAdapter().build_command(
        make_ctx(hosts=["WWW.Example.COM", "www.example.com", "api.example.com"])
    )
    assert Path(argv[0]).name == "httpx"
    assert argv[1:] == [
        "-silent",
        "-json",
        "-no-stdin",
        "-duc",
        "-nc",
        "-sc",
        "-title",
        "-location",
        "-td",
        "-cdn",
        "-u",
        "www.example.com",
        "-u",
        "api.example.com",
    ]


def test_httpx_command_carries_header_and_user_agent() -> None:
    """docs/02 section 3: `-H` is the real flag (`httpx -h`: custom http headers)."""
    argv = HttpxAdapter().build_command(
        make_ctx(
            hosts=["www.example.com"],
            headers={"X-Test": "abc"},
            user_agent="reconkit-test",
        )
    )
    assert "-H" in argv
    assert "X-Test: abc" in argv
    assert "User-Agent: reconkit-test" in argv
    # headers stay before the first -u host, so they apply to every probe
    assert argv.index("-H") < argv.index("-u")


def test_naabu_command_and_ports() -> None:
    argv = NaabuAdapter().build_command(
        make_ctx(hosts=["www.example.com"], ports=[443, 80, 70000, 0])
    )
    assert Path(argv[0]).name == "naabu"
    assert argv[1:] == [
        "-silent",
        "-json",
        "-no-stdin",
        "-duc",
        "-nc",
        "-scan-type",
        "c",
        "-host",
        "www.example.com",
        "-p",
        "443,80",
    ]


def test_naabu_accepts_verified_ip_inputs() -> None:
    """docs/05 rule 6 (2026-11-17): the scope-present branch hands naabu IPs.

    `naabu -h` documents `-host string[] hosts to scan ports for
    (comma-separated)`, and a real run with `-host 127.0.0.1` accepts an IP
    literal. The adapter must pass such inputs through normalized, never as a
    hostname it invented.
    """
    argv = NaabuAdapter().build_command(
        make_ctx(hosts=["203.0.113.5", "203.0.113.6", "2001:0db8::5"], ports=[443])
    )
    assert argv[argv.index("-host") + 1] == "203.0.113.5,203.0.113.6,2001:db8::5"
    assert "example.com" not in argv


@pytest.mark.parametrize("adapter", [HttpxAdapter(), NaabuAdapter()])
def test_flag_like_host_is_rejected_before_argv(adapter: HttpxAdapter | NaabuAdapter) -> None:
    from reconkit.errors import ToolFailed

    with pytest.raises(ToolFailed, match="invalid host"):
        adapter.build_command(make_ctx(hosts=["-oN /tmp/x"]))


def test_empty_host_list_is_a_failed_command() -> None:
    from reconkit.errors import ToolFailed

    with pytest.raises(ToolFailed, match="no hosts"):
        HttpxAdapter().build_command(make_ctx())


def test_flag_like_target_is_rejected() -> None:
    from reconkit.errors import ToolFailed

    ctx = make_ctx()
    ctx.target = "-d example.com"
    with pytest.raises(ToolFailed, match="invalid target"):
        SubfinderAdapter().build_command(ctx)


# ------------------------------------------------------------------- parsing


def test_subfinder_and_assetfinder_parse_fixtures() -> None:
    sub = SubfinderAdapter().parse_output(fixture("subfinder", "example.com.synthetic.txt"))
    assert [r.fqdn for r in sub] == ["www.example.com", "api.example.com", "dev.example.com"]
    assert all(isinstance(r, SubdomainRecord) for r in sub)

    asset = AssetfinderAdapter().parse_output(fixture("assetfinder", "example.com.synthetic.txt"))
    assert [r.fqdn for r in asset] == ["www.example.com", "blog.example.com", "api.example.com"]


def test_httpx_parse_fixture() -> None:
    records = HttpxAdapter().parse_output(fixture("httpx", "example.com.synthetic.jsonl"))
    assert [r.fqdn for r in records] == ["www.example.com", "api.example.com"]
    www = records[0]
    assert www.state is HostState.ALIVE
    assert www.status_code == 200
    assert www.title == "Example Domain"
    assert www.tech == ["Nginx"]
    assert www.waf == "cloudflare"


def test_naabu_parse_fixture() -> None:
    records = NaabuAdapter().parse_output(fixture("naabu", "example.com.synthetic.jsonl"))
    assert [(r.fqdn, r.ip, r.port, r.state) for r in records] == [
        ("www.example.com", "203.0.113.5", 443, "open"),
        ("www.example.com", "203.0.113.5", 80, "open"),
        ("203.0.113.6", "203.0.113.6", 8080, "open"),
    ]
    assert all(isinstance(r, PortRecord) for r in records)


def test_ansi_and_log_noise_are_ignored() -> None:
    raw = "\x1b[31mwww.example.com\x1b[0m\n[INF] Enumerating example.com\napi.example.com\n"
    records = SubfinderAdapter().parse_output(raw)
    assert [r.fqdn for r in records] == ["www.example.com", "api.example.com"]


def test_empty_output_is_ok() -> None:
    for adapter in (SubfinderAdapter(), AssetfinderAdapter(), HttpxAdapter(), NaabuAdapter()):
        assert adapter.parse_output("") == []


@pytest.mark.parametrize(
    ("adapter", "raw", "match"),
    [
        (SubfinderAdapter(), "not a host\n", "invalid subdomain line"),
        (AssetfinderAdapter(), "<html>nope</html>\n", "invalid subdomain line"),
        (HttpxAdapter(), "{not json\n", "invalid JSON line"),
        (HttpxAdapter(), '{"status_code": 200}\n', "no input/url"),
        (HttpxAdapter(), '{"input":"www.example.com","status_code":"200"}\n', "status_code"),
        (NaabuAdapter(), "{not json\n", "invalid JSON line"),
        (NaabuAdapter(), '{"ip":"203.0.113.5"}\n', "needs an ip"),
        (NaabuAdapter(), '{"ip":"not-an-ip","port":80}\n', "invalid JSON line"),
        (NaabuAdapter(), '{"ip":"203.0.113.5","port":70000}\n', "invalid JSON line"),
    ],
)
def test_malformed_output_fails_without_raising(
    adapter: BinaryAdapter, raw: str, match: str
) -> None:
    from reconkit.errors import ParseError

    with pytest.raises(ParseError, match=match):
        adapter.parse_output(raw)


def test_duplicate_httpx_and_naabu_lines_are_merged() -> None:
    httpx_raw = '{"input":"www.example.com","status_code":200}\n' * 2
    assert len(HttpxAdapter().parse_output(httpx_raw)) == 1
    naabu_raw = '{"host":"www.example.com","ip":"203.0.113.5","port":443}\n' * 2
    assert len(NaabuAdapter().parse_output(naabu_raw)) == 1


# -------------------------------------------------------------- run behavior


async def test_run_normal_uses_fixture_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome(fixture("subfinder", "example.com.synthetic.txt")))
    result = await SubfinderAdapter().run(make_ctx())
    assert result.status is ToolStatus.OK
    assert [r.fqdn for r in result.records] == [
        "www.example.com",
        "api.example.com",
        "dev.example.com",
    ]


async def test_run_timeout_is_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    """D52: reaching the stage budget is still `timeout`, not `failed`."""
    fake_exec(monkeypatch, outcome(timed_out=True, returncode=None))
    result = await HttpxAdapter().run(make_ctx(hosts=["www.example.com"]))
    assert result.status is ToolStatus.TIMEOUT
    assert result.error is not None and "timed out at stage budget" in result.error


async def test_run_nonzero_exit_is_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome("partial\n", "boom", returncode=2))
    result = await HttpxAdapter().run(make_ctx(hosts=["www.example.com"]))
    assert result.status is ToolStatus.FAILED
    assert result.error == "exit 2: boom"
    assert result.records == []


async def test_run_missing_binary_is_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome("", "no such file", returncode=None))
    result = await HttpxAdapter().run(make_ctx(hosts=["www.example.com"]))
    assert result.status is ToolStatus.FAILED
    assert result.error == "not installed or not executable: no such file"


async def test_run_truncated_output_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(
        monkeypatch, outcome(fixture("subfinder", "example.com.synthetic.txt"), truncated=True)
    )
    result = await SubfinderAdapter().run(make_ctx())
    assert result.status is ToolStatus.OK
    assert result.error == "output truncated"


async def test_run_runner_error_is_a_failed_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: PIT-16 a runner error becomes a failed result, not a traceback."""

    def explode(*_args: object, **_kwargs: object) -> ExecResult:
        raise RuntimeError("pipes")

    monkeypatch.setattr(base_module, "run_exec", explode)
    result = await HttpxAdapter().run(make_ctx(hosts=["www.example.com"]))
    assert result.status is ToolStatus.FAILED
    assert result.error == "runner error: pipes"


async def test_run_malformed_output_becomes_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome("{not json\n"))
    result = await HttpxAdapter().run(make_ctx(hosts=["www.example.com"]))
    assert result.status is ToolStatus.FAILED
    assert "invalid JSON line" in (result.error or "")


@pytest.mark.parametrize(
    ("adapter", "path"),
    [
        (SubfinderAdapter(), ("subfinder", "example.com.synthetic.txt")),
        (AssetfinderAdapter(), ("assetfinder", "example.com.synthetic.txt")),
        (HttpxAdapter(), ("httpx", "example.com.synthetic.jsonl")),
        (NaabuAdapter(), ("naabu", "example.com.synthetic.jsonl")),
    ],
)
async def test_mock_mode_reads_fixture(
    adapter: BinaryAdapter, path: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*_args: object, **_kwargs: object) -> ExecResult:
        raise AssertionError("mock mode must not run a binary")

    monkeypatch.setattr(base_module, "run_exec", explode)
    ctx = make_ctx(hosts=["www.example.com"], mock=True)
    result = await adapter.run(ctx)
    assert result.status is ToolStatus.OK
    assert result.records


# ------------------------------------------------- subfinder provider config


def _capture_provider(argv: list[str], seen: dict[str, object]) -> None:
    path = Path(argv[argv.index("-pc") + 1])
    seen["argv"] = list(argv)
    seen["path"] = path
    seen["content"] = path.read_text(encoding="utf-8")
    seen["mode"] = path.stat().st_mode
    seen["existed_during_run"] = path.exists()


async def test_subfinder_writes_and_deletes_provider_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: PIT-18 keys live only in the 0600 temp file, never argv or the result."""
    keys = {
        "VT_API_KEY": "vt-secret-value",
        "GITHUB_TOKEN": "gh-secret-value",
    }
    seen: dict[str, object] = {}
    fake_exec(
        monkeypatch,
        outcome("www.example.com\n"),
        on_call=lambda argv, _kwargs: _capture_provider(argv, seen),
    )
    adapter = SubfinderAdapter()
    result = await adapter.run(make_ctx(env=keys))
    assert result.status is ToolStatus.OK

    content = str(seen["content"])
    assert "virustotal:" in content
    assert "vt-secret-value" in content
    assert "github:" in content
    assert "gh-secret-value" in content
    assert "gh-secret-value" not in " ".join(result.model_dump_json().split())
    argv = seen["argv"]
    assert isinstance(argv, list)
    assert all("secret" not in arg for arg in argv)
    assert seen["existed_during_run"] is True
    assert Path(seen["path"]).exists() is False
    if os.name != "nt":
        assert oct(int(seen["mode"]))[-3:] == "600"


async def test_subfinder_without_keys_has_no_provider_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = fake_exec(monkeypatch, outcome("www.example.com\n"))
    await SubfinderAdapter().run(make_ctx())
    assert "-pc" not in calls[0][0]


async def test_subfinder_deletes_provider_config_on_parse_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}
    fake_exec(
        monkeypatch,
        outcome("not a host\n"),
        on_call=lambda argv, _kwargs: _capture_provider(argv, seen),
    )
    result = await SubfinderAdapter().run(make_ctx(env={"VT_API_KEY": "vt-secret-value"}))
    assert result.status is ToolStatus.FAILED
    assert Path(seen["path"]).exists() is False


async def test_subfinder_deletes_provider_config_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}
    fake_exec(
        monkeypatch,
        outcome(timed_out=True, returncode=None),
        on_call=lambda argv, _kwargs: _capture_provider(argv, seen),
    )
    result = await SubfinderAdapter().run(make_ctx(env={"VT_API_KEY": "vt-secret-value"}))
    assert result.status is ToolStatus.TIMEOUT
    assert Path(seen["path"]).exists() is False


def test_subfinder_provider_envs_are_registry_keys() -> None:
    declared = {key.env for key in get_spec("subfinder").keys}
    assert set(PROVIDERS) == declared


async def test_provider_config_lives_in_a_0700_per_run_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """12g: the file moved into a per-run 0700 directory, still 0600, still gone after."""
    seen: dict[str, object] = {}

    def capture(argv: list[str], _kwargs: dict[str, object]) -> None:
        path = Path(argv[argv.index("-pc") + 1])
        seen["path"] = path
        seen["parent"] = path.parent
        seen["name"] = path.parent.name
        seen["dir_mode"] = path.parent.stat().st_mode
        seen["file_mode"] = path.stat().st_mode
        seen["content"] = path.read_text(encoding="utf-8")

    fake_exec(monkeypatch, outcome("www.example.com\n"), on_call=capture)
    result = await SubfinderAdapter().run(make_ctx(env={"VT_API_KEY": "vt-secret-value"}))
    assert result.status is ToolStatus.OK
    assert str(seen["name"]).startswith(f"reconkit-subfinder-{os.getpid()}-")
    assert "vt-secret-value" in str(seen["content"])
    assert Path(str(seen["parent"])).exists() is False
    if os.name != "nt":
        assert oct(int(seen["dir_mode"]))[-3:] == "700"
        assert oct(int(seen["file_mode"]))[-3:] == "600"


@pytest.mark.skipif(os.name == "nt", reason="SIGKILL is POSIX-only")
async def test_a_sigkilled_run_leaves_a_directory_the_next_start_removes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: PIT-45 - a SIGKILL'd run's provider dir is removed by the next run."""
    root = tmp_path / "provider-root"
    root.mkdir()
    script = (
        "import os, pathlib, sys, tempfile\n"
        "root = pathlib.Path(sys.argv[1])\n"
        "prefix = 'reconkit-subfinder-%d-' % os.getpid()\n"
        "d = pathlib.Path(tempfile.mkdtemp(dir=root, prefix=prefix))\n"
        "(d / 'provider-config.yaml').write_text('virustotal:\\n  - sk-live\\n')\n"
        "os.kill(os.getpid(), 9)\n"
    )
    proc = subprocess.run([sys.executable, "-c", script, str(root)], check=False)
    assert proc.returncode != 0

    leftovers = [
        path
        for path in root.iterdir()
        if path.is_dir() and path.name.startswith("reconkit-subfinder-")
    ]
    assert len(leftovers) == 1
    assert (leftovers[0] / "provider-config.yaml").is_file()

    # The next run must clean the stale directory at startup, not just in a unit call.
    monkeypatch.setattr(subfinder_module.tempfile, "gettempdir", lambda: str(root))
    fake_exec(monkeypatch, outcome("www.example.com\n"))
    result = await SubfinderAdapter().run(make_ctx(env={"VT_API_KEY": "vt-secret-value"}))
    assert result.status is ToolStatus.OK
    assert [path for path in root.iterdir() if path.name.startswith("reconkit-subfinder-")] == []


@pytest.mark.skipif(os.name == "nt", reason="SIGKILL is POSIX-only")
def test_cleanup_reports_the_number_of_removed_directories(tmp_path: Path) -> None:
    root = tmp_path / "provider-root"
    root.mkdir()
    script = (
        "import os, pathlib, sys, tempfile\n"
        "root = pathlib.Path(sys.argv[1])\n"
        "prefix = 'reconkit-subfinder-%d-' % os.getpid()\n"
        "tempfile.mkdtemp(dir=root, prefix=prefix)\n"
        "os.kill(os.getpid(), 9)\n"
    )
    proc = subprocess.run([sys.executable, "-c", script, str(root)], check=False)
    assert proc.returncode != 0
    assert cleanup_stale_provider_dirs(root) == 1
    assert list(root.iterdir()) == []


def test_cleanup_never_touches_its_own_run(tmp_path: Path) -> None:
    own = tmp_path / f"reconkit-subfinder-{os.getpid()}-own"
    own.mkdir()
    (own / "provider-config.yaml").write_text("x", encoding="utf-8")
    assert cleanup_stale_provider_dirs(tmp_path) == 0
    assert (own / "provider-config.yaml").is_file()


def test_cleanup_leaves_a_concurrent_runs_directory_alone(tmp_path: Path) -> None:
    """Adversarial: a second live run must not have its key file deleted."""
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        live = tmp_path / f"reconkit-subfinder-{child.pid}-live"
        live.mkdir()
        (live / "provider-config.yaml").write_text("x", encoding="utf-8")
        assert cleanup_stale_provider_dirs(tmp_path) == 0
        assert (live / "provider-config.yaml").is_file()
    finally:
        child.kill()
        child.wait()


def test_when_liveness_is_unknown_age_alone_decides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When liveness is unknown, the documented fallback is the age rule."""
    monkeypatch.setattr(subfinder_module, "_pid_alive", lambda _pid: True)
    fresh = tmp_path / "reconkit-subfinder-424242-fresh"
    stale = tmp_path / "reconkit-subfinder-424242-stale"
    fresh.mkdir()
    stale.mkdir()
    old = time.time() - STALE_AFTER_S - 1
    os.utime(stale, (old, old))
    assert cleanup_stale_provider_dirs(tmp_path) == 1
    assert fresh.exists() is True
    assert stale.exists() is False


def test_stale_pre_12g_files_are_removed_but_fresh_ones_are_kept(tmp_path: Path) -> None:
    old = tmp_path / "reconkit-subfinder-old.yaml"
    new = tmp_path / "reconkit-subfinder-new.yaml"
    old.write_text("virustotal:\n  - sk-old\n", encoding="utf-8")
    new.write_text("virustotal:\n  - sk-new\n", encoding="utf-8")
    stale_time = time.time() - STALE_AFTER_S - 1
    os.utime(old, (stale_time, stale_time))
    assert cleanup_stale_provider_dirs(tmp_path) == 1
    assert old.exists() is False
    assert new.exists() is True


def test_a_write_failure_removes_the_per_run_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Adversarial: crash between mkdir and write must not strand the directory."""
    real_mkdtemp = tempfile.mkdtemp
    created: list[Path] = []

    def fake_mkdtemp(*args: object, **kwargs: object) -> str:
        path = Path(real_mkdtemp(*args, dir=tmp_path, **kwargs))
        created.append(path)
        return str(path)

    def boom(*_args: object, **_kwargs: object) -> None:
        raise yaml.YAMLError("no")

    monkeypatch.setattr(subfinder_module.tempfile, "mkdtemp", fake_mkdtemp)
    monkeypatch.setattr(subfinder_module.yaml, "safe_dump", boom)
    with pytest.raises(ToolFailed):
        SubfinderAdapter()._write_provider_config(make_ctx(env={"VT_API_KEY": "vt-secret-value"}))
    assert len(created) == 1
    assert created[0].exists() is False


# ------------------------------------------------------------- dependency rule

FORBIDDEN = (
    "reconkit.core.store",
    "reconkit.core.scope",
    "reconkit.ui",
    "reconkit.cli",
    "subprocess",
)


@pytest.mark.parametrize("module", ["subfinder", "assetfinder", "httpx_tool", "naabu"])
def test_binary_adapters_import_no_forbidden_modules(module: str) -> None:
    path = ADAPTER_DIR / f"{module}.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [node.module or ""]
        else:
            continue
        for name in modules:
            assert not any(
                name == forbidden or name.startswith(f"{forbidden}.") for forbidden in FORBIDDEN
            ), f"{path.name} imports {name}"


def test_httpx_parser_skips_lines_without_a_status() -> None:
    """Regression: PIT-15 a line without an integer status_code is not ALIVE."""
    raw = (
        '{"input":"down.example.com","failed":true}\n'
        '{"input":"www.example.com","status_code":200}\n'
    )
    records = HttpxAdapter().parse_output(raw)
    assert [r.fqdn for r in records] == ["www.example.com"]


def test_httpx_parser_handles_url_input() -> None:
    records = HttpxAdapter().parse_output(
        '{"url":"https://WWW.Example.COM:8443/admin","status_code":403}\n'
    )
    assert records[0].fqdn == "www.example.com"
    assert records[0].status_code == 403


def test_naabu_parser_accepts_ipv6() -> None:
    records = NaabuAdapter().parse_output('{"ip":"2001:db8::5","port":443}\n')
    assert records[0].fqdn == "2001:db8::5"
    assert records[0].ip == "2001:db8::5"


# ------------------------------------------------------------ 12a raw capture


async def test_binary_run_captures_stdout_and_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both streams reach raw_text, stderr under its own marker."""
    fake_exec(monkeypatch, outcome(stdout="a.example.com\n", stderr="[INF] warning\n"))
    result = await SubfinderAdapter().run(make_ctx())
    assert result.status is ToolStatus.OK
    assert result.raw_text == "a.example.com\n--- stderr ---\n[INF] warning\n"


async def test_binary_run_without_stderr_keeps_stdout_only(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome(stdout="a.example.com\n"))
    result = await SubfinderAdapter().run(make_ctx())
    assert result.raw_text == "a.example.com\n"


async def test_binary_failed_run_captures_its_output(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome(stdout="partial line\n", stderr="error: boom", returncode=1))
    result = await SubfinderAdapter().run(make_ctx())
    assert result.status is ToolStatus.FAILED
    assert result.raw_text == "partial line\n--- stderr ---\nerror: boom"


async def test_binary_timeout_captures_partial_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """D52: a stopped run keeps what arrived, whatever stopped it."""
    fake_exec(monkeypatch, outcome(stdout="a.example.com\n", timed_out=True))
    result = await SubfinderAdapter().run(make_ctx())
    assert result.status is ToolStatus.TIMEOUT
    assert [record.fqdn for record in result.records] == ["a.example.com"]
    assert result.raw_text == "a.example.com\n"


async def test_parse_error_keeps_the_raw_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """A parse bug is the case the raw file exists for."""
    fake_exec(monkeypatch, outcome(stdout="@@ not a host @@\n"))
    result = await SubfinderAdapter().run(make_ctx())
    assert result.status is ToolStatus.FAILED
    assert result.raw_text == "@@ not a host @@\n"


async def test_mock_run_captures_the_fixture_text(tmp_path: Path) -> None:
    fixtures = tmp_path / "fixtures"
    directory = fixtures / "subfinder"
    directory.mkdir(parents=True)
    (directory / "example.com.txt").write_text("a.example.com\n", encoding="utf-8")
    result = await SubfinderAdapter(fixtures_dir=fixtures).run(make_ctx(mock=True))
    assert result.status is ToolStatus.OK
    assert result.raw_text == "a.example.com\n"


# ------------------------------------------------- adapter wave 1 (phase 3)
# Every sample below is the real shape the tool printed on this box, with the
# live values replaced by the testfire.net fixture data.


def test_dnsx_adapter_parses_jsonl() -> None:
    records = DnsxAdapter().parse_output(fixture("adapters", "dnsx.synthetic.jsonl"))
    resolved = {record.fqdn: record for record in records if isinstance(record, SubdomainRecord)}
    assert set(resolved) == {"www.testfire.net", "testfire.net"}
    assert resolved["testfire.net"].ips == ["65.61.137.117", "65.61.137.118"]
    # PIT-01: NXDOMAIN is the only answer that may become DEAD.
    dead = [record for record in records if isinstance(record, HostStatusRecord)]
    assert [(record.fqdn, record.state) for record in dead] == [
        ("mail.testfire.net", HostState.DEAD)
    ]


def test_dnsx_keeps_a_noanswer_host_undecided() -> None:
    """A NOERROR line with no A record is not evidence of death (PIT-01)."""
    raw = '{"host":"empty.testfire.net","status_code":"NOERROR","a":[]}\n'
    assert DnsxAdapter().parse_output(raw) == []


def test_dnsx_puts_every_host_in_one_comma_separated_list_flag() -> None:
    """dnsx has no repeatable `-u`: its input flag is `-l` (verified help text)."""
    adapter = DnsxAdapter(finder=lambda _name: "/usr/bin/dnsx")
    argv = adapter.build_command(make_ctx(hosts=["a.example.com", "b.example.com"]))
    assert argv[argv.index("-l") + 1] == "a.example.com,b.example.com"
    assert "-json" in argv and "-a" in argv


def test_tlsx_adapter_extracts_sans_and_marks_alive() -> None:
    records = TlsxAdapter().parse_output(fixture("adapters", "tlsx.synthetic.jsonl"))
    hosts = {record.fqdn: record for record in records if isinstance(record, HostStatusRecord)}
    assert set(hosts) == {"www.testfire.net", "testfire.net"}
    assert all(record.state is HostState.ALIVE for record in hosts.values())
    assert hosts["www.testfire.net"].ips == ["65.61.137.117"]
    sans = {record.fqdn: record.source for record in records if isinstance(record, SubdomainRecord)}
    # The wildcard SAN names its parent, which is the host worth remembering; the
    # second certificate carries no subject_an at all.
    assert sans == {"www.testfire.net": "tlsx:san", "testfire.net": "tlsx:san"}


def test_tlsx_marks_a_failed_handshake_unknown_not_alive() -> None:
    raw = '{"host":"quiet.testfire.net","ip":"65.61.137.117","port":"443","probe_status":false}\n'
    records = TlsxAdapter().parse_output(raw)
    assert len(records) == 1
    assert isinstance(records[0], HostStatusRecord)
    assert (records[0].state, records[0].detail) == (HostState.UNKNOWN, "tls probe failed")


def test_tlsx_repeats_the_host_flag_once_per_input() -> None:
    adapter = TlsxAdapter(finder=lambda _name: "/usr/bin/tlsx")
    argv = adapter.build_command(make_ctx(hosts=["a.example.com", "b.example.com"]))
    assert argv.count("-u") == 2
    assert "-san" in argv and "-json" in argv


def test_katana_adapter_parses_jsonl() -> None:
    records = KatanaAdapter().parse_output(fixture("adapters", "katana.synthetic.jsonl"))
    assert [record.url for record in records] == [
        "https://testfire.net/",
        "https://testfire.net/login.jsp",
        "https://testfire.net/bank/main.jsp?login=1",
    ]
    assert {record.source for record in records} == {"katana"}


def test_katana_skips_a_crawl_error_line() -> None:
    """`{"error": "max depth reached"}` is not a URL (real katana output)."""
    raw = '{"timestamp":"2026-11-17T11:00:02Z","error":"max depth reached"}\n'
    assert KatanaAdapter().parse_output(raw) == []


def test_katana_skips_invalid_json_lines() -> None:
    """Regression: PIT-58 katana sometimes prints warnings on stdout.

    A real scan failed the whole tool with `katana: invalid JSON line` although
    it had found URLs; the three valid lines must survive and the two junk lines
    must be counted, with the tool still `ok`.
    """
    raw = (
        '{"request":{"endpoint":"https://testfire.net/"}}\n'
        "WARN: crawl started\n"
        '{"request":{"endpoint":"https://testfire.net/login.jsp"}}\n'
        "this is not json at all\n"
        '{"request":{"endpoint":"https://testfire.net/admin"}}\n'
    )
    adapter = KatanaAdapter()
    records = adapter.parse_output(raw)
    assert [record.url for record in records] == [
        "https://testfire.net/",
        "https://testfire.net/login.jsp",
        "https://testfire.net/admin",
    ]
    assert len(adapter.skipped_lines) == 2


def test_katana_warning_lines_reach_the_detail_and_stay_ok(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The skipped lines are two warnings in the Tools detail, status `ok`."""
    raw = (
        '{"request":{"endpoint":"https://testfire.net/"}}\n'
        "WARN: something happened\n"
        '{"request":{"endpoint":"https://testfire.net/a"}}\n'
        "another non-json line\n"
        '{"request":{"endpoint":"https://testfire.net/b"}}\n'
    )
    calls = fake_exec(monkeypatch, outcome(stdout=raw))
    result = asyncio.run(
        KatanaAdapter(finder=lambda _name: "/usr/bin/katana").run(make_ctx(hosts=["testfire.net"]))
    )
    assert calls  # the binary really ran (through the fake runner)
    assert result.status is ToolStatus.OK
    assert len(result.records) == 3
    assert (result.error or "").count("skipped unusable line") == 2


def test_katana_many_junk_lines_are_summarised_once() -> None:
    """Rate limit: more than ten bad lines cost one summary, not a wall of text."""
    raw = "".join(f"junk line {index}\n" for index in range(25))
    adapter = KatanaAdapter()
    assert adapter.parse_output(raw) == []
    assert len(adapter.skipped_lines) == 25
    note = adapter._skip_note()
    assert note is not None
    assert "25 unusable line(s)" in note
    assert note.count("skipped") == 1


@pytest.mark.parametrize(
    ("adapter", "junk", "good"),
    [
        (HakrawlerAdapter(), "not a url at all", "http://testfire.net/a"),
        (GospiderAdapter(), "[info] - crawl started", "https://testfire.net/a"),
        (SubjsAdapter(), "Fetching https://testfire.net/ failed", "https://testfire.net/app.js"),
    ],
)
def test_crawler_parsers_skip_unusable_lines(adapter: BinaryAdapter, junk: str, good: str) -> None:
    """Regression: PIT-58 one bad line must not throw away a whole crawl."""
    raw = f"{junk}\n{good}\n"
    records = adapter.parse_output(raw)
    assert [record.url for record in records] == [good]
    assert adapter.skipped_lines == [junk]


def test_hakrawler_idle_window_is_its_own(monkeypatch: pytest.MonkeyPatch) -> None:
    """D52: hakrawler runs until it exits; silence past its window kills it."""
    adapter = HakrawlerAdapter(finder=lambda _name: "/usr/bin/hakrawler")
    calls = fake_exec(
        monkeypatch,
        outcome(
            stdout="http://testfire.net/a\nhttp://testfire.net/b\n",
            timed_out=True,
            idle_killed=True,
            last_output_s=60.0,
        ),
    )
    ctx = make_ctx(hosts=["testfire.net"])
    ctx.timeout = 600.0  # the real stage budget
    ctx.limits = {"hakrawler": ToolLimits(idle_s=60.0)}
    result = asyncio.run(adapter.run(ctx))
    assert calls[0][1]["timeout"] == 600.0
    assert calls[0][1]["idle_timeout"] == 60.0
    assert result.status is ToolStatus.KILLED
    assert [record.url for record in result.records] == [
        "http://testfire.net/a",
        "http://testfire.net/b",
    ]
    assert "idle" in (result.error or "")


def test_subjs_idle_window_is_its_own(monkeypatch: pytest.MonkeyPatch) -> None:
    """D52: same for subjs, with its own one-minute window."""
    adapter = SubjsAdapter(finder=lambda _name: "/usr/bin/subjs")
    calls = fake_exec(
        monkeypatch,
        outcome(
            stdout="https://testfire.net/app.js\n",
            timed_out=True,
            idle_killed=True,
            last_output_s=60.0,
        ),
    )
    ctx = make_ctx(hosts=["testfire.net"])
    ctx.timeout = 600.0
    ctx.limits = {"subjs": ToolLimits(idle_s=60.0)}
    result = asyncio.run(adapter.run(ctx))
    assert calls[0][1]["timeout"] == 600.0
    assert calls[0][1]["idle_timeout"] == 60.0
    assert result.status is ToolStatus.KILLED
    assert [record.url for record in result.records] == ["https://testfire.net/app.js"]
    assert "idle" in (result.error or "")


def test_gau_adapter_parses_plain_urls() -> None:
    plain = (
        "http://testfire.net/\n"
        "http://testfire.net/login.jsp\n"
        "http://testfire.net/bank/main.jsp\n"
        "https://www.testfire.net/admin/admin.aspx\n"
        "https://testfire.net/search.jsp?query=abc\n"
    )
    records = GauAdapter().parse_output(plain)
    assert [record.url for record in records] == [
        "http://testfire.net/",
        "http://testfire.net/login.jsp",
        "http://testfire.net/bank/main.jsp",
        "https://www.testfire.net/admin/admin.aspx",
        "https://testfire.net/search.jsp?query=abc",
    ]


def test_gau_parses_its_json_output_and_drops_the_fragment() -> None:
    records = GauAdapter().parse_output(fixture("adapters", "gau.synthetic.txt"))
    assert len(records) == 5
    assert records[-1].url == "https://testfire.net/search.jsp?query=abc"
    # A repeated URL is one record: two archives can return the same page.
    assert GauAdapter().parse_output('{"url":"http://testfire.net/"}\nhttp://testfire.net/\n') == [
        records[0]
    ]


async def test_gau_ignores_its_stderr_config_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only stdout is parsed; the "config file not found" notice is stderr."""
    fake_exec(
        monkeypatch,
        outcome(
            stdout='{"url":"http://testfire.net/"}\n',
            stderr=(
                'time="2026-11-17T11:04:42-05:00" level=warning msg="error reading'
                " config: Config file /home/kali/.gau.toml not found, using default"
                ' config"\n'
            ),
        ),
    )
    result = await GauAdapter(finder=lambda _name: "/usr/bin/gau").run(
        make_ctx(hosts=["testfire.net"])
    )
    assert result.status is ToolStatus.OK
    assert [record.url for record in result.records] == ["http://testfire.net/"]


def test_gau_caps_its_http_timeout_instead_of_using_the_run_budget() -> None:
    """2026-11-18: `--timeout` is gau's HTTP client timeout, not a run budget.

    The adapter passed the per-tool budget here, so one stalled provider request
    could block for the whole stage: a real run timed out at 600 s with 0 items,
    where `--timeout=45 --retries=1 --threads=5` returned 345 URLs in 31 s.
    """
    adapter = GauAdapter(finder=lambda _name: "/usr/bin/gau")
    command = adapter.build_command(make_ctx(hosts=["testfire.net"]))
    assert "--timeout=5" in command  # the 5 s run budget is smaller, so it wins
    assert "--threads=5" in command
    assert "--retries=1" in command
    assert "--json" in command
    assert command[-1] == "testfire.net"


def test_gau_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: PIT-14 pattern - a namesake binary is not gau."""
    fake_exec(monkeypatch, outcome("gau 0.1.0-something-else\n"))
    status = GauAdapter(finder=lambda _name: "/usr/bin/gau").check_installed()
    assert status.installed is False


def test_gau_identity_accepts_the_real_version_banner(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome("gau version: 2.2.4\n"))
    status = GauAdapter(finder=lambda _name: "/usr/bin/gau").check_installed()
    assert status.installed is True
    assert status.version == "2.2.4"


# ------------------------------------------------------- adapter wave 2 (2026-11-17)


def test_httprobe_adapter_parses_plain_urls() -> None:
    """`httprobe` prints one `scheme://host` per answered probe, no JSON."""
    records = HttprobeAdapter().parse_output(fixture("adapters", "httprobe.synthetic.txt"))
    assert [(record.fqdn, record.state) for record in records] == [
        ("testfire.net", HostState.ALIVE),
        ("www.testfire.net", HostState.ALIVE),
    ]
    # Two probes (http and https) on one host are one host fact, not two rows.
    assert HttprobeAdapter().parse_output("http://a.testfire.net\nhttps://a.testfire.net\n") == [
        HostStatusRecord(fqdn="a.testfire.net", source="httprobe", state=HostState.ALIVE)
    ]


def test_httprobe_feeds_hosts_on_stdin_and_never_uses_a_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """httprobe has no input flag: the host list travels on stdin (D11)."""
    calls = fake_exec(monkeypatch, outcome(stdout="http://testfire.net\n"))
    adapter = HttprobeAdapter(finder=lambda _name: "/usr/bin/httprobe")
    ctx = make_ctx(hosts=["testfire.net", "www.testfire.net"])
    command = adapter.build_command(ctx)
    assert command[:1] == ["/usr/bin/httprobe"]
    assert "-t" in command
    assert adapter.stdin_text(ctx) == "testfire.net\nwww.testfire.net\n"
    assert "www.testfire.net" not in command
    assert calls == []


def test_httprobe_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    """A namesake that prints some other usage is not httprobe (PIT-14 pattern)."""
    fake_exec(monkeypatch, outcome("Usage of /usr/bin/httprobe: some other tool\n"))
    status = HttprobeAdapter(finder=lambda _name: "/usr/bin/httprobe").check_installed()
    assert status.installed is False


def test_httprobe_identity_accepts_the_real_usage(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(
        monkeypatch,
        outcome(
            "Usage of /usr/bin/httprobe:\n  -c int\n\t\tset the concurrency level (default 20)\n"
            "  -s\tskip the default probes (http:80 and https:443)\n"
        ),
    )
    status = HttprobeAdapter(finder=lambda _name: "/usr/bin/httprobe").check_installed()
    assert status.installed is True


def test_webanalyze_adapter_parses_technologies() -> None:
    """One JSON document per host, `matches[].app_name` is the technology."""
    records = WebanalyzeAdapter().parse_output(fixture("adapters", "webanalyze.synthetic.json"))
    assert [(record.fqdn, record.tech) for record in records] == [
        ("testfire.net", ["Apache Tomcat", "Java"]),
        ("www.testfire.net", ["Java"]),
    ]
    assert all(record.state is HostState.ALIVE for record in records)


def test_webanalyze_takes_its_hosts_from_a_file_it_removes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`-hosts` is a file path, so the adapter writes and deletes one (D11)."""
    calls = fake_exec(monkeypatch, outcome(stdout=""))
    adapter = WebanalyzeAdapter(finder=lambda _name: "/usr/bin/webanalyze")
    ctx = make_ctx(hosts=["testfire.net"]).model_copy(update={"workspace": tmp_path})
    with adapter.prepare(ctx):
        command = adapter.build_command(ctx)
        hosts_file = Path(command[command.index("-hosts") + 1])
        assert hosts_file.read_text(encoding="utf-8") == "testfire.net\n"
        assert command[command.index("-output") + 1] == "json"
        assert "-apps" in command
    assert not hosts_file.exists()
    assert calls == []


def test_webanalyze_with_no_technology_match_stores_nothing() -> None:
    """A fetched host with no match carries no technology fact."""
    raw = '{"hostname": "https://testfire.net", "matches": []}\n'
    assert WebanalyzeAdapter().parse_output(raw) == []


def test_webanalyze_requires_update_documented() -> None:
    """The one-time `-update` is documented where the operator will look."""
    tools_yaml = (Path(__file__).resolve().parents[1] / "tools.yaml").read_text(encoding="utf-8")
    webanalyze_line = next(
        line for line in tools_yaml.splitlines() if line.strip().startswith("webanalyze:")
    )
    assert "webanalyze -update" in webanalyze_line
    assert "technologies.json" in webanalyze_line
    manual = (Path(__file__).resolve().parents[1] / "docs" / "10_TOOL_SOURCES.md").read_text(
        encoding="utf-8"
    )
    assert "webanalyze -update" in manual


async def test_webanalyze_missing_database_is_a_failed_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_exec(
        monkeypatch,
        outcome(
            stderr="error: can not open apps file : could not find the technologies file: "
            "technologies.json\n",
            returncode=1,
        ),
    )
    ctx = make_ctx(hosts=["testfire.net"]).model_copy(update={"workspace": tmp_path})
    result = await WebanalyzeAdapter(finder=lambda _name: "/usr/bin/webanalyze").run(ctx)
    assert result.status is ToolStatus.FAILED
    assert "can not open apps file" in (result.error or "")


def test_webanalyze_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome("Usage of /usr/bin/webanalyze:\n  -x\tother tool\n"))
    status = WebanalyzeAdapter(finder=lambda _name: "/usr/bin/webanalyze").check_installed()
    assert status.installed is False


def test_cdncheck_adapter_parses_waf_fields() -> None:
    """WAF goes to `waf`, CDN/cloud become technologies, no liveness claim."""
    records = CdncheckAdapter().parse_output(fixture("adapters", "cdncheck.synthetic.jsonl"))
    assert [(record.fqdn, record.waf, record.tech) for record in records] == [
        ("testfire.net", "cloudflare", ["google"]),
        ("www.testfire.net", None, ["aws"]),
    ]
    assert all(record.state is HostState.UNKNOWN for record in records)


def test_cdncheck_repeats_the_input_flag_for_each_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = fake_exec(monkeypatch, outcome(stdout=""))
    adapter = CdncheckAdapter(finder=lambda _name: "/usr/bin/cdncheck")
    command = adapter.build_command(make_ctx(hosts=["testfire.net", "www.testfire.net"]))
    assert command[1:3] == ["-silent", "-jsonl"]
    assert command[3:] == ["-i", "testfire.net", "-i", "www.testfire.net"]
    assert calls == []


def test_cdncheck_silence_is_no_match_not_failure() -> None:
    assert CdncheckAdapter().parse_output("") == []


def test_cdncheck_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome("cdncheck 1.4.0 by someone else\n"))
    status = CdncheckAdapter(finder=lambda _name: "/usr/bin/cdncheck").check_installed()
    assert status.installed is False


def test_waybackurls_adapter_parses_plain_urls() -> None:
    records = WaybackurlsAdapter().parse_output(fixture("adapters", "waybackurls.synthetic.txt"))
    assert len(records) == 5
    assert records[1].url == "https://testfire.net/login.jsp"
    assert all(record.source == "waybackurls" for record in records)


def test_waybackurls_feeds_domains_on_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    """waybackurls takes no positional domain and has no list flag (D11)."""
    calls = fake_exec(monkeypatch, outcome(stdout="https://testfire.net/\n"))
    adapter = WaybackurlsAdapter(finder=lambda _name: "/usr/bin/waybackurls")
    ctx = make_ctx(hosts=["testfire.net"])
    assert adapter.build_command(ctx) == ["/usr/bin/waybackurls"]
    assert adapter.stdin_text(ctx) == "testfire.net\n"
    assert calls == []


def test_waybackurls_asks_once_per_root_not_once_per_host() -> None:
    """2026-11-18: `*.<apex>/*` already covers the subdomains, per its own `-h`.

    Feeding all 42 hosts asked the same wildcard question 42 times in sequence:
    302 s in the 10:14 run, against 503 answers that morning.
    """
    adapter = WaybackurlsAdapter(finder=lambda _name: "/usr/bin/waybackurls")
    hosts = [
        "testfire.net",
        "www.testfire.net",
        "api.testfire.net",
        "WWW.TestFire.net",
        "other.example",
        "sub.other.example",
    ]
    ctx = make_ctx(hosts=hosts, target="testfire.net")
    # Every testfire host folds into one wildcard query; the other domain keeps
    # its own line, and its own subdomain cannot be assumed covered by it.
    assert adapter.stdin_text(ctx) == "testfire.net\nother.example\nsub.other.example\n"


def test_waybackurls_does_not_swallow_a_lookalike_apex() -> None:
    """`nottestfire.net` is not under `testfire.net`; suffix matching without
    the dot would have folded it into the wrong query."""
    adapter = WaybackurlsAdapter(finder=lambda _name: "/usr/bin/waybackurls")
    ctx = make_ctx(hosts=["nottestfire.net"])
    assert adapter.stdin_text(ctx) == "nottestfire.net\n"


def test_waybackurls_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome("Usage of /usr/bin/waybackurls:\n  -other\n"))
    status = WaybackurlsAdapter(finder=lambda _name: "/usr/bin/waybackurls").check_installed()
    assert status.installed is False


# ------------------------------------------------------- adapter wave 3 (2026-11-17)


def test_hakrawler_adapter_parses_plain_urls() -> None:
    """hakrawler prints one URL per line, no prefix, no JSON."""
    records = HakrawlerAdapter().parse_output(fixture("adapters", "hakrawler.synthetic.txt"))
    assert len(records) == 5
    assert records[0].url == "http://testfire.net/"
    assert records[-1].url == "http://testfire.net/index.jsp?content=inside_contact.htm"
    assert all(record.source == "hakrawler" for record in records)
    # A repeated URL is one record: a nav bar links the same page everywhere.
    assert HakrawlerAdapter().parse_output("http://testfire.net/a\nhttp://testfire.net/a\n") == [
        UrlRecord(url="http://testfire.net/a", source="hakrawler")
    ]


def test_hakrawler_offers_both_schemes_on_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bare hostnames cannot be crawled: https first, then http (verified)."""
    calls = fake_exec(monkeypatch, outcome(stdout=""))
    adapter = HakrawlerAdapter(finder=lambda _name: "/usr/bin/hakrawler")
    ctx = make_ctx(hosts=["testfire.net"])
    assert adapter.build_command(ctx)[1:2] == ["-d"]
    assert "-u" in adapter.build_command(ctx)
    assert adapter.stdin_text(ctx) == "https://testfire.net/\nhttp://testfire.net/\n"
    assert calls == []


def test_hakrawler_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome("flag provided but not defined: -version\n"))
    status = HakrawlerAdapter(finder=lambda _name: "/usr/bin/hakrawler").check_installed()
    assert status.installed is False


def test_hakrawler_identity_accepts_the_real_usage(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(
        monkeypatch,
        outcome(
            "flag provided but not defined: -version\nUsage of hakrawler:\n"
            "  -d int\n\t\tDepth to crawl. (default 2)\n"
            "  -u\tShow only unique urls.\n",
            returncode=2,
        ),
    )
    status = HakrawlerAdapter(finder=lambda _name: "/usr/bin/hakrawler").check_installed()
    assert status.installed is True


def test_gospider_adapter_parses_and_strips_prefix() -> None:
    """The verbose shape `[tag] - [code-200] - URL` becomes the URL alone."""
    records = GospiderAdapter().parse_output(fixture("adapters", "gospider.synthetic.txt"))
    assert [record.url for record in records] == [
        "https://testfire.net/",
        "https://testfire.net/style.css",
        "https://testfire.net/index.jsp",
        "https://testfire.net/login.jsp",
        "https://testfire.net/feedback.jsp",
    ]
    # `-q` prints bare URLs, which must parse too (same process, other flag set).
    assert GospiderAdapter().parse_output("https://testfire.net/a\n") == [
        UrlRecord(url="https://testfire.net/a", source="gospider")
    ]


def test_gospider_writes_and_removes_its_sites_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`-s` is a single string and there is no stdin, so `-S` gets a file."""
    calls = fake_exec(monkeypatch, outcome(stdout=""))
    adapter = GospiderAdapter(finder=lambda _name: "/usr/bin/gospider")
    ctx = make_ctx(hosts=["testfire.net"]).model_copy(update={"workspace": tmp_path})
    with adapter.prepare(ctx):
        command = adapter.build_command(ctx)
        sites_file = Path(command[command.index("-S") + 1])
        assert sites_file.read_text(encoding="utf-8") == (
            "https://testfire.net/\nhttp://testfire.net/\n"
        )
        assert command[command.index("-q")] == "-q"
        assert command[command.index("-d") + 1] == "2"
    assert not sites_file.exists()
    assert calls == []


def test_gospider_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome("Version: v9.9.9\n"))
    status = GospiderAdapter(finder=lambda _name: "/usr/bin/gospider").check_installed()
    assert status.installed is False


def test_subjs_adapter_parses_js_urls() -> None:
    records = SubjsAdapter().parse_output(fixture("adapters", "subjs.synthetic.txt"))
    assert [record.url for record in records] == [
        "http://testfire.net/js/validate.js",
        "http://testfire.net/js/menu.js",
        "http://testfire.net/vendor/jquery.min.js",
    ]
    assert all(record.source == "subjs" for record in records)


def test_subjs_sends_the_honest_user_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    """These are reconkit's own requests, so the UA names reconkit (AGENTS rule 8)."""
    fake_exec(monkeypatch, outcome(stdout=""))
    adapter = SubjsAdapter(finder=lambda _name: "/usr/bin/subjs")
    command = adapter.build_command(make_ctx(hosts=["testfire.net"]))
    assert command[command.index("-ua") + 1].startswith("reconkit/")
    overridden = adapter.build_command(make_ctx(hosts=["testfire.net"], user_agent="custom/1.0"))
    assert overridden[overridden.index("-ua") + 1] == "custom/1.0"


def test_subjs_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome("subjs 9.9.9\n"))
    status = SubjsAdapter(finder=lambda _name: "/usr/bin/subjs").check_installed()
    assert status.installed is False


def test_urlfinder_adapter_parses_plain_urls() -> None:
    records = UrlfinderAdapter().parse_output(fixture("adapters", "urlfinder.synthetic.txt"))
    assert len(records) == 4
    assert records[2].url == "http://testfire.net/javadoc/"
    assert all(record.source == "urlfinder" for record in records)


def test_urlfinder_skips_archived_junk_and_feeds_domains(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stored probe string with spaces is not a URL; domains arrive on stdin."""
    junk = "http://testfire.net/api/v1/license/keys-status/;curl d9q...oast.live\n"
    good = "https://testfire.net/login.jsp\n"
    assert [record.url for record in UrlfinderAdapter().parse_output(junk + good)] == [
        "https://testfire.net/login.jsp"
    ]
    calls = fake_exec(monkeypatch, outcome(stdout=good))
    adapter = UrlfinderAdapter(finder=lambda _name: "/usr/bin/urlfinder")
    ctx = make_ctx(hosts=["testfire.net", "www.testfire.net"])
    # 2026-11-18: `-timeout` is the per-request timeout (capped at 30 s, its own
    # default); the per-tool budget used to be passed as `-timeout`, which gave
    # every slow source ten minutes to answer one request. D52: `-max-time` is
    # gone entirely - the binary ignores it and there is no runtime cap left.
    assert adapter.build_command(ctx)[1:] == [
        "-all",
        "-silent",
        "-nc",
        "-timeout",
        "5",
    ]
    big = make_ctx(hosts=["testfire.net"])
    big.timeout = 7200.0
    # A longer stage budget raises the per-request timeout only to its own 30 s
    # ceiling; the whole run is bounded by the stage budget and the idle window.
    assert "-max-time" not in adapter.build_command(big)
    assert adapter.build_command(big)[-1] == "30"
    assert adapter.stdin_text(ctx) == "testfire.net\nwww.testfire.net\n"
    assert calls == []


def test_urlfinder_keeps_partial_urls_when_the_idle_watchdog_kills_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PIT-56, D52: an idle kill keeps what the tool found before it went quiet."""
    adapter = UrlfinderAdapter(finder=lambda _name: "/usr/bin/urlfinder")
    ctx = make_ctx(hosts=["testfire.net"])
    ctx.timeout = 1800.0  # the real `urls` stage budget
    ctx.limits = {"urlfinder": ToolLimits(idle_s=180.0)}
    calls = fake_exec(
        monkeypatch,
        outcome(
            stdout="https://testfire.net/login.jsp\nhttps://testfire.net/admin\n",
            timed_out=True,
            idle_killed=True,
            last_output_s=180.0,
        ),
    )
    result = asyncio.run(adapter.run(ctx))

    # D52: the only hard wall is the stage budget; the early stop is the window.
    assert calls[0][1]["timeout"] == 1800.0
    assert calls[0][1]["idle_timeout"] == 180.0
    assert result.status is ToolStatus.KILLED
    assert [record.url for record in result.records] == [
        "https://testfire.net/login.jsp",
        "https://testfire.net/admin",
    ]
    assert result.error is not None and "idle" in result.error


def test_urlfinder_idle_timeout_kills_stuck_source(monkeypatch: pytest.MonkeyPatch) -> None:
    """D52: a source that stopped answering is killed after its idle window.

    The window comes from `runtime_idle` / the tool's `class:`, never from a
    runtime cap: there is no `max_s` and no floor any more.
    """
    adapter = UrlfinderAdapter(finder=lambda _name: "/usr/bin/urlfinder")
    ctx = make_ctx(hosts=["testfire.net"])
    ctx.timeout = 600.0
    ctx.limits = {"urlfinder": ToolLimits(idle_s=60.0)}
    calls = fake_exec(
        monkeypatch,
        outcome(
            stdout="https://testfire.net/login.jsp\nhttps://testfire.net/admin\n",
            timed_out=True,
            idle_killed=True,
            last_output_s=60.0,
        ),
    )
    result = asyncio.run(adapter.run(ctx))

    kwargs = calls[0][1]
    assert kwargs["timeout"] == 600.0  # the stage budget is the hard wall
    assert kwargs["idle_timeout"] == 60.0
    assert result.status is ToolStatus.KILLED
    assert [record.url for record in result.records] == [
        "https://testfire.net/login.jsp",
        "https://testfire.net/admin",
    ]


def test_urlfinder_runs_until_it_exits_if_productive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D52: a tool that keeps producing is never cut short by a cap."""
    adapter = UrlfinderAdapter(finder=lambda _name: "/usr/bin/urlfinder")
    ctx = make_ctx(hosts=["testfire.net"])
    ctx.timeout = 600.0
    ctx.limits = {"urlfinder": ToolLimits(idle_s=60.0)}
    urls = "".join(f"https://testfire.net/p{index}\n" for index in range(50))
    calls = fake_exec(monkeypatch, outcome(stdout=urls))
    result = asyncio.run(adapter.run(ctx))

    assert calls[0][1]["timeout"] == 600.0
    assert calls[0][1]["idle_timeout"] == 60.0
    # Not capped, not killed: everything the tool printed is kept.
    assert result.status is ToolStatus.OK
    assert len(result.records) == 50
    assert result.error is None


def test_urlfinder_stage_budget_timeout_says_it_was_the_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D52: a budget kill reports the budget and how stale the last output was."""
    adapter = UrlfinderAdapter(finder=lambda _name: "/usr/bin/urlfinder")
    ctx = make_ctx(hosts=["testfire.net"])
    ctx.timeout = 1800.0
    ctx.limits = {"urlfinder": ToolLimits(idle_s=180.0)}
    fake_exec(
        monkeypatch,
        outcome(
            stdout="https://testfire.net/login.jsp\n",
            timed_out=True,
            last_output_s=400.0,
        ),
    )
    result = asyncio.run(adapter.run(ctx))

    # D52: an idle kill is `killed` and exits 0; the stage budget is `timeout`
    # (R13/D45), and both keep the partial output.
    assert result.status is ToolStatus.TIMEOUT
    assert result.error == ("timed out at stage budget 1800s, 1 partial, last output 400s ago")
    assert [record.url for record in result.records] == ["https://testfire.net/login.jsp"]


def test_urlfinder_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome("[INF] Current Version: v0.0.3\n", stderr="some other tool\n"))
    status = UrlfinderAdapter(finder=lambda _name: "/usr/bin/urlfinder").check_installed()
    assert status.installed is False


# ------------------------------------------------- wave 4 (unfurl, wafw00f, whatweb, httpx_tech)


def test_unfurl_adapter_parses_output() -> None:
    """`format '%s://%d%:%P%p?%q'` rebuilds one canonical URL per line."""
    records = UnfurlAdapter().parse_output(fixture("adapters", "unfurl.synthetic.txt"))
    assert [record.url for record in records] == [
        "https://testfire.net/",
        "https://testfire.net/login.jsp?uid=1&pw=2",
        "http://testfire.net/login.jsp",
        "https://demo.testfire.net/bank/queryxpath.jsp?query=1",
    ]
    assert all(isinstance(record, UrlRecord) for record in records)
    assert all(record.source == "unfurl" for record in records)
    adapter = UnfurlAdapter(finder=lambda _name: "/usr/bin/unfurl")
    ctx = make_ctx(hosts=["testfire.net"])
    assert adapter.build_command(ctx)[1:] == ["-u", "format", "%s://%d%:%P%p?%q"]
    # Scheme-pair input, the same order the crawlers get: unfurl has no URL feed.
    assert adapter.stdin_text(ctx) == "https://testfire.net/\nhttp://testfire.net/\n"


def test_unfurl_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    """`-h` writes the usage to stderr; another `unfurl` named binary fails."""
    fake_exec(
        monkeypatch,
        outcome(stderr="Format URLs provided on stdin\n\nUsage:\n  unfurl [OPTIONS] [MODE]\n"),
    )
    accepted = UnfurlAdapter(finder=lambda _name: "/usr/bin/unfurl").check_installed()
    assert accepted.installed is True
    fake_exec(monkeypatch, outcome("urlfinder v0.0.3\n"))
    rejected = UnfurlAdapter(finder=lambda _name: "/usr/bin/unfurl").check_installed()
    assert rejected.installed is False


def test_wafw00f_adapter_parses_waf_detection() -> None:
    """Only `detected: true` becomes a record; the name lands in `waf`."""
    records = Wafw00fAdapter().parse_output(fixture("adapters", "wafw00f.synthetic.json"))
    assert [(record.fqdn, record.waf, record.tech) for record in records] == [
        ("testfire.net", "Cloudflare", [])
    ]
    assert all(record.state is HostState.UNKNOWN for record in records)
    adapter = Wafw00fAdapter(finder=lambda _name: "/usr/bin/wafw00f")
    command = adapter.build_command(make_ctx(hosts=["testfire.net"]))
    assert command[1:6] == ["-a", "-f", "json", "-o", "-"]
    assert command[6:] == ["https://testfire.net/", "http://testfire.net/"]


def test_wafw00f_handles_no_waf_case() -> None:
    """A `detected: false` entry is silence, not an empty answer (cdncheck rule)."""
    raw = (
        '[{"detected": false, "firewall": "None", "manufacturer": "None",'
        ' "trigger_url": null, "url": "http://testfire.net/"}]'
    )
    assert Wafw00fAdapter().parse_output(raw) == []
    assert Wafw00fAdapter().parse_output("") == []


def test_wafw00f_and_cdncheck_merge_or_replace_waf(tmp_path: Path) -> None:
    """WAF is one name chosen by `waf_priority`, not by who finished first (D12).

    Wave 4 found the old rule kept the first non-None `waf` in `results` order
    and the latest pass across runs, so `cdncheck` or `httpx_tech` could beat
    `wafw00f` (or a rerun could flip the winner). The owner ruling made it
    priority-based: wafw00f 100 > cdncheck 80 > whatweb 50 > httpx_tech 20, and
    an equal priority keeps the first writer. Tech still merges as a list.
    """
    db = Store(tmp_path / "recon.db")
    try:
        target_id = db.create_target("testfire.net")
        run_id = db.create_scan_run(target_id, "tech")
        sub_id = db.upsert_subdomain(target_id, "testfire.net", run_id=run_id)
        # The tech stage annotates the live row; it never creates one (D11).
        assert db.update_host_extras(sub_id, waf="cloudflare") is False
        db.append_host_status(sub_id, run_id, "ALIVE")
        engine = Engine(
            load_config(CONFIG),
            db,
            specs={name: get_spec(name) for name in ("wafw00f", "cdncheck")},
            adapters={},
            scope_path=None,
            workspace_root=tmp_path / "workspaces",
        )
        cdncheck = ToolResult(
            tool="cdncheck",
            status=ToolStatus.OK,
            records=[
                HostStatusRecord(
                    fqdn="testfire.net",
                    source="cdncheck",
                    state=HostState.UNKNOWN,
                    tech=["google"],
                    waf="cloudflare",
                )
            ],
        )
        wafw00f = ToolResult(
            tool="wafw00f",
            status=ToolStatus.OK,
            records=[
                HostStatusRecord(
                    fqdn="testfire.net",
                    source="wafw00f",
                    state=HostState.UNKNOWN,
                    waf="Cloudflare",
                )
            ],
        )
        engine._persist_tech(target_id, run_id, [cdncheck, wafw00f], "testfire.net")
        stored = db._conn.execute(
            "SELECT tech_json, waf, waf_priority FROM host_status_history ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert (stored["waf"], stored["waf_priority"]) == ("Cloudflare", 100)
        assert stored["tech_json"] == '["google"]'
        # The tools finishing in the other order produce exactly the same row:
        # the priority decides, and the tech list still merges.
        engine._persist_tech(target_id, run_id, [wafw00f, cdncheck], "testfire.net")
        stored = db._conn.execute(
            "SELECT tech_json, waf, waf_priority FROM host_status_history ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert (stored["waf"], stored["waf_priority"]) == ("Cloudflare", 100)
        assert stored["tech_json"] == '["google"]'
    finally:
        db.close()


def test_whatweb_adapter_parses_tech_list() -> None:
    """Plugin names are the technologies; informational plugins are filtered."""
    records = WhatwebAdapter().parse_output(fixture("adapters", "whatweb.synthetic.json"))
    assert [(record.fqdn, record.tech) for record in records] == [
        ("testfire.net", ["Apache", "HTTPServer", "Java"]),
    ]
    assert all(record.state is HostState.UNKNOWN for record in records)
    adapter = WhatwebAdapter(finder=lambda _name: "/usr/bin/whatweb")
    command = adapter.build_command(make_ctx(hosts=["testfire.net"]))
    # `--quiet` is what makes `--log-json=-` usable: without it whatweb writes its
    # brief to the same closed stream and exits 1 (verified on the real binary).
    assert command[1:7] == ["--quiet", "--log-json=-", "--no-errors", "--color=never", "-a", "1"]
    assert command[7:] == ["https://testfire.net/", "http://testfire.net/"]


def test_whatweb_merges_tech_with_webanalyze(tmp_path: Path) -> None:
    """Tech is a merged list: the row keeps what it had, new names are appended."""
    db = Store(tmp_path / "recon.db")
    try:
        target_id = db.create_target("testfire.net")
        run_id = db.create_scan_run(target_id, "tech")
        sub_id = db.upsert_subdomain(target_id, "testfire.net", run_id=run_id)
        db.append_host_status(
            sub_id, run_id, "ALIVE", tech=["Apache Tomcat", "Java"], tools=["webanalyze"]
        )
        assert db.update_host_extras(sub_id, tech=["Apache", "HTTPServer", "Java"]) is True
        stored = db._conn.execute(
            "SELECT tech_json FROM host_status_history ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert stored["tech_json"] == '["Apache Tomcat", "Java", "Apache", "HTTPServer"]'
    finally:
        db.close()


def test_httpx_tech_adapter_parses_tech_from_httpx_json() -> None:
    """`-td` gives `tech` (and `cdn_name` for `waf`); neither empty is no record."""
    records = HttpxTechAdapter().parse_output(fixture("adapters", "httpx_tech.synthetic.jsonl"))
    assert [(record.fqdn, record.tech, record.waf) for record in records] == [
        ("testfire.net", ["Apache Tomcat", "Java"], "cloudflare"),
        ("www.testfire.net", ["Java"], None),
    ]
    assert all(record.state is HostState.UNKNOWN for record in records)
    assert all(record.source == "httpx_tech" for record in records)


def test_httpx_tech_and_httpx_share_the_invocation_logic() -> None:
    """One command builder, two stages: the tech adapter inherits it unchanged."""
    ctx = make_ctx(hosts=["testfire.net", "www.testfire.net", "testfire.net"])
    live = HttpxAdapter(finder=lambda _name: "/usr/bin/httpx")
    tech = HttpxTechAdapter(finder=lambda _name: "/usr/bin/httpx")
    assert live.build_command(ctx) == tech.build_command(ctx)
    command = tech.build_command(ctx)
    assert "-td" in command
    assert command.count("testfire.net") == 1  # shared dedupe
    assert live.name != tech.name and live.stage is not tech.stage
    # The identity check 01daa8b added is inherited, not re-written.
    assert tech.version_args == live.version_args == ["-version"]
    assert tech.identity_markers == live.identity_markers


def test_httpx_tech_identity_rejects_the_python_httpx_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The namesake Python CLI prints no ProjectDiscovery banner: still rejected."""
    fake_exec(monkeypatch, outcome(stderr="usage: httpx [-h] [--version]\nhttpx: error: ...\n"))
    status = HttpxTechAdapter(finder=lambda _name: "/usr/bin/httpx").check_installed()
    assert status.installed is False


def test_a_javascript_href_is_skipped_not_a_parse_error() -> None:
    """Real hakrawler output on testfire.net carried a `javascript:` href (PIT-52)."""
    raw = (
        "http://testfire.net/index.jsp\n"
        "javascript:checkSiteStatus('AltoroMutual')\n"
        "mailto:info@testfire.net\n"
        "http://testfire.net/login.jsp\n"
    )
    crawlers: tuple[BinaryAdapter, ...] = (
        HakrawlerAdapter(),
        GospiderAdapter(),
        SubjsAdapter(),
        UrlfinderAdapter(),
    )
    for adapter in crawlers:
        urls = [record.url for record in adapter.parse_output(raw) if isinstance(record, UrlRecord)]
        assert urls == ["http://testfire.net/index.jsp", "http://testfire.net/login.jsp"], (
            adapter.name
        )


# --------------------------------------------- wave 5 (nuclei, subzy)


def test_nuclei_adapter_parses_jsonl_findings() -> None:
    """Each JSONL match becomes a FindingRecord with the tool's own severity."""
    records = NucleiAdapter().parse_output(fixture("adapters", "nuclei.synthetic.jsonl"))
    assert [(r.fqdn, r.severity, r.template_id) for r in records] == [
        ("testfire.net", "high", "takeover-detect"),
        ("www.testfire.net", "medium", "exposed-panels"),
        ("testfire.net", "unknown", "tech-detect-generic"),
    ]
    assert all(isinstance(record, FindingRecord) for record in records)
    assert all(record.source == "nuclei" for record in records)
    assert records[0].title == "Subdomain Takeover - Unclaimed S3 Bucket"
    assert records[0].evidence == "https://testfire.net/"
    assert records[1].kind == "http"
    # `severity: unknown` is a real nuclei value (42 installed templates).
    assert records[2].severity == "unknown"


def test_nuclei_adapter_scans_the_given_hosts_with_safe_tags(tmp_path: Path) -> None:
    adapter = NucleiAdapter(finder=lambda _name: "/usr/bin/nuclei")
    ctx = make_ctx(hosts=["testfire.net", "www.testfire.net", "testfire.net"])
    ctx.workspace = tmp_path
    command = adapter.build_command(ctx)
    assert command[1:4] == ["-l", str(tmp_path / f"nuclei-hosts-{os.getpid()}.txt"), "-jsonl"]
    assert "-duc" in command and "-silent" in command and "-nc" in command
    # `-or` keeps the raw request/response out: on a real full run they pushed
    # the JSONL past the 1 MB stdout cap and truncated the last line.
    assert "-or" in command
    assert command[command.index("-tags") + 1] == "takeover,exposure,misconfig"
    assert "-severity" not in command  # severity is stored, never used to hide findings
    assert "-rl" not in command  # no pacing (D3)


def test_nuclei_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome(stdout="[INF] Nuclei Engine Version: v3.11.1\n"))
    accepted = NucleiAdapter(finder=lambda _name: "/usr/bin/nuclei").check_installed()
    assert accepted.installed is True
    fake_exec(monkeypatch, outcome(stdout="nuclei 1.0 — not the scanner\n"))
    rejected = NucleiAdapter(finder=lambda _name: "/usr/bin/nuclei").check_installed()
    assert rejected.installed is False


def test_subzy_adapter_parses_takeover_findings() -> None:
    """Only `vulnerable: true` becomes a finding; a clean name is silence."""
    records = SubzyAdapter().parse_output(fixture("adapters", "subzy.synthetic.json"))
    assert len(records) == 1
    (finding,) = records
    assert isinstance(finding, FindingRecord)
    assert (finding.fqdn, finding.kind, finding.severity) == (
        "old.testfire.net",
        "takeover",
        "high",
    )
    assert finding.title == "subdomain takeover: Amazon S3"
    assert finding.evidence is not None and "can-i-take-over-xyz" in finding.evidence
    assert finding.source == "subzy"


def test_subzy_reads_its_findings_from_the_output_file(tmp_path: Path) -> None:
    """stdout is only the tool's log; the JSON array is in the `--output` file."""
    adapter = SubzyAdapter(finder=lambda _name: "/usr/bin/subzy")
    ctx = make_ctx(hosts=["testfire.net"])
    ctx.workspace = tmp_path

    with pytest.raises(ParseError, match="no --output file"):
        adapter.read_output(ctx)

    output = tmp_path / f"subzy-output-{os.getpid()}.json"
    output.write_text(fixture("adapters", "subzy.synthetic.json"), encoding="utf-8")
    assert "old.testfire.net" in (adapter.read_output(ctx) or "")


async def test_the_base_flow_parses_the_document_a_tool_wrote_to_a_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`read_output` is what makes a --output-only tool usable (wave 5)."""
    adapter = SubzyAdapter(finder=lambda _name: "/usr/bin/subzy")
    ctx = make_ctx(hosts=["testfire.net"])
    ctx.workspace = tmp_path
    document = fixture("adapters", "subzy.synthetic.json")

    def fake(argv: list[str], **_kwargs: object) -> ExecResult:
        output = Path(argv[argv.index("--output") + 1])
        output.write_text(document, encoding="utf-8")
        return outcome(stdout="[ * ] Saved output to the file\n")

    monkeypatch.setattr(base_module, "run_exec", fake)
    result = await adapter.run(ctx)

    assert result.status is ToolStatus.OK
    assert all(isinstance(record, FindingRecord) for record in result.records)
    findings = [record for record in result.records if isinstance(record, FindingRecord)]
    assert [record.fqdn for record in findings] == ["old.testfire.net"]
    assert result.raw_text is not None and "old.testfire.net" in result.raw_text


def test_subzy_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome(stdout="subzy version: v1.2.0\n"))
    accepted = SubzyAdapter(finder=lambda _name: "/usr/bin/subzy").check_installed()
    assert accepted.installed is True
    fake_exec(monkeypatch, outcome(stdout="subzy 9.9 (not a takeover tool)\n"))
    rejected = SubzyAdapter(finder=lambda _name: "/usr/bin/subzy").check_installed()
    assert rejected.installed is False


def test_regression_a_nuclei_host_with_a_port_keeps_its_name() -> None:
    """Regression: PIT-53 - the real tool prints `host` as `host:port`."""
    raw = (
        '{"template-id":"t","info":{"name":"N","severity":"info"},'
        '"type":"http","host":"demo.testfire.net:443"}'
    )
    (record,) = NucleiAdapter().parse_output(raw)
    assert isinstance(record, FindingRecord)
    assert record.fqdn == "demo.testfire.net"
    assert record.evidence is None


def test_dnsreaper_parses_confidence_levels_as_severities() -> None:
    """CONFIRMED/POTENTIAL/UNLIKELY are the tool's real levels (D100)."""
    records = DnsreaperAdapter().parse_output(fixture("adapters", "dnsreaper.synthetic.json"))
    assert [(r.fqdn, r.severity) for r in records] == [
        ("old.testfire.net", "high"),
        ("blog.testfire.net", "medium"),
        ("docs.testfire.net", "low"),
    ]
    assert all(isinstance(record, FindingRecord) for record in records)
    assert all(record.kind == "takeover" for record in records)
    assert all(record.source == "dnsreaper" for record in records)
    first = records[0]
    assert first.title == "subdomain takeover: AWS/S3"
    assert first.template_id == "AWS/S3"
    assert first.evidence is not None and "CNAME: old-testfire.s3.amazonaws.com" in first.evidence


def test_dnsreaper_treats_an_empty_file_as_no_findings() -> None:
    """The real writer emits nothing at all when nothing matched, not `[]`."""
    assert DnsreaperAdapter().parse_output("") == []
    assert DnsreaperAdapter().parse_output("[]") == []


def test_dnsreaper_reads_its_findings_from_the_out_file(tmp_path: Path) -> None:
    adapter = DnsreaperAdapter(finder=lambda _name: "/usr/bin/dnsreaper")
    ctx = make_ctx(hosts=["testfire.net"])
    ctx.workspace = tmp_path

    with pytest.raises(ParseError, match="no --out file"):
        adapter.read_output(ctx)

    output = tmp_path / f"dnsreaper-output-{os.getpid()}.json"
    output.write_text(fixture("adapters", "dnsreaper.synthetic.json"), encoding="utf-8")
    assert "old.testfire.net" in (adapter.read_output(ctx) or "")


def test_dnsreaper_scans_the_given_hosts_with_a_file(tmp_path: Path) -> None:
    adapter = DnsreaperAdapter(finder=lambda _name: "/usr/bin/dnsreaper")
    ctx = make_ctx(hosts=["testfire.net", "www.testfire.net", "testfire.net"])
    ctx.workspace = tmp_path
    command = adapter.build_command(ctx)
    assert command[1] == "file"
    assert command[command.index("--filename") + 1] == str(
        tmp_path / f"dnsreaper-hosts-{os.getpid()}.txt"
    )
    assert command[command.index("--out-format") + 1] == "json"
    assert "--nocolour" in command
    assert "--parallelism" not in command  # the tool's default stands, no pacing (D3)


def test_dnsreaper_identity_rejects_wrong_program(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_exec(
        monkeypatch,
        outcome(stdout="DNS Reaper ☠️\nScan all your DNS records for subdomain takeovers!\n"),
    )
    accepted = DnsreaperAdapter(finder=lambda _name: "/usr/bin/dnsreaper").check_installed()
    assert accepted.installed is True
    fake_exec(monkeypatch, outcome(stdout="dnsreaper 1.0 - not the takeover tool\n"))
    rejected = DnsreaperAdapter(finder=lambda _name: "/usr/bin/dnsreaper").check_installed()
    assert rejected.installed is False


def test_subzy_treats_a_null_document_as_no_findings() -> None:
    """Regression: the real tool writes `null`, not `[]`, when nothing matched."""
    assert SubzyAdapter().parse_output("null\n") == []
    assert SubzyAdapter().parse_output("[]") == []
    assert SubzyAdapter().parse_output("") == []


# ------------------------------------------------- ffuf (wave 5 completion)

from reconkit.adapters.ffuf import DEFAULT_WORDLIST, FfufAdapter  # noqa: E402


def test_ffuf_adapter_parses_json_matches() -> None:
    """Each match is an info finding: a path that exists, not a vulnerability."""
    records = FfufAdapter().parse_output(fixture("adapters", "ffuf.synthetic.json"))
    assert [(r.fqdn, r.title, r.evidence) for r in records] == [
        ("testfire.net", "200 /admin", "https://testfire.net/admin"),
        ("testfire.net", "403 /.env", "https://testfire.net/.env"),
    ]
    assert all(isinstance(record, FindingRecord) for record in records)
    assert all(record.severity == "info" and record.kind == "path" for record in records)
    assert records[0].source == "ffuf"


def test_ffuf_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome(stdout="ffuf version: 2.3.0\n"))
    accepted = FfufAdapter(finder=lambda _name: "/usr/bin/ffuf").check_installed()
    assert accepted.installed is True
    fake_exec(monkeypatch, outcome(stdout="ffuf 1.0 - a different tool\n"))
    rejected = FfufAdapter(finder=lambda _name: "/usr/bin/ffuf").check_installed()
    assert rejected.installed is False


def test_ffuf_uses_default_wordlist_when_no_flag_given() -> None:
    adapter = FfufAdapter(finder=lambda _name: "/usr/bin/ffuf")
    ctx = make_ctx(hosts=["testfire.net"])
    assert ctx.ffuf_wordlist is None
    assert adapter.wordlist(ctx) == DEFAULT_WORDLIST
    assert ctx.ffuf_wordlist is None  # the adapter never mutates its context


def test_ffuf_wordlist_flag_overrides_default(tmp_path: Path) -> None:
    adapter = FfufAdapter(finder=lambda _name: "/usr/bin/ffuf")
    custom = tmp_path / "paths.txt"
    custom.write_text("admin\napi\n", encoding="utf-8")
    ctx = make_ctx(hosts=["testfire.net"])
    ctx.ffuf_wordlist = custom
    assert adapter.wordlist(ctx) == custom
    command = adapter.build_command(ctx)
    assert f"{custom}:FFUF" in command
    assert str(DEFAULT_WORDLIST) not in command


def test_ffuf_default_wordlist_exists_and_is_nonempty() -> None:
    assert DEFAULT_WORDLIST.is_file()
    lines = [line for line in DEFAULT_WORDLIST.read_text(encoding="utf-8").splitlines() if line]
    assert 50 <= len(lines) <= 150
    assert "admin" in lines and ".git/HEAD" in lines and ".env" in lines


def test_ffuf_missing_wordlist_is_a_failed_tool() -> None:
    adapter = FfufAdapter(finder=lambda _name: "/usr/bin/ffuf")
    ctx = make_ctx(hosts=["testfire.net"])
    ctx.ffuf_wordlist = Path("/nonexistent/wordlist.txt")
    with pytest.raises(ToolFailed, match="wordlist not found"):
        adapter.wordlist(ctx)


def test_ffuf_hosts_wordlist_has_no_trailing_slash() -> None:
    """Regression: `FHOST/FFUF` joins literally, so a slash gave `//admin`."""
    adapter = FfufAdapter(finder=lambda _name: "/usr/bin/ffuf")
    ctx = make_ctx(hosts=["testfire.net"])
    assert adapter._roots(ctx) == ["https://testfire.net", "http://testfire.net"]


# -------------------------------------------------------- ports (wave 6)


def test_nmap_adapter_parses_xml_ports() -> None:
    """Two hosts, open ports only, service/version kept as the -sV fingerprint."""
    from reconkit.adapters.nmap import NmapAdapter

    records = NmapAdapter().parse_output(fixture("adapters", "nmap.synthetic.xml"))
    assert [(r.fqdn, r.ip, r.port, r.state, r.service, r.version) for r in records] == [
        (
            "testfire.net",
            "65.61.137.117",
            80,
            "open",
            "http",
            "Apache Tomcat/Coyote JSP engine 1.1",
        ),
        (
            "testfire.net",
            "65.61.137.117",
            443,
            "open",
            "http",
            "Apache Tomcat/Coyote JSP engine 1.1",
        ),
        (
            "shop.testfire.net",
            "65.61.137.118",
            22,
            "open",
            "ssh",
            "OpenSSH 8.9p1 Ubuntu 3ubuntu0.4",
        ),
    ]
    assert all(isinstance(record, PortRecord) and record.source == "nmap" for record in records)


def test_nmap_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    from reconkit.adapters.nmap import NmapAdapter

    fake_exec(monkeypatch, outcome(stdout="Nmap version 7.991 ( https://nmap.org )\n"))
    accepted = NmapAdapter(finder=lambda _name: "/usr/bin/nmap").check_installed()
    assert accepted.installed is True
    assert accepted.version == "7.991"
    fake_exec(monkeypatch, outcome(stdout="ncat 7.94\n"))
    rejected = NmapAdapter(finder=lambda _name: "/usr/bin/nmap").check_installed()
    assert rejected.installed is False


def test_nmap_respects_ports_flag() -> None:
    from reconkit.adapters.nmap import TOP_PORTS, NmapAdapter

    adapter = NmapAdapter(finder=lambda _name: "/usr/bin/nmap")
    plain = adapter.build_command(make_ctx(hosts=["testfire.net"]))
    assert plain[1:3] == ["-sV", "-Pn"]
    assert "-sS" not in plain and "-O" not in plain
    top = plain.index("--top-ports")
    assert plain[top : top + 2] == ["--top-ports", TOP_PORTS]
    assert plain[-1] == "testfire.net"
    chosen = adapter.build_command(make_ctx(hosts=["testfire.net"], ports=[80, 443, 8000]))
    assert ["-p", "80,443,8000"] == chosen[chosen.index("-p") : chosen.index("-p") + 2]
    assert "--top-ports" not in chosen


def test_nmap_parses_the_xml_file_it_wrote(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`-oX` output is read through read_output, not from stdout."""
    from reconkit.adapters.nmap import NmapAdapter

    adapter = NmapAdapter(finder=lambda _name: "/usr/bin/nmap")
    ctx = make_ctx(hosts=["testfire.net"])
    ctx.workspace = tmp_path
    fake_exec(
        monkeypatch,
        outcome(stdout="Starting Nmap 7.991\n"),
        on_call=lambda argv, _kwargs: Path(argv[argv.index("-oX") + 1]).write_text(
            fixture("adapters", "nmap.synthetic.xml"), encoding="utf-8"
        ),
    )
    import asyncio

    result = asyncio.run(adapter.run(ctx))
    assert result.status is ToolStatus.OK
    assert len(result.records) == 3
    assert result.raw_text is not None and result.raw_text.startswith("<?xml")


def test_nmap_malformed_xml_is_a_parse_error() -> None:
    from reconkit.adapters.nmap import NmapAdapter

    with pytest.raises(ParseError, match="invalid XML"):
        NmapAdapter().parse_output("<nmaprun><host></nmaprun>")


def test_rustscan_adapter_parses_plain_ports() -> None:
    from reconkit.adapters.rustscan import RustscanAdapter

    records = RustscanAdapter().parse_output(fixture("adapters", "rustscan.synthetic.txt"))
    assert [(r.fqdn, r.ip, r.port) for r in records] == [
        ("65.61.137.117", "65.61.137.117", 443),
        ("65.61.137.117", "65.61.137.117", 80),
        ("65.61.137.118", "65.61.137.118", 22),
    ]
    assert all(record.state == "open" and record.source == "rustscan" for record in records)


def test_rustscan_single_host_keeps_the_name_it_scanned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Greppable output prints the resolved address; one host means one owner."""
    from reconkit.adapters.rustscan import RustscanAdapter

    adapter = RustscanAdapter(finder=lambda _name: "/usr/bin/rustscan")
    ctx = make_ctx(hosts=["testfire.net"])
    fake_exec(monkeypatch, outcome(stdout="65.61.137.117 -> [443,80]\n"))
    result = asyncio.run(adapter.run(ctx))
    assert [(r.fqdn, r.ip, r.port) for r in result.records if isinstance(r, PortRecord)] == [
        ("testfire.net", "65.61.137.117", 443),
        ("testfire.net", "65.61.137.117", 80),
    ]


def test_rustscan_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    from reconkit.adapters.rustscan import RustscanAdapter

    fake_exec(monkeypatch, outcome(stdout="rustscan 2.3.0\n"))
    assert RustscanAdapter(finder=lambda _name: "/x").check_installed().installed is True
    fake_exec(monkeypatch, outcome(stdout="some other scanner 1.0\n"))
    assert RustscanAdapter(finder=lambda _name: "/x").check_installed().installed is False


def test_rustscan_does_not_need_nmap_in_greppable_mode() -> None:
    """Verified with nmap off PATH: `-g` prints ports itself (`No Nmap`)."""
    from reconkit.adapters.rustscan import RustscanAdapter

    adapter = RustscanAdapter(finder=lambda _name: "/usr/bin/rustscan")
    command = adapter.build_command(make_ctx(hosts=["testfire.net"]))
    assert "-g" in command
    assert "--" not in command and "-oX" not in command
    assert "nmap" not in " ".join(command)


def test_rustscan_respects_ports_flag() -> None:
    from reconkit.adapters.rustscan import RustscanAdapter

    adapter = RustscanAdapter(finder=lambda _name: "/usr/bin/rustscan")
    plain = adapter.build_command(make_ctx(hosts=["testfire.net"]))
    assert plain[-1] == "--top"
    chosen = adapter.build_command(make_ctx(hosts=["testfire.net"], ports=[22, 2222]))
    assert chosen[-2:] == ["-p", "22,2222"]
    assert "--top" not in chosen


def test_smap_adapter_parses_json_ports() -> None:
    from reconkit.adapters.smap import SmapAdapter

    records = SmapAdapter().parse_output(fixture("adapters", "smap.synthetic.json"))
    assert [(r.fqdn, r.ip, r.port, r.service) for r in records] == [
        ("testfire.net", "65.61.137.117", 80, "http?"),
        ("testfire.net", "65.61.137.117", 443, "https?"),
        ("testfire.net", "65.61.137.117", 8080, "http-proxy?"),
    ]
    assert all(record.source == "smap" and record.state == "open" for record in records)


def test_smap_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    from reconkit.adapters.smap import SmapAdapter

    fake_exec(monkeypatch, outcome(stdout="Smap 1.0.0-beta\nUsage: smap <targets here>\n"))
    accepted = SmapAdapter(finder=lambda _name: "/x").check_installed()
    assert accepted.installed is True and accepted.version == "1.0.0"
    fake_exec(monkeypatch, outcome(stdout="Smap-ish 2.0\n"))
    assert SmapAdapter(finder=lambda _name: "/x").check_installed().installed is False


def test_smap_ports_flag_filters_passive_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """smap cannot choose ports, so `--ports` filters what Shodan reported."""
    from reconkit.adapters.smap import SmapAdapter

    adapter = SmapAdapter(finder=lambda _name: "/usr/bin/smap")
    ctx = make_ctx(hosts=["testfire.net"], ports=[443])
    ctx.workspace = tmp_path
    fake_exec(
        monkeypatch,
        outcome(stdout="smap: querying shodan\n"),
        on_call=lambda argv, _kwargs: Path(argv[argv.index("-oJ") + 1]).write_text(
            fixture("adapters", "smap.synthetic.json"), encoding="utf-8"
        ),
    )
    import asyncio

    result = asyncio.run(adapter.run(ctx))
    assert [record.port for record in result.records if isinstance(record, PortRecord)] == [443]


def test_masscan_skips_when_not_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-root: skipped with the reason, and masscan is never spawned."""
    from reconkit.adapters import masscan as masscan_module
    from reconkit.adapters.masscan import MasscanAdapter

    monkeypatch.setattr(masscan_module, "is_root", lambda: False)
    calls = fake_exec(monkeypatch, outcome(stdout="open tcp 80 1.2.3.4 1\n"))
    import asyncio

    result = asyncio.run(MasscanAdapter(finder=lambda _name: "/usr/bin/masscan").run(make_ctx()))
    assert result.status is ToolStatus.SKIPPED
    assert result.error == "requires root / sudo"
    assert calls == []


def test_masscan_adapter_parses_json_ports() -> None:
    from reconkit.adapters.masscan import MasscanAdapter

    records = MasscanAdapter().parse_output(fixture("adapters", "masscan.synthetic.list"))
    assert [(r.fqdn, r.ip, r.port, r.state) for r in records] == [
        ("65.61.137.117", "65.61.137.117", 80, "open"),
        ("65.61.137.117", "65.61.137.117", 443, "open"),
        ("65.61.137.118", "65.61.137.118", 22, "open"),
    ]
    assert all(record.source == "masscan" and record.protocol == "tcp" for record in records)


def test_masscan_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    from reconkit.adapters.masscan import MasscanAdapter

    # `masscan --version` exits 1 while printing a valid banner (PIT-35).
    fake_exec(
        monkeypatch,
        outcome(
            stdout="Masscan version 1.3.2 (https://github.com/robertdavidgraham/masscan)\n",
            returncode=1,
        ),
    )
    accepted = MasscanAdapter(finder=lambda _name: "/x").check_installed()
    assert accepted.installed is True and accepted.version == "1.3.2"
    fake_exec(monkeypatch, outcome(stdout="nmap version 7.99\n"))
    assert MasscanAdapter(finder=lambda _name: "/x").check_installed().installed is False


def test_masscan_builds_ip_targets_and_respects_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    """masscan takes IPs only, so a name is resolved locally and checked."""
    from reconkit.adapters import masscan as masscan_module
    from reconkit.adapters.masscan import MasscanAdapter

    monkeypatch.setattr(masscan_module, "_resolve", lambda host: ["93.184.216.34"])
    adapter = MasscanAdapter(finder=lambda _name: "/usr/bin/masscan")
    ctx = make_ctx(hosts=["example.com"], ports=[80, 443])
    ctx.ip_allowed = lambda ip: True
    command = adapter.build_command(ctx)
    assert command[1] == "93.184.216.34"
    assert command[2] == "-p80,443"
    assert command[command.index("--rate") + 1] == "1000"
    assert "-oL" in command and "--open-only" not in command


def test_masscan_refuses_targets_outside_the_allowed_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from reconkit.adapters import masscan as masscan_module
    from reconkit.adapters.masscan import MasscanAdapter

    monkeypatch.setattr(masscan_module, "_resolve", lambda host: ["203.0.113.9"])
    adapter = MasscanAdapter(finder=lambda _name: "/usr/bin/masscan")
    ctx = make_ctx(hosts=["example.com"])
    ctx.ip_allowed = lambda ip: False
    with pytest.raises(ToolFailed, match="no permitted IP addresses"):
        adapter.build_command(ctx)


def test_ports_adapters_are_registered_with_the_right_stage() -> None:
    from reconkit.adapters.masscan import MasscanAdapter
    from reconkit.adapters.nmap import NmapAdapter
    from reconkit.adapters.rustscan import RustscanAdapter
    from reconkit.adapters.smap import SmapAdapter
    from reconkit.models import Stage

    assert ADAPTERS["nmap"] is NmapAdapter
    assert ADAPTERS["rustscan"] is RustscanAdapter
    assert ADAPTERS["smap"] is SmapAdapter
    assert ADAPTERS["masscan"] is MasscanAdapter
    for name in ("nmap", "rustscan", "smap", "masscan"):
        assert ADAPTERS[name].stage is Stage.PORTS


# --------------------------------------------------------- subs (wave 7)

from reconkit.adapters.amass import AmassAdapter  # noqa: E402
from reconkit.adapters.chaos import ChaosAdapter  # noqa: E402
from reconkit.adapters.findomain import FindomainAdapter  # noqa: E402
from reconkit.adapters.github_subdomains import GithubSubdomainsAdapter  # noqa: E402


def test_amass_adapter_parses_subdomains() -> None:
    """The parsed text is `subs -names` output: one host per line, no decoration."""
    records = AmassAdapter().parse_output(fixture("adapters", "amass.subs.txt"))
    assert [record.fqdn for record in records] == [
        "altoro.testfire.net",
        "demo.testfire.net",
        "demo2.testfire.net",
        "evil.testfire.net",
        "ftp.testfire.net",
        "localhost.testfire.net",
        "testfire.net",
        "www.testfire.net",
    ]
    assert all(record.source == "amass" for record in records)


def test_amass_enum_header_alone_yields_only_the_target() -> None:
    """v5 `enum` stdout is the header only; it used to become one useless record."""
    records = AmassAdapter().parse_output("\nSession Scope\n\nFQDN:\n\ntestfire.net\n")
    assert [record.fqdn for record in records] == ["testfire.net"]


def test_amass_reads_findings_back_from_subs(monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful `enum` is followed by `subs -names`, whose stdout is parsed."""
    replies = [
        outcome(stdout="\nSession Scope\n\nFQDN:\n\ntestfire.net\n"),
        outcome(stdout=fixture("adapters", "amass.subs.txt")),
    ]
    calls: list[list[str]] = []

    def fake(argv: list[str], **_kwargs: object) -> ExecResult:
        calls.append(argv)
        return replies[len(calls) - 1]

    monkeypatch.setattr(base_module, "run_exec", fake)
    adapter = AmassAdapter(finder=lambda _name: "/usr/bin/amass")
    result = asyncio.run(adapter.run(make_ctx(target="testfire.net")))
    assert len(calls) == 2
    assert calls[0][1:4] == ["enum", "-d", "testfire.net"]
    assert calls[1][1:] == ["subs", "-d", "testfire.net", "-names"]
    assert result.status is ToolStatus.OK
    assert len(result.records) == 8
    assert "altoro.testfire.net" in [record.fqdn for record in result.records]


def test_amass_failed_read_back_is_a_failed_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """Findings that can not be read back mean the run produced nothing usable."""
    replies = [
        outcome(stdout="\nSession Scope\n\nFQDN:\n\ntestfire.net\n"),
        outcome(returncode=1, stderr="no database"),
    ]
    calls: list[list[str]] = []

    def fake(argv: list[str], **_kwargs: object) -> ExecResult:
        calls.append(argv)
        return replies[len(calls) - 1]

    monkeypatch.setattr(base_module, "run_exec", fake)
    result = asyncio.run(
        AmassAdapter(finder=lambda _name: "/usr/bin/amass").run(make_ctx(target="testfire.net"))
    )
    assert result.status is ToolStatus.FAILED
    assert result.error is not None and "read-back" in result.error


def test_amass_uses_v5_subcommand_syntax() -> None:
    adapter = AmassAdapter(finder=lambda _name: "/usr/bin/amass")
    command = adapter.build_command(make_ctx(target="testfire.net"))
    assert command[1:4] == ["enum", "-d", "testfire.net"]
    assert "-passive" not in command


def test_amass_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome(stdout="v5.1.3\n\nOWASP Amass Project - @owaspamass\n"))
    assert AmassAdapter(finder=lambda _name: "/x").check_installed().installed is True
    fake_exec(monkeypatch, outcome(stdout="assetfinder 0.1\n"))
    assert AmassAdapter(finder=lambda _name: "/x").check_installed().installed is False


def test_findomain_adapter_parses_plain_subdomains() -> None:
    records = FindomainAdapter().parse_output(fixture("adapters", "findomain.synthetic.txt"))
    assert "www.testfire.net" in [record.fqdn for record in records]
    assert len(records) == 9
    assert all(record.source == "findomain" for record in records)


def test_findomain_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome(stdout="findomain 11.0.0\n"))
    assert FindomainAdapter(finder=lambda _name: "/x").check_installed().installed is True
    fake_exec(monkeypatch, outcome(stdout="subfinder v2\n"))
    assert FindomainAdapter(finder=lambda _name: "/x").check_installed().installed is False


def test_chaos_adapter_parses_subdomains() -> None:
    records = ChaosAdapter().parse_output(fixture("adapters", "chaos.synthetic.txt"))
    assert [record.fqdn for record in records] == [
        "dev.testfire.net",
        "stage.testfire.net",
        "api.testfire.net",
    ]
    assert all(record.source == "chaos" for record in records)


def test_chaos_skips_when_key_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The tool cannot run keyless (`[FTL] PDCP_API_KEY not specified`): a skip."""
    assert ChaosAdapter.requires_env == ("PDCP_API_KEY",)
    adapter = ChaosAdapter(finder=lambda _name: "/usr/bin/chaos")
    command = adapter.build_command(make_ctx(target="testfire.net", env={}))
    assert command[1:] == ["-d", "testfire.net", "-silent", "-duc"]


def test_chaos_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(
        monkeypatch, outcome(stdout="[INF] Current Version: 0.5.2\n chaos.projectdiscovery.io\n")
    )
    assert ChaosAdapter(finder=lambda _name: "/x").check_installed().installed is True
    fake_exec(monkeypatch, outcome(stdout="chaos monkey 1.0\n"))
    assert ChaosAdapter(finder=lambda _name: "/x").check_installed().installed is False


def test_github_subdomains_adapter_parses_output() -> None:
    records = GithubSubdomainsAdapter().parse_output(
        fixture("adapters", "github_subdomains.synthetic.txt")
    )
    assert [record.fqdn for record in records] == [
        "dev.testfire.net",
        "qa.testfire.net",
        "old.testfire.net",
    ]
    assert all(record.source == "github_subdomains" for record in records)


def test_github_subdomains_skips_when_no_token(tmp_path: Path) -> None:
    assert GithubSubdomainsAdapter.requires_env == ("GITHUB_TOKEN",)
    adapter = GithubSubdomainsAdapter(finder=lambda _name: "/usr/bin/github-subdomains")
    ctx = make_ctx(target="testfire.net")
    ctx.workspace = tmp_path
    command = adapter.build_command(ctx)
    # `-o` is always passed: the tool's default writes <domain>.txt into the CWD.
    assert command[3] == "-o"
    assert Path(command[4]).parent == tmp_path


def test_github_subdomains_reads_the_output_file(tmp_path: Path) -> None:
    adapter = GithubSubdomainsAdapter(finder=lambda _name: "/usr/bin/github-subdomains")
    ctx = make_ctx(target="testfire.net")
    ctx.workspace = tmp_path
    output = tmp_path / f"github-subdomains-{os.getpid()}.txt"
    output.write_text("dev.testfire.net\n", encoding="utf-8")
    assert adapter.read_output(ctx) == "dev.testfire.net\n"


# -------------------------------------- dns / shots / vulns (wave 8)

import reconkit.adapters.gowitness as gowitness_module  # noqa: E402
from reconkit.adapters.dig import DigAdapter  # noqa: E402
from reconkit.adapters.gowitness import GowitnessAdapter  # noqa: E402
from reconkit.adapters.massdns import DEFAULT_RESOLVERS, MassdnsAdapter  # noqa: E402
from reconkit.adapters.nikto import NiktoAdapter  # noqa: E402
from reconkit.adapters.puredns import PurednsAdapter  # noqa: E402


def test_dig_adapter_parses_a_records() -> None:
    records = DigAdapter().parse_output(fixture("adapters", "dig.synthetic.txt"))
    by_host = {record.fqdn: record for record in records}
    assert by_host["testfire.net"].ips == ["65.61.137.117"]
    assert by_host["demo.testfire.net"].ips == ["65.61.137.117"]
    assert by_host["www.testfire.net"].cnames == ["testfire.net"]
    assert all(record.source == "dig" for record in records)


def test_dig_ignores_resolver_diagnostics() -> None:
    """2026-11-18: a resolver timeout is a lost lookup, not a corrupt answer.

    A real run of testfire.net failed the whole tool with
    `dig: unexpected answer line ';; communications error to 192.168.31.1#53:
    timed out'`, which turns one resolver hiccup into `dig failed 0 item(s)`.
    """
    raw = (
        ";; communications error to 192.168.31.1#53: timed out\n"
        "; <<>> DiG 9.20 <<>> +noall +answer\n"
        "testfire.net.\t\t300\tIN\tA\t65.61.137.117\n"
    )
    records = DigAdapter().parse_output(raw)
    assert [record.fqdn for record in records] == ["testfire.net"]
    assert records[0].ips == ["65.61.137.117"]


def test_dig_uses_a_hosts_file_not_repeated_arguments(tmp_path: Path) -> None:
    adapter = DigAdapter(finder=lambda _name: "/usr/bin/dig")
    ctx = make_ctx(hosts=["testfire.net", "www.testfire.net"])
    ctx.workspace = tmp_path
    with adapter.prepare(ctx):
        command = adapter.build_command(ctx)
        assert command[1:3] == ["+noall", "+answer"]
        assert command[3] == "-f"
        assert Path(command[4]).read_text(encoding="utf-8") == "testfire.net\nwww.testfire.net\n"
    assert not Path(command[4]).exists()


def test_dig_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome(stdout="DiG 9.20.30-1-Debian\n"))
    assert DigAdapter(finder=lambda _name: "/x").check_installed().installed is True
    fake_exec(monkeypatch, outcome(stdout="nslookup 1.0\n"))
    assert DigAdapter(finder=lambda _name: "/x").check_installed().installed is False


def test_massdns_adapter_parses_output() -> None:
    records = MassdnsAdapter().parse_output(fixture("adapters", "massdns.synthetic.txt"))
    by_host = {record.fqdn: record for record in records}
    assert by_host["testfire.net"].ips == ["65.61.137.117"]
    assert by_host["www.testfire.net"].cnames == ["testfire.net"]
    assert all(record.source == "massdns" for record in records)


def test_massdns_uses_bundled_resolvers(tmp_path: Path) -> None:
    adapter = MassdnsAdapter(finder=lambda _name: "/usr/bin/massdns")
    ctx = make_ctx(hosts=["testfire.net"])
    ctx.workspace = tmp_path
    assert ctx.resolvers is None
    with adapter.prepare(ctx):
        command = adapter.build_command(ctx)
    assert DEFAULT_RESOLVERS.is_file()
    assert str(DEFAULT_RESOLVERS) in command
    assert command[command.index("-o") + 1] == "S"


def test_massdns_resolvers_flag_overrides(tmp_path: Path) -> None:
    adapter = MassdnsAdapter(finder=lambda _name: "/usr/bin/massdns")
    custom = tmp_path / "my-resolvers.txt"
    custom.write_text("1.1.1.1\n", encoding="utf-8")
    ctx = make_ctx(hosts=["testfire.net"], resolvers=custom)
    ctx.workspace = tmp_path
    with adapter.prepare(ctx):
        command = adapter.build_command(ctx)
    assert str(custom) in command
    assert str(DEFAULT_RESOLVERS) not in command


def test_massdns_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(
        monkeypatch,
        outcome(
            stdout="massdns \nUsage: massdns [options] [domainlist]\n -r --resolvers text file\n"
        ),
    )
    assert MassdnsAdapter(finder=lambda _name: "/x").check_installed().installed is True
    fake_exec(monkeypatch, outcome(stdout="dnsx 1.0\n"))
    assert MassdnsAdapter(finder=lambda _name: "/x").check_installed().installed is False


def test_puredns_adapter_parses_output() -> None:
    records = PurednsAdapter().parse_output(fixture("adapters", "puredns.synthetic.txt"))
    assert [record.fqdn for record in records] == [
        "testfire.net",
        "www.testfire.net",
        "demo.testfire.net",
    ]
    assert all(record.source == "puredns" for record in records)


def test_puredns_points_at_the_resolved_massdns_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "reconkit.adapters.puredns.which",
        lambda name: "/usr/bin/massdns" if name == "massdns" else None,
    )
    adapter = PurednsAdapter(finder=lambda _name: "/usr/bin/puredns")
    ctx = make_ctx(hosts=["testfire.net"])
    ctx.workspace = tmp_path
    with adapter.prepare(ctx):
        command = adapter.build_command(ctx)
    assert command[1] == "resolve"
    assert "-b" in command
    assert command[command.index("-b") + 1].endswith("massdns")


def test_puredns_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome(stdout="puredns version v2.1.1\n"))
    assert PurednsAdapter(finder=lambda _name: "/x").check_installed().installed is True
    fake_exec(monkeypatch, outcome(stdout="massdns \n"))
    assert PurednsAdapter(finder=lambda _name: "/x").check_installed().installed is False


def test_nikto_adapter_parses_findings() -> None:
    records = NiktoAdapter().parse_output(fixture("adapters", "nikto.synthetic.json"))
    assert [(record.fqdn, record.title, record.evidence) for record in records] == [
        (
            "testfire.net",
            "Web Server returns a valid response with junk HTTP methods "
            "which may cause false positives.",
            "testfire.net:80/",
        ),
        ("testfire.net", "/admin/: Admin login page/section found.", "testfire.net:80/admin/"),
    ]
    assert all(isinstance(record, FindingRecord) for record in records)
    assert all(record.severity == "info" and record.kind == "nikto" for record in records)


def test_nikto_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome(stdout="Nikto 2.6.1 (LW 2.5)\n"))
    assert NiktoAdapter(finder=lambda _name: "/x").check_installed().installed is True
    fake_exec(monkeypatch, outcome(stdout="nmap 7.99\n"))
    assert NiktoAdapter(finder=lambda _name: "/x").check_installed().installed is False


def test_nikto_runs_once_per_host_with_json_output(tmp_path: Path) -> None:
    adapter = NiktoAdapter(finder=lambda _name: "/usr/bin/nikto")
    ctx = make_ctx(hosts=["testfire.net", "www.testfire.net"])
    ctx.workspace = tmp_path
    command = adapter._command(ctx, "testfire.net", 0, 75.0)
    assert command[1:3] == ["-h", "testfire.net"]
    assert command[command.index("-maxtime") + 1] == "75s"
    assert command[command.index("-Format") + 1] == "json"
    assert command[command.index("-output") + 1].endswith(".json")


def test_nikto_shares_the_stage_budget_across_hosts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: PIT-55 one slow host must not use the whole stage budget.

    The engine cancels the tool at `ctx.timeout`, so a single host allowed to
    run for the entire budget left nikto with a timeout and 0 findings on every
    real full run. Each host now gets the remaining time divided by the hosts
    still to run.
    """
    adapter = NiktoAdapter(finder=lambda _name: "/usr/bin/nikto")
    ctx = make_ctx(hosts=["a.testfire.net", "b.testfire.net", "c.testfire.net"])
    ctx.timeout = 30.0
    ctx.workspace = tmp_path
    calls: list[float] = []

    def fake(argv: list[str], **kwargs: object) -> ExecResult:
        calls.append(float(kwargs["timeout"]))  # type: ignore[arg-type]
        Path(argv[argv.index("-output") + 1]).write_text(
            fixture("adapters", "nikto.synthetic.json"), encoding="utf-8"
        )
        return outcome()

    monkeypatch.setattr(nikto_module, "run_exec", fake)
    result = asyncio.run(adapter.run(ctx))

    assert result.status is ToolStatus.OK
    assert len(calls) == 3
    # The first host gets a third of the budget; a host that returns at once
    # hands its unused time to the next one, but no share may exceed the budget.
    assert calls[0] <= 10.1
    assert all(1.0 <= value <= 30.0 for value in calls)


def test_gowitness_writes_screenshots_and_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Screenshots are per-run files plus a JSONL manifest (D17, no DB row)."""
    adapter = GowitnessAdapter(finder=lambda _name: "/usr/bin/gowitness")
    results_root = tmp_path / "results"
    ctx = make_ctx(hosts=["testfire.net"])
    monkeypatch.setattr(adapter, "run_dir", lambda _ctx: results_root / "testfire.net" / "run1")
    shots = results_root / "testfire.net" / "run1" / "screenshots"

    def on_call(argv: list[str]) -> None:
        target = Path(argv[argv.index("-s") + 1])
        target.mkdir(parents=True, exist_ok=True)
        (target / "testfire.net.png").write_bytes(b"\x89PNG\r\n")

    def fake(argv: list[str], **_kwargs: object) -> ExecResult:
        on_call(argv)
        return outcome(stdout="")

    # gowitness calls run_exec from its own module namespace, not base's.
    monkeypatch.setattr(gowitness_module, "run_exec", fake)
    result = asyncio.run(adapter.run(ctx))
    assert result.status is ToolStatus.OK
    assert [record.url for record in result.records] == ["https://testfire.net"]
    manifest = results_root / "testfire.net" / "run1" / "screenshots.jsonl"
    entry = json.loads(manifest.read_text(encoding="utf-8").strip())
    assert set(entry) == {"url", "path", "timestamp"}
    assert entry["url"] == "https://testfire.net"
    assert entry["path"].endswith("testfire.net.png")
    assert shots.is_dir()


def test_gowitness_manifest_format_is_one_json_object_per_line() -> None:
    manifest = '{"path": "/tmp/a.png", "timestamp": "2026-11-17T00:00:00+00:00", "url": "https://a.example"}\n'
    entry = json.loads(manifest.strip())
    assert sorted(entry) == ["path", "timestamp", "url"]


def test_gowitness_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome(stdout="gowitness: 3.2.2\ngit hash: dev\n"))
    assert GowitnessAdapter(finder=lambda _name: "/x").check_installed().installed is True
    fake_exec(monkeypatch, outcome(stdout="screenshot-tool 1.0\n"))
    assert GowitnessAdapter(finder=lambda _name: "/x").check_installed().installed is False


def test_gowitness_without_a_browser_is_a_gap_not_a_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D35: gowitness ran, the box has no Chromium -> gap, never exit 5.

    Regression: the run answered `ok 0` with a per-host \"no screenshot\" note,
    which read like a reconkit fault and produced no gap for the operator.
    """
    from reconkit.adapters.gowitness import NO_BROWSER_ERROR

    adapter = GowitnessAdapter(finder=lambda _name: "/usr/bin/gowitness")
    ctx = make_ctx(hosts=["testfire.net"])
    monkeypatch.setattr(
        adapter, "run_dir", lambda _ctx: tmp_path / "results" / "testfire.net" / "run1"
    )

    def fake(argv: list[str], **_kwargs: object) -> ExecResult:
        return outcome(stderr="Error: failed to initialize chrome context: exec: no chrome\n")

    # gowitness calls run_exec from its own module namespace, not base's.
    monkeypatch.setattr(gowitness_module, "run_exec", fake)
    result = asyncio.run(adapter.run(ctx))

    assert result.status is ToolStatus.GAP
    assert result.error == NO_BROWSER_ERROR
    assert result.records == []


def test_gowitness_zero_screenshots_without_a_browser_message_stays_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A page that simply produced no PNG is not a missing browser (D35)."""
    adapter = GowitnessAdapter(finder=lambda _name: "/usr/bin/gowitness")
    ctx = make_ctx(hosts=["testfire.net"])
    monkeypatch.setattr(
        adapter, "run_dir", lambda _ctx: tmp_path / "results" / "testfire.net" / "run1"
    )

    def fake(argv: list[str], **_kwargs: object) -> ExecResult:
        return outcome(stdout="scan finished: 0 screenshots\n")

    monkeypatch.setattr(gowitness_module, "run_exec", fake)
    result = asyncio.run(adapter.run(ctx))

    assert result.status is ToolStatus.OK
    assert result.error is not None and "no screenshot" in result.error


# ------------------------------------- D53: per-request timeouts are constants
#
# `ctx.timeout` is the stage budget and belongs to the hard wall only. Before
# D53 these adapters passed it straight into a per-request flag, so a 600 s
# solution-wide default (and now a whole stage budget) became one request's
# timeout. Each helper below observes the number an adapter actually hands to
# its tool or client when the stage budget is 1800 s - the old bug case.


def _argv_flag(argv: list[str], flag: str) -> float:
    return float(argv[argv.index(flag) + 1])


def _hakrawler_request_timeout(_monkeypatch: pytest.MonkeyPatch, _tmp_path: Path) -> float:
    adapter = HakrawlerAdapter(finder=lambda _name: "/usr/bin/hakrawler")
    ctx = make_ctx(hosts=["a.example.com"], timeout=1800.0)
    return _argv_flag(adapter.build_command(ctx), "-timeout")


def _gospider_request_timeout(_monkeypatch: pytest.MonkeyPatch, _tmp_path: Path) -> float:
    adapter = GospiderAdapter(finder=lambda _name: "/usr/bin/gospider")
    ctx = make_ctx(hosts=["a.example.com"], timeout=1800.0)
    return _argv_flag(adapter.build_command(ctx), "-m")


def _subjs_request_timeout(_monkeypatch: pytest.MonkeyPatch, _tmp_path: Path) -> float:
    adapter = SubjsAdapter(finder=lambda _name: "/usr/bin/subjs")
    ctx = make_ctx(hosts=["a.example.com"], timeout=1800.0)
    return _argv_flag(adapter.build_command(ctx), "-t")


def _httprobe_request_timeout(_monkeypatch: pytest.MonkeyPatch, _tmp_path: Path) -> float:
    adapter = HttprobeAdapter(finder=lambda _name: "/usr/bin/httprobe")
    ctx = make_ctx(hosts=["a.example.com"], timeout=1800.0)
    # `-t` is milliseconds; the observed value is seconds so every row compares.
    return _argv_flag(adapter.build_command(ctx), "-t") / 1000


def _gowitness_request_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> float:
    adapter = GowitnessAdapter(finder=lambda _name: "/usr/bin/gowitness")
    monkeypatch.setattr(adapter, "run_dir", lambda _ctx: tmp_path / "run")
    seen: list[float] = []

    def fake(argv: list[str], **kwargs: object) -> ExecResult:
        seen.append(float(kwargs["timeout"]))  # type: ignore[arg-type]
        return outcome(stdout="")

    monkeypatch.setattr(gowitness_module, "run_exec", fake)
    asyncio.run(adapter.run(make_ctx(hosts=["testfire.net"], timeout=1800.0)))
    assert seen
    return seen[0]


def _pyscan_request_timeout(monkeypatch: pytest.MonkeyPatch, _tmp_path: Path) -> float:
    from reconkit.adapters import pyscan as pyscan_module

    seen: list[float] = []

    async def fake_wait_for(awaitable: object, timeout: object) -> object:
        seen.append(float(timeout))  # type: ignore[arg-type]
        return await awaitable  # type: ignore[misc]

    class Writer:
        def close(self) -> None:
            return None

        async def wait_closed(self) -> None:
            return None

    async def connect(_ip: str, _port: int) -> tuple[None, Writer]:
        return None, Writer()

    monkeypatch.setattr(pyscan_module.asyncio, "wait_for", fake_wait_for)
    adapter = pyscan_module.PyscanAdapter(connect=connect)
    asyncio.run(adapter._probe(make_ctx(timeout=1800.0), "203.0.113.5", 80))
    assert seen
    return seen[0]


@pytest.mark.parametrize(
    ("observe", "expected_s"),
    [
        (_hakrawler_request_timeout, 10.0),
        (_gospider_request_timeout, 10.0),
        (_subjs_request_timeout, 10.0),
        (_httprobe_request_timeout, 10.0),
        (_gowitness_request_timeout, 30.0),
        (_pyscan_request_timeout, 5.0),
    ],
    ids=["hakrawler", "gospider", "subjs", "httprobe", "gowitness", "pyscan"],
)
def test_request_timeout_is_a_constant(
    observe: Callable[[pytest.MonkeyPatch, Path], float],
    expected_s: float,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Six adapters, six constants: none of them may see the 1800 s stage budget."""
    assert observe(monkeypatch, tmp_path) == pytest.approx(expected_s)


def test_hakrawler_timeout_is_a_constant_not_the_stage_budget() -> None:
    """D53: `-timeout` is seconds per URL, so the stage budget never reaches it."""
    adapter = HakrawlerAdapter(finder=lambda _name: "/usr/bin/hakrawler")
    argv = adapter.build_command(make_ctx(hosts=["testfire.net"], timeout=1800.0))
    assert argv[argv.index("-timeout") + 1] == "10"
    assert "1800" not in argv


def test_httprobe_timeout_is_milliseconds_constant() -> None:
    """D53: `-t` is per-probe milliseconds; 1800 s must not become 1 800 000."""
    adapter = HttprobeAdapter(finder=lambda _name: "/usr/bin/httprobe")
    argv = adapter.build_command(make_ctx(hosts=["testfire.net"], timeout=1800.0))
    assert argv[argv.index("-t") + 1] == "10000"
    assert "1800000" not in argv


def test_an_adapter_with_no_request_flag_is_unaffected(monkeypatch: pytest.MonkeyPatch) -> None:
    """D53 leaves the hard wall alone: `run_exec` still gets `ctx.timeout`."""
    calls = fake_exec(monkeypatch, outcome(stdout="a.example.com\n"))
    adapter = AssetfinderAdapter(finder=lambda _name: "/usr/bin/assetfinder")
    asyncio.run(adapter.run(make_ctx(timeout=1800.0)))
    assert calls
    assert float(calls[0][1]["timeout"]) == pytest.approx(1800.0)  # type: ignore[arg-type]
