"""Binary adapter tests: fake run_exec, synthetic fixtures, no installed tools."""

from __future__ import annotations

import ast
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
from reconkit.adapters import subfinder as subfinder_module
from reconkit.adapters.assetfinder import AssetfinderAdapter
from reconkit.adapters.base import BinaryAdapter
from reconkit.adapters.cdncheck import CdncheckAdapter
from reconkit.adapters.dnsx import DnsxAdapter
from reconkit.adapters.gau import GauAdapter
from reconkit.adapters.httprobe import HttprobeAdapter
from reconkit.adapters.httpx_tool import HttpxAdapter
from reconkit.adapters.katana import KatanaAdapter
from reconkit.adapters.naabu import NaabuAdapter
from reconkit.adapters.registry import get_spec, load_tools
from reconkit.adapters.subfinder import (
    PROVIDERS,
    STALE_AFTER_S,
    SubfinderAdapter,
    cleanup_stale_provider_dirs,
)
from reconkit.adapters.tlsx import TlsxAdapter
from reconkit.adapters.waybackurls import WaybackurlsAdapter
from reconkit.adapters.webanalyze import WebanalyzeAdapter
from reconkit.core.runner import ExecResult
from reconkit.errors import ToolFailed
from reconkit.models import (
    HostState,
    HostStatusRecord,
    PortRecord,
    RunContext,
    SubdomainRecord,
    ToolStatus,
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
) -> RunContext:
    return RunContext(
        target="example.com",
        hosts=hosts or [],
        ports=ports or [],
        timeout=5.0,
        workspace=REPO / "workspaces" / "example.com",
        mock=mock,
        env=env or {},
        headers=headers or {},
        user_agent=user_agent,
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
) -> ExecResult:
    return ExecResult(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        truncated=truncated,
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
    assert calls[0][1]["env"] == {"HOME": str(isolated_home)}


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
    fake_exec(monkeypatch, outcome(timed_out=True, returncode=None))
    result = await HttpxAdapter().run(make_ctx(hosts=["www.example.com"]))
    assert result.status is ToolStatus.TIMEOUT
    assert result.error == "timed out"


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
    """Windows has no safe liveness probe; the documented fallback is the age rule."""
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
    fake_exec(monkeypatch, outcome(stdout="a.example.com\n", timed_out=True))
    result = await SubfinderAdapter().run(make_ctx())
    assert result.status is ToolStatus.TIMEOUT
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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_exec(
        monkeypatch,
        outcome(
            stderr="error: can not open apps file : could not find the technologies file: "
            "technologies.json\n",
            returncode=1,
        ),
    )
    result = await WebanalyzeAdapter(finder=lambda _name: "/usr/bin/webanalyze").run(
        make_ctx(hosts=["testfire.net"])
    )
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


def test_waybackurls_identity_rejects_wrong_program(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_exec(monkeypatch, outcome("Usage of /usr/bin/waybackurls:\n  -other\n"))
    status = WaybackurlsAdapter(finder=lambda _name: "/usr/bin/waybackurls").check_installed()
    assert status.installed is False
