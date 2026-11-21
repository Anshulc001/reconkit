"""Part 6a: engine pipeline, selection, gating, env, timeout and redaction."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import ssl
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from reconkit import engine as engine_module
from reconkit.adapters import base as base_module
from reconkit.adapters import subfinder as subfinder_module
from reconkit.adapters.base import BaseToolAdapter
from reconkit.adapters.dnspython import DnsOutcome, DnsResult
from reconkit.adapters.registry import ToolKey, ToolSpec, get_spec
from reconkit.adapters.subfinder import SubfinderAdapter
from reconkit.adapters.tlsx import TlsxAdapter
from reconkit.config import load_config
from reconkit.core.runner import MAX_OUTPUT_BYTES, ExecResult
from reconkit.core.scope import ScopeGate
from reconkit.core.store import REDACTED, Store
from reconkit.core.workspace import Workspace
from reconkit.engine import (
    MODE_STAGES,
    MODE_TOOLS,
    STAGE_ORDER,
    UNREACHABLE,
    UNTRUSTED,
    CompletionGap,
    DnsSignal,
    Engine,
    ExitCode,
    HostEvidence,
    HostSnapshot,
    ScanOptions,
    ScanSummary,
    allowed_tiers,
    confidence_for,
    decide_host_state,
)
from reconkit.errors import ConfigError
from reconkit.models import (
    Confidence,
    HostState,
    HostStatusRecord,
    Mode,
    PortRecord,
    Record,
    RunContext,
    Stage,
    SubdomainRecord,
    Tier,
    ToolResult,
    ToolStatus,
    UrlRecord,
)
from reconkit.ui import REPORT_FIELDS, report_text

REPO = Path(__file__).resolve().parents[1]
CONFIG = REPO / "config.yaml"
SCOPE = """\
authorization: "engagement 2026-11"
expires: 2099-01-01
in_scope:
  - example.com
  - "*.example.com"
out_of_scope:
  - api.example.com
allow_active: true
max_speed: fast
"""

# D56: an included range with one excluded half, so one predicate answers both.
SCOPE_WITH_EXCLUSIONS = (
    SCOPE + "in_scope_cidrs:\n  - 203.0.113.0/24\nexclude_cidrs:\n  - 203.0.113.128/25\n"
)


class SilentRng:
    def __init__(self) -> None:
        self._next = 0

    def uniform(self, low: float, _high: float) -> float:
        return low

    def shuffle(self, items: list[object]) -> None:
        return None

    def choice(self, seq: str) -> str:
        # Deterministic but varying, so random labels stay unique (PIT-13).
        value = seq[self._next % len(seq)]
        self._next += 1
        return value


class Recorder:
    def __init__(self) -> None:
        self.names: list[str] = []
        self.hosts: list[list[str]] = []
        self.envs: list[dict[str, str]] = []
        self.built: list[str] = []
        self.user_agents: list[str | None] = []


def adapter(
    name: str,
    stage: Stage,
    rec: Recorder,
    *,
    records: list[Record] | None = None,
    error: Exception | None = None,
    wait: bool = False,
    raw_text: str | None = None,
    status: ToolStatus = ToolStatus.OK,
    duration_s: float = 0.0,
    delay: float = 0.0,
    detail: str | None = None,
) -> type[BaseToolAdapter]:
    class Fake(BaseToolAdapter):
        async def run(self, ctx: RunContext) -> ToolResult:
            rec.names.append(name)
            rec.hosts.append(list(ctx.hosts))
            rec.envs.append(dict(ctx.env))
            rec.user_agents.append(ctx.user_agent)
            if error is not None:
                raise error
            if wait:
                await asyncio.Event().wait()
            if delay:
                await asyncio.sleep(delay)
            return ToolResult(
                tool=name,
                status=status,
                records=records or [],
                duration_s=duration_s,
                error=detail
                if status in (ToolStatus.OK, ToolStatus.GAP) and detail is not None
                else (None if status is ToolStatus.OK else "exit 1: boom"),
                raw_text=raw_text,
            )

        def build_command(self, ctx: RunContext) -> list[str]:
            rec.built.append(name)
            raise AssertionError("build_command must not be called")

        def parse_output(self, raw: str) -> list[object]:
            return []

    Fake.name = name
    Fake.stage = stage
    return Fake


def tool(
    name: str,
    stage: Stage,
    *,
    tier: Tier = Tier.CORE,
    mode: Mode = Mode.PASSIVE,
    keys: tuple[ToolKey, ...] = (),
    exploitation: bool = False,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        stage=stage,
        kind="python",
        tier=tier,
        mode=mode,
        phase=2,
        keys=keys,
        exploitation=exploitation,
    )


def sub(fqdn: str) -> SubdomainRecord:
    return SubdomainRecord(fqdn=fqdn, source="fake")


def alive(fqdn: str) -> HostStatusRecord:
    return HostStatusRecord(fqdn=fqdn, source="fake", state=HostState.ALIVE)


def host(fqdn: str, state: HostState, source: str = "fake") -> HostStatusRecord:
    return HostStatusRecord(fqdn=fqdn, source=source, state=state)


def unknown(fqdn: str, detail: str, source: str = "fake") -> HostStatusRecord:
    return HostStatusRecord(fqdn=fqdn, source=source, state=HostState.UNKNOWN, detail=detail)


def make_engine(
    tmp_path: Path,
    specs: Mapping[str, ToolSpec],
    adapters: Mapping[str, type[BaseToolAdapter]],
    *,
    env: dict[str, str] | None = None,
    store: Store | None = None,
    scope_text: str | None = SCOPE,
    now: Callable[[], str] | None = None,
    installed: Callable[[type[BaseToolAdapter]], bool] | None = None,
    resolve: Callable[[str], object] | None = None,
    user_agent: str | None = None,
    activity: Callable[[str], None] | None = None,
    progress: Callable[[str], None] | None = None,
    url_probe_transport: object | None = None,
) -> Engine:
    config = load_config(CONFIG)
    if user_agent is not None:
        config.user_agent = user_agent
    tmp_path.mkdir(parents=True, exist_ok=True)
    store = store if store is not None else Store(tmp_path / "recon.db")
    scope = tmp_path / "scope.yaml"
    # scope_text=None is the documented no-scope-file mode (docs/05 rule 2):
    # the path is still handed to the engine and simply does not exist.
    if scope_text is not None:
        scope.write_text(scope_text, encoding="utf-8")
    return Engine(
        config,
        store,
        specs=specs,
        adapters=adapters,
        scope_path=scope,
        workspace_root=tmp_path / "workspaces",
        env=env or {},
        rng=SilentRng(),
        installed=installed,
        now=now,
        resolve=resolve,
        activity=activity,
        progress=progress,
        url_probe_transport=url_probe_transport,
    )


def rows(store: Store, sql: str) -> list[object]:
    return list(store._conn.execute(sql).fetchall())


async def test_stage_order_and_tool_rows(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {
        "subs-fake": tool("subs-fake", Stage.SUBS),
        "dns-fake": tool("dns-fake", Stage.DNS),
        "live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE),
        "ports-fake": tool("ports-fake", Stage.PORTS, mode=Mode.ACTIVE),
        "tech-fake": tool("tech-fake", Stage.TECH, mode=Mode.ACTIVE),
        "urls-fake": tool("urls-fake", Stage.URLS, mode=Mode.ACTIVE),
        "vulns-fake": tool("vulns-fake", Stage.VULNS, mode=Mode.ACTIVE),
    }
    adapters = {
        "subs-fake": adapter("subs-fake", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "dns-fake": adapter("dns-fake", Stage.DNS, rec, records=[sub("www.example.com")]),
        "live-fake": adapter("live-fake", Stage.LIVE, rec, records=[alive("www.example.com")]),
        "ports-fake": adapter(
            "ports-fake",
            Stage.PORTS,
            rec,
            records=[
                PortRecord(
                    fqdn="www.example.com", ip="1.2.3.4", port=443, state="open", source="fake"
                )
            ],
        ),
        "tech-fake": adapter("tech-fake", Stage.TECH, rec, records=[alive("www.example.com")]),
        "urls-fake": adapter(
            "urls-fake",
            Stage.URLS,
            rec,
            records=[UrlRecord(url="https://www.example.com/a", source="fake")],
        ),
        "vulns-fake": adapter("vulns-fake", Stage.VULNS, rec, records=[]),
    }
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run("example.com", ScanOptions(active=True, mock=True))
    assert rec.names == [
        "subs-fake",
        "dns-fake",
        "live-fake",
        "ports-fake",
        "tech-fake",
        "urls-fake",
        "vulns-fake",
    ]
    # Pipeline order. `shots` has no spec in this fixture, so the stage selects
    # nothing and produces no outcome (D19 wired the stage, not the fake tools).
    assert [stage.stage for stage in summary.stages] == [
        stage for stage in STAGE_ORDER if stage is not Stage.SHOTS
    ]
    assert rec.built == []
    statuses = rows(engine.store, "SELECT tool, status FROM tool_runs ORDER BY id")
    assert [(row["tool"], row["status"]) for row in statuses] == [
        (name, "ok") for name in rec.names
    ]


async def test_ports_stage_command_uses_stored_alive_hosts(tmp_path: Path) -> None:
    """PIT-67: a standalone `ports` run had no hosts and silently did nothing.

    The stage command has no `live` stage, so `_stage_hosts(PORTS)` only saw the
    in-memory alive set, which was empty; the stage was skipped, no scan_runs
    row existed, and the table showed `Ports -` with exit 0 (a real
    `reconkit ports -d slice.bank.in` after a completed `--active` run,
    2026-11-20). Seed every run that has no discovery stage of its own from the
    hosts an earlier run already stored.
    """
    rec = Recorder()
    specs = {"ports-fake": tool("ports-fake", Stage.PORTS, mode=Mode.ACTIVE)}
    adapters = {"ports-fake": adapter("ports-fake", Stage.PORTS, rec)}
    engine = make_engine(tmp_path, specs, adapters, installed=lambda _adapter: True)
    target_id = engine.store.create_target("example.com")
    run_id = engine.store.create_scan_run(target_id, "live")
    engine.store.upsert_subdomain(
        target_id, "www.example.com", run_id=run_id, state="ALIVE", provenance="subs"
    )
    engine.store.finish_scan_run(run_id, "completed")

    summary = await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.PORTS,), active=True, no_scope=True, mock=True),
    )

    assert rec.names == ["ports-fake"]
    assert rec.hosts == [["www.example.com"]]
    stages = rows(engine.store, "SELECT stage FROM scan_runs ORDER BY id")
    assert [row["stage"] for row in stages] == ["live", "ports"]
    assert summary.exit_code is ExitCode.SUCCESS


async def test_ports_stage_skips_cdn_waf_fronted_hosts(tmp_path: Path) -> None:
    """docs/05 rule 7 (D110): scanning a CDN/WAF edge records the edge's ports.

    A real `slice.bank.in` scan stored 2982 "open" ports for b.slice.bank.in
    (Cloudflare, 172.65.64.158): TCP connected on 1, 3, 7, 9, 31337 and 65389.
    The pre-check was documented but not implemented, so the stage must now skip
    a host whose stored status carries a CDN/WAF name and scan the rest.
    """
    rec = Recorder()
    specs = {"ports-fake": tool("ports-fake", Stage.PORTS, mode=Mode.ACTIVE)}
    adapters = {"ports-fake": adapter("ports-fake", Stage.PORTS, rec)}
    engine = make_engine(tmp_path, specs, adapters, installed=lambda _adapter: True)
    target_id = engine.store.create_target("example.com")
    run_id = engine.store.create_scan_run(target_id, "live")
    engine.store.upsert_subdomain(
        target_id, "www.example.com", run_id=run_id, state="ALIVE", provenance="subs"
    )
    fronted_id = engine.store.upsert_subdomain(
        target_id, "cdn.example.com", run_id=run_id, state="ALIVE", provenance="subs"
    )
    engine.store.append_host_status(fronted_id, run_id, "ALIVE", waf="Cloudflare")
    engine.store.finish_scan_run(run_id, "completed")

    summary = await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.PORTS,), active=True, no_scope=True, mock=True),
    )

    assert rec.names == ["ports-fake"]
    assert rec.hosts == [["www.example.com"]]
    assert summary.exit_code is ExitCode.SUCCESS


async def test_tools_flag_overrides_tier_gating(tmp_path: Path) -> None:
    """A named tool runs whatever its tier; an unknown name is still a usage error.

    Changed 2026-11-17 from `test_tier_gating_and_explicit_intrusive_refusal`:
    the old test asserted that `--tools intrusive` raised ConfigError, which is
    exactly the rule the owner replaced (an explicit name now bypasses tier
    gating). Tier gating without a name is asserted here too.
    """
    rec = Recorder()
    specs = {
        "core": tool("core", Stage.SUBS),
        "noisy": tool("noisy", Stage.SUBS, tier=Tier.OPT_IN),
        "intrusive": tool("intrusive", Stage.SUBS, tier=Tier.INTRUSIVE),
    }
    adapters = {
        "core": adapter("core", Stage.SUBS, rec, records=[]),
        "noisy": adapter("noisy", Stage.SUBS, rec, records=[]),
        "intrusive": adapter("intrusive", Stage.SUBS, rec, records=[]),
    }
    engine = make_engine(tmp_path, specs, adapters)
    await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    assert rec.names == ["core"]

    engine = make_engine(tmp_path / "second", specs, adapters)
    await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS,), include_noisy=True, mock=True),
    )
    assert rec.names[-2:] == ["core", "noisy"]

    engine = make_engine(tmp_path / "third", specs, adapters)
    await engine.run(
        "example.com", ScanOptions(stages=(Stage.SUBS,), tools=("intrusive",), mock=True)
    )
    assert rec.names[-1] == "intrusive"

    with pytest.raises(ConfigError, match="unknown"):
        await make_engine(tmp_path / "fourth", specs, adapters).run(
            "example.com", ScanOptions(tools=("missing",), mock=True)
        )


async def test_active_without_flag_skips_and_scope_drops_host(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {
        "subs": tool("subs", Stage.SUBS),
        "live": tool("live", Stage.LIVE, mode=Mode.ACTIVE),
    }
    adapters = {
        "subs": adapter(
            "subs", Stage.SUBS, rec, records=[sub("www.example.com"), sub("api.example.com")]
        ),
        "live": adapter("live", Stage.LIVE, rec, records=[alive("www.example.com")]),
    }
    engine = make_engine(tmp_path, specs, adapters)
    await engine.run("example.com", ScanOptions(stages=(Stage.SUBS, Stage.LIVE), mock=True))
    assert rec.names == ["subs"]
    assert rec.hosts == [["example.com"]]

    engine = make_engine(tmp_path / "active", specs, adapters)
    summary = await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS, Stage.LIVE), active=True, mock=True),
    )
    assert "live" in rec.names
    live_hosts = rec.hosts[rec.names.index("live")]
    assert "api.example.com" not in live_hosts
    assert "www.example.com" in live_hosts
    live_stage = next(stage for stage in summary.stages if stage.stage is Stage.LIVE)
    assert live_stage.dropped_hosts == ["api.example.com"]


async def test_naabu_is_selectable_in_active_mode(tmp_path: Path) -> None:
    """Changed from `test_naabu_stays_blocked_because_it_resolves_inside_the_binary`.

    That test asserted the unconditional 11c-G-7 block. The owner replaced it on
    2026-11-17 (MASTER_PLAN D2): `naabu` is now an ordinary active tool at
    selection time in both scope modes, and the IP verification happens in the
    scope-file-present branch instead. Passive mode still skips it.
    """
    rec = Recorder()
    specs = {
        "pyscan": tool("pyscan", Stage.PORTS, mode=Mode.ACTIVE),
        "naabu": tool("naabu", Stage.PORTS, mode=Mode.ACTIVE),
    }
    adapters = {
        "pyscan": adapter("pyscan", Stage.PORTS, rec),
        "naabu": adapter("naabu", Stage.PORTS, rec),
    }
    engine = make_engine(tmp_path, specs, adapters, installed=lambda _adapter: True)
    selected, skipped = await engine._select(
        Stage.PORTS, ScanOptions(active=True, tools=["pyscan", "naabu"])
    )
    assert [spec.name for spec, _ in selected] == ["pyscan", "naabu"]
    assert skipped == []

    passive, passive_skipped = await engine._select(
        Stage.PORTS, ScanOptions(active=False, tools=["pyscan", "naabu"])
    )
    assert passive == []
    assert {reason for _spec, reason in passive_skipped} == {
        "tool mode not included in passive mode"
    }


async def test_an_uninstalled_tool_is_skipped_and_the_others_still_run(tmp_path: Path) -> None:
    """Baseline for the 2026-11-17 installer-removal refactor (docs/09 selection).

    A tool whose binary is absent is recorded as `skipped (not installed)` and
    every installed tool in the same stage still runs. This is the guarantee
    that must survive deleting `installer/`: no install command, no change to
    what a scan does with a missing binary.
    """
    rec = Recorder()
    specs = {
        "subs-fake": tool("subs-fake", Stage.SUBS),
        "live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE),
        "naabu": tool("naabu", Stage.PORTS, mode=Mode.ACTIVE),
        "pyscan": tool("pyscan", Stage.PORTS, mode=Mode.ACTIVE),
    }
    adapters = {
        "subs-fake": adapter("subs-fake", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "live-fake": adapter("live-fake", Stage.LIVE, rec, records=[alive("www.example.com")]),
        "naabu": adapter("naabu", Stage.PORTS, rec),
        "pyscan": adapter("pyscan", Stage.PORTS, rec),
    }
    engine = make_engine(
        tmp_path,
        specs,
        adapters,
        scope_text=None,
        installed=lambda candidate: candidate.name != "pyscan",
    )
    summary = await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS, Stage.LIVE, Stage.PORTS), active=True, no_scope=True),
    )
    assert rec.names == ["subs-fake", "live-fake", "naabu"]
    assert [(skip.tool, skip.reason) for skip in summary.skipped] == [("pyscan", "not installed")]
    statuses = rows(engine.store, "SELECT tool, status, error FROM tool_runs ORDER BY id")
    assert ("pyscan", "skipped", "not installed") in [tuple(row) for row in statuses]
    assert ("naabu", "ok", None) in [tuple(row) for row in statuses]


async def test_active_ports_stage_receives_the_cidr_predicate(tmp_path: Path) -> None:
    """Regression: 11c-G-7.

    The adapter must not import `scope`, so the engine hands down the same
    `ip_allowed` predicate the active gate's scope file produced.
    """
    seen: list[Callable[[str], bool] | None] = []
    rec = Recorder()

    class FakePorts(BaseToolAdapter):
        name = "ports-fake"
        stage = Stage.PORTS

        async def run(self, ctx: RunContext) -> ToolResult:
            seen.append(ctx.ip_allowed)
            return ToolResult(tool=self.name, status=ToolStatus.OK, records=[])

        def build_command(self, ctx: RunContext) -> list[str]:
            raise AssertionError("build_command must not be called")

        def parse_output(self, raw: str) -> list[object]:
            return []

    specs = {
        "live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE),
        "ports-fake": tool("ports-fake", Stage.PORTS, mode=Mode.ACTIVE),
    }
    adapters: dict[str, type[BaseToolAdapter]] = {
        "live-fake": adapter("live-fake", Stage.LIVE, rec, records=[alive("example.com")]),
        "ports-fake": FakePorts,
    }
    engine = make_engine(
        tmp_path,
        specs,
        adapters,
        scope_text=SCOPE + "in_scope_cidrs:\n  - 203.0.113.0/24\n",
        installed=lambda _adapter: True,
    )
    await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.LIVE, Stage.PORTS), active=True),
    )
    assert len(seen) == 1
    predicate = seen[0]
    assert predicate is not None, "the active ports stage must get a CIDR predicate"
    assert predicate("203.0.113.5") is True
    assert predicate("198.51.100.5") is False


async def test_an_excluded_cidr_is_refused_by_the_ports_predicate(tmp_path: Path) -> None:
    """D56: the predicate handed down refuses an address inside `exclude_cidrs`."""
    seen: list[Callable[[str], bool] | None] = []
    rec = Recorder()

    class FakePorts(BaseToolAdapter):
        name = "ports-fake"
        stage = Stage.PORTS

        async def run(self, ctx: RunContext) -> ToolResult:
            seen.append(ctx.ip_allowed)
            return ToolResult(tool=self.name, status=ToolStatus.OK, records=[])

        def build_command(self, ctx: RunContext) -> list[str]:
            raise AssertionError("build_command must not be called")

        def parse_output(self, raw: str) -> list[object]:
            return []

    specs = {
        "live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE),
        "ports-fake": tool("ports-fake", Stage.PORTS, mode=Mode.ACTIVE),
    }
    adapters: dict[str, type[BaseToolAdapter]] = {
        "live-fake": adapter("live-fake", Stage.LIVE, rec, records=[alive("example.com")]),
        "ports-fake": FakePorts,
    }
    engine = make_engine(
        tmp_path,
        specs,
        adapters,
        scope_text=SCOPE_WITH_EXCLUSIONS,
        installed=lambda _adapter: True,
    )
    await engine.run("example.com", ScanOptions(stages=(Stage.LIVE, Stage.PORTS), active=True))
    predicate = seen[0]
    assert predicate is not None
    assert predicate("203.0.113.5") is True
    assert predicate("203.0.113.200") is False
    assert predicate("198.51.100.5") is False


async def test_scope_warnings_name_the_tools_that_resolve_in_the_child(
    tmp_path: Path,
) -> None:
    """D56 ruling 2: a partial CIDR exclusion is announced once and reaches the report."""
    import json
    from datetime import UTC, datetime

    from reconkit import ui as ui_module

    rec = Recorder()
    lines: list[str] = []
    specs = {"live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE)}
    adapters: dict[str, type[BaseToolAdapter]] = {
        "live-fake": adapter("live-fake", Stage.LIVE, rec, records=[alive("example.com")])
    }
    engine = make_engine(
        tmp_path,
        specs,
        adapters,
        scope_text=SCOPE_WITH_EXCLUSIONS,
        installed=lambda _adapter: True,
        progress=lines.append,
    )
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.LIVE,), active=True))
    assert len(summary.scope_warnings) == 1
    note = summary.scope_warnings[0]
    assert "exclude_cidrs" in note
    assert "live-fake" in note
    assert [line for line in lines if "exclude_cidrs" in line] == [note]
    document = ui_module.summary_document(summary)
    assert document["scope_warnings"] == [note]
    directory = tmp_path / "report"
    directory.mkdir()
    ui_module.write_field_report(
        directory,
        "example.com",
        (),
        (),
        run_at=datetime.now(UTC),
        scope_warnings=[note],
    )
    assert note in (directory / "report.txt").read_text(encoding="utf-8")
    written = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    assert written["scope_warnings"] == [note]


async def test_regression_live_discovered_subdomain_reaches_the_subdomains_table(
    tmp_path: Path,
) -> None:
    """Regression: PIT-49.

    A live adapter that names a host while probing (a certificate SAN) must leave
    a `subdomains` row, not only an in-memory discovered entry.
    """
    rec = Recorder()
    specs = {"live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE)}
    adapters: dict[str, type[BaseToolAdapter]] = {
        "live-fake": adapter(
            "live-fake",
            Stage.LIVE,
            rec,
            records=[
                alive("example.com"),
                SubdomainRecord(fqdn="cert.example.com", source="fake"),
            ],
        )
    }
    store = Store(tmp_path / "recon.db")
    engine = make_engine(tmp_path, specs, adapters, store=store)
    await engine.run("example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True))

    row = store._conn.execute(
        "SELECT provenance, source_count FROM subdomains WHERE fqdn = 'cert.example.com'"
    ).fetchone()
    assert row is not None, "the SAN must reach the subdomains table"
    assert (row["provenance"], row["source_count"]) == ("subs", 1)
    assert (
        store._conn.execute(
            "SELECT COUNT(*) AS n FROM subdomain_sources WHERE subdomain_id ="
            " (SELECT id FROM subdomains WHERE fqdn = 'cert.example.com')"
        ).fetchone()["n"]
        == 1
    )
    # The probed host itself is still persisted, so the fix adds rows, never
    # replaces the host-state path.
    assert (
        store._conn.execute(
            "SELECT COUNT(*) AS n FROM host_status_history WHERE subdomain_id ="
            " (SELECT id FROM subdomains WHERE fqdn = 'example.com')"
        ).fetchone()["n"]
        == 1
    )


async def test_tlsx_sans_enter_discovered_and_reach_subdomains_table(tmp_path: Path) -> None:
    """Ruling A: a SAN is a new host, so it is discovered *and* persisted.

    Runs the real `TlsxAdapter` over its synthetic fixture (no network, no
    binary): the certificate names `www.testfire.net`, the later urls stage must
    receive it as input, and it must leave a `subdomains` row (PIT-49).
    """
    rec = Recorder()
    specs = {
        "tlsx": tool("tlsx", Stage.LIVE, mode=Mode.ACTIVE),
        "urls-fake": tool("urls-fake", Stage.URLS, mode=Mode.ACTIVE),
    }
    adapters: dict[str, type[BaseToolAdapter]] = {
        "tlsx": TlsxAdapter,
        "urls-fake": adapter("urls-fake", Stage.URLS, rec, records=[]),
    }
    store = Store(tmp_path / "recon.db")
    engine = make_engine(tmp_path, specs, adapters, store=store, scope_text=None)
    await engine.run(
        "testfire.net",
        ScanOptions(stages=(Stage.LIVE, Stage.URLS), active=True, mock=True, no_scope=True),
    )
    assert set(rec.hosts[-1]) == {"testfire.net", "www.testfire.net"}
    persisted = {
        str(row["fqdn"]): str(row["provenance"])
        for row in rows(store, "SELECT fqdn, provenance FROM subdomains")
    }
    assert persisted.get("www.testfire.net") == "subs"
    sources = [
        str(row["tool"])
        for row in rows(
            store,
            "SELECT tool FROM subdomain_sources WHERE subdomain_id ="
            " (SELECT id FROM subdomains WHERE fqdn = 'www.testfire.net')",
        )
    ]
    assert sources == ["tlsx"]


async def test_passive_run_outside_scope_warns(tmp_path: Path) -> None:
    """Regression: 11c-G-3.

    docs/05 rule 1: a passive run needs no scope file, but when one exists and the
    target is outside it, the run warns instead of staying silent.
    """
    rec = Recorder()
    specs = {"subs-fake": tool("subs-fake", Stage.SUBS)}
    adapters = {"subs-fake": adapter("subs-fake", Stage.SUBS, rec, records=[])}
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run("other.test", ScanOptions(stages=(Stage.SUBS,), mock=True))
    assert summary.warnings == [
        "other.test is outside scope.yaml",
        "continuing with passive stages only",
    ]

    engine = make_engine(tmp_path / "in_scope", specs, adapters)
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    assert summary.warnings == []


async def test_env_filtering_and_no_keys(tmp_path: Path) -> None:
    rec = Recorder()
    keys = (ToolKey(env="ONLY_ME", url="https://example.com/key", adds="test"),)
    specs = {"subs": tool("subs", Stage.SUBS, keys=keys)}
    adapters = {"subs": adapter("subs", Stage.SUBS, rec, records=[])}
    engine = make_engine(
        tmp_path,
        specs,
        adapters,
        env={"ONLY_ME": "secret-value", "OTHER": "not-for-you"},
    )
    await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    assert rec.envs == [{"ONLY_ME": "secret-value"}]

    engine = make_engine(
        tmp_path / "nokeys",
        specs,
        adapters,
        env={"ONLY_ME": "secret-value", "OTHER": "not-for-you"},
    )
    await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), no_keys=True, mock=True))
    assert rec.envs[-1] == {}


async def test_one_crash_does_not_stop_the_stage(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {
        "good": tool("good", Stage.SUBS),
        "bad": tool("bad", Stage.SUBS),
    }
    adapters = {
        "good": adapter("good", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "bad": adapter("bad", Stage.SUBS, rec, error=RuntimeError("boom")),
    }
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    statuses = {
        (row["tool"], row["status"])
        for row in rows(engine.store, "SELECT tool, status FROM tool_runs")
    }
    assert ("good", "ok") in statuses
    assert ("bad", "failed") in statuses
    assert len(summary.stages[0].results) == 2


async def test_all_tools_failing_is_not_an_exception(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {"a": tool("a", Stage.SUBS), "b": tool("b", Stage.SUBS)}
    adapters = {
        "a": adapter("a", Stage.SUBS, rec, error=RuntimeError("a")),
        "b": adapter("b", Stage.SUBS, rec, error=RuntimeError("b")),
    }
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    assert all(result.status is ToolStatus.FAILED for result in summary.stages[0].results)
    run = engine.store._conn.execute("SELECT status FROM scan_runs").fetchone()
    assert run["status"] == "partial"


async def test_activity_reports_the_running_tool_snapshot(tmp_path: Path) -> None:
    """2026-11-18: the live status line names the tools still in flight.

    The durable progress lines only appear when a tool finishes, so a 600 s run
    looked like a hang; this channel carries the in-place snapshot the CLI shows
    as a spinner (docs/02 section 5).
    """
    rec = Recorder()
    specs = {"a": tool("a", Stage.SUBS), "b": tool("b", Stage.SUBS)}
    adapters = {
        "a": adapter("a", Stage.SUBS, rec, records=[]),
        "b": adapter("b", Stage.SUBS, rec, records=[]),
    }
    seen: list[str] = []
    engine = make_engine(tmp_path, specs, adapters, activity=seen.append)
    await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,)))
    assert seen, "the activity channel must say something while a stage runs"
    assert seen[0] == "subs: 0/2 tool(s) done, 0s elapsed - running: a"
    # Every tool is announced as it starts, so no tool is invisible while it runs.
    assert any("running: b" in message for message in seen)
    # The last snapshot of the stage is empty: nothing is left to run.
    assert seen[-1].endswith("2/2 tool(s) done, 0s elapsed - running: none")


async def test_phase_timeout_records_a_timeout_row(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {"slow": tool("slow", Stage.SUBS)}
    adapters = {"slow": adapter("slow", Stage.SUBS, rec, wait=True)}
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS,), mock=True, phase_timeout=0.02),
    )
    # The stage's result list now carries the timeout too, so the summary line
    # and `--json` cannot say "0 timeout" while the run exits 5 (Part M).
    assert [(result.tool, result.status) for result in summary.stages[0].results] == [
        ("slow", ToolStatus.TIMEOUT)
    ]
    # Every selected tool timed out, so this is "nothing usable" (4), not 5 -
    # the documented all-failed boundary (D34). D52 keeps this exactly: only an
    # idle kill is `killed` and exits 0.
    assert summary.exit_code is ExitCode.NO_TOOL
    row = engine.store._conn.execute("SELECT status, error FROM tool_runs").fetchone()
    assert (row["status"], row["error"]) == ("timeout", "timed out at stage budget 1s")


async def test_tool_error_is_redacted_before_storage(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {"subs": tool("subs", Stage.SUBS)}
    adapters = {"subs": adapter("subs", Stage.SUBS, rec, error=RuntimeError("token sk-live-abc"))}
    engine = make_engine(tmp_path, specs, adapters, env={"API_KEY": "sk-live-abc"})
    await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    row = engine.store._conn.execute("SELECT error FROM tool_runs").fetchone()
    assert "sk-live-abc" not in row["error"]
    assert REDACTED in row["error"]


async def test_tools_start_together_without_a_pace_limit(tmp_path: Path) -> None:
    """2026-11-17: the pacer is gone, so a stage's tools all run concurrently."""
    rec = Recorder()
    active = 0
    peak = 0
    release = asyncio.Event()
    started = asyncio.Event()

    async def track() -> None:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        if active == 2:
            started.set()
        await release.wait()
        active -= 1

    specs = {"a": tool("a", Stage.SUBS), "b": tool("b", Stage.SUBS)}

    class Tracked(BaseToolAdapter):
        stage = Stage.SUBS

        async def run(self, ctx: RunContext) -> ToolResult:
            rec.names.append("tracked")
            await track()
            return ToolResult(tool="tracked", status=ToolStatus.OK, records=[])

        def parse_output(self, raw: str) -> list[object]:
            return []

    engine = make_engine(tmp_path, specs, {"a": Tracked, "b": Tracked})
    running = asyncio.create_task(
        engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    )
    await asyncio.wait_for(started.wait(), timeout=5)
    assert peak == 2
    release.set()
    await asyncio.wait_for(running, timeout=5)
    assert engine.store.count("scan_runs") == 1


# ---------------------------------------------------------------- confidence

HIGH_MIN = 3
MEDIUM_MIN = 2


def test_confidence_three_distinct_tools_high() -> None:
    assert (
        confidence_for(["a", "b", "c"], high_min=HIGH_MIN, medium_min=MEDIUM_MIN) is Confidence.HIGH
    )


def test_confidence_two_distinct_tools_medium() -> None:
    assert confidence_for(["a", "b"], high_min=HIGH_MIN, medium_min=MEDIUM_MIN) is Confidence.MEDIUM


def test_confidence_one_tool_low() -> None:
    assert confidence_for(["a"], high_min=HIGH_MIN, medium_min=MEDIUM_MIN) is Confidence.LOW


def test_confidence_disagreement_unconfirmed() -> None:
    assert (
        confidence_for(["a", "b", "c"], high_min=HIGH_MIN, medium_min=MEDIUM_MIN, disagree=True)
        is Confidence.UNCONFIRMED
    )


def test_same_tool_three_results_is_not_high() -> None:
    assert (
        confidence_for(["same", "same", "same"], high_min=HIGH_MIN, medium_min=MEDIUM_MIN)
        is Confidence.LOW
    )


async def test_engine_persists_three_distinct_tools_as_high(tmp_path: Path) -> None:
    rec = Recorder()
    names = ("a", "b", "c")
    specs = {name: tool(name, Stage.SUBS) for name in names}
    adapters = {
        name: adapter(name, Stage.SUBS, rec, records=[sub("www.example.com")]) for name in names
    }
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    assert summary.exit_code is ExitCode.SUCCESS
    row = engine.store._conn.execute(
        "SELECT confidence, source_count FROM subdomains WHERE fqdn = ?",
        ("www.example.com",),
    ).fetchone()
    assert (row["confidence"], row["source_count"]) == ("HIGH", 3)


async def test_dns_pass_does_not_overwrite_discovery_confidence(tmp_path: Path) -> None:
    """Regression: 11d-findings-a.

    A dns pass used to write `source_count=len(transition.sources)`, and on a
    DNS-only pass those are the DNS tools alone, so it lowered the discovery
    row from (MEDIUM, 2) to (LOW, 1) on every later stage. `source_count` is
    defined by `subdomain_sources`, which only the discovery pass writes, so a
    state pass must leave it alone. Fix `_write_host`, never this expectation.
    """
    rec = Recorder()
    specs = {
        "subs-a": tool("subs-a", Stage.SUBS),
        "subs-b": tool("subs-b", Stage.SUBS),
        "dns-a": tool("dns-a", Stage.DNS),
    }
    adapters = {
        "subs-a": adapter("subs-a", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "subs-b": adapter("subs-b", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "dns-a": adapter(
            "dns-a",
            Stage.DNS,
            rec,
            records=[SubdomainRecord(fqdn="www.example.com", source="fake", ips=["1.2.3.4"])],
        ),
    }
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run(
        "example.com", ScanOptions(stages=(Stage.SUBS, Stage.DNS), mock=True)
    )
    assert summary.exit_code is ExitCode.SUCCESS
    row = engine.store._conn.execute(
        "SELECT confidence, source_count FROM subdomains WHERE fqdn = ?",
        ("www.example.com",),
    ).fetchone()
    assert (row["confidence"], row["source_count"]) == ("MEDIUM", 2)
    # The pass-local tools are not lost: the dns pass still records them.
    status = engine.store._conn.execute(
        "SELECT tools_json FROM host_status_history ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert json.loads(status["tools_json"]) == ["dns-a"]


async def test_engine_disagreement_is_unconfirmed(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {
        "a": tool("a", Stage.LIVE, mode=Mode.ACTIVE),
        "b": tool("b", Stage.LIVE, mode=Mode.ACTIVE),
    }
    adapters = {
        "a": adapter("a", Stage.LIVE, rec, records=[alive("example.com")]),
        "b": adapter("b", Stage.LIVE, rec, records=[host("example.com", HostState.UNKNOWN)]),
    }
    engine = make_engine(tmp_path, specs, adapters)
    await engine.run("example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True))
    row = engine.store._conn.execute(
        "SELECT state, confidence FROM subdomains WHERE fqdn = ?", ("example.com",)
    ).fetchone()
    assert (row["state"], row["confidence"]) == ("ALIVE", "UNCONFIRMED")


# ------------------------------------- provider keys and the raw-output file


async def test_subfinder_raw_file_never_contains_the_provider_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The 12a raw file must not leak a key even when the tool echoes it.

    Real subfinder gets its keys in a 0600 `provider-config.yaml`, never argv, and
    does not normally print them - so this simulates the worst case, a verbose
    child that dumps its loaded config to stderr, and checks the bytes that reach
    `<workspace>/example.com/subs/<run>-subfinder.txt`. The engine hands
    `Workspace.write` the same secret set it redacts `tool_runs.error` with, so a
    key echoed by the tool is masked on the way to disk (12a + 12f's `redact()`).
    """
    key_value = "sk-live-abc123-provider-key"
    provider_root = tmp_path / "provider-root"
    provider_root.mkdir()
    monkeypatch.setattr(subfinder_module.tempfile, "gettempdir", lambda: str(provider_root))
    calls: list[list[str]] = []
    seen_config: list[str] = []

    def fake_exec(argv: list[str], **_kwargs: object) -> ExecResult:
        calls.append(argv)
        config_path = Path(argv[argv.index("-pc") + 1])
        echoed = config_path.read_text(encoding="utf-8")
        seen_config.append(echoed)
        return ExecResult(
            returncode=0,
            stdout="www.example.com\n",
            stderr=f"[DBG] loaded provider config from {config_path.name}:\n{echoed}",
            timed_out=False,
            truncated=False,
        )

    monkeypatch.setattr(base_module, "run_exec", fake_exec)
    engine = make_engine(
        tmp_path,
        # The real registry entry, so `_tool_env` passes the adapter's own keys.
        {"subfinder": get_spec("subfinder")},
        {"subfinder": SubfinderAdapter},
        env={"VT_API_KEY": key_value},
        installed=lambda _adapter: True,
    )

    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,)))

    result = summary.stages[0].results[0]
    assert result.status is ToolStatus.OK
    assert result.raw_path is not None
    written = Path(result.raw_path).read_text(encoding="utf-8")
    # The child really did receive and echo the key, so the assertion is not vacuous.
    assert "-pc" in calls[0]
    assert key_value in seen_config[0]
    assert "[DBG] loaded provider config" in written
    assert "www.example.com" in written
    assert key_value not in written
    assert REDACTED in written
    # The per-run provider directory is gone, and nothing else in the tree holds it.
    assert [path for path in provider_root.iterdir()] == []
    assert key_value not in json.dumps(summary.stages[0].results[0].model_dump(mode="json"))


# --------------------------------------------------- host_status_history.detail


def seed_unknown_state(engine: Engine, host_name: str) -> int:
    """Give a host a stored `UNKNOWN` state so the next pass persists a row.

    Since 12e a first-run inconclusive `live` pass with a record writes its own
    row, so this seeded shape models what older builds and hand-seeded databases
    hold, and what a pass that already had a previous state starts from.
    """
    target_id = engine.store.create_target("example.com")
    run_id = engine.store.create_scan_run(target_id, "live")
    sub_id = engine.store.upsert_subdomain(target_id, host_name, run_id=run_id)
    engine.store.append_host_status(sub_id, run_id, "UNKNOWN")
    engine.store.finish_scan_run(run_id, "completed")
    return target_id


async def test_unknown_tls_failure_stores_a_redacted_bounded_reason(tmp_path: Path) -> None:
    """12d: an UNKNOWN host keeps why it could not be decided (PIT-46).

    The TLS text was classified by substring and thrown away, so two very
    different failures were indistinguishable afterwards.
    """
    rec = Recorder()
    # Bare, no `key=value` shape, so only the value-based redaction can mask it.
    key_value = "provider-secret-value"
    raw = (
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
        f"{key_value}\nhostname mismatch " + "y" * 400
    )
    specs = {"live": tool("live", Stage.LIVE, mode=Mode.ACTIVE)}
    adapters = {"live": adapter("live", Stage.LIVE, rec, records=[unknown("example.com", raw)])}
    engine = make_engine(tmp_path, specs, adapters, env={"PROVIDER_KEY": key_value})
    seed_unknown_state(engine, "example.com")

    summary = await engine.run(
        "example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True)
    )

    row = engine.store._conn.execute(
        "SELECT state, detail FROM host_status_history ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row["state"] == "UNKNOWN"
    detail = str(row["detail"])
    assert key_value not in detail
    assert REDACTED in detail
    assert "\n" not in detail
    assert len(detail) <= 200
    assert detail.startswith("[SSL: CERTIFICATE_VERIFY_FAILED]")
    hosts = engine.host_rows(summary.target_id)
    assert hosts[0].detail == detail


async def test_an_inconclusive_pass_keeps_the_previous_state_and_records_the_reason(
    tmp_path: Path,
) -> None:
    """docs/04 section 5: the kept state is the old one; the reason explains why."""
    rec = Recorder()
    specs = {"live": tool("live", Stage.LIVE, mode=Mode.ACTIVE)}
    engine = make_engine(
        tmp_path,
        specs,
        {
            "live": adapter(
                "live",
                Stage.LIVE,
                rec,
                records=[unknown("example.com", "tls: untrusted CA")],
            )
        },
    )
    target_id = engine.store.create_target("example.com")
    run_id = engine.store.create_scan_run(target_id, "dns")
    sub_id = engine.store.upsert_subdomain(target_id, "example.com", run_id=run_id)
    engine.store.append_host_status(sub_id, run_id, "DNS_ONLY")
    engine.store.finish_scan_run(run_id, "completed")

    await engine.run("example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True))

    row = engine.store._conn.execute(
        "SELECT state, detail FROM host_status_history ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert (row["state"], row["detail"]) == ("DNS_ONLY", "tls: untrusted CA")


async def test_a_plain_connect_failure_stores_no_reason(tmp_path: Path) -> None:
    """A plain connect failure is `unreachable=`, never a row with a reason.

    docs/09: `pyprobe` emits no record for it, so no status row exists to carry
    a detail - the opposite of the TLS case, and distinguishable by that alone.
    """
    rec = Recorder()
    specs = {"live": tool("live", Stage.LIVE, mode=Mode.ACTIVE)}
    adapters = {
        "live": adapter("live", Stage.LIVE, rec, records=[], error=None),
    }
    engine = make_engine(tmp_path, specs, adapters)

    summary = await engine.run(
        "example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True)
    )

    assert rows(engine.store, "SELECT COUNT(*) AS n FROM host_status_history")[0]["n"] == 0
    assert engine.host_rows(summary.target_id)[0].detail is None


async def test_a_later_alive_pass_does_not_resurrect_the_reason(tmp_path: Path) -> None:
    """12d: the reason belongs to the row that recorded it, not to the host."""
    rec = Recorder()
    specs = {"live": tool("live", Stage.LIVE, mode=Mode.ACTIVE)}
    first = make_engine(
        tmp_path,
        specs,
        {
            "live": adapter(
                "live",
                Stage.LIVE,
                rec,
                records=[unknown("example.com", "certificate has expired")],
            )
        },
    )
    seed_unknown_state(first, "example.com")
    await first.run("example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True))
    stored = first.store._conn.execute(
        "SELECT detail FROM host_status_history ORDER BY id DESC LIMIT 1"
    ).fetchone()["detail"]
    assert stored == "certificate has expired"

    second = make_engine(
        tmp_path,
        specs,
        {"live": adapter("live", Stage.LIVE, rec, records=[alive("example.com")])},
        store=first.store,
    )
    summary = await second.run(
        "example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True)
    )

    latest = second.store._conn.execute(
        "SELECT state, detail FROM host_status_history ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert (latest["state"], latest["detail"]) == ("ALIVE", None)
    assert second.host_rows(summary.target_id)[0].detail is None


# --------------------------- an attempted probe leaves a row (12e, PIT-47)


async def test_a_first_inconclusive_live_pass_writes_an_unknown_row(tmp_path: Path) -> None:
    """Regression: PIT-47 docs/04 - a first pass that probed is not invisible."""
    rec = Recorder()
    specs = {"live": tool("live", Stage.LIVE, mode=Mode.ACTIVE)}
    adapters = {
        "live": adapter(
            "live", Stage.LIVE, rec, records=[unknown("example.com", "tls: untrusted CA")]
        )
    }
    engine = make_engine(tmp_path, specs, adapters)

    summary = await engine.run(
        "example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True)
    )

    stored = rows(engine.store, "SELECT state, detail, tools_json FROM host_status_history")
    assert len(stored) == 1
    assert (stored[0]["state"], stored[0]["detail"]) == ("UNKNOWN", "tls: untrusted CA")
    assert json.loads(stored[0]["tools_json"]) == ["live"]
    assert engine.host_rows(summary.target_id)[0].detail == "tls: untrusted CA"


async def test_only_the_host_a_tool_reported_gets_the_unknown_row(tmp_path: Path) -> None:
    """docs/04: attempted is per host, not per stage."""
    rec = Recorder()
    specs = {
        "subs": tool("subs", Stage.SUBS),
        "live": tool("live", Stage.LIVE, mode=Mode.ACTIVE),
    }
    adapters = {
        "subs": adapter(
            "subs", Stage.SUBS, rec, records=[sub("www.example.com"), sub("api.example.com")]
        ),
        "live": adapter(
            "live", Stage.LIVE, rec, records=[unknown("www.example.com", "tls: expired")]
        ),
    }
    engine = make_engine(tmp_path, specs, adapters)

    await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS, Stage.LIVE), active=True, mock=True),
    )

    stored = rows(
        engine.store,
        "SELECT subdomains.fqdn AS fqdn, host_status_history.state AS state "
        "FROM host_status_history JOIN subdomains "
        "ON subdomains.id = host_status_history.subdomain_id",
    )
    assert [(row["fqdn"], row["state"]) for row in stored] == [("www.example.com", "UNKNOWN")]


async def test_a_host_without_a_record_gets_no_row_even_when_another_did(
    tmp_path: Path,
) -> None:
    """docs/04: the skip stays per host, not per stage (12e).

    The live tool answered for `www` only; the apex was never answered, so the
    inconclusive pass there must stay invisible even though the stage succeeded.
    """
    rec = Recorder()
    specs = {
        "subs": tool("subs", Stage.SUBS),
        "dns": tool("dns", Stage.DNS),
        "live": tool("live", Stage.LIVE, mode=Mode.ACTIVE),
    }
    adapters = {
        "subs": adapter("subs", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "dns": adapter(
            "dns",
            Stage.DNS,
            rec,
            records=[SubdomainRecord(fqdn="www.example.com", source="fake", ips=["1.2.3.4"])],
        ),
        "live": adapter(
            "live", Stage.LIVE, rec, records=[unknown("www.example.com", "tls: expired")]
        ),
    }
    engine = make_engine(tmp_path, specs, adapters)

    await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS, Stage.DNS, Stage.LIVE), active=True, mock=True),
    )

    stored = rows(
        engine.store,
        "SELECT subdomains.fqdn AS fqdn, host_status_history.state AS state "
        "FROM host_status_history JOIN subdomains "
        "ON subdomains.id = host_status_history.subdomain_id",
    )
    assert [(row["fqdn"], row["state"]) for row in stored] == [("www.example.com", "DNS_ONLY")]


async def test_a_failed_live_tool_attempted_nothing_and_writes_no_row(tmp_path: Path) -> None:
    """docs/04: a tool that failed returned no record, so nothing was attempted."""
    rec = Recorder()
    specs = {"live": tool("live", Stage.LIVE, mode=Mode.ACTIVE)}
    adapters = {
        "live": adapter("live", Stage.LIVE, rec, records=[], status=ToolStatus.FAILED),
    }
    engine = make_engine(tmp_path, specs, adapters)

    await engine.run("example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True))

    assert rows(engine.store, "SELECT COUNT(*) AS n FROM host_status_history")[0]["n"] == 0


# ------------------------ blocking file I/O stays off the loop (12h)


def active_engine(
    tmp_path: Path,
    *,
    specs: Mapping[str, ToolSpec] | None = None,
    adapters: Mapping[str, type[BaseToolAdapter]] | None = None,
) -> Engine:
    """One active `live` stage, so the scope gate and the workspace both run."""
    rec = Recorder()
    return make_engine(
        tmp_path,
        specs or {"live": tool("live", Stage.LIVE, mode=Mode.ACTIVE)},
        adapters or {"live": adapter("live", Stage.LIVE, rec, records=[alive("example.com")])},
        installed=lambda _adapter: True,
    )


async def test_the_scope_read_and_workspace_create_run_off_the_event_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """12h/docs/03 section 11: kernel I/O must not run on the loop thread."""
    main = threading.main_thread()
    seen: dict[str, bool] = {}
    real_load_scope = engine_module.load_scope
    real_create = Workspace.create

    def recording_scope(path: Path | str | None = None) -> ScopeGate:
        seen.setdefault("scope", threading.current_thread() is not main)
        return real_load_scope(path)

    def recording_create(
        cls: type[Workspace], root: Path | str, target: str, *, secrets: Iterable[str] = ()
    ) -> Workspace:
        seen.setdefault("workspace", threading.current_thread() is not main)
        return real_create(root, target, secrets=secrets)

    monkeypatch.setattr(engine_module, "load_scope", recording_scope)
    monkeypatch.setattr(Workspace, "create", classmethod(recording_create))
    engine = active_engine(tmp_path)

    await engine.run("example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True))

    assert seen == {"scope": True, "workspace": True}


async def test_a_slow_scope_read_does_not_block_a_heartbeat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """12h: the loop keeps turning while the scope file is being read."""
    ticks = 0
    stop = asyncio.Event()
    real_load_scope = engine_module.load_scope

    def slow_scope(path: Path | str | None = None) -> ScopeGate:
        time.sleep(0.25)
        return real_load_scope(path)

    async def heartbeat() -> None:
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            await asyncio.sleep(0.005)

    monkeypatch.setattr(engine_module, "load_scope", slow_scope)
    engine = active_engine(tmp_path)
    task = asyncio.create_task(heartbeat())
    await asyncio.sleep(0.01)

    await engine.run("example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True))

    stop.set()
    await task
    # Two 0.25 s reads: a blocked loop could only tick before and after them.
    assert ticks >= 10


async def test_the_persistence_block_stays_on_the_loop_in_stage_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """12h: SQLite persistence stays on the loop, deliberately (docs/03)."""
    main = threading.main_thread()
    on_loop: list[bool] = []
    real_persist = Engine._persist_stage

    def recording_persist(self: Engine, *args: object, **kwargs: object) -> None:
        on_loop.append(threading.current_thread() is main)
        real_persist(self, *args, **kwargs)

    monkeypatch.setattr(Engine, "_persist_stage", recording_persist)
    rec = Recorder()
    specs = {
        "subs": tool("subs", Stage.SUBS),
        "live": tool("live", Stage.LIVE, mode=Mode.ACTIVE),
    }
    adapters = {
        "subs": adapter("subs", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "live": adapter("live", Stage.LIVE, rec, records=[alive("www.example.com")]),
    }
    engine = make_engine(tmp_path, specs, adapters, installed=lambda _adapter: True)

    await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS, Stage.LIVE), active=True, mock=True),
    )

    assert on_loop == [True, True]
    stages = [row["stage"] for row in rows(engine.store, "SELECT stage FROM scan_runs ORDER BY id")]
    assert stages == ["subs", "live"]
    run_ids = [
        row["run_id"]
        for row in rows(engine.store, "SELECT run_id FROM host_status_history ORDER BY id")
    ]
    assert run_ids == sorted(run_ids)


# ------------------------------------------------------------ host transitions


def transition(previous: HostState | None, evidence: HostEvidence):
    return decide_host_state(
        previous,
        evidence,
        target="example.com",
        high_min=HIGH_MIN,
        medium_min=MEDIUM_MIN,
    )


def test_regression_dns_servfail_not_dead() -> None:
    """Regression: PIT-01 SERVFAIL maps to UNCERTAIN, never DEAD."""
    result = transition(
        None,
        HostEvidence(dns=DnsSignal.UNCERTAIN, dns_tools=("dnspython",)),
    )
    assert result.state is HostState.UNKNOWN
    assert result.state is not HostState.DEAD


def test_regression_an_attempted_probe_persists_with_no_previous_state() -> None:
    """Regression: PIT-47 the persist rule is "a record came back", not "decided".

    docs/04 section 5: an inconclusive first pass writes `UNKNOWN`/LOW when a
    live tool returned a record, and writes nothing when no record came back.
    """
    attempted = transition(
        None,
        HostEvidence(dns=DnsSignal.UNCERTAIN, web=(("pyprobe", HostState.UNKNOWN),)),
    )
    assert attempted.persist is True
    assert (attempted.state, attempted.confidence) == (HostState.UNKNOWN, Confidence.LOW)
    assert attempted.sources == ("pyprobe",)

    nothing = transition(
        None,
        HostEvidence(dns=DnsSignal.UNCERTAIN, dns_tools=("dnspython",)),
    )
    assert nothing.persist is False
    assert nothing.state is HostState.UNKNOWN


def test_regression_dns_timeout_not_dead() -> None:
    """Regression: PIT-01 timeout/SERVFAIL must never produce DEAD."""
    kept = transition(
        HostState.ALIVE,
        HostEvidence(
            dns=DnsSignal.UNCERTAIN,
            dns_tools=("dnspython",),
            web=(("pyprobe", HostState.UNKNOWN),),
        ),
    )
    assert kept.state is HostState.ALIVE
    assert any("kept previous" in warning for warning in kept.warnings)

    first = transition(
        None,
        HostEvidence(dns=DnsSignal.UNCERTAIN, dns_tools=("dnspython",)),
    )
    assert first.state is HostState.UNKNOWN
    assert first.state is not HostState.DEAD


def test_shut_down_after_alive_with_external_cname() -> None:
    result = transition(
        HostState.ALIVE,
        HostEvidence(
            dns=DnsSignal.NXDOMAIN,
            dns_tools=("dnspython",),
            cnames=("old.appspot.com",),
        ),
    )
    assert result.state is HostState.SHUT_DOWN
    assert result.state is not HostState.DEAD
    assert any("dangling CNAME" in warning for warning in result.warnings)


async def test_regression_dangling_cname_survives_restart(tmp_path: Path) -> None:
    """Regression: PIT-29 stored CNAME evidence must survive a process restart."""
    rec = Recorder()
    specs = {"dns-fake": tool("dns-fake", Stage.DNS)}
    first_adapters = {
        "dns-fake": adapter(
            "dns-fake",
            Stage.DNS,
            rec,
            records=[
                SubdomainRecord(
                    fqdn="old.example.com",
                    source="fake",
                    ips=["203.0.113.9"],
                    cnames=["old.appspot.com"],
                )
            ],
        )
    }
    first_store = Store(tmp_path / "recon.db")
    first_engine = make_engine(tmp_path, specs, first_adapters, store=first_store)
    await first_engine.run("example.com", ScanOptions(stages=(Stage.DNS,), mock=True))
    first_store.close()

    second_store = Store(tmp_path / "recon.db")
    second_adapters = {
        "dns-fake": adapter(
            "dns-fake",
            Stage.DNS,
            rec,
            records=[host("old.example.com", HostState.DEAD)],
        )
    }
    second_engine = make_engine(tmp_path, specs, second_adapters, store=second_store)
    summary = await second_engine.run("example.com", ScanOptions(stages=(Stage.DNS,), mock=True))
    assert any("dangling CNAME" in warning for warning in summary.warnings)
    row = second_store._conn.execute(
        "SELECT state, cnames_json, dangling_cname FROM host_status_history"
        " ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert (row["state"], row["cnames_json"], row["dangling_cname"]) == (
        "SHUT_DOWN",
        '["old.appspot.com"]',
        "old.appspot.com",
    )
    second_store.close()


async def test_dns_resolved_then_two_nxdomain_is_shut_down_then_dead(tmp_path: Path) -> None:
    """Regression: PIT-29's extra DNS_ONLY row must not break the DEAD rule."""
    rec = Recorder()
    specs = {"dns-fake": tool("dns-fake", Stage.DNS)}
    db_path = tmp_path / "recon.db"
    resolved = SubdomainRecord(
        fqdn="old.example.com",
        source="fake",
        ips=["203.0.113.9"],
        cnames=["old.appspot.com"],
    )
    nxdomain = host("old.example.com", HostState.DEAD)
    states: list[str] = []
    warnings: list[str] = []
    for records in ([resolved], [nxdomain], [nxdomain]):
        store = Store(db_path)
        adapters = {"dns-fake": adapter("dns-fake", Stage.DNS, rec, records=records)}
        engine = make_engine(tmp_path, specs, adapters, store=store)
        summary = await engine.run("example.com", ScanOptions(stages=(Stage.DNS,), mock=True))
        row = store._conn.execute(
            "SELECT h.state, h.cnames_json, h.dangling_cname"
            " FROM host_status_history h JOIN subdomains s ON s.id = h.subdomain_id"
            " WHERE s.fqdn = ? ORDER BY h.id DESC LIMIT 1",
            ("old.example.com",),
        ).fetchone()
        states.append(str(row["state"]))
        warnings.extend(summary.warnings)
        store.close()

    assert states == ["DNS_ONLY", "SHUT_DOWN", "DEAD"]
    assert any("dangling CNAME" in warning for warning in warnings)
    store = Store(db_path)
    try:
        history = store._conn.execute(
            "SELECT h.state, h.cnames_json, h.dangling_cname"
            " FROM host_status_history h JOIN subdomains s ON s.id = h.subdomain_id"
            " WHERE s.fqdn = ? ORDER BY h.id",
            ("old.example.com",),
        ).fetchall()
        assert [str(row["state"]) for row in history] == states
        assert [row["cnames_json"] for row in history] == ['["old.appspot.com"]'] * 3
        assert [row["dangling_cname"] for row in history] == [
            None,
            "old.appspot.com",
            None,
        ]
    finally:
        store.close()


def test_dead_only_on_nxdomain() -> None:
    assert (
        transition(None, HostEvidence(dns=DnsSignal.NXDOMAIN, dns_tools=("dns",))).state
        is HostState.DEAD
    )
    assert (
        transition(HostState.ALIVE, HostEvidence(dns=DnsSignal.NXDOMAIN, dns_tools=("dns",))).state
        is HostState.SHUT_DOWN
    )
    assert (
        transition(None, HostEvidence(dns=DnsSignal.UNCERTAIN, dns_tools=("dns",))).state
        is not HostState.DEAD
    )


def test_state_recovers_unknown_alive_shut_down_alive() -> None:
    first = transition(None, HostEvidence(web=(("probe", HostState.ALIVE),)))
    second = transition(first.state, HostEvidence(dns=DnsSignal.NXDOMAIN, dns_tools=("dns",)))
    third = transition(second.state, HostEvidence(web=(("probe", HostState.ALIVE),)))
    assert [first.state, second.state, third.state] == [
        HostState.ALIVE,
        HostState.SHUT_DOWN,
        HostState.ALIVE,
    ]


def test_unprobed_host_stays_unknown() -> None:
    first = transition(None, HostEvidence())
    assert first.state is HostState.UNKNOWN
    assert first.persist is False
    kept = transition(HostState.ALIVE, HostEvidence())
    assert kept.state is HostState.ALIVE
    assert kept.persist is False


def test_dns_resolved_without_web_is_dns_only() -> None:
    result = transition(
        None,
        HostEvidence(
            dns=DnsSignal.RESOLVED,
            dns_tools=("dnspython",),
            web=(("pyprobe", HostState.UNKNOWN),),
        ),
    )
    assert result.state is HostState.DNS_ONLY


async def test_injected_clock_controls_state_and_run_timestamps(tmp_path: Path) -> None:
    rec = Recorder()
    fixed = "2026-02-03T04:05:06Z"
    specs = {"live": tool("live", Stage.LIVE)}
    adapters = {"live": adapter("live", Stage.LIVE, rec, records=[alive("example.com")])}
    engine = make_engine(tmp_path, specs, adapters, now=lambda: fixed)
    await engine.run("example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True))
    target = engine.store._conn.execute("SELECT created_at FROM targets").fetchone()
    run = engine.store._conn.execute("SELECT started_at, finished_at FROM scan_runs").fetchone()
    history = engine.store._conn.execute("SELECT checked_at FROM host_status_history").fetchone()
    assert target["created_at"] == fixed
    assert (run["started_at"], run["finished_at"]) == (fixed, fixed)
    assert history["checked_at"] == fixed


# --------------------------------------------------------------------- resume


def canceling(name: str, stage: Stage, rec: Recorder) -> type[BaseToolAdapter]:
    class Cancel(BaseToolAdapter):
        async def run(self, ctx: RunContext) -> ToolResult:
            rec.names.append(name)
            raise asyncio.CancelledError()

        def parse_output(self, raw: str) -> list[object]:
            return []

    Cancel.name = name
    Cancel.stage = stage
    return Cancel


async def test_resume_skips_completed_stages_and_continues(tmp_path: Path) -> None:
    """Regression: PIT-28 resumed live stages must see hosts persisted by earlier stages."""
    rec1 = Recorder()
    specs = {
        "subs-fake": tool("subs-fake", Stage.SUBS),
        "dns-fake": tool("dns-fake", Stage.DNS),
        "live-fake": tool("live-fake", Stage.LIVE),
    }
    adapters1 = {
        "subs-fake": adapter("subs-fake", Stage.SUBS, rec1, records=[sub("www.example.com")]),
        "dns-fake": adapter(
            "dns-fake",
            Stage.DNS,
            rec1,
            records=[SubdomainRecord(fqdn="www.example.com", source="fake", ips=["1.2.3.4"])],
        ),
        "live-fake": canceling("live-fake", Stage.LIVE, rec1),
    }
    store = Store(tmp_path / "recon.db")
    engine1 = make_engine(tmp_path, specs, adapters1, store=store)
    with pytest.raises(asyncio.CancelledError):
        await engine1.run(
            "example.com",
            ScanOptions(stages=(Stage.SUBS, Stage.DNS, Stage.LIVE), mock=True),
        )
    statuses = [
        (row["stage"], row["status"])
        for row in engine1.store._conn.execute("SELECT stage, status FROM scan_runs ORDER BY id")
    ]
    assert statuses == [
        ("subs", "completed"),
        ("dns", "completed"),
        ("live", "interrupted"),
    ]

    rec2 = Recorder()
    adapters2 = {
        "subs-fake": adapter("subs-fake", Stage.SUBS, rec2, records=[sub("www.example.com")]),
        "dns-fake": adapter("dns-fake", Stage.DNS, rec2, records=[]),
        "live-fake": adapter("live-fake", Stage.LIVE, rec2, records=[alive("www.example.com")]),
    }
    engine2 = make_engine(tmp_path, specs, adapters2, store=store)
    summary = await engine2.run(
        "example.com",
        ScanOptions(
            stages=(Stage.SUBS, Stage.DNS, Stage.LIVE),
            mock=True,
            resume=True,
        ),
    )
    assert rec2.names == ["live-fake"]
    assert set(rec2.hosts[-1]) == {"example.com", "www.example.com"}
    assert summary.resumed is True
    assert [stage.stage for stage in summary.stages] == [Stage.SUBS, Stage.DNS, Stage.LIVE]
    assert [stage.resumed for stage in summary.stages] == [True, True, False]
    counts = [
        (row["stage"], row["status"])
        for row in engine2.store._conn.execute("SELECT stage, status FROM scan_runs ORDER BY id")
    ]
    assert counts == [
        ("subs", "completed"),
        ("dns", "completed"),
        ("live", "interrupted"),
        ("live", "completed"),
    ]
    tool_counts = dict(
        engine2.store._conn.execute(
            "SELECT tool, COUNT(*) AS n FROM tool_runs GROUP BY tool"
        ).fetchall()
    )
    assert dict(tool_counts) == {"subs-fake": 1, "dns-fake": 1, "live-fake": 1}
    row = engine2.store._conn.execute(
        "SELECT state FROM subdomains WHERE fqdn = ?", ("www.example.com",)
    ).fetchone()
    assert row["state"] == "ALIVE"


# ------------------------------------------------------------------ exit codes


def test_exit_code_constants_match_docs() -> None:
    """Regression: 11c-G-4.

    docs/02 section 6 gives code 6 to install/update only; a scan with every tool
    failed is code 4 (no usable tool). The engine enum must not offer a sixth
    scan outcome that nothing can return.
    """
    assert ExitCode.ERROR == 1
    assert ExitCode.USAGE == 2
    assert ExitCode.INTERRUPTED == 130
    assert {int(code) for code in ExitCode} == {0, 1, 2, 3, 4, 5, 130}


async def test_exit_code_clean_is_success(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {"a": tool("a", Stage.SUBS)}
    adapters = {"a": adapter("a", Stage.SUBS, rec, records=[])}
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.SUBS,), active=True, mock=True)
    )
    assert summary.exit_code is ExitCode.SUCCESS


async def test_tools_receive_the_configured_idle_windows(tmp_path: Path) -> None:
    """D52: the engine hands `runtime_idle` down as `RunContext.limits`.

    An adapter never reads config.yaml itself (docs/09 section 4a2b). A tool gets
    the window of its own `class:` and nothing else - no cap, no floor. The urls
    tools are the ones that used to carry caps, so their classes are pinned too.
    """
    seen: dict[str, object] = {}

    class Urls(BaseToolAdapter):
        name = "urls-fake"
        stage = Stage.SUBS

        async def run(self, ctx: RunContext) -> ToolResult:
            seen.update(ctx.limits)
            return ToolResult(tool=self.name, status=ToolStatus.OK)

        def parse_output(self, raw: str) -> list[Record]:
            return []

    # A python-kind row, so the run does not need an installed binary; the class
    # is what this test is about.
    from dataclasses import replace

    spec = replace(tool("urls-fake", Stage.SUBS, mode=Mode.ACTIVE), class_="archive")
    specs = {"urls-fake": spec}
    summary = await make_engine(tmp_path, specs, {"urls-fake": Urls}).run(
        "example.com", ScanOptions(stages=(Stage.SUBS,), active=True, mock=True)
    )
    assert summary.exit_code is ExitCode.SUCCESS
    assert seen["urls-fake"].idle_s == 180.0  # class: archive
    assert set(seen["urls-fake"].model_dump()) == {"idle_s"}
    # The real registry rows the urls stage selects, and the class each carries.
    assert get_spec("urlfinder").class_ == "archive"
    assert get_spec("hakrawler").class_ == "crawler"
    assert get_spec("subjs").class_ == "crawler"


def _dedup_run(
    tmp_path: Path,
    *,
    bare: tuple[int | None, HostState],
    www: tuple[int | None, HostState] | None,
    bare_ips: tuple[str, ...] = ("192.0.2.10",),
    www_ips: tuple[str, ...] = ("192.0.2.10",),
) -> dict[str, HostSnapshot]:
    """Run dns+live with the given answers and return the stored host rows.

    `www=None` means the www name does not exist at all (not in DNS, not probed).
    """
    rec = Recorder()
    specs = {
        "dns-fake": tool("dns-fake", Stage.DNS),
        "live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE),
    }
    dns_records: list[Record] = [
        SubdomainRecord(fqdn="example.com", source="dns-fake", ips=list(bare_ips))
    ]
    live_records: list[Record] = [
        HostStatusRecord(
            fqdn="example.com",
            source="live-fake",
            state=bare[1],
            status_code=bare[0],
        )
    ]
    if www is not None:
        dns_records.append(
            SubdomainRecord(fqdn="www.example.com", source="dns-fake", ips=list(www_ips))
        )
        live_records.append(
            HostStatusRecord(
                fqdn="www.example.com",
                source="live-fake",
                state=www[1],
                status_code=www[0],
            )
        )
    adapters = {
        "dns-fake": adapter("dns-fake", Stage.DNS, rec, records=dns_records),
        "live-fake": adapter("live-fake", Stage.LIVE, rec, records=live_records),
    }
    engine = make_engine(tmp_path, specs, adapters, scope_text=SCOPE)
    summary = asyncio.run(
        engine.run(
            "example.com",
            ScanOptions(stages=(Stage.DNS, Stage.LIVE), active=True, mock=True),
        )
    )
    return {row.fqdn: row for row in engine.host_rows(summary.target_id)}


def test_www_redirect_to_bare_is_marked_duplicate(tmp_path: Path) -> None:
    """D22: www.X 301 + X 200 -> www.X is the duplicate (the bare name is canonical)."""
    rows = _dedup_run(tmp_path, bare=(200, HostState.ALIVE), www=(301, HostState.ALIVE))
    assert rows["www.example.com"].duplicate_of == "example.com"
    assert rows["example.com"].duplicate_of is None


def test_bare_redirect_to_www_is_marked_duplicate(tmp_path: Path) -> None:
    """The other direction: X 301 + www.X 200 -> X is the duplicate."""
    rows = _dedup_run(tmp_path, bare=(301, HostState.ALIVE), www=(200, HostState.ALIVE))
    assert rows["example.com"].duplicate_of == "www.example.com"
    assert rows["www.example.com"].duplicate_of is None


def test_both_200_independent_servers_not_marked_duplicate(tmp_path: Path) -> None:
    """Both serve content: two sites, so neither is a duplicate (D22 rule 2)."""
    rows = _dedup_run(
        tmp_path,
        bare=(200, HostState.ALIVE),
        www=(200, HostState.ALIVE),
        bare_ips=("192.0.2.10",),
        www_ips=("192.0.2.11",),
    )
    assert rows["example.com"].duplicate_of is None
    assert rows["www.example.com"].duplicate_of is None
    assert rows["example.com"].www_note == "has www sibling at www.example.com"
    assert rows["www.example.com"].www_note == "has www sibling at example.com"


def test_same_status_on_one_server_marks_the_www_variant(tmp_path: Path) -> None:
    """The example.com 403 pair: same code, shared IP -> www is the duplicate."""
    rows = _dedup_run(
        tmp_path,
        bare=(403, HostState.ALIVE),
        www=(403, HostState.ALIVE),
        bare_ips=("192.0.2.10",),
        www_ips=("192.0.2.10",),
    )
    assert rows["www.example.com"].duplicate_of == "example.com"
    assert rows["example.com"].duplicate_of is None


def test_same_status_on_different_servers_is_only_a_note(tmp_path: Path) -> None:
    rows = _dedup_run(
        tmp_path,
        bare=(403, HostState.ALIVE),
        www=(403, HostState.ALIVE),
        bare_ips=("192.0.2.10",),
        www_ips=("192.0.2.11",),
    )
    assert rows["example.com"].duplicate_of is None
    assert rows["www.example.com"].duplicate_of is None
    assert rows["example.com"].www_note == "www variant on a different server"
    assert rows["www.example.com"].www_note == "www variant on a different server"


def test_www_both_null_status_not_marked_duplicate(tmp_path: Path) -> None:
    """NULL is "no HTTP status observed", not a status both names share (D25)."""
    rows = _dedup_run(
        tmp_path,
        bare=(None, HostState.ALIVE),
        www=(None, HostState.ALIVE),
        bare_ips=("192.0.2.10",),
        www_ips=("192.0.2.10",),
    )
    # The pair is ALIVE on both names and shares an IP, but neither name has a
    # status code, so nothing licenses the claim "same website" (PIT-61).
    assert rows["example.com"].duplicate_of is None
    assert rows["www.example.com"].duplicate_of is None
    assert rows["example.com"].www_note is None
    assert rows["www.example.com"].www_note is None


def test_www_dead_is_not_marked_duplicate(tmp_path: Path) -> None:
    """A dead variant is a name that does not resolve, not a duplicate website."""
    rows = _dedup_run(tmp_path, bare=(200, HostState.ALIVE), www=(None, HostState.DEAD))
    assert rows["example.com"].duplicate_of is None
    assert rows["www.example.com"].duplicate_of is None
    assert rows["www.example.com"].www_note is None


def test_single_variant_not_touched(tmp_path: Path) -> None:
    rows = _dedup_run(tmp_path, bare=(200, HostState.ALIVE), www=None)
    assert set(rows) == {"example.com"}
    assert rows["example.com"].duplicate_of is None
    assert rows["example.com"].www_note is None


def test_www_dedup_never_changes_host_state_or_confidence(tmp_path: Path) -> None:
    """Frozen boundary (D22): metadata only - state, confidence and counts stay."""
    rows = _dedup_run(tmp_path, bare=(200, HostState.ALIVE), www=(301, HostState.ALIVE))
    assert rows["www.example.com"].state is HostState.ALIVE
    assert rows["www.example.com"].status_code == 301
    assert rows["example.com"].state is HostState.ALIVE


async def test_exit_code_scope_violation(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {"live": tool("live", Stage.LIVE, mode=Mode.ACTIVE)}
    adapters = {"live": adapter("live", Stage.LIVE, rec, records=[alive("example.com")])}
    scope = SCOPE.replace("allow_active: true", "allow_active: false")
    summary = await make_engine(tmp_path, specs, adapters, scope_text=scope).run(
        "example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True)
    )
    assert summary.scope_denied is True
    assert summary.exit_code is ExitCode.SCOPE


async def test_exit_code_scope_denied_with_passive_success(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {
        "subs": tool("subs", Stage.SUBS),
        "live": tool("live", Stage.LIVE, mode=Mode.ACTIVE),
    }
    adapters = {
        "subs": adapter("subs", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "live": adapter("live", Stage.LIVE, rec, records=[alive("www.example.com")]),
    }
    scope = SCOPE.replace("allow_active: true", "allow_active: false")
    summary = await make_engine(tmp_path, specs, adapters, scope_text=scope).run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS, Stage.LIVE), active=True, mock=True),
    )
    passive = next(stage for stage in summary.stages if stage.stage is Stage.SUBS)
    assert any(result.status is ToolStatus.OK for result in passive.results)
    assert "live" not in rec.names
    assert summary.scope_denied is True
    assert summary.exit_code is ExitCode.SCOPE


async def test_exit_code_all_tools_failed_is_no_tool(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {"a": tool("a", Stage.SUBS), "b": tool("b", Stage.SUBS)}
    adapters = {
        "a": adapter("a", Stage.SUBS, rec, error=RuntimeError("a")),
        "b": adapter("b", Stage.SUBS, rec, error=RuntimeError("b")),
    }
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.SUBS,), active=True, mock=True)
    )
    assert summary.exit_code is ExitCode.NO_TOOL


async def test_exit_code_partial_success(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {"a": tool("a", Stage.SUBS), "b": tool("b", Stage.SUBS)}
    adapters = {
        "a": adapter("a", Stage.SUBS, rec, records=[]),
        "b": adapter("b", Stage.SUBS, rec, error=RuntimeError("b")),
    }
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.SUBS,), active=True, mock=True)
    )
    assert summary.exit_code is ExitCode.PARTIAL


async def test_an_external_service_gap_exits_zero_and_is_named_in_the_gaps(tmp_path: Path) -> None:
    """Owner ruling 2026-11-18: 429/quota/5xx is a gap, never exit 5.

    The example.com case: every subs source was refused by its provider, the run
    looked broken (exit 5) although nothing on this box was wrong.
    """
    rec = Recorder()
    specs = {"otx": tool("otx", Stage.SUBS), "crtsh": tool("crtsh", Stage.SUBS)}
    adapters = {
        "otx": adapter(
            "otx",
            Stage.SUBS,
            rec,
            status=ToolStatus.GAP,
            detail="otx: rate limited (HTTP 429)",
        ),
        "crtsh": adapter(
            "crtsh",
            Stage.SUBS,
            rec,
            status=ToolStatus.GAP,
            detail="crtsh: server error (HTTP 502)",
        ),
    }
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    assert summary.exit_code is ExitCode.SUCCESS
    assert summary.completion_status == "complete_with_gaps"
    assert [gap.stage for gap in summary.gaps] == [Stage.SUBS]
    assert summary.gaps[0].skipped == 0
    assert "otx: rate limited (HTTP 429)" in summary.gaps[0].reason
    assert "crtsh: server error (HTTP 502)" in summary.gaps[0].reason

    # The database says gap, not failed (schema 8).
    rows = engine.store._conn.execute("SELECT tool, status FROM tool_runs ORDER BY tool").fetchall()
    assert [(row["tool"], row["status"]) for row in rows] == [
        ("crtsh", "gap"),
        ("otx", "gap"),
    ]
    # A gap does not make the stage row partial either.
    run = engine.store._conn.execute("SELECT status FROM scan_runs").fetchone()
    assert run["status"] == "completed"


async def test_a_gap_never_masks_a_real_failure(tmp_path: Path) -> None:
    """A gap is exit 0 on its own, but it must not hide a failed tool."""
    rec = Recorder()
    specs = {"otx": tool("otx", Stage.SUBS), "crtsh": tool("crtsh", Stage.SUBS)}
    adapters = {
        "otx": adapter(
            "otx",
            Stage.SUBS,
            rec,
            status=ToolStatus.GAP,
            detail="otx: rate limited (HTTP 429)",
        ),
        "crtsh": adapter("crtsh", Stage.SUBS, rec, error=RuntimeError("boom")),
    }
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.SUBS,), active=True, mock=True)
    )
    assert summary.exit_code is ExitCode.PARTIAL
    assert [gap.stage for gap in summary.gaps] == [Stage.SUBS]


async def test_exit_code_tool_crash_is_partial(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {"a": tool("a", Stage.SUBS), "b": tool("b", Stage.SUBS)}
    adapters = {
        "a": adapter("a", Stage.SUBS, rec, records=[]),
        "b": adapter("b", Stage.SUBS, rec, error=RuntimeError("crash")),
    }
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.SUBS,), active=True, mock=True)
    )
    assert summary.exit_code is ExitCode.PARTIAL
    assert any(result.status is ToolStatus.FAILED for result in summary.results)


# ------------------------------------------------------- 12k: stages that ran nothing


def empty_stage_warnings(summary: ScanSummary) -> list[str]:
    return [warning for warning in summary.warnings if "executed no tools" in warning]


async def test_a_stage_with_no_adapter_warns_by_name_and_is_a_gap_not_a_failure(
    tmp_path: Path,
) -> None:
    """Changed 2026-11-17 from `test_an_empty_stage_warns_by_name_and_makes_the_run_partial`.

    Old: a zero-tool stage always made the run partial (exit 5), PIT-40.
    New: owner ruling - when the only cause is an absent tool (no adapter yet,
    not installed) the run used every tool available, so it exits 0 and the
    gap is reported in `summary.gaps` plus the existing warning.
    """
    rec = Recorder()
    specs = {"alpha": tool("alpha", Stage.SUBS), "ghost": tool("ghost", Stage.TECH)}
    adapters = {"alpha": adapter("alpha", Stage.SUBS, rec, records=[sub("www.example.com")])}
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.SUBS, Stage.TECH), mock=True)
    )

    assert summary.exit_code is ExitCode.SUCCESS
    tech = next(stage for stage in summary.stages if stage.stage is Stage.TECH)
    assert tech.results == []
    assert [skip.tool for skip in tech.skipped] == ["ghost"]
    notes = empty_stage_warnings(summary)
    assert len(notes) == 1
    assert "tech" in notes[0]
    assert "1 tool(s) skipped" in notes[0]
    assert summary.gaps == [CompletionGap(Stage.TECH, "no adapter yet (phase 2)", 1)]
    assert summary.completion_status == "complete_with_gaps"


async def test_a_stage_of_uninstalled_tools_is_a_gap(tmp_path: Path) -> None:
    """The second absence reason: an adapter exists but the tool is not installed."""
    rec = Recorder()
    specs = {"alpha": tool("alpha", Stage.SUBS), "beta": tool("beta", Stage.LIVE)}
    adapters = {
        "alpha": adapter("alpha", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "beta": adapter("beta", Stage.LIVE, rec, records=[]),
    }
    missing = adapters["beta"]
    summary = await make_engine(
        tmp_path, specs, adapters, installed=lambda adapter: adapter is not missing
    ).run("example.com", ScanOptions(stages=(Stage.SUBS, Stage.LIVE), mock=False, active=True))

    assert summary.exit_code is ExitCode.SUCCESS
    assert summary.gaps == [CompletionGap(Stage.LIVE, "not installed", 1)]


async def test_a_stage_emptied_by_a_tier_rule_is_not_a_gap(tmp_path: Path) -> None:
    """A deliberate exclusion is not an absence: no adapter was missing.

    The stage's only tool is intrusive, so `passive` mode skips it for the tier.
    That is still a stage that ran nothing -> exit 5, never a gap.
    """
    rec = Recorder()
    specs = {
        "alpha": tool("alpha", Stage.SUBS),
        "brute": tool("brute", Stage.TECH, tier=Tier.INTRUSIVE, mode=Mode.ACTIVE),
    }
    adapters = {
        "alpha": adapter("alpha", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "brute": adapter("brute", Stage.TECH, rec, records=[]),
    }
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.SUBS, Stage.TECH), mock=True)
    )

    assert summary.gaps == []
    assert summary.completion_status == "complete"
    assert summary.exit_code is ExitCode.PARTIAL


async def test_gaps_and_a_failed_tool_together_stay_partial(tmp_path: Path) -> None:
    """Exit 5 is reserved for real partials: a gap must not mask a failure."""
    rec = Recorder()
    specs = {
        "alpha": tool("alpha", Stage.SUBS),
        "beta": tool("beta", Stage.SUBS),
        "ghost": tool("ghost", Stage.TECH),
    }
    adapters = {
        "alpha": adapter("alpha", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "beta": adapter("beta", Stage.SUBS, rec, error=RuntimeError("boom")),
    }
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.SUBS, Stage.TECH), mock=True)
    )

    assert summary.exit_code is ExitCode.PARTIAL
    assert [gap.stage for gap in summary.gaps] == [Stage.TECH]


async def test_every_requested_stage_empty_is_no_tool_not_partial(tmp_path: Path) -> None:
    """docs/02 section 6: all stages empty means nothing usable ran -> 4, each named."""
    specs = {"ghost": tool("ghost", Stage.TECH), "phantom": tool("phantom", Stage.URLS)}
    summary = await make_engine(tmp_path, specs, {}).run(
        "example.com", ScanOptions(stages=(Stage.TECH, Stage.URLS), mock=True)
    )

    assert summary.exit_code is ExitCode.NO_TOOL
    notes = empty_stage_warnings(summary)
    assert len(notes) == 2
    assert {note.split(" ", 1)[0] for note in notes} == {"tech", "urls"}


async def test_empty_stages_and_a_partial_failure_together_are_still_partial(
    tmp_path: Path,
) -> None:
    """One empty stage must not hide another warning or the existing failure cause."""
    rec = Recorder()
    specs = {
        "alpha": tool("alpha", Stage.SUBS),
        "beta": tool("beta", Stage.SUBS),
        "ghost": tool("ghost", Stage.TECH),
        "phantom": tool("phantom", Stage.URLS),
    }
    adapters = {
        "alpha": adapter("alpha", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "beta": adapter("beta", Stage.SUBS, rec, error=RuntimeError("boom")),
    }
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.SUBS, Stage.TECH, Stage.URLS), mock=True)
    )

    assert summary.exit_code is ExitCode.PARTIAL
    assert any(result.status is ToolStatus.FAILED for result in summary.results)
    notes = empty_stage_warnings(summary)
    assert {note.split(" ", 1)[0] for note in notes} == {"tech", "urls"}


async def test_one_empty_stage_plus_a_tool_failure_stays_partial(tmp_path: Path) -> None:
    """Exactly one empty stage next to one failed tool: still 5, and the warning names it.

    Regression: PIT-40 - the two causes are independent, so neither may mask the other.
    """
    rec = Recorder()
    specs = {
        "alpha": tool("alpha", Stage.SUBS),
        "beta": tool("beta", Stage.SUBS),
        "ghost": tool("ghost", Stage.TECH),
    }
    adapters = {
        "alpha": adapter("alpha", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "beta": adapter("beta", Stage.SUBS, rec, error=RuntimeError("boom")),
    }
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.SUBS, Stage.TECH), mock=True)
    )

    assert summary.exit_code is ExitCode.PARTIAL
    failed = [result.tool for result in summary.results if result.status is ToolStatus.FAILED]
    assert failed == ["beta"]
    notes = empty_stage_warnings(summary)
    assert len(notes) == 1
    assert notes[0].startswith("tech ")


async def test_all_tools_failed_still_outranks_an_empty_stage(tmp_path: Path) -> None:
    """Precedence: no usable tool (4) wins over the empty-stage 5 (docs/02 section 6)."""
    rec = Recorder()
    specs = {
        "alpha": tool("alpha", Stage.SUBS),
        "beta": tool("beta", Stage.SUBS),
        "ghost": tool("ghost", Stage.TECH),
    }
    adapters = {
        "alpha": adapter("alpha", Stage.SUBS, rec, error=RuntimeError("a")),
        "beta": adapter("beta", Stage.SUBS, rec, error=RuntimeError("b")),
    }
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.SUBS, Stage.TECH), mock=True)
    )

    assert summary.exit_code is ExitCode.NO_TOOL
    assert "tech" in empty_stage_warnings(summary)[0]


async def test_a_stage_filtered_out_by_tools_is_not_an_empty_stage(tmp_path: Path) -> None:
    """A deliberate `--tools` filter is not "no adapter exists": no warning, exit 0."""
    rec = Recorder()
    specs = {"alpha": tool("alpha", Stage.SUBS), "ghost": tool("ghost", Stage.TECH)}
    adapters = {"alpha": adapter("alpha", Stage.SUBS, rec, records=[])}
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS, Stage.TECH), tools=("alpha",), mock=True),
    )

    assert summary.exit_code is ExitCode.SUCCESS
    assert [stage.stage for stage in summary.stages] == [Stage.SUBS]
    assert empty_stage_warnings(summary) == []


async def test_a_resumed_run_does_not_warn_about_completed_stages(tmp_path: Path) -> None:
    """A stage finished in the earlier run is not an empty stage on resume."""
    rec = Recorder()
    specs = {"alpha": tool("alpha", Stage.SUBS)}
    adapters = {"alpha": adapter("alpha", Stage.SUBS, rec, records=[sub("www.example.com")])}
    engine = make_engine(tmp_path, specs, adapters)
    first = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    second = await engine.run(
        "example.com", ScanOptions(stages=(Stage.SUBS,), mock=True, resume=True)
    )

    assert first.exit_code is ExitCode.SUCCESS
    assert second.resumed is True
    assert second.exit_code is ExitCode.SUCCESS
    assert empty_stage_warnings(second) == []


async def test_two_stages_that_ran_tools_still_exit_zero(tmp_path: Path) -> None:
    """Regression guard: no empty stage and no failure still means 0."""
    rec = Recorder()
    specs = {"alpha": tool("alpha", Stage.SUBS), "beta": tool("beta", Stage.TECH)}
    adapters = {
        "alpha": adapter("alpha", Stage.SUBS, rec, records=[]),
        "beta": adapter("beta", Stage.TECH, rec, records=[]),
    }
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.SUBS, Stage.TECH), mock=True)
    )

    assert summary.exit_code is ExitCode.SUCCESS
    assert empty_stage_warnings(summary) == []


async def test_scope_denial_keeps_code_3_even_with_an_empty_stage(tmp_path: Path) -> None:
    """Precedence: scope (3) outranks the empty-stage partial."""
    rec = Recorder()
    specs = {
        "live": tool("live", Stage.LIVE, mode=Mode.ACTIVE),
        "ghost": tool("ghost", Stage.TECH),
    }
    adapters = {"live": adapter("live", Stage.LIVE, rec, records=[alive("example.com")])}
    scope = SCOPE.replace("allow_active: true", "allow_active: false")
    summary = await make_engine(tmp_path, specs, adapters, scope_text=scope).run(
        "example.com",
        ScanOptions(stages=(Stage.LIVE, Stage.TECH), active=True, mock=True),
    )

    assert summary.scope_denied is True
    assert summary.exit_code is ExitCode.SCOPE
    assert any("live" in note for note in empty_stage_warnings(summary)) or any(
        "tech" in note for note in empty_stage_warnings(summary)
    )


async def test_min_sources_hides_low_source_results(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {"a": tool("a", Stage.SUBS), "b": tool("b", Stage.SUBS)}
    adapters = {
        "a": adapter(
            "a",
            Stage.SUBS,
            rec,
            records=[sub("www.example.com"), sub("one.example.com")],
        ),
        "b": adapter("b", Stage.SUBS, rec, records=[sub("www.example.com")]),
    }
    engine = make_engine(tmp_path, specs, adapters)
    await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True, min_sources=2))
    hosts = [
        row["fqdn"]
        for row in engine.store._conn.execute("SELECT fqdn FROM subdomains ORDER BY fqdn")
    ]
    assert hosts == ["www.example.com"]
    row = engine.store._conn.execute(
        "SELECT confidence, source_count FROM subdomains WHERE fqdn = ?",
        ("www.example.com",),
    ).fetchone()
    assert (row["confidence"], row["source_count"]) == ("MEDIUM", 2)


# ----------------------------------------------------------------- wildcard


def dns_tool(
    rec: Recorder,
    *,
    records: list[Record],
    answer: DnsResult,
    probes: list[str],
) -> type[BaseToolAdapter]:
    """dnspython stand-in: fixed stage records plus one scripted probe answer."""

    class FakeDns(BaseToolAdapter):
        async def run(self, ctx: RunContext) -> ToolResult:
            rec.names.append(self.name)
            return ToolResult(tool=self.name, status=ToolStatus.OK, records=records)

        async def resolve_host(self, ctx: RunContext, host: str) -> DnsResult:
            probes.append(host)
            return answer

        def parse_output(self, raw: str) -> list[Record]:
            return []

    FakeDns.name = "dnspython"
    FakeDns.stage = Stage.DNS
    return FakeDns


def wildcard_setup(
    tmp_path: Path,
    answer: DnsResult,
) -> tuple[Engine, list[str]]:
    rec = Recorder()
    probes: list[str] = []
    specs = {"dnspython": tool("dnspython", Stage.DNS)}
    adapters = {
        "dnspython": dns_tool(
            rec,
            records=[
                SubdomainRecord(fqdn="www.example.com", source="dnspython", ips=["1.2.3.4"]),
                SubdomainRecord(fqdn="own.example.com", source="dnspython", ips=["9.9.9.9"]),
            ],
            answer=answer,
            probes=probes,
        )
    }
    return make_engine(tmp_path, specs, adapters), probes


def stored_wildcard(engine: Engine) -> dict[str, int]:
    return {
        str(row["fqdn"]): int(row["is_wildcard"])
        for row in engine.store._conn.execute("SELECT fqdn, is_wildcard FROM subdomains")
    }


async def test_wildcard_present_marks_matching_hosts(tmp_path: Path) -> None:
    engine, probes = wildcard_setup(tmp_path, DnsResult(DnsOutcome.RESOLVED, ips=["1.2.3.4"]))
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.DNS,)))
    assert len(probes) == 3
    assert all(probe.endswith(".example.com") and probe != "example.com" for probe in probes)
    assert summary.warnings == []
    assert stored_wildcard(engine) == {"www.example.com": 1, "own.example.com": 0}


async def test_wildcard_none_marks_nothing(tmp_path: Path) -> None:
    engine, probes = wildcard_setup(tmp_path, DnsResult(DnsOutcome.NXDOMAIN))
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.DNS,)))
    assert len(probes) == 3
    assert summary.warnings == []
    assert stored_wildcard(engine) == {"www.example.com": 0, "own.example.com": 0}


async def test_wildcard_unknown_warns_and_marks_nothing(tmp_path: Path) -> None:
    engine, probes = wildcard_setup(tmp_path, DnsResult(DnsOutcome.TIMEOUT))
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.DNS,)))
    assert len(probes) == 3
    assert any("wildcard check inconclusive" in warning for warning in summary.warnings), (
        summary.warnings
    )
    assert stored_wildcard(engine) == {"www.example.com": 0, "own.example.com": 0}


async def test_wildcard_mark_reaches_the_subdomains_table(tmp_path: Path) -> None:
    engine, _probes = wildcard_setup(tmp_path, DnsResult(DnsOutcome.RESOLVED, ips=["1.2.3.4"]))
    await engine.run("example.com", ScanOptions(stages=(Stage.DNS,)))
    rows = {
        str(row["fqdn"]): int(row["is_wildcard"])
        for row in engine.store._conn.execute(
            "SELECT fqdn, is_wildcard FROM subdomains WHERE fqdn IN (?, ?)",
            ("www.example.com", "own.example.com"),
        )
    }
    assert rows == {"www.example.com": 1, "own.example.com": 0}


async def test_wildcard_never_probes_under_mock(tmp_path: Path) -> None:
    engine, probes = wildcard_setup(tmp_path, DnsResult(DnsOutcome.RESOLVED, ips=["1.2.3.4"]))
    await engine.run("example.com", ScanOptions(stages=(Stage.DNS,), mock=True))
    assert probes == []
    assert stored_wildcard(engine) == {"www.example.com": 0, "own.example.com": 0}


def seed_subs_run(
    store: Store, target_id: int, hosts: list[str], *, status: str = "completed"
) -> int:
    run_id = store.create_scan_run(target_id, Stage.SUBS.value)
    for fqdn in hosts:
        sub_id = store.upsert_subdomain(target_id, fqdn, run_id=run_id, provenance="subs")
        store.add_subdomain_source(sub_id, run_id, "subfinder")
    store.finish_scan_run(run_id, status)
    return run_id


def test_diff_with_two_runs_reports_pending_and_no_gone(tmp_path: Path) -> None:
    """Regression: docs/02 two-miss rule - one miss is never GONE."""
    engine = make_engine(tmp_path, specs={}, adapters={})
    target_id = engine.store.create_target("example.com")
    first = seed_subs_run(engine.store, target_id, ["gone.example.com", "kept.example.com"])
    latest = seed_subs_run(engine.store, target_id, ["kept.example.com"])

    report = engine.diff("example.com")

    assert (report.baseline_run_id, report.previous_run_id, report.latest_run_id) == (
        None,
        first,
        latest,
    )
    assert report.gone == ()
    assert report.pending_gone == ("gone.example.com",)


def test_diff_with_three_runs_confirms_gone(tmp_path: Path) -> None:
    engine = make_engine(tmp_path, specs={}, adapters={})
    target_id = engine.store.create_target("example.com")
    baseline = seed_subs_run(engine.store, target_id, ["gone.example.com", "kept.example.com"])
    seed_subs_run(engine.store, target_id, ["kept.example.com"])
    latest = seed_subs_run(engine.store, target_id, ["kept.example.com"])

    report = engine.diff("example.com")

    assert report.baseline_run_id == baseline
    assert report.latest_run_id == latest
    assert report.gone == ("gone.example.com",)
    assert report.pending_gone == ()


async def test_dns_only_host_has_dns_provenance_and_is_never_new(tmp_path: Path) -> None:
    """Regression: PIT-44 (12b) - a DNS-resolved host is not a discovery result.

    The dns stage used to create the row with no marker, so `diff_new` (which
    keyed on `first_seen_run`) reported a host no discovery tool ever returned
    as NEW. The row stays, marked `dns`, and is excluded from NEW.
    """
    specs = {"subs-a": tool("subs-a", Stage.SUBS), "dns-a": tool("dns-a", Stage.DNS)}
    first = make_engine(
        tmp_path,
        specs,
        {
            "subs-a": adapter("subs-a", Stage.SUBS, Recorder(), records=[sub("base.example.com")]),
            "dns-a": adapter("dns-a", Stage.DNS, Recorder(), records=[]),
        },
    )
    await first.run("example.com", ScanOptions(stages=(Stage.SUBS, Stage.DNS), mock=True))
    second = make_engine(
        tmp_path,
        specs,
        {
            "subs-a": adapter("subs-a", Stage.SUBS, Recorder(), records=[]),
            "dns-a": adapter(
                "dns-a",
                Stage.DNS,
                Recorder(),
                records=[SubdomainRecord(fqdn="alias.example.com", source="fake", ips=["1.2.3.4"])],
            ),
        },
        store=first.store,
    )
    await second.run("example.com", ScanOptions(stages=(Stage.SUBS, Stage.DNS), mock=True))

    row = second.store._conn.execute(
        "SELECT provenance, source_count FROM subdomains WHERE fqdn = ?",
        ("alias.example.com",),
    ).fetchone()
    assert (row["provenance"], row["source_count"]) == ("dns", 0)
    sources = second.store._conn.execute(
        "SELECT COUNT(*) FROM subdomain_sources x JOIN subdomains s ON s.id = x.subdomain_id"
        " WHERE s.fqdn = ?",
        ("alias.example.com",),
    ).fetchone()[0]
    assert sources == 0
    assert second.diff("example.com").new == ()


async def test_a_discovered_host_keeps_its_real_provenance_and_is_new(
    tmp_path: Path,
) -> None:
    """Regression guard: real discovery is still `subs` and still NEW."""
    specs = {"subs-a": tool("subs-a", Stage.SUBS), "dns-a": tool("dns-a", Stage.DNS)}
    first = make_engine(
        tmp_path,
        specs,
        {
            "subs-a": adapter("subs-a", Stage.SUBS, Recorder(), records=[sub("base.example.com")]),
            "dns-a": adapter("dns-a", Stage.DNS, Recorder(), records=[]),
        },
    )
    await first.run("example.com", ScanOptions(stages=(Stage.SUBS, Stage.DNS), mock=True))
    second = make_engine(
        tmp_path,
        specs,
        {
            "subs-a": adapter("subs-a", Stage.SUBS, Recorder(), records=[sub("www.example.com")]),
            "dns-a": adapter(
                "dns-a",
                Stage.DNS,
                Recorder(),
                records=[
                    SubdomainRecord(fqdn="www.example.com", source="fake", ips=["1.2.3.4"]),
                    SubdomainRecord(fqdn="alias.example.com", source="fake", ips=["1.2.3.4"]),
                ],
            ),
        },
        store=first.store,
    )
    await second.run("example.com", ScanOptions(stages=(Stage.SUBS, Stage.DNS), mock=True))

    rows = {
        str(row["fqdn"]): str(row["provenance"])
        for row in second.store._conn.execute("SELECT fqdn, provenance FROM subdomains")
    }
    assert rows == {
        "alias.example.com": "dns",
        "base.example.com": "subs",
        "www.example.com": "subs",
    }
    assert second.diff("example.com").new == ("www.example.com",)


def test_diff_with_one_run_has_nothing_to_compare(tmp_path: Path) -> None:
    """First-ever run: no crash, no spurious GONE, nothing pending."""
    engine = make_engine(tmp_path, specs={}, adapters={})
    target_id = engine.store.create_target("example.com")
    latest = seed_subs_run(engine.store, target_id, ["a.example.com"])

    report = engine.diff("example.com")

    assert (report.baseline_run_id, report.previous_run_id, report.latest_run_id) == (
        None,
        None,
        latest,
    )
    assert (report.gone, report.pending_gone) == ((), ())


# ------------------------------------------------------- 12a raw output on disk


def raw_result(summary, tool_name: str):
    """The one ToolResult for `tool_name` in a single-stage run."""
    results = [result for stage in summary.stages for result in stage.results]
    return next(result for result in results if result.tool == tool_name)


async def test_each_executed_tool_writes_one_raw_file_and_sets_raw_path(tmp_path: Path) -> None:
    """12a: one redacted file per executed tool, named by run and tool."""
    rec = Recorder()
    specs = {"alpha": tool("alpha", Stage.SUBS), "beta": tool("beta", Stage.SUBS)}
    adapters = {
        "alpha": adapter(
            "alpha", Stage.SUBS, rec, records=[sub("a.example.com")], raw_text="alpha out\n"
        ),
        "beta": adapter(
            "beta", Stage.SUBS, rec, records=[sub("b.example.com")], raw_text="beta out\n"
        ),
    }
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))

    run_id = summary.stages[0].run_id
    stage_dir = tmp_path / "workspaces" / "example.com" / "subs"
    assert sorted(path.name for path in stage_dir.iterdir()) == sorted(
        [f"{run_id}-alpha.txt", f"{run_id}-beta.txt"]
    )
    for name in ("alpha", "beta"):
        written = raw_result(summary, name).raw_path
        assert written is not None
        assert Path(written).read_text(encoding="utf-8") == f"{name} out\n"


async def test_failed_tool_still_writes_its_raw_output(tmp_path: Path) -> None:
    """Regression: PIT-41 - a failed tool keeps its bytes on disk (12a, G-1)."""
    rec = Recorder()
    specs = {"flaky": tool("flaky", Stage.SUBS)}
    adapters = {
        "flaky": adapter(
            "flaky",
            Stage.SUBS,
            rec,
            raw_text="partial line\n--- stderr ---\nexit 1: boom",
            status=ToolStatus.FAILED,
        )
    }
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))

    result = raw_result(summary, "flaky")
    written = Path(result.raw_path or "")
    assert written.is_file()
    assert written.read_text(encoding="utf-8") == "partial line\n--- stderr ---\nexit 1: boom"
    row = engine.store._conn.execute("SELECT status FROM tool_runs").fetchone()
    assert row["status"] == "failed"


async def test_a_crashed_tool_writes_an_empty_file_instead_of_nothing(tmp_path: Path) -> None:
    """One executed tool = exactly one file, even when it raised before any output."""
    rec = Recorder()
    specs = {"crasher": tool("crasher", Stage.SUBS)}
    adapters = {"crasher": adapter("crasher", Stage.SUBS, rec, error=RuntimeError("boom"))}
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))

    result = raw_result(summary, "crasher")
    assert result.status is ToolStatus.FAILED
    written = Path(result.raw_path or "")
    assert written.is_file()
    assert written.read_bytes() == b""


async def test_raw_output_file_is_capped_at_max_output_bytes(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {"chatty": tool("chatty", Stage.SUBS)}
    adapters = {
        "chatty": adapter("chatty", Stage.SUBS, rec, raw_text="A" * (MAX_OUTPUT_BYTES + 5000))
    }
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))

    written = Path(raw_result(summary, "chatty").raw_path or "")
    assert written.stat().st_size == MAX_OUTPUT_BYTES


async def test_raw_output_file_is_redacted_with_the_run_secrets(tmp_path: Path) -> None:
    """PIT-22 extended to the file the engine now fills with tool output."""
    rec = Recorder()
    specs = {"leaky": tool("leaky", Stage.SUBS)}
    adapters = {"leaky": adapter("leaky", Stage.SUBS, rec, raw_text="provider token=sk-live-abc\n")}
    engine = make_engine(tmp_path, specs, adapters, env={"ONLY_ME": "sk-live-abc"})
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))

    content = Path(raw_result(summary, "leaky").raw_path or "").read_text(encoding="utf-8")
    assert "sk-live-abc" not in content
    assert REDACTED in content


async def test_a_failed_workspace_write_keeps_the_tool_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A raw-write failure is contained: the result, row and assets survive."""

    def boom(*_args: object, **_kwargs: object) -> Path:
        raise OSError("disk full")

    monkeypatch.setattr(Workspace, "write", boom)
    rec = Recorder()
    specs = {"tool": tool("tool", Stage.SUBS)}
    adapters = {
        "tool": adapter("tool", Stage.SUBS, rec, records=[sub("www.example.com")], raw_text="out\n")
    }
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))

    result = raw_result(summary, "tool")
    assert result.status is ToolStatus.OK
    assert result.raw_path is None
    row = engine.store._conn.execute("SELECT status FROM tool_runs").fetchone()
    assert row["status"] == "ok"
    stored = engine.store._conn.execute("SELECT fqdn FROM subdomains").fetchone()
    assert stored["fqdn"] == "www.example.com"


async def test_adapter_reported_duration_is_stored_and_never_overwritten(tmp_path: Path) -> None:
    """Regression: PIT-43 - the adapter's own duration is stored, never replaced (12c)."""
    rec = Recorder()
    specs = {"timed": tool("timed", Stage.SUBS)}
    adapters = {"timed": adapter("timed", Stage.SUBS, rec, duration_s=12.5)}
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))

    assert raw_result(summary, "timed").duration_s == 12.5
    row = engine.store._conn.execute("SELECT duration_s FROM tool_runs").fetchone()
    assert row["duration_s"] == 12.5


async def test_missing_adapter_duration_gets_the_harness_wall_clock(tmp_path: Path) -> None:
    """12c: `0.0` means "not measured"; the fallback is a real wall-clock reading."""
    rec = Recorder()
    specs = {"slowish": tool("slowish", Stage.SUBS)}
    adapters = {"slowish": adapter("slowish", Stage.SUBS, rec, duration_s=0.0, delay=0.05)}
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))

    row = engine.store._conn.execute("SELECT duration_s FROM tool_runs").fetchone()
    # The adapter slept 50 ms and reported nothing, so the stored number can only
    # be the harness's own measurement of that call - not a default or a copy.
    assert row["duration_s"] > 0.04
    assert row["duration_s"] < 5.0
    assert raw_result(summary, "slowish").duration_s == row["duration_s"]


async def test_a_non_positive_adapter_duration_is_never_stored(tmp_path: Path) -> None:
    """A frozen or backwards clock must not produce a zero or negative row."""
    rec = Recorder()
    specs = {"weird": tool("weird", Stage.SUBS)}
    adapters = {"weird": adapter("weird", Stage.SUBS, rec, duration_s=-1.0, delay=0.02)}
    engine = make_engine(tmp_path, specs, adapters)
    await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))

    row = engine.store._conn.execute("SELECT duration_s FROM tool_runs").fetchone()
    assert row["duration_s"] > 0


async def test_raw_file_names_do_not_collide_across_tools_or_runs(tmp_path: Path) -> None:
    """Two tools in one stage and the same tool in two runs keep separate files."""
    rec = Recorder()
    specs = {"alpha": tool("alpha", Stage.SUBS), "beta": tool("beta", Stage.SUBS)}
    adapters = {
        "alpha": adapter("alpha", Stage.SUBS, rec, raw_text="alpha\n"),
        "beta": adapter("beta", Stage.SUBS, rec, raw_text="beta\n"),
    }
    engine = make_engine(tmp_path, specs, adapters)
    options = ScanOptions(stages=(Stage.SUBS,), mock=True)
    first = await engine.run("example.com", options)
    second = await engine.run("example.com", options)

    paths = [
        raw_result(summary, name).raw_path
        for summary in (first, second)
        for name in ("alpha", "beta")
    ]
    assert len(set(paths)) == 4
    stage_dir = tmp_path / "workspaces" / "example.com" / "subs"
    assert len(list(stage_dir.iterdir())) == 4


async def test_raw_output_keeps_nul_and_ansi_bytes_verbatim(tmp_path: Path) -> None:
    """A binary payload is evidence: NUL and ANSI bytes reach the file unchanged."""
    rec = Recorder()
    payload = "a\x00b\x1b[31mred\x1b[0m\n"
    specs = {"ansi": tool("ansi", Stage.SUBS)}
    adapters = {"ansi": adapter("ansi", Stage.SUBS, rec, raw_text=payload)}
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))

    written = Path(raw_result(summary, "ansi").raw_path or "")
    assert written.read_bytes() == payload.encode("utf-8")


# ---------------------------------------- no scope file (docs/05 rule 2, 2026-11-17)


async def test_no_scope_file_refuses_active_stages(tmp_path: Path) -> None:
    """D82: no scope file is a refusal, not an implicit unrestricted run.

    Passive stages still run; every active stage is skipped and the run exits 3.
    The CLI refuses earlier, but the engine keeps the same guard for direct
    callers.
    """
    rec = Recorder()
    specs = {
        "subs": tool("subs", Stage.SUBS),
        "live": tool("live", Stage.LIVE, mode=Mode.ACTIVE),
        "ports": tool("ports", Stage.PORTS, mode=Mode.ACTIVE),
    }
    adapters = {
        "subs": adapter(
            "subs", Stage.SUBS, rec, records=[sub("www.example.com"), sub("api.example.com")]
        ),
        "live": adapter(
            "live",
            Stage.LIVE,
            rec,
            records=[alive("www.example.com"), alive("api.example.com")],
        ),
        "ports": adapter("ports", Stage.PORTS, rec, records=[]),
    }
    summary = await make_engine(
        tmp_path, specs, adapters, scope_text=None, installed=lambda _adapter: True
    ).run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS, Stage.LIVE, Stage.PORTS), active=True, mock=True),
    )

    assert rec.names == ["subs"]
    assert summary.scope_denied is True
    assert summary.exit_code is ExitCode.SCOPE
    assert any("No scope.yaml found" in note for note in summary.warnings)
    live_stage = next(item for item in summary.stages if item.stage is Stage.LIVE)
    assert live_stage.skipped
    assert all("No scope.yaml found" in skip.reason for skip in live_stage.skipped)


async def test_a_present_scope_file_is_enforced_exactly_as_before(tmp_path: Path) -> None:
    """The scope file that *is* present keeps the unchanged gate (docs/05 rule 2)."""
    rec = Recorder()
    specs = {"live": tool("live", Stage.LIVE, mode=Mode.ACTIVE)}
    adapters = {"live": adapter("live", Stage.LIVE, rec, records=[alive("example.com")])}
    scope = SCOPE.replace("allow_active: true", "allow_active: false")
    summary = await make_engine(tmp_path, specs, adapters, scope_text=scope).run(
        "example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True)
    )
    assert "live" not in rec.names
    assert summary.scope_denied is True
    assert summary.exit_code is ExitCode.SCOPE


async def test_no_scope_file_never_loads_or_derives_a_scope_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No scope file must not construct a scope from the target.

    `load_scope` is made fatal for the duration of the run: if the no-file path
    loaded a scope (or derived one from `example.com`) the run would raise here.
    D82 then skips every active stage, so no adapter should receive an IP
    predicate at all.
    """
    rec = Recorder()
    predicates: list[Callable[[str], bool] | None] = []

    class FakePorts(BaseToolAdapter):
        name = "ports-fake"
        stage = Stage.PORTS

        async def run(self, ctx: RunContext) -> ToolResult:
            predicates.append(ctx.ip_allowed)
            return ToolResult(tool=self.name, status=ToolStatus.OK, records=[])

        def build_command(self, ctx: RunContext) -> list[str]:
            raise AssertionError("build_command must not be called")

        def parse_output(self, raw: str) -> list[object]:
            return []

    def fatal_load_scope(path: object = None) -> object:
        raise AssertionError(f"no scope file may be loaded (path={path!r})")

    monkeypatch.setattr(engine_module, "load_scope", fatal_load_scope)
    specs = {
        "subs": tool("subs", Stage.SUBS),
        "live": tool("live", Stage.LIVE, mode=Mode.ACTIVE),
        "ports": tool("ports", Stage.PORTS, mode=Mode.ACTIVE),
    }
    adapters: dict[str, type[BaseToolAdapter]] = {
        "subs": adapter("subs", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "live": adapter("live", Stage.LIVE, rec, records=[alive("www.example.com")]),
        "ports": FakePorts,
    }
    summary = await make_engine(
        tmp_path, specs, adapters, scope_text=None, installed=lambda _adapter: True
    ).run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS, Stage.LIVE, Stage.PORTS), active=True, mock=True),
    )

    assert summary.exit_code is ExitCode.SCOPE
    assert rec.names == ["subs"]
    assert predicates == []
    assert not (tmp_path / "scope.yaml").exists()


# --------------------------------------- naabu scope modes (docs/05 rule 6, 2026-11-17)

SCOPE_WITH_CIDRS = SCOPE.replace(
    "max_speed: fast",
    "in_scope_cidrs:\n  - 203.0.113.0/24\nmax_speed: fast",
)


def ports_engine(
    tmp_path: Path,
    rec: Recorder,
    *,
    scope_text: str | None,
    resolve: Callable[[str], object],
) -> Engine:
    specs = {
        "subs": tool("subs", Stage.SUBS),
        "live": tool("live", Stage.LIVE, mode=Mode.ACTIVE),
        "pyscan": tool("pyscan", Stage.PORTS, mode=Mode.ACTIVE),
        "naabu": tool("naabu", Stage.PORTS, mode=Mode.ACTIVE),
    }
    adapters = {
        "subs": adapter(
            "subs", Stage.SUBS, rec, records=[sub("example.com"), sub("www.example.com")]
        ),
        "live": adapter(
            "live",
            Stage.LIVE,
            rec,
            records=[alive("example.com"), alive("www.example.com")],
        ),
        "pyscan": adapter("pyscan", Stage.PORTS, rec),
        "naabu": adapter("naabu", Stage.PORTS, rec),
    }
    return make_engine(
        tmp_path,
        specs,
        adapters,
        scope_text=scope_text,
        installed=lambda _adapter: True,
        resolve=resolve,
    )


async def test_no_scope_flag_runs_naabu_on_hostnames_unrestricted(tmp_path: Path) -> None:
    """(a) With --no-scope: naabu is an ordinary active tool, no resolve step."""
    rec = Recorder()
    resolved: list[str] = []

    async def resolve(host: str) -> list[str]:
        resolved.append(host)
        return ["203.0.113.5"]

    engine = ports_engine(tmp_path, rec, scope_text=None, resolve=resolve)
    summary = await engine.run(
        "example.com",
        ScanOptions(
            stages=(Stage.SUBS, Stage.LIVE, Stage.PORTS),
            active=True,
            mock=True,
            no_scope=True,
        ),
    )

    assert "naabu" in rec.names
    naabu_hosts = rec.hosts[rec.names.index("naabu")]
    assert set(naabu_hosts) == {"example.com", "www.example.com"}
    assert not any(host[0].isdigit() for host in naabu_hosts)
    # No pre-resolution gate: the no-scope path never resolves anything itself.
    assert resolved == []
    assert summary.exit_code is not ExitCode.SCOPE
    naabu_stage = next(stage for stage in summary.stages if stage.stage is Stage.PORTS)
    assert naabu_stage.skipped == []


async def test_scope_file_passes_naabu_only_verified_ips(tmp_path: Path) -> None:
    """(b) Scope file present: naabu gets IPs only, every one inside in_scope_cidrs."""
    rec = Recorder()
    answers = {
        "example.com": ["203.0.113.5"],
        "www.example.com": ["203.0.113.6"],
    }

    async def resolve(host: str) -> list[str]:
        return answers[host]

    engine = ports_engine(tmp_path, rec, scope_text=SCOPE_WITH_CIDRS, resolve=resolve)
    await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS, Stage.LIVE, Stage.PORTS), active=True),
    )

    naabu_hosts = rec.hosts[rec.names.index("naabu")]
    # The alive set has no order; the content is what matters.
    assert set(naabu_hosts) == {"203.0.113.5", "203.0.113.6"}
    assert "example.com" not in naabu_hosts
    assert "www.example.com" not in naabu_hosts
    for address in naabu_hosts:
        ipaddress.ip_address(address)
        assert ipaddress.ip_address(address) in ipaddress.ip_network("203.0.113.0/24")


async def test_scope_file_omits_a_target_whose_resolution_fails(tmp_path: Path) -> None:
    """(c) Resolution failure: that target is left out, never passed as a domain."""
    rec = Recorder()

    async def resolve(host: str) -> list[str]:
        if host == "www.example.com":
            raise OSError("temporary failure in name resolution")
        return ["203.0.113.5"]

    engine = ports_engine(tmp_path, rec, scope_text=SCOPE_WITH_CIDRS, resolve=resolve)
    summary = await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS, Stage.LIVE, Stage.PORTS), active=True),
    )

    naabu_hosts = rec.hosts[rec.names.index("naabu")]
    assert naabu_hosts == ["203.0.113.5"]
    assert "www.example.com" not in naabu_hosts
    assert any("1 target(s) skipped" in warning for warning in summary.warnings)


async def test_scope_file_omits_a_target_that_resolves_out_of_scope(tmp_path: Path) -> None:
    """(d) Out-of-scope address: that target is left out of the naabu call."""
    rec = Recorder()
    answers = {
        "example.com": ["203.0.113.5"],
        "www.example.com": ["198.51.100.9"],
    }

    async def resolve(host: str) -> list[str]:
        return answers[host]

    engine = ports_engine(tmp_path, rec, scope_text=SCOPE_WITH_CIDRS, resolve=resolve)
    summary = await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS, Stage.LIVE, Stage.PORTS), active=True),
    )

    naabu_hosts = rec.hosts[rec.names.index("naabu")]
    assert naabu_hosts == ["203.0.113.5"]
    assert "198.51.100.9" not in naabu_hosts
    assert "www.example.com" not in naabu_hosts
    assert any("1 target(s) skipped" in warning for warning in summary.warnings)


async def test_scope_file_skips_naabu_when_no_target_verifies(tmp_path: Path) -> None:
    """No verified address anywhere: naabu is a recorded skip, not a domain fallback."""
    rec = Recorder()

    async def resolve(host: str) -> list[str]:
        return ["198.51.100.9"]

    engine = ports_engine(tmp_path, rec, scope_text=SCOPE_WITH_CIDRS, resolve=resolve)
    summary = await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS, Stage.LIVE, Stage.PORTS), active=True),
    )

    assert "naabu" not in rec.names
    assert "pyscan" in rec.names
    stage = next(item for item in summary.stages if item.stage is Stage.PORTS)
    assert [(skip.tool, skip.reason) for skip in stage.skipped] == [
        (
            "naabu",
            "blocked: no in-scope IP for any target "
            "(resolution failed or the address is outside in_scope_cidrs)",
        )
    ]


async def test_passive_mode_never_runs_naabu_with_or_without_a_scope_file(
    tmp_path: Path,
) -> None:
    """(e) Passive mode: naabu skipped in both scope modes (tool mode excluded)."""
    rec = Recorder()

    async def resolve(host: str) -> list[str]:
        return ["203.0.113.5"]

    for name, scope_text in (("no_scope", None), ("scope", SCOPE_WITH_CIDRS)):
        engine = ports_engine(tmp_path / name, rec, scope_text=scope_text, resolve=resolve)
        selected, skipped = await engine._select(
            Stage.PORTS, ScanOptions(active=False, tools=("naabu",))
        )
        assert selected == []
        assert [(spec.name, reason) for spec, reason in skipped] == [
            ("naabu", "tool mode not included in passive mode")
        ]


# ---------------------------------------------------------------- scan modes (2026-11-17)

DENYING_SCOPE = """\
authorization: "engagement 2026-11"
in_scope:
  - other.example
allow_active: true
"""


def test_mode_stages_and_mode_tools_dicts_are_the_single_source_of_truth() -> None:
    """docs/02 section 2: the two tables are the only place a mode is defined."""
    assert MODE_STAGES == {
        "passive": (Stage.SUBS, Stage.DNS, Stage.URLS),
        "active": (
            Stage.SUBS,
            Stage.DNS,
            Stage.LIVE,
            Stage.TECH,
            Stage.URLS,
            Stage.URL_PROBE,
        ),
        "full": STAGE_ORDER,
    }
    assert MODE_TOOLS["passive"].tool_modes == frozenset({Mode.PASSIVE})
    assert MODE_TOOLS["active"].tool_modes == frozenset({Mode.PASSIVE, Mode.ACTIVE})
    assert MODE_TOOLS["full"].tool_modes == frozenset({Mode.PASSIVE, Mode.ACTIVE})
    assert MODE_TOOLS["passive"].tiers == frozenset({Tier.CORE})
    assert MODE_TOOLS["active"].tiers == frozenset({Tier.CORE})
    assert MODE_TOOLS["full"].tiers == frozenset({Tier.CORE, Tier.OPT_IN, Tier.INTRUSIVE})
    assert allowed_tiers("passive", include_noisy=False) == frozenset({Tier.CORE})
    assert allowed_tiers("passive", include_noisy=True) == frozenset({Tier.CORE, Tier.OPT_IN})
    assert allowed_tiers("full", include_noisy=False) == MODE_TOOLS["full"].tiers
    assert ScanOptions(full=True).mode == "full"
    assert ScanOptions(active=True).mode == "active"
    assert ScanOptions().mode == "passive"


async def test_passive_mode_runs_passive_urls_tools(tmp_path: Path) -> None:
    """D10: `passive` runs the urls stage, with passive urls tools only.

    gau/waybackurls query an archive by domain, so they are handed the discovered
    names; katana is an active crawler and is skipped at selection, never fed.
    """
    rec = Recorder()
    specs = {
        "subs-fake": tool("subs-fake", Stage.SUBS),
        "gau-like": tool("gau-like", Stage.URLS),
        "katana-like": tool("katana-like", Stage.URLS, mode=Mode.ACTIVE),
    }
    adapters = {
        "subs-fake": adapter("subs-fake", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "gau-like": adapter("gau-like", Stage.URLS, rec, records=[]),
        "katana-like": adapter("katana-like", Stage.URLS, rec, records=[]),
    }
    engine = make_engine(tmp_path, specs, adapters, scope_text=None)

    summary = await engine.run("example.com", ScanOptions(stages=MODE_STAGES["passive"]))

    assert [stage.stage for stage in summary.stages] == [Stage.SUBS, Stage.URLS]
    assert "gau-like" in rec.names
    assert "katana-like" not in rec.names
    assert rec.hosts[rec.names.index("gau-like")] == ["example.com", "www.example.com"]
    urls_stage = summary.stages[1]
    assert [(skip.tool, skip.reason) for skip in urls_stage.skipped] == [
        ("katana-like", "tool mode not included in passive mode")
    ]


async def test_active_mode_runs_urls_and_tech_stages(tmp_path: Path) -> None:
    """D10: `active` includes the tech and urls stages (after live)."""
    rec = Recorder()
    specs = {
        "subs-fake": tool("subs-fake", Stage.SUBS),
        "live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE),
        "webanalyze-like": tool("webanalyze-like", Stage.TECH, mode=Mode.ACTIVE),
        "cdncheck-like": tool("cdncheck-like", Stage.TECH),
        "katana-like": tool("katana-like", Stage.URLS, mode=Mode.ACTIVE),
    }
    adapters = {
        "subs-fake": adapter("subs-fake", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "live-fake": adapter("live-fake", Stage.LIVE, rec, records=[alive("www.example.com")]),
        "webanalyze-like": adapter("webanalyze-like", Stage.TECH, rec, records=[]),
        "cdncheck-like": adapter("cdncheck-like", Stage.TECH, rec, records=[]),
        "katana-like": adapter("katana-like", Stage.URLS, rec, records=[]),
    }
    engine = make_engine(tmp_path, specs, adapters, scope_text=SCOPE)

    summary = await engine.run("example.com", ScanOptions(active=True))

    assert [stage.stage for stage in summary.stages] == [
        Stage.SUBS,
        Stage.LIVE,
        Stage.TECH,
        Stage.URLS,
        # D23: the probe follows the crawl and is engine-owned (no tools).
        Stage.URL_PROBE,
    ]
    assert {"webanalyze-like", "cdncheck-like", "katana-like"} <= set(rec.names)
    # tech and the active crawler both see the alive host, in that order.
    tech_index = rec.names.index("webanalyze-like")
    urls_index = rec.names.index("katana-like")
    assert rec.hosts[tech_index] == ["www.example.com"]
    assert rec.hosts[urls_index] == ["www.example.com"]
    assert tech_index < urls_index


async def test_active_mode_urls_stage_runs_after_live(tmp_path: Path) -> None:
    """Stage order is STAGE_ORDER, so urls never runs before live in any mode."""
    rec = Recorder()
    specs = {
        "subs-fake": tool("subs-fake", Stage.SUBS),
        "live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE),
        "katana-like": tool("katana-like", Stage.URLS, mode=Mode.ACTIVE),
    }
    adapters = {
        "subs-fake": adapter("subs-fake", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "live-fake": adapter("live-fake", Stage.LIVE, rec, records=[alive("www.example.com")]),
        "katana-like": adapter("katana-like", Stage.URLS, rec, records=[]),
    }
    engine = make_engine(tmp_path, specs, adapters, scope_text=SCOPE)

    summary = await engine.run("example.com", ScanOptions(active=True))

    order = [stage.stage for stage in summary.stages]
    assert order.index(Stage.LIVE) < order.index(Stage.URLS)
    assert rec.names.index("live-fake") < rec.names.index("katana-like")
    assert list(MODE_STAGES["active"]) == [
        stage for stage in STAGE_ORDER if stage in MODE_STAGES["active"]
    ]


async def test_full_mode_unchanged_by_expansion() -> None:
    """D19: full is every stage, `shots` included since the stage was wired."""
    assert MODE_STAGES["full"] == STAGE_ORDER
    assert len(MODE_STAGES["full"]) == 9
    assert set(MODE_STAGES["full"]) == set(Stage)
    assert set(MODE_STAGES["passive"]) < set(MODE_STAGES["active"]) < set(MODE_STAGES["full"])


def test_shots_stage_is_in_full_mode_only() -> None:
    """D19: gowitness is runnable from `--full` and from nowhere else."""
    assert Stage.SHOTS in MODE_STAGES["full"]
    assert Stage.SHOTS not in MODE_STAGES["passive"]
    assert Stage.SHOTS not in MODE_STAGES["active"]
    # Pipeline position: after URL discovery, before the findings stage.
    order = list(STAGE_ORDER)
    assert order.index(Stage.URLS) < order.index(Stage.SHOTS) < order.index(Stage.VULNS)
    # Every mode tuple is ordered by the one pipeline order.
    for stages in MODE_STAGES.values():
        assert list(stages) == [stage for stage in STAGE_ORDER if stage in stages]


async def test_full_runs_all_tool_modes_and_enables_opt_in_and_intrusive(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {
        "core-passive": tool("core-passive", Stage.VULNS),
        "core-active": tool("core-active", Stage.VULNS, mode=Mode.ACTIVE),
        "noisy": tool("noisy", Stage.VULNS, tier=Tier.OPT_IN, mode=Mode.ACTIVE),
        "intrusive": tool("intrusive", Stage.VULNS, tier=Tier.INTRUSIVE, mode=Mode.ACTIVE),
    }
    adapters = {name: adapter(name, Stage.VULNS, rec, records=[]) for name in specs}
    engine = make_engine(tmp_path, specs, adapters, installed=lambda _adapter: True)

    selected, skipped = await engine._select(Stage.VULNS, ScanOptions(full=True))
    assert [spec.name for spec, _ in selected] == [
        "core-passive",
        "core-active",
        "noisy",
        "intrusive",
    ]
    assert skipped == []

    selected, skipped = await engine._select(Stage.VULNS, ScanOptions(active=True))
    assert [spec.name for spec, _ in selected] == ["core-passive", "core-active"]
    assert {reason for _spec, reason in skipped} == {"tier not included in active mode"}


async def test_full_skips_exploitation_tools_unless_named(tmp_path: Path) -> None:
    """2026-11-17 pre-ruling: `full` never auto-fires an exploitation tool."""
    rec = Recorder()
    specs = {
        "sqlmap-like": tool(
            "sqlmap-like",
            Stage.VULNS,
            tier=Tier.INTRUSIVE,
            mode=Mode.ACTIVE,
            exploitation=True,
        )
    }
    adapters = {"sqlmap-like": adapter("sqlmap-like", Stage.VULNS, rec, records=[])}
    engine = make_engine(tmp_path, specs, adapters, installed=lambda _adapter: True)

    selected, skipped = await engine._select(Stage.VULNS, ScanOptions(full=True))
    assert selected == []
    assert [(spec.name, reason) for spec, reason in skipped] == [
        ("sqlmap-like", "exploitation tool requires explicit --tools")
    ]

    selected, _skipped = await engine._select(
        Stage.VULNS, ScanOptions(full=True, tools=("sqlmap-like",))
    )
    assert [spec.name for spec, _ in selected] == ["sqlmap-like"]


async def test_no_scope_flag_ignores_present_scope_file(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {
        "subs": tool("subs", Stage.SUBS),
        "live": tool("live", Stage.LIVE, mode=Mode.ACTIVE),
    }
    adapters = {
        "subs": adapter("subs", Stage.SUBS, rec, records=[]),
        "live": adapter("live", Stage.LIVE, rec, records=[]),
    }
    engine = make_engine(tmp_path, specs, adapters, scope_text=DENYING_SCOPE)
    summary = await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS, Stage.LIVE), active=True, no_scope=True, mock=True),
    )
    assert "live" in rec.names
    assert summary.scope_denied is False
    assert summary.scope_mode == "unrestricted_flag"


async def test_scan_writes_enforced_scope_mode_when_a_scope_file_is_used(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {"subs": tool("subs", Stage.SUBS)}
    adapters = {"subs": adapter("subs", Stage.SUBS, rec, records=[])}
    engine = make_engine(tmp_path, specs, adapters, scope_text=SCOPE)
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    assert summary.scope_mode == "enforced"
    row = engine.store._conn.execute(
        "SELECT scope_mode FROM scan_runs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row["scope_mode"] == "enforced"


async def test_scan_writes_no_file_scope_mode_when_no_scope_file(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {"subs": tool("subs", Stage.SUBS)}
    adapters = {"subs": adapter("subs", Stage.SUBS, rec, records=[])}
    engine = make_engine(tmp_path, specs, adapters, scope_text=None)
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    assert summary.scope_mode == "no_file"
    row = engine.store._conn.execute(
        "SELECT scope_mode FROM scan_runs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row["scope_mode"] == "no_file"


# ------------------------------------------- tech-stage persistence (2026-11-17, D11)


async def test_tech_stage_annotates_the_latest_host_row(tmp_path: Path) -> None:
    """A tech match lands on the row the live pass wrote; no new state row (D11)."""
    rec = Recorder()
    specs = {
        "subs-fake": tool("subs-fake", Stage.SUBS),
        "live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE),
        "webanalyze-like": tool("webanalyze-like", Stage.TECH, mode=Mode.ACTIVE),
        "cdncheck-like": tool("cdncheck-like", Stage.TECH),
    }
    tech_record = HostStatusRecord(
        fqdn="www.example.com",
        source="webanalyze-like",
        state=HostState.ALIVE,
        tech=["Apache Tomcat", "Java"],
    )
    waf_record = HostStatusRecord(
        fqdn="www.example.com",
        source="cdncheck-like",
        state=HostState.UNKNOWN,
        tech=["google"],
        waf="cloudflare",
    )
    adapters = {
        "subs-fake": adapter("subs-fake", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "live-fake": adapter("live-fake", Stage.LIVE, rec, records=[alive("www.example.com")]),
        "webanalyze-like": adapter(
            "webanalyze-like", Stage.TECH, rec, records=[tech_record, waf_record]
        ),
        "cdncheck-like": adapter("cdncheck-like", Stage.TECH, rec, records=[]),
    }
    engine = make_engine(tmp_path, specs, adapters, scope_text=SCOPE)
    store = engine.store

    await engine.run("example.com", ScanOptions(active=True))

    host_rows = store.host_rows(store.get_target("example.com") or 0)
    row = next(item for item in host_rows if item["fqdn"] == "www.example.com")
    # The union of both tech tools, and the WAF the cdncheck-style record named.
    assert row["tech"] == ("Apache Tomcat", "Java", "google")
    assert row["state"] == "ALIVE"  # the tech pass never re-decides liveness
    history = rows(store, "SELECT state, tech_json, waf FROM host_status_history ORDER BY id")
    assert len(history) == 1, "the tech stage must not append a second status row"
    assert "cloudflare" in str(history[0][2])


async def test_tech_stage_drops_a_host_outside_the_target(tmp_path: Path) -> None:
    """The tech pass keeps the same target rule as every other stage."""
    rec = Recorder()
    specs = {
        "subs-fake": tool("subs-fake", Stage.SUBS),
        "live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE),
        "webanalyze-like": tool("webanalyze-like", Stage.TECH, mode=Mode.ACTIVE),
    }
    adapters = {
        "subs-fake": adapter("subs-fake", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "live-fake": adapter("live-fake", Stage.LIVE, rec, records=[alive("www.example.com")]),
        "webanalyze-like": adapter(
            "webanalyze-like",
            Stage.TECH,
            rec,
            records=[
                HostStatusRecord(
                    fqdn="elsewhere.test",
                    source="webanalyze-like",
                    state=HostState.ALIVE,
                    tech=["Java"],
                )
            ],
        ),
    }
    engine = make_engine(tmp_path, specs, adapters, scope_text=SCOPE)

    await engine.run("example.com", ScanOptions(active=True))

    assert "elsewhere.test" not in {item["fqdn"] for item in engine.store.host_rows(1)}


def test_waf_priority_deterministic_merge(tmp_path: Path) -> None:
    """D12: the highest `waf_priority` wins whatever order the tools finish in.

    Regression: docs/MASTER_PLAN.md D12. `results` is completion order, so the
    old first-non-None rule let a lower-priority tool name the WAF whenever it
    happened to finish first - the stored value could flip between runs.
    """
    from dataclasses import replace
    from itertools import permutations

    names = {"wafw00f": "Cloudflare", "cdncheck": "cloudflare", "httpx_tech": "cloudflare"}
    specs = {
        "wafw00f": replace(tool("wafw00f", Stage.TECH), waf_priority=100),
        "cdncheck": replace(tool("cdncheck", Stage.TECH), waf_priority=80),
        "httpx_tech": replace(tool("httpx_tech", Stage.TECH), waf_priority=20),
    }
    stored: set[tuple[str | None, int]] = set()
    for order in permutations(names):
        db = Store(tmp_path / f"{'-'.join(order)}.db")
        try:
            target_id = db.create_target("example.com")
            run_id = db.create_scan_run(target_id, "live")
            sub_id = db.upsert_subdomain(target_id, "www.example.com", run_id=run_id)
            db.append_host_status(sub_id, run_id, "ALIVE")
            engine = Engine(
                load_config(CONFIG),
                db,
                specs=specs,
                adapters={},
                scope_path=None,
                workspace_root=tmp_path / "workspaces",
            )
            results = [
                ToolResult(
                    tool=name,
                    status=ToolStatus.OK,
                    records=[
                        HostStatusRecord(
                            fqdn="www.example.com",
                            source=name,
                            state=HostState.UNKNOWN,
                            waf=names[name],
                        )
                    ],
                )
                for name in order
            ]
            engine._persist_tech(target_id, run_id, results, "example.com")
            row = db._conn.execute("SELECT waf, waf_priority FROM host_status_history").fetchone()
            stored.add((row["waf"], int(row["waf_priority"])))
        finally:
            db.close()

    # Every one of the six orders ends with wafw00f's detection and its priority.
    assert stored == {("Cloudflare", 100)}


async def test_a_service_fingerprint_is_stored_and_raises_port_confidence(
    tmp_path: Path,
) -> None:
    """docs/09 section 5: the `-sV`/banner fingerprint is stored and bumps one level.

    Real `nmap -sV` on testfire.net reports `service=http version=Apache
    Tomcat/Coyote JSP engine 1.1`; before this test that record reached the parse
    and was dropped by `_persist_ports`, so the documented rule never fired.
    """
    rec = Recorder()
    specs = {
        "live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE),
        "nmap": tool("nmap", Stage.PORTS, mode=Mode.ACTIVE),
    }
    adapters = {
        "live-fake": adapter("live-fake", Stage.LIVE, rec, records=[alive("example.com")]),
        "nmap": adapter(
            "nmap",
            Stage.PORTS,
            rec,
            records=[
                PortRecord(
                    fqdn="example.com",
                    ip="203.0.113.10",
                    port=443,
                    state="open",
                    service="http",
                    version="Apache Tomcat/Coyote JSP engine 1.1",
                    source="nmap",
                )
            ],
        ),
    }
    engine = make_engine(tmp_path, specs, adapters, installed=lambda _adapter: True)
    await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.LIVE, Stage.PORTS), active=True),
    )
    stored = [
        tuple(row)
        for row in rows(engine.store, "SELECT state, service, version, confidence FROM ports")
    ]
    assert stored == [("open", "http", "Apache Tomcat/Coyote JSP engine 1.1", "MEDIUM")]


async def test_two_tools_disagreeing_on_the_service_store_no_fingerprint(
    tmp_path: Path,
) -> None:
    """smap says `http?` and nmap says `http`: an invented winner is worse than none."""
    rec = Recorder()
    specs = {
        "live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE),
        "nmap": tool("nmap", Stage.PORTS, mode=Mode.ACTIVE),
        "smap": tool("smap", Stage.PORTS, mode=Mode.ACTIVE),
    }
    mine = PortRecord(fqdn="example.com", ip="203.0.113.10", port=80, state="open", source="nmap")
    theirs = PortRecord(
        fqdn="example.com", ip="203.0.113.10", port=80, state="open", service="http?", source="smap"
    )
    adapters = {
        "live-fake": adapter("live-fake", Stage.LIVE, rec, records=[alive("example.com")]),
        "nmap": adapter(
            "nmap",
            Stage.PORTS,
            rec,
            records=[mine.model_copy(update={"service": "http"})],
        ),
        "smap": adapter("smap", Stage.PORTS, rec, records=[theirs]),
    }
    engine = make_engine(tmp_path, specs, adapters, installed=lambda _adapter: True)
    await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.LIVE, Stage.PORTS), active=True),
    )
    # Two tools is MEDIUM (high_min_sources is 3); a fingerprint would bump it to
    # HIGH, so staying MEDIUM is the proof that nothing was invented.
    stored = [tuple(row) for row in rows(engine.store, "SELECT service, confidence FROM ports")]
    assert stored == [(None, "MEDIUM")]


async def test_a_tool_that_cannot_run_without_a_key_is_skipped_not_failed(
    tmp_path: Path,
) -> None:
    """chaos/github-subdomains: no key means no query, so the stage records a skip.

    A runtime `SKIPPED` would count as a failed tool and push the run to exit 5;
    the key-gating therefore happens at selection (`requires_env`, D18), exactly
    like masscan's `needs_root`.
    """
    rec = Recorder()

    class Keyed(BaseToolAdapter):
        name = "keyed"
        stage = Stage.SUBS
        requires_env = ("PDCP_API_KEY",)

        async def run(self, ctx: RunContext) -> ToolResult:  # pragma: no cover - must not run
            raise AssertionError("a keyless tool must never be spawned")

        def build_command(self, ctx: RunContext) -> list[str]:
            raise NotImplementedError

        def parse_output(self, raw: str) -> list[Record]:
            return []

    specs = {
        "subs-fake": tool("subs-fake", Stage.SUBS),
        "keyed": tool("keyed", Stage.SUBS),
    }
    adapters: dict[str, type[BaseToolAdapter]] = {
        "subs-fake": adapter("subs-fake", Stage.SUBS, rec, records=[sub("www.example.com")]),
        "keyed": Keyed,
    }
    engine = make_engine(tmp_path, specs, adapters, env={}, installed=lambda _adapter: True)
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,)))
    assert rec.names == ["subs-fake"]
    assert [(skip.tool, skip.reason) for skip in summary.skipped] == [
        ("keyed", "requires PDCP_API_KEY")
    ]
    assert summary.exit_code is ExitCode.SUCCESS

    engine_with_key = make_engine(
        tmp_path / "key", specs, adapters, env={"PDCP_API_KEY": "k"}, installed=lambda _a: True
    )
    with_key = await engine_with_key.run("example.com", ScanOptions(stages=(Stage.SUBS,)))
    # With the key present the tool is selected and runs; the fake adapter there
    # records nothing, so the proof is that no skip reason is produced.
    assert "keyed" not in [skip.tool for skip in with_key.skipped]


def _probe_transport(answers: dict[str, object], calls: list[str]) -> httpx.MockTransport:
    """A `url_probe` transport: a status per URL, or an exception to raise."""

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        answer = answers.get(str(request.url))
        if isinstance(answer, Exception):
            raise answer
        return httpx.Response(int(answer or 200))

    return httpx.MockTransport(handler)


def _probe_engine(
    tmp_path: Path,
    urls: list[str],
    *,
    transport: object | None = None,
    scope_text: str | None = SCOPE,
    progress: Callable[[str], None] | None = None,
) -> Engine:
    rec = Recorder()
    # R10 (2026-11-19): an active urls tool with no alive host is now skipped, so
    # this fixture is a *passive* urls tool - the class that receives the apex
    # even when the live stage found nothing (it stands in for gau/waybackurls).
    specs = {"urls-fake": tool("urls-fake", Stage.URLS, mode=Mode.PASSIVE)}
    adapters = {
        "urls-fake": adapter(
            "urls-fake",
            Stage.URLS,
            rec,
            records=[UrlRecord(url=url, source="fake") for url in urls],
        )
    }
    return make_engine(
        tmp_path,
        specs,
        adapters,
        scope_text=scope_text,
        url_probe_transport=transport,
        progress=progress,
    )


async def test_url_probe_stores_status_codes_and_marks_unreachable(tmp_path: Path) -> None:
    """D23: one GET per stored URL; `-1` is the stored answer for no answer."""
    calls: list[str] = []
    transport = _probe_transport(
        {
            "https://www.example.com/a": 200,
            "https://www.example.com/b": 404,
            "https://www.example.com/c": httpx.ConnectError("refused"),
        },
        calls,
    )
    engine = _probe_engine(
        tmp_path,
        [
            "https://www.example.com/a",
            "https://www.example.com/b",
            "https://www.example.com/c",
        ],
        transport=transport,
    )
    summary = await engine.run("example.com", ScanOptions(active=True))
    stored = {
        str(row["url"]): row["status_code"]
        for row in rows(engine.store, "SELECT url, status_code FROM urls ORDER BY id")
    }
    assert stored == {
        "https://www.example.com/a": 200,
        "https://www.example.com/b": 404,
        "https://www.example.com/c": -1,
    }
    assert sorted(calls) == sorted(stored)
    # The probe is engine-owned: a stage outcome, but no tool row of its own.
    assert [stage.stage for stage in summary.stages] == [Stage.URLS, Stage.URL_PROBE]
    assert summary.stages[-1].results == []
    tools = [str(row["tool"]) for row in rows(engine.store, "SELECT tool FROM tool_runs")]
    assert tools == ["urls-fake"]
    # An engine-owned stage is never an "empty stage": exit 0, no warnings.
    assert summary.exit_code is ExitCode.SUCCESS
    assert not [note for note in summary.warnings if "url_probe" in note]


async def test_url_probe_never_reprobes_a_stored_answer(tmp_path: Path) -> None:
    """`NULL` alone means "not probed"; `-1` is an answer and is never retried."""
    calls: list[str] = []
    transport = _probe_transport({}, calls)
    engine = _probe_engine(tmp_path, ["https://www.example.com/a"], transport=transport)
    first = await engine.run("example.com", ScanOptions(active=True))
    assert calls == ["https://www.example.com/a"]
    assert first.urls_probed_this_run == 1
    assert first.urls_skipped_already_probed == 0
    # A second run finds nothing NULL and sends nothing.
    second = await engine.run("example.com", ScanOptions(active=True))
    assert calls == ["https://www.example.com/a"]
    # D78: the stored answer is what the report counts as skipped.
    assert second.urls_probed_this_run == 0
    assert second.urls_skipped_already_probed == 1


async def test_reprobe_urls_probes_urls_that_already_carry_an_answer(tmp_path: Path) -> None:
    """D24: `--reprobe-urls` sends every stored URL again, default sends only NULLs."""
    calls: list[str] = []
    transport = _probe_transport(
        {"https://www.example.com/a": 200, "https://www.example.com/b": 404}, calls
    )
    engine = _probe_engine(
        tmp_path,
        ["https://www.example.com/a", "https://www.example.com/b"],
        transport=transport,
    )
    await engine.run("example.com", ScanOptions(active=True))
    assert sorted(calls) == ["https://www.example.com/a", "https://www.example.com/b"]
    # Nothing is NULL any more, so the default second run sends nothing.
    calls.clear()
    await engine.run("example.com", ScanOptions(active=True))
    assert calls == []
    # --reprobe-urls asks again, which is how a URL that went dead is found.
    await engine.run("example.com", ScanOptions(active=True, reprobe_urls=True))
    assert sorted(calls) == ["https://www.example.com/a", "https://www.example.com/b"]


async def test_url_probe_records_the_reprobe_flag_on_the_run(tmp_path: Path) -> None:
    """The probe run records `reprobe` so the pass is auditable afterwards."""
    transport = _probe_transport({}, [])
    engine = _probe_engine(tmp_path, ["https://www.example.com/a"], transport=transport)
    await engine.run("example.com", ScanOptions(active=True, reprobe_urls=True))
    params = [
        json.loads(str(row["params_json"]))
        for row in rows(
            engine.store, "SELECT params_json FROM scan_runs WHERE stage = 'url_probe' ORDER BY id"
        )
    ]
    assert [item["reprobe"] for item in params] == [True]


async def test_url_probe_uses_the_url_probe_config_bounds(tmp_path: Path) -> None:
    """The `url_probe:` block bounds one pass and the run says what it skipped."""
    calls: list[str] = []
    transport = _probe_transport({}, calls)
    engine = _probe_engine(
        tmp_path,
        [f"https://www.example.com/{index}" for index in range(5)],
        transport=transport,
    )
    engine.config.url_probe.max_urls = 2
    summary = await engine.run("example.com", ScanOptions(active=True))
    assert len(calls) == 2
    assert any("probed the first 2 URL(s) only" in note for note in summary.warnings)
    left = rows(engine.store, "SELECT COUNT(*) FROM urls WHERE status_code IS NULL")
    assert int(left[0][0]) == 3


async def test_url_probe_is_skipped_in_mock_mode(tmp_path: Path) -> None:
    """`--mock` sends no traffic and leaves every status NULL, saying so."""
    calls: list[str] = []
    transport = _probe_transport({}, calls)
    engine = _probe_engine(tmp_path, ["https://www.example.com/a"], transport=transport)
    summary = await engine.run("example.com", ScanOptions(active=True, mock=True))
    assert calls == []
    assert [row["status_code"] for row in rows(engine.store, "SELECT status_code FROM urls")] == [
        None
    ]
    assert any(
        "url_probe: skipped in --mock (1 URL(s) left unprobed)" in note for note in summary.warnings
    )


async def test_probe_candidates_logs_unreachable_skip_count(tmp_path: Path) -> None:
    """D55: a probe pass says how many URLs it dropped for an unreachable host."""
    lines: list[str] = []
    calls: list[str] = []
    transport = _probe_transport({}, calls)
    urls = (
        [f"https://www.example.com/{index}" for index in range(6)]
        + [f"https://dead.example.com/{index}" for index in range(4)]
        + [f"https://dns-only.example.com/{index}" for index in range(2)]
    )
    engine = _probe_engine(tmp_path, urls, transport=transport, progress=lines.append)
    target_id = engine.store.create_target("example.com")
    dns_run = engine.store.create_scan_run(target_id, "dns")
    engine.store.upsert_subdomain(target_id, "dead.example.com", run_id=dns_run, state="DEAD")
    engine.store.upsert_subdomain(
        target_id, "dns-only.example.com", run_id=dns_run, state="DNS_ONLY"
    )
    await engine.run("example.com", ScanOptions(active=True))
    assert [line for line in lines if "whose host is unreachable" in line] == [
        "url_probe: skipping 6 URL(s) whose host is unreachable"
    ]
    assert [url for url in calls if "www.example.com" not in url] == []
    assert len(calls) == 6


async def test_skipping_the_url_probe_stage_leaves_every_status_null(tmp_path: Path) -> None:
    """`--skip-url-probe` narrows the stage list; nothing is probed."""
    calls: list[str] = []
    transport = _probe_transport({}, calls)
    engine = _probe_engine(tmp_path, ["https://www.example.com/a"], transport=transport)
    stages = tuple(stage for stage in STAGE_ORDER if stage is not Stage.URL_PROBE)
    summary = await engine.run("example.com", ScanOptions(stages=stages, active=True))
    assert calls == []
    assert [row["status_code"] for row in rows(engine.store, "SELECT status_code FROM urls")] == [
        None
    ]
    assert Stage.URL_PROBE not in [stage.stage for stage in summary.stages]


async def test_url_probe_sends_only_in_scope_urls(tmp_path: Path) -> None:
    """The probe is an active stage: the scope gate filters its input (docs/05)."""
    calls: list[str] = []
    transport = _probe_transport({}, calls)
    engine = _probe_engine(
        tmp_path,
        ["https://www.example.com/a", "https://api.example.com/b"],
        transport=transport,
    )
    await engine.run("example.com", ScanOptions(active=True))
    assert calls == ["https://www.example.com/a"]
    stored = {
        str(row["url"]): row["status_code"]
        for row in rows(engine.store, "SELECT url, status_code FROM urls ORDER BY id")
    }
    assert stored["https://api.example.com/b"] is None


async def test_url_probe_marks_an_unverified_certificate_apart_from_unreachable(
    tmp_path: Path,
) -> None:
    """`-2` (answered, certificate did not verify) is not `-1` (no answer) - D23.

    Found on a real testfire.net run: every URL there has a certificate issued
    for `www.testfire.net`, so a hostname mismatch stored `-1` and made a live
    site look dead. Verification stays on; the fact is just recorded as itself.
    """
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        cause = ssl.SSLCertVerificationError("certificate is not valid for 'testfire.net'")
        raise httpx.ConnectError(str(cause), request=request) from cause

    engine = _probe_engine(
        tmp_path,
        ["https://www.example.com/index.jsp"],
        transport=httpx.MockTransport(handler),
    )
    summary = await engine.run("example.com", ScanOptions(active=True))
    assert len(requests) == 1
    stored = [row["status_code"] for row in rows(engine.store, "SELECT status_code FROM urls")]
    assert stored == [UNTRUSTED]
    assert summary.exit_code is ExitCode.SUCCESS


async def test_url_probe_sees_a_certificate_error_in_the_context_chain(tmp_path: Path) -> None:
    """httpx/httpcore chain the ssl error through `__context__`, not `__cause__`."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/refused":
            # The plain case: no ssl error anywhere in the chain.
            raise httpx.ConnectError("connection refused", request=request)
        certificate = ssl.SSLCertVerificationError("hostname mismatch")
        try:
            raise certificate
        except ssl.SSLCertVerificationError:
            # `from None` keeps the ssl error off `__cause__`, exactly as httpx
            # and httpcore leave it: it survives only as `__context__`.
            raise httpx.ConnectError(str(certificate), request=request) from None

    engine = _probe_engine(
        tmp_path,
        ["https://www.example.com/a", "https://www.example.com/refused"],
        transport=httpx.MockTransport(handler),
    )
    await engine.run("example.com", ScanOptions(active=True))
    stored = {
        str(row["url"]): row["status_code"]
        for row in rows(engine.store, "SELECT url, status_code FROM urls")
    }
    assert stored == {
        "https://www.example.com/a": UNTRUSTED,
        "https://www.example.com/refused": UNREACHABLE,
    }


def _slow_transport(delays: dict[str, float], calls: list[str]) -> httpx.MockTransport:
    """A transport that never answers for a URL whose delay is huge."""

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        await asyncio.sleep(delays.get(str(request.url), 0.0))
        return httpx.Response(200)

    return httpx.MockTransport(handler)


async def test_url_probe_respects_phase_timeout(tmp_path: Path) -> None:
    """D26: the probe pass is bounded by --phase-timeout and keeps exit 0."""
    calls: list[str] = []
    transport = _slow_transport({"https://www.example.com/slow": 30.0}, calls)
    engine = _probe_engine(tmp_path, ["https://www.example.com/slow"], transport=transport)
    summary = await engine.run("example.com", ScanOptions(active=True, phase_timeout=0.3))
    assert summary.exit_code is ExitCode.SUCCESS
    assert any("url_probe: timed out after 0.3s" in note for note in summary.warnings)
    assert [row["status_code"] for row in rows(engine.store, "SELECT status_code FROM urls")] == [
        None
    ]
    # A timed-out probe is a gap, not a partial run (docs/02 section 6).
    assert summary.completion_status == "complete_with_gaps"
    assert [(gap.stage, gap.reason) for gap in summary.gaps] == [
        (Stage.URL_PROBE, "timed out after 0.3s (0/1 URL(s) probed)")
    ]
    statuses = [
        str(row["status"])
        for row in rows(
            engine.store, "SELECT status FROM scan_runs WHERE stage = 'url_probe' ORDER BY id"
        )
    ]
    assert statuses == ["partial"]


async def test_url_probe_timeout_keeps_the_batches_it_finished(tmp_path: Path) -> None:
    """Committed batches survive the kill; the unreached URL stays NULL."""
    calls: list[str] = []
    transport = _slow_transport({"https://www.example.com/slow": 30.0}, calls)
    engine = _probe_engine(
        tmp_path,
        ["https://www.example.com/fast", "https://www.example.com/slow"],
        transport=transport,
    )
    engine.config.url_probe.batch_size = 1
    summary = await engine.run("example.com", ScanOptions(active=True, phase_timeout=0.5))
    stored = {
        str(row["url"]): row["status_code"]
        for row in rows(engine.store, "SELECT url, status_code FROM urls ORDER BY id")
    }
    assert stored == {"https://www.example.com/fast": 200, "https://www.example.com/slow": None}
    assert any("(1/2 URL(s) probed)" in note for note in summary.warnings)
    assert summary.exit_code is ExitCode.SUCCESS


async def test_url_probe_uses_the_config_timeout_when_no_flag_is_given(tmp_path: Path) -> None:
    """No --phase-timeout: `timeouts.url_probe` from config.yaml is the deadline."""
    calls: list[str] = []
    transport = _slow_transport({"https://www.example.com/slow": 30.0}, calls)
    engine = _probe_engine(tmp_path, ["https://www.example.com/slow"], transport=transport)
    engine.config.timeouts.url_probe = 1
    summary = await engine.run("example.com", ScanOptions(active=True))
    assert any("url_probe: timed out after 1s" in note for note in summary.warnings)
    assert summary.exit_code is ExitCode.SUCCESS


async def test_degraded_tools_never_exit_five_but_a_local_fault_does(tmp_path: Path) -> None:
    """R8 (2026-11-18): "upstream said no" is a gap; "reconkit broke" is exit 5.

    The four cases the ruling names, in one place:
      * every failure is an upstream refusal -> exit 0, completion gaps named;
      * a local failure next to a refusal      -> exit 5, the gap never masks it;
      * a missing binary next to a working tool -> exit 5;
      * every tool ok                           -> exit 0, no gaps.
    `ToolStatus.GAP` is the encoded name for R8's "degraded" (D34).
    """
    upstream = {
        "otx": adapter(
            "otx", Stage.SUBS, Recorder(), status=ToolStatus.GAP, detail="otx: HTTP 429"
        ),
        "hackertarget": adapter(
            "hackertarget",
            Stage.SUBS,
            Recorder(),
            status=ToolStatus.GAP,
            detail="hackertarget: free quota exceeded",
        ),
    }
    specs = {name: tool(name, Stage.SUBS) for name in upstream}
    summary = await make_engine(tmp_path, specs, upstream).run(
        "example.com", ScanOptions(stages=(Stage.SUBS,), active=True, mock=True)
    )
    assert summary.exit_code is ExitCode.SUCCESS
    assert summary.completion_status == "complete_with_gaps"
    assert [gap.stage for gap in summary.gaps] == [Stage.SUBS]

    mixed = {
        "otx": adapter(
            "otx", Stage.SUBS, Recorder(), status=ToolStatus.GAP, detail="otx: HTTP 429"
        ),
        "crtsh": adapter(
            "crtsh",
            Stage.SUBS,
            Recorder(),
            status=ToolStatus.FAILED,
            detail="crtsh: invalid JSON line",
        ),
    }
    summary = await make_engine(
        tmp_path / "mixed", {name: tool(name, Stage.SUBS) for name in mixed}, mixed
    ).run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    assert summary.exit_code is ExitCode.PARTIAL

    missing = {
        "otx": adapter("otx", Stage.SUBS, Recorder(), records=[]),
        "crtsh": adapter(
            "crtsh",
            Stage.SUBS,
            Recorder(),
            status=ToolStatus.FAILED,
            detail="not installed or not executable: no such file",
        ),
    }
    summary = await make_engine(
        tmp_path / "missing", {name: tool(name, Stage.SUBS) for name in missing}, missing
    ).run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    assert summary.exit_code is ExitCode.PARTIAL

    ok = {
        "otx": adapter("otx", Stage.SUBS, Recorder(), records=[]),
        "crtsh": adapter("crtsh", Stage.SUBS, Recorder(), records=[]),
    }
    summary = await make_engine(
        tmp_path / "ok", {name: tool(name, Stage.SUBS) for name in ok}, ok
    ).run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    assert summary.exit_code is ExitCode.SUCCESS
    assert summary.gaps == []


async def test_shots_without_chromium_is_a_gap_and_exit_zero(tmp_path: Path) -> None:
    """D35: no browser -> shots is a completion gap, never exit 5."""
    rec = Recorder()
    specs = {"gowitness": tool("gowitness", Stage.SHOTS)}
    adapters = {
        "gowitness": adapter(
            "gowitness",
            Stage.SHOTS,
            rec,
            status=ToolStatus.GAP,
            detail="no chromium; 0 screenshots",
        )
    }
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.SHOTS,), mock=True)
    )
    assert summary.exit_code is ExitCode.SUCCESS
    assert summary.completion_status == "complete_with_gaps"
    assert [gap.stage for gap in summary.gaps] == [Stage.SHOTS]
    assert "no chromium; 0 screenshots" in summary.gaps[0].reason


async def test_a_tool_with_no_input_hosts_is_skipped_not_failed(tmp_path: Path) -> None:
    """R10 (2026-11-19): an empty host list is a skip, never a broken tool.

    The `tech` stage's pool is handed the alive hosts; with none, whatweb has
    nothing to scan. Calling it anyway turned its own `no hosts to scan` guard
    into a FAILED result and made a starved run look broken.
    """
    rec = Recorder()
    specs = {"whatweb": tool("whatweb", Stage.TECH, mode=Mode.ACTIVE)}
    adapters = {"whatweb": adapter("whatweb", Stage.TECH, rec, records=[])}
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.TECH,), active=True, mock=True)
    )
    tech = summary.stages[0]
    assert [(result.tool, result.status) for result in tech.results] == [
        ("whatweb", ToolStatus.SKIPPED)
    ]
    assert tech.results[0].error == "no input hosts"
    assert tech.results[0].raw_path is None  # the tool never ran
    assert rec.names == []  # the adapter was never invoked
    assert summary.exit_code is ExitCode.SUCCESS


async def test_a_stage_of_only_skipped_tools_is_a_gap_and_exits_zero(tmp_path: Path) -> None:
    """R10: nothing was broken, so the stage is a completion gap (exit 0)."""
    rec = Recorder()
    specs = {
        "katana": tool("katana", Stage.URLS, mode=Mode.ACTIVE),
        "hakrawler": tool("hakrawler", Stage.URLS, mode=Mode.ACTIVE),
    }
    adapters = {
        "katana": adapter("katana", Stage.URLS, rec, records=[]),
        "hakrawler": adapter("hakrawler", Stage.URLS, rec, records=[]),
    }
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.URLS,), active=True, mock=True)
    )
    assert all(result.status is ToolStatus.SKIPPED for result in summary.stages[0].results)
    assert summary.exit_code is ExitCode.SUCCESS
    assert summary.completion_status == "complete_with_gaps"
    assert [gap.stage for gap in summary.gaps] == [Stage.URLS]
    assert summary.gaps[0].reason == "no input hosts"


async def test_a_skip_does_not_mask_a_real_failure(tmp_path: Path) -> None:
    """R10: the skip is not a failure, but it never hides one either.

    `katana` is skipped for having no alive host; `crtsh` really failed. The run
    must still be partial (5) - a skip cannot launder a broken tool.
    """
    rec = Recorder()
    specs = {
        "katana": tool("katana", Stage.URLS, mode=Mode.ACTIVE),
        "crtsh": tool("crtsh", Stage.SUBS, mode=Mode.PASSIVE),
    }
    adapters = {
        "katana": adapter("katana", Stage.URLS, rec, records=[]),
        "crtsh": adapter(
            "crtsh",
            Stage.SUBS,
            rec,
            status=ToolStatus.FAILED,
            detail="crtsh: invalid JSON line",
        ),
    }
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.SUBS, Stage.URLS), active=True, mock=True)
    )
    urls = next(stage for stage in summary.stages if stage.stage is Stage.URLS)
    assert [result.status for result in urls.results] == [ToolStatus.SKIPPED]
    assert summary.exit_code is ExitCode.PARTIAL


async def test_live_still_scans_the_apex_when_nothing_was_discovered(tmp_path: Path) -> None:
    """R10's exemption: `live` receives the target itself, so it never skips.

    With an empty discovered set the live stage is still given `example.com` and
    must run - a scan of the target is the point of the stage.
    """
    rec = Recorder()
    specs = {"live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE)}
    adapters = {"live-fake": adapter("live-fake", Stage.LIVE, rec, records=[alive("example.com")])}
    summary = await make_engine(tmp_path, specs, adapters).run(
        "example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True)
    )
    live = summary.stages[0]
    assert [(result.tool, result.status) for result in live.results] == [
        ("live-fake", ToolStatus.OK)
    ]
    assert rec.hosts == [["example.com"]]
    assert summary.exit_code is ExitCode.SUCCESS


# ---- D52: runtime classes drive idle windows, never caps -----------------------


def class_spec(name: str, class_: str | None, stage: Stage = Stage.URLS) -> ToolSpec:
    """A registry row of the shape the class system reads."""
    return ToolSpec(
        name=name,
        stage=stage,
        kind="binary",
        tier=Tier.CORE,
        mode=Mode.ACTIVE,
        phase=3,
        class_=class_,
    )


class NoopAdapter(BaseToolAdapter):
    """Never instantiated by these tests; `_limits` only reads the spec."""

    name = "noop"

    def parse_output(self, raw: str) -> list[Record]:
        return []


def limits_for(
    tmp_path: Path,
    specs: Mapping[str, ToolSpec],
) -> dict[str, object]:
    engine = make_engine(tmp_path, specs, {})
    selected = [(spec, NoopAdapter) for spec in specs.values()]
    return engine._limits(selected)


def test_a_classed_tool_gets_its_class_idle_window(tmp_path: Path) -> None:
    """D52/D109: `class: crawler` -> 120 s of silence, and nothing else."""
    limits = limits_for(tmp_path, {"gau": class_spec("gau", "crawler")})
    assert limits["gau"].idle_s == 120.0
    # There is no cap left to hold: the model has exactly one field.
    assert set(limits["gau"].model_dump()) == {"idle_s"}


def test_a_tool_with_no_class_gets_no_idle_window(tmp_path: Path) -> None:
    """D52: an unclassed tool has no window; only the stage budget bounds it."""
    limits = limits_for(tmp_path, {"waybackurls": class_spec("waybackurls", None)})
    assert limits == {}


def test_a_tool_idle_s_entry_wins_over_its_class(tmp_path: Path) -> None:
    """D52: one `idle_s:` in tools.yaml overrides the class for that one tool."""
    from dataclasses import replace

    spec = replace(class_spec("nikto", "scanner", Stage.VULNS), idle_s=45.0)
    limits = limits_for(tmp_path, {"nikto": spec})
    assert limits["nikto"].idle_s == 45.0


def test_an_unknown_class_is_a_config_error(tmp_path: Path) -> None:
    """D52: a typo in `class:` must not silently mean "no window at all"."""
    specs = {"mystery": class_spec("mystery", "crawlerr")}
    engine = make_engine(tmp_path, specs, {})
    with pytest.raises(ConfigError, match="crawlerr"):
        engine._limits([(specs["mystery"], NoopAdapter)])


class SilentAdapter(BaseToolAdapter):
    """A tool that never prints anything: the idle watchdog's target."""

    name = "quiet"
    stage = Stage.SUBS

    async def run(self, ctx: RunContext) -> ToolResult:
        await asyncio.Event().wait()
        return ToolResult(tool=self.name, status=ToolStatus.OK)  # pragma: no cover

    def parse_output(self, raw: str) -> list[Record]:
        return []


class ChattyAdapter(BaseToolAdapter):
    """A tool that keeps producing output, however slowly."""

    name = "chatty"
    stage = Stage.SUBS

    async def run(self, ctx: RunContext) -> ToolResult:
        for _ in range(6):
            await asyncio.sleep(0.1)
            if ctx.activity is not None:
                ctx.activity()
        return ToolResult(tool=self.name, status=ToolStatus.OK, records=[])

    def parse_output(self, raw: str) -> list[Record]:
        return []


def _short_crawler_window(engine: Engine) -> None:
    """A 0.3 s crawler window, so a kill test does not take a minute."""
    from reconkit.config import RuntimeClassConfig

    engine.config = engine.config.model_copy(
        update={
            "runtime_idle": {"crawler": RuntimeClassConfig(idle=0.3)},
        }
    )


async def test_a_silent_tool_is_killed_and_reported(tmp_path: Path) -> None:
    """D52: silence past the class window kills the tool, and the run says so."""
    spec = class_spec("quiet", "crawler", Stage.SUBS)
    engine = make_engine(tmp_path, {"quiet": spec}, {"quiet": SilentAdapter})
    _short_crawler_window(engine)
    summary = await engine.run(
        "example.com", ScanOptions(stages=(Stage.SUBS,), active=True, mock=True)
    )
    killed = summary.stages[0].results
    assert [(result.tool, result.status) for result in killed] == [("quiet", ToolStatus.KILLED)]
    assert killed[0].error is not None and "killed after 0.3s idle" in killed[0].error
    row = engine.store._conn.execute("SELECT status, error FROM tool_runs").fetchone()
    assert row["status"] == "killed"
    assert "killed after 0.3s idle" in row["error"]
    # A kill is a deliberate stop, not a broken tool: today's run still completed.
    assert summary.exit_code is ExitCode.SUCCESS


async def test_a_productive_tool_is_not_killed_at_its_idle_window(tmp_path: Path) -> None:
    """D52: activity resets the clock - a slow but working tool runs to the end."""
    spec = class_spec("chatty", "crawler", Stage.SUBS)
    engine = make_engine(tmp_path, {"chatty": spec}, {"chatty": ChattyAdapter})
    _short_crawler_window(engine)
    summary = await engine.run(
        "example.com", ScanOptions(stages=(Stage.SUBS,), active=True, mock=True)
    )
    statuses = [result.status for result in summary.stages[0].results]
    assert statuses == [ToolStatus.OK]


def test_a_new_tool_with_class_in_tools_yaml_needs_no_engine_edit(tmp_path: Path) -> None:
    """D52's zero-edit claim: a new crawler is a tools.yaml row, not code."""
    from reconkit.adapters.registry import load_tools

    registry = tmp_path / "tools.yaml"
    registry.write_text(
        "version: 1\n"
        "stages: {urls: {mode: active, desc: 'x'}}\n"
        "tools:\n"
        "  newcrawl:\n"
        "    stage: urls\n"
        "    kind: binary\n"
        "    tier: core\n"
        "    mode: active\n"
        "    phase: 3\n"
        "    class: crawler\n"
        "    binary: newcrawl\n",
        encoding="utf-8",
    )
    specs = load_tools(registry)
    assert specs["newcrawl"].class_ == "crawler"

    limits = limits_for(tmp_path, specs)
    assert limits["newcrawl"].idle_s == 120.0  # crawler window, no code names the tool
    source = Path(engine_module.__file__).read_text(encoding="utf-8")
    assert "newcrawl" not in source


# ---- D50: one heartbeat line per long-running tool ----------------------------


class SleepyAdapter(BaseToolAdapter):
    """A tool that simply takes a while, the way a crawler does."""

    name = "sleepy"
    stage = Stage.URLS

    def __init__(self, seconds: float) -> None:
        super().__init__()
        self._seconds = seconds

    async def run(self, ctx: RunContext) -> ToolResult:
        await asyncio.sleep(self._seconds)
        return ToolResult(tool=self.name, status=ToolStatus.OK, records=[])


async def test_heartbeat_prints_while_a_tool_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D50: a tool still running after the delay gets one stderr line, in place."""
    monkeypatch.setattr(engine_module, "HEARTBEAT_AFTER_S", 0.15)
    lines: list[str] = []
    specs = {"sleepy": tool("sleepy", Stage.URLS, mode=Mode.ACTIVE)}
    adapters = {"sleepy": type("Sleepy", (SleepyAdapter,), {"__init__": lambda self: None})}
    engine = make_engine(tmp_path, specs, adapters, progress=lines.append)
    monkeypatch.setattr(
        engine, "_run_one", lambda run_id, adapter, ctx, workspace: _slow_result(0.5)
    )
    await engine.run("example.com", ScanOptions(stages=(Stage.URLS,), active=True, mock=True))
    beats = [line for line in lines if "running (" in line]
    assert beats, f"no heartbeat in {lines!r}"
    assert beats[0].startswith("urls: sleepy running (")
    assert beats[0].endswith("s)")


async def _slow_result(seconds: float) -> ToolResult:
    await asyncio.sleep(seconds)
    return ToolResult(tool="sleepy", status=ToolStatus.OK, records=[])


async def test_heartbeat_is_suppressed_by_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """D50: `--silent` passes `progress=None`, so no heartbeat exists at all."""
    monkeypatch.setattr(engine_module, "HEARTBEAT_AFTER_S", 0.1)
    specs = {"sleepy": tool("sleepy", Stage.URLS, mode=Mode.ACTIVE)}
    adapters = {"sleepy": type("Sleepy", (SleepyAdapter,), {"__init__": lambda self: None})}
    engine = make_engine(tmp_path, specs, adapters, progress=None)
    monkeypatch.setattr(
        engine, "_run_one", lambda run_id, adapter, ctx, workspace: _slow_result(0.3)
    )
    await engine.run("example.com", ScanOptions(stages=(Stage.URLS,), active=True, mock=True))
    captured = capsys.readouterr()
    assert engine._progress_cb is None
    assert "running (" not in captured.err
    assert "running (" not in captured.out


async def test_heartbeat_stops_when_the_tool_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D50: a tool that exits before the delay never produces a heartbeat."""
    monkeypatch.setattr(engine_module, "HEARTBEAT_AFTER_S", 10.0)
    lines: list[str] = []
    specs = {"sleepy": tool("sleepy", Stage.URLS, mode=Mode.ACTIVE)}
    adapters = {"sleepy": type("Sleepy", (SleepyAdapter,), {"__init__": lambda self: None})}
    engine = make_engine(tmp_path, specs, adapters, progress=lines.append)
    monkeypatch.setattr(
        engine, "_run_one", lambda run_id, adapter, ctx, workspace: _slow_result(0.05)
    )
    await engine.run("example.com", ScanOptions(stages=(Stage.URLS,), active=True, mock=True))
    assert [line for line in lines if "running (" in line] == []


# ------------------------------------------------- D58 bounded second resolve


def _seed_known_host(engine: Engine, fqdn: str) -> int:
    """Give the run a host that a discovery pass already found."""
    target_id = engine.store.create_target("example.com")
    run_id = engine.store.create_scan_run(target_id, "subs")
    engine.store.upsert_subdomain(target_id, fqdn, run_id=run_id, provenance="subs")
    engine.store.finish_scan_run(run_id, "completed")
    return target_id


def _url_records(*hosts: str) -> list[Record]:
    return [UrlRecord(url=f"https://{host}/page", source="fake") for host in hosts]


async def test_second_resolve_adds_url_only_hosts_in_passive(tmp_path: Path) -> None:
    """D58: a name only the URL pool found gets a row, stateless no longer."""
    rec = Recorder()
    lines: list[str] = []
    specs = {"urls-fake": tool("urls-fake", Stage.URLS)}
    adapters = {
        "urls-fake": adapter(
            "urls-fake",
            Stage.URLS,
            rec,
            records=_url_records("known.example.com", "new1.example.com", "new2.example.com"),
        ),
        "dnspython": adapter(
            "dnspython",
            Stage.DNS,
            rec,
            records=[sub("new1.example.com"), sub("new2.example.com")],
        ),
    }
    engine = make_engine(tmp_path, specs, adapters, progress=lines.append)
    _seed_known_host(engine, "known.example.com")

    summary = await engine.run("example.com", ScanOptions(stages=(Stage.URLS,), mock=True))

    # The URL pool is the only thing that ran as a stage, then one DNS adapter.
    assert rec.names == ["urls-fake", "dnspython"]
    assert rec.hosts[-1] == ["new1.example.com", "new2.example.com"]
    assert "urls: 2 host(s) found only in URLs; resolved" in lines
    assert summary.exit_code is ExitCode.SUCCESS
    rows = {
        str(row["fqdn"]): row
        for row in engine.store._conn.execute(
            "SELECT fqdn, state, source_count, provenance FROM subdomains"
        )
    }
    assert set(rows) == {"known.example.com", "new1.example.com", "new2.example.com"}
    for host in ("new1.example.com", "new2.example.com"):
        assert rows[host]["state"] == HostState.DNS_ONLY.value
        # D58: provenance stays `dns` (a DNS pass made the row) and one source
        # names the URL pool, so the report shows where the name came from.
        assert rows[host]["provenance"] == "dns"
        assert rows[host]["source_count"] == 1
        sources = [
            str(row["tool"])
            for row in engine.store._conn.execute(
                "SELECT x.tool FROM subdomain_sources x"
                " JOIN subdomains s ON s.id = x.subdomain_id WHERE s.fqdn = ?",
                (host,),
            )
        ]
        assert sources == ["url-derived"]


async def test_second_resolve_live_checks_new_hosts_in_active(tmp_path: Path) -> None:
    """D58: active/full probes the new hosts, so `url_probe` sees a state."""
    rec = Recorder()
    lines: list[str] = []
    specs = {"urls-fake": tool("urls-fake", Stage.URLS)}
    adapters = {
        "urls-fake": adapter(
            "urls-fake",
            Stage.URLS,
            rec,
            records=_url_records("new1.example.com", "new2.example.com"),
        ),
        "dnspython": adapter(
            "dnspython",
            Stage.DNS,
            rec,
            records=[sub("new1.example.com"), sub("new2.example.com")],
        ),
        "pyprobe": adapter(
            "pyprobe",
            Stage.LIVE,
            rec,
            records=[alive("new1.example.com"), alive("new2.example.com")],
        ),
    }
    engine = make_engine(tmp_path, specs, adapters, progress=lines.append)

    await engine.run("example.com", ScanOptions(stages=(Stage.URLS,), active=True, mock=True))

    assert rec.names == ["urls-fake", "dnspython", "pyprobe"]
    assert rec.hosts[-1] == ["new1.example.com", "new2.example.com"]
    assert "urls: 2 host(s) found only in URLs; resolved, 2 now ALIVE" in lines
    states = {
        str(row["fqdn"]): str(row["state"])
        for row in engine.store._conn.execute("SELECT fqdn, state FROM subdomains")
    }
    assert states == {"new1.example.com": "ALIVE", "new2.example.com": "ALIVE"}


async def test_second_resolve_does_not_duplicate_existing_hosts(tmp_path: Path) -> None:
    """D58: every URL host already known means no resolve and no new row."""
    rec = Recorder()
    lines: list[str] = []
    specs = {"urls-fake": tool("urls-fake", Stage.URLS)}
    adapters = {
        "urls-fake": adapter(
            "urls-fake", Stage.URLS, rec, records=_url_records("known.example.com")
        ),
        "dnspython": adapter("dnspython", Stage.DNS, rec, records=[]),
        "pyprobe": adapter("pyprobe", Stage.LIVE, rec, records=[]),
    }
    engine = make_engine(tmp_path, specs, adapters, progress=lines.append, scope_text=SCOPE)
    _seed_known_host(engine, "known.example.com")

    await engine.run("example.com", ScanOptions(stages=(Stage.URLS,), mock=True))

    assert rec.names == ["urls-fake"]
    assert "urls: 0 host(s) found only in URLs; resolved" in lines
    assert engine.store._conn.execute("SELECT COUNT(*) FROM subdomains").fetchone()[0] == 1


async def test_second_resolve_is_one_pass(tmp_path: Path) -> None:
    """D58: a URL stored during the pass is not resolved by the same run.

    The candidates are read once, before any DNS work. This adapter writes a
    new URL row while it is running, which is the only way to prove the pass
    never re-extracts: a second extraction would have found `late.example.com`
    and resolved it too.
    """
    rec = Recorder()
    box: dict[str, object] = {}

    class LateUrlDns(BaseToolAdapter):
        name = "dnspython"
        stage = Stage.DNS

        async def run(self, ctx: RunContext) -> ToolResult:
            rec.names.append(self.name)
            rec.hosts.append(list(ctx.hosts))
            store = box["store"]
            latest = store._conn.execute("SELECT MAX(id) FROM scan_runs").fetchone()[0]
            store.upsert_url(int(box["target_id"]), "https://late.example.com/x", run_id=latest)
            return ToolResult(
                tool=self.name,
                status=ToolStatus.OK,
                records=[sub("new1.example.com")],
            )

        def parse_output(self, raw: str) -> list[object]:
            return []

    specs = {"urls-fake": tool("urls-fake", Stage.URLS)}
    adapters = {
        "urls-fake": adapter(
            "urls-fake", Stage.URLS, rec, records=_url_records("new1.example.com")
        ),
        "dnspython": LateUrlDns,
    }
    engine = make_engine(tmp_path, specs, adapters)
    box["store"] = engine.store
    box["target_id"] = engine.store.create_target("example.com")

    await engine.run("example.com", ScanOptions(stages=(Stage.URLS,), mock=True))

    assert rec.names.count("dnspython") == 1
    # The first entry is the urls adapter's own input (the target); the DNS
    # pass saw exactly the hosts extracted before it ran, once.
    assert rec.hosts[-1] == ["new1.example.com"]
    names = {str(row["fqdn"]) for row in engine.store._conn.execute("SELECT fqdn FROM subdomains")}
    assert names == {"new1.example.com"}


# --- D69: the live pass keeps an observed HTTP status on the host row -------


async def test_alive_host_has_status_code_in_report(tmp_path: Path) -> None:
    """The 200 a live adapter observed reaches `host_status_history` and the report.

    Regression: `_persist_live` took the first ALIVE record in completion order,
    so a live pool mixing adapters with a status (`pyprobe`, `httpx`) and
    adapters without one (`httprobe`, `tlsx`) could store `NULL` while the
    report showed `-` for an ALIVE host. Measured on `target.com` run 203.
    """
    rec = Recorder()
    specs = {"live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE)}
    adapters = {
        "live-fake": adapter(
            "live-fake",
            Stage.LIVE,
            rec,
            records=[
                HostStatusRecord(
                    fqdn="example.com",
                    source="live-fake",
                    state=HostState.ALIVE,
                    status_code=200,
                    title="home",
                )
            ],
        )
    }
    store = Store(tmp_path / "recon.db")
    engine = make_engine(tmp_path, specs, adapters, store=store)
    summary = await engine.run(
        "example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True)
    )

    stored = store._conn.execute(
        "SELECT status_code FROM host_status_history ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert stored["status_code"] == 200

    text = report_text(
        "example.com",
        engine.host_rows(summary.target_id),
        REPORT_FIELDS,
        run_at=datetime(2026, 11, 19, 20, 0, tzinfo=UTC),
    )
    row = next(line for line in text.splitlines() if line.startswith("example.com"))
    # REPORT_FIELDS order: hostname, state, confidence, sources, source count,
    # IPs, HTTP status code - so the seventh cell is the one that used to be `-`.
    assert row.split()[6] == "200", row


async def test_tech_stage_does_not_clear_host_status(tmp_path: Path) -> None:
    """`tech` annotates the newest status row; it must not blank `status_code`.

    It already only writes `tech`/`waf` (`Store.update_host_extras`), so this is
    the guard that keeps a future merge from re-introducing the D69 symptom.
    """
    rec = Recorder()
    specs = {
        "live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE),
        "tech-fake": tool("tech-fake", Stage.TECH, mode=Mode.ACTIVE),
    }
    adapters = {
        "live-fake": adapter(
            "live-fake",
            Stage.LIVE,
            rec,
            records=[
                HostStatusRecord(
                    fqdn="example.com", source="live-fake", state=HostState.ALIVE, status_code=200
                )
            ],
        ),
        "tech-fake": adapter(
            "tech-fake",
            Stage.TECH,
            rec,
            records=[
                HostStatusRecord(
                    fqdn="example.com",
                    source="tech-fake",
                    state=HostState.ALIVE,
                    tech=["nginx"],
                )
            ],
        ),
    }
    store = Store(tmp_path / "recon.db")
    engine = make_engine(tmp_path, specs, adapters, store=store)
    await engine.run(
        "example.com", ScanOptions(stages=(Stage.LIVE, Stage.TECH), active=True, mock=True)
    )

    row = store._conn.execute(
        "SELECT status_code, tech_json FROM host_status_history ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row["status_code"] == 200
    assert json.loads(str(row["tech_json"])) == ["nginx"]


async def test_multiple_live_adapters_prefer_200_over_other(tmp_path: Path) -> None:
    """A 200 wins over a 301 even when the redirecting tool finishes first.

    Completion order must never decide the row: the 301 adapter returns
    immediately and the 200 adapter waits, which is the order that used to lose
    the 200.
    """
    rec = Recorder()
    specs = {
        "redirect-fake": tool("redirect-fake", Stage.LIVE, mode=Mode.ACTIVE),
        "probe-fake": tool("probe-fake", Stage.LIVE, mode=Mode.ACTIVE),
    }
    adapters = {
        "redirect-fake": adapter(
            "redirect-fake",
            Stage.LIVE,
            rec,
            delay=0.0,
            records=[
                HostStatusRecord(
                    fqdn="example.com",
                    source="redirect-fake",
                    state=HostState.ALIVE,
                    status_code=301,
                )
            ],
        ),
        "probe-fake": adapter(
            "probe-fake",
            Stage.LIVE,
            rec,
            delay=0.02,
            records=[
                HostStatusRecord(
                    fqdn="example.com", source="probe-fake", state=HostState.ALIVE, status_code=200
                )
            ],
        ),
    }
    store = Store(tmp_path / "recon.db")
    engine = make_engine(tmp_path, specs, adapters, store=store)
    await engine.run("example.com", ScanOptions(stages=(Stage.LIVE,), active=True, mock=True))

    row = store._conn.execute(
        "SELECT status_code FROM host_status_history ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row["status_code"] == 200


# --- D75: url-derived hosts are tech-scanned on a follow-up run ------------


def _seed_url_derived(
    store: Store, hosts: tuple[str, ...] = ("orphan.example.com",), urls: tuple[str, ...] = ()
) -> None:
    """Rows an earlier D58 pass left behind: the host plus its URL, no tech."""
    target_id = store.create_target("example.com")
    run_id = store.create_scan_run(target_id, "urls")
    for fqdn in hosts:
        sub_id = store.upsert_subdomain(target_id, fqdn, run_id=run_id)
        store.add_subdomain_source(sub_id, run_id, "url-derived")
    for url in urls:
        store.upsert_url(target_id, url, run_id=run_id, source_count=1)


def _latest_tech(store: Store, fqdn: str) -> list[str] | None:
    row = store._conn.execute(
        "SELECT h.tech_json FROM host_status_history h JOIN subdomains s ON s.id = h.subdomain_id"
        " WHERE s.fqdn = ? ORDER BY h.id DESC LIMIT 1",
        (fqdn,),
    ).fetchone()
    return None if row is None else json.loads(str(row["tech_json"]))


async def test_url_derived_host_gets_tech_on_follow_up_run(tmp_path: Path) -> None:
    """D75: a host D58 created is tech-scanned by the next active run.

    Nothing else would ever offer it again: `url_only_hosts()` skips a name with
    a row, and a fresh run does not seed `discovered` from the store.
    """
    rec = Recorder()
    specs = {
        "urls-fake": tool("urls-fake", Stage.URLS),
        "tech-fake": tool("tech-fake", Stage.TECH, mode=Mode.ACTIVE),
    }
    adapters = {
        "urls-fake": adapter("urls-fake", Stage.URLS, rec, records=[]),
        "pyprobe": adapter(
            "pyprobe",
            Stage.LIVE,
            rec,
            records=[
                HostStatusRecord(
                    fqdn="orphan.example.com",
                    source="pyprobe",
                    state=HostState.ALIVE,
                    status_code=200,
                )
            ],
        ),
        "tech-fake": adapter(
            "tech-fake",
            Stage.TECH,
            rec,
            records=[
                HostStatusRecord(
                    fqdn="orphan.example.com",
                    source="tech-fake",
                    state=HostState.ALIVE,
                    tech=["nginx"],
                )
            ],
        ),
    }
    store = Store(tmp_path / "recon.db")
    _seed_url_derived(store, urls=("https://orphan.example.com/x",))
    engine = make_engine(tmp_path, specs, adapters, store=store)
    await engine.run("example.com", ScanOptions(stages=(Stage.URLS,), active=True, mock=True))

    assert _latest_tech(store, "orphan.example.com") == ["nginx"]
    assert "tech-fake" in rec.names


async def test_url_derived_host_is_not_re_resolved_if_it_has_a_state(tmp_path: Path) -> None:
    """D75: the DNS step only ever sees names with no `subdomains` row."""
    rec = Recorder()
    specs = {
        "urls-fake": tool("urls-fake", Stage.URLS),
        "tech-fake": tool("tech-fake", Stage.TECH, mode=Mode.ACTIVE),
    }
    adapters = {
        "urls-fake": adapter("urls-fake", Stage.URLS, rec, records=[]),
        "dnspython": adapter("dnspython", Stage.DNS, rec, records=[]),
        "pyprobe": adapter("pyprobe", Stage.LIVE, rec, records=[]),
        "tech-fake": adapter("tech-fake", Stage.TECH, rec, records=[]),
    }
    store = Store(tmp_path / "recon.db")
    _seed_url_derived(
        store,
        hosts=("orphan.example.com",),
        urls=("https://orphan.example.com/x", "https://new.example.com/y"),
    )
    engine = make_engine(tmp_path, specs, adapters, store=store)
    await engine.run("example.com", ScanOptions(stages=(Stage.URLS,), active=True, mock=True))

    assert rec.names.count("dnspython") == 1
    assert rec.hosts[rec.names.index("dnspython")] == ["new.example.com"]


async def test_passive_does_not_tech_scan_url_derived_hosts(tmp_path: Path) -> None:
    """D75: passive is unchanged - no live probe and no tech pool."""
    rec = Recorder()
    specs = {
        "urls-fake": tool("urls-fake", Stage.URLS),
        "tech-fake": tool("tech-fake", Stage.TECH, mode=Mode.ACTIVE),
    }
    adapters = {
        "urls-fake": adapter("urls-fake", Stage.URLS, rec, records=[]),
        "dnspython": adapter("dnspython", Stage.DNS, rec, records=[]),
        "pyprobe": adapter("pyprobe", Stage.LIVE, rec, records=[]),
        "tech-fake": adapter("tech-fake", Stage.TECH, rec, records=[]),
    }
    store = Store(tmp_path / "recon.db")
    _seed_url_derived(store, urls=("https://orphan.example.com/x",))
    engine = make_engine(tmp_path, specs, adapters, store=store)
    await engine.run("example.com", ScanOptions(stages=(Stage.URLS,), mock=True))

    assert "pyprobe" not in rec.names
    assert "tech-fake" not in rec.names
    assert _latest_tech(store, "orphan.example.com") is None


async def test_new_and_previously_orphaned_hosts_both_processed(tmp_path: Path) -> None:
    """D75: one pass covers both halves - the new name and the earlier one."""
    rec = Recorder()
    specs = {
        "urls-fake": tool("urls-fake", Stage.URLS),
        "tech-fake": tool("tech-fake", Stage.TECH, mode=Mode.ACTIVE),
    }
    adapters = {
        "urls-fake": adapter("urls-fake", Stage.URLS, rec, records=[]),
        "dnspython": adapter("dnspython", Stage.DNS, rec, records=[]),
        "pyprobe": adapter(
            "pyprobe",
            Stage.LIVE,
            rec,
            records=[
                HostStatusRecord(
                    fqdn="orphan.example.com",
                    source="pyprobe",
                    state=HostState.ALIVE,
                    status_code=200,
                ),
                HostStatusRecord(
                    fqdn="new.example.com", source="pyprobe", state=HostState.ALIVE, status_code=200
                ),
            ],
        ),
        "tech-fake": adapter(
            "tech-fake",
            Stage.TECH,
            rec,
            records=[
                HostStatusRecord(
                    fqdn="orphan.example.com",
                    source="tech-fake",
                    state=HostState.ALIVE,
                    tech=["nginx"],
                ),
                HostStatusRecord(
                    fqdn="new.example.com",
                    source="tech-fake",
                    state=HostState.ALIVE,
                    tech=["caddy"],
                ),
            ],
        ),
    }
    store = Store(tmp_path / "recon.db")
    _seed_url_derived(
        store,
        hosts=("orphan.example.com",),
        urls=("https://orphan.example.com/x", "https://new.example.com/y"),
    )
    engine = make_engine(tmp_path, specs, adapters, store=store)
    await engine.run("example.com", ScanOptions(stages=(Stage.URLS,), active=True, mock=True))

    assert _latest_tech(store, "orphan.example.com") == ["nginx"]
    assert _latest_tech(store, "new.example.com") == ["caddy"]
    tech_hosts = rec.hosts[rec.names.index("tech-fake")]
    assert sorted(tech_hosts) == ["new.example.com", "orphan.example.com"]


# ------------------------------- (D76) third-party URLs stay out of hosts


async def test_third_party_hosts_are_not_added_to_subdomains(tmp_path: Path) -> None:
    """D76: a URL on another domain is stored, tagged, and never becomes a host."""
    rec = Recorder()
    specs = {"urls-fake": tool("urls-fake", Stage.URLS, mode=Mode.PASSIVE)}
    adapters = {
        "urls-fake": adapter(
            "urls-fake",
            Stage.URLS,
            rec,
            records=[
                UrlRecord(url="https://www.example.com/a", source="fake"),
                UrlRecord(url="https://www.google.com/search?q=example", source="fake"),
                UrlRecord(url="https://fonts.googleapis.com/css", source="fake"),
            ],
        )
    }
    engine = make_engine(tmp_path, specs, adapters)
    await engine.run("example.com", ScanOptions(stages=(Stage.URLS,)))

    sources = {
        str(row["url"]): row["source"]
        for row in rows(engine.store, "SELECT url, source FROM urls ORDER BY url")
    }
    assert sources == {
        "https://fonts.googleapis.com/css": "external",
        "https://www.example.com/a": None,
        "https://www.google.com/search?q=example": "external",
    }
    fqdns = {str(row["fqdn"]) for row in rows(engine.store, "SELECT fqdn FROM subdomains")}
    assert "www.example.com" in fqdns
    assert "www.google.com" not in fqdns
    assert "fonts.googleapis.com" not in fqdns
    # The second resolve never even offered a third-party name to DNS.
    assert not [host for host in rec.hosts if "google" in host]


# ------------------------------- (D77) how much each URL tool added


async def test_unique_count_is_zero_for_all_duplicate_tool(tmp_path: Path) -> None:
    """D77: a tool whose whole output is already stored contributes 0 new URLs."""
    rec = Recorder()
    specs = {"urls-fake": tool("urls-fake", Stage.URLS, mode=Mode.PASSIVE)}
    adapters = {
        "urls-fake": adapter(
            "urls-fake",
            Stage.URLS,
            rec,
            records=[UrlRecord(url="https://www.example.com/a", source="fake")],
        )
    }
    engine = make_engine(tmp_path, specs, adapters)
    first = await engine.run("example.com", ScanOptions(stages=(Stage.URLS,)))
    assert first.stages[0].results[0].unique_count == 1

    second = await engine.run("example.com", ScanOptions(stages=(Stage.URLS,)))
    assert second.stages[0].results[0].unique_count == 0
    assert len(rows(engine.store, "SELECT url FROM urls")) == 1


async def test_user_agent_defaults_to_config_value(tmp_path: Path) -> None:
    """D84: config.user_agent is read, and {version} is filled from __version__."""
    from reconkit import __version__

    rec = Recorder()
    specs = {"subs-fake": tool("subs-fake", Stage.SUBS)}
    adapters = {"subs-fake": adapter("subs-fake", Stage.SUBS, rec, records=[])}
    engine = make_engine(
        tmp_path, specs, adapters, scope_text=None, user_agent="configured/{version}"
    )
    await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    assert rec.user_agents == [f"configured/{__version__}"]


async def test_user_agent_flag_overrides_config(tmp_path: Path) -> None:
    """D84: a --user-agent value wins over config.user_agent."""
    rec = Recorder()
    specs = {"subs-fake": tool("subs-fake", Stage.SUBS)}
    adapters = {"subs-fake": adapter("subs-fake", Stage.SUBS, rec, records=[])}
    engine = make_engine(tmp_path, specs, adapters, scope_text=None, user_agent="config-agent")
    await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS,), mock=True, user_agent="flag-agent"),
    )
    assert rec.user_agents == ["flag-agent"]


# ------------------------------------- persistence boundaries (PIT-68..70)


def _seed_alive(engine: Engine, fqdn: str = "www.example.com") -> tuple[int, int]:
    """One stored ALIVE host, so a standalone stage command has input."""
    target_id = engine.store.create_target("example.com")
    run_id = engine.store.create_scan_run(target_id, "live")
    engine.store.upsert_subdomain(target_id, fqdn, run_id=run_id, state="ALIVE", provenance="subs")
    engine.store.finish_scan_run(run_id, "completed")
    return target_id, run_id


async def test_regression_url_variants_store_one_canonical_row(tmp_path: Path) -> None:
    """Regression: PIT-68 one page is one `urls` row, however it is spelled.

    Archives and crawlers emit `http://host`, `http://host/` and
    `http://HOST:80/` for the same page; before canonicalization the unique key
    saw three different strings and the table grew duplicate rows for one
    resource.
    """
    rec = Recorder()
    specs = {"urls-fake": tool("urls-fake", Stage.URLS, mode=Mode.ACTIVE)}
    adapters = {
        "urls-fake": adapter(
            "urls-fake",
            Stage.URLS,
            rec,
            records=[
                UrlRecord(url=value, source="fake")
                for value in (
                    "http://www.example.com",
                    "http://www.example.com/",
                    "http://WWW.EXAMPLE.COM:80/",
                    "https://www.example.com:443/a#frag",
                    "https://www.example.com/a",
                    "https://legacy.example.com/",
                )
            ],
        )
    }
    engine = make_engine(tmp_path, specs, adapters)
    target_id, run_id = _seed_alive(engine)
    # A row written before canonicalization: the canonical twin must not be added.
    engine.store.upsert_url(target_id, "https://legacy.example.com", run_id=run_id)

    await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.URLS,), active=True, no_scope=True, mock=True),
    )

    stored = sorted(str(row["url"]) for row in rows(engine.store, "SELECT url FROM urls"))
    assert stored == [
        "http://www.example.com/",
        "https://legacy.example.com",
        "https://www.example.com/a",
    ]


async def test_regression_ports_keep_protocol_and_drop_a_foreign_host(tmp_path: Path) -> None:
    """Regression: PIT-70 tcp/53 and udp/53 are two facts; a foreign host is none.

    The persistence path grouped on `(host, ip, port)` and called `upsert_port`
    without `protocol`, so a UDP finding was stored as TCP under the TCP row.
    It also wrote any host a port adapter named, with no target check.
    """
    rec = Recorder()
    specs = {"ports-fake": tool("ports-fake", Stage.PORTS, mode=Mode.ACTIVE)}
    adapters = {
        "ports-fake": adapter(
            "ports-fake",
            Stage.PORTS,
            rec,
            records=[
                PortRecord(
                    fqdn="www.example.com",
                    ip="1.2.3.4",
                    port=53,
                    protocol="tcp",
                    state="open",
                    source="fake",
                ),
                PortRecord(
                    fqdn="www.example.com",
                    ip="1.2.3.4",
                    port=53,
                    protocol="udp",
                    state="open",
                    source="fake",
                ),
                PortRecord(
                    fqdn="WWW.Example.COM.",
                    ip="1.2.3.4",
                    port=443,
                    protocol="tcp",
                    state="open",
                    source="fake",
                ),
                PortRecord(
                    fqdn="evil.example.org",
                    ip="9.9.9.9",
                    port=22,
                    protocol="tcp",
                    state="open",
                    source="fake",
                ),
            ],
        )
    }
    engine = make_engine(tmp_path, specs, adapters)
    _seed_alive(engine)

    await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.PORTS,), active=True, no_scope=True, mock=True),
    )

    stored = sorted(
        (str(row["ip"]), int(row["port"]), str(row["protocol"]))
        for row in rows(engine.store, "SELECT ip, port, protocol FROM ports")
    )
    assert stored == [
        ("1.2.3.4", 53, "tcp"),
        ("1.2.3.4", 53, "udp"),
        ("1.2.3.4", 443, "tcp"),
    ]
    fqdns = {str(row["fqdn"]) for row in rows(engine.store, "SELECT fqdn FROM subdomains")}
    assert fqdns == {"www.example.com"}


async def test_regression_discovery_records_are_canonical_and_in_scope(tmp_path: Path) -> None:
    """Regression: PIT-69 a mixed-case or foreign record is not a new row.

    A discovery record went straight into the `subdomains` unique key. Now the
    engine canonicalizes it (`validate_host`) and drops a host outside the
    target before the write, so one name has one row and a foreign name has none.
    """
    rec = Recorder()
    specs = {"subs-fake": tool("subs-fake", Stage.SUBS)}
    adapters = {
        "subs-fake": adapter(
            "subs-fake",
            Stage.SUBS,
            rec,
            records=[sub("WWW.Example.COM."), sub("*.api.example.com"), sub("evil.example.org")],
        )
    }
    engine = make_engine(tmp_path, specs, adapters)

    summary = await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))

    stored = sorted(str(row["fqdn"]) for row in rows(engine.store, "SELECT fqdn FROM subdomains"))
    assert stored == ["api.example.com", "www.example.com"]
    assert summary.exit_code is ExitCode.SUCCESS


async def test_regression_two_identical_subs_runs_keep_one_row(tmp_path: Path) -> None:
    """Regression: PIT-69 a second scan of the same data is not duplicate rows.

    Facts are keyed by their natural identity; only the per-run source rows may
    grow (one `(subdomain, run, tool)` row per sighting, by design).
    """
    rec = Recorder()
    specs = {"subs-fake": tool("subs-fake", Stage.SUBS)}
    adapters = {
        "subs-fake": adapter("subs-fake", Stage.SUBS, rec, records=[sub("www.example.com")])
    }
    engine = make_engine(tmp_path, specs, adapters)

    await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))
    await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True))

    def count(sql: str) -> int:
        return int(rows(engine.store, sql)[0]["n"])

    assert count("SELECT COUNT(*) AS n FROM subdomains") == 1
    assert count("SELECT COUNT(*) AS n FROM subdomain_sources") == 2


async def test_regression_missing_mock_fixture_is_a_skip_not_a_failure(
    tmp_path: Path,
) -> None:
    """Regression: PIT-71 a mock target with no fixture is a skip, never exit 5.

    `_read_fixture` used to raise `FetchFailed`, so an adapter whose fixture set
    had no file for the target was reported as a failed tool. A mock run on an
    arbitrary target then exited 5 although nothing was broken.
    """

    class NoFixture(BaseToolAdapter):
        name = "nofix"
        stage = Stage.SUBS

        def parse_output(self, raw: str) -> list[Record]:
            return []

    adapter = NoFixture(fixtures_dir=tmp_path / "fixtures")
    ctx = RunContext(
        target="example.org",
        hosts=["example.org"],
        timeout=5,
        workspace=tmp_path,
        mock=True,
    )

    result = await adapter.run(ctx)

    assert result.status is ToolStatus.SKIPPED
    assert "no fixture for example.org" in (result.error or "")


async def test_regression_stage_inputs_match_the_documented_pool(tmp_path: Path) -> None:
    """AGENTS 0e rule 4: every stage gets exactly the previous stage's output.

    A stage that silently narrows its input is how a tool appears to run but
    receives no data. The pool is `_stage_hosts()`: subs gets the target, dns
    and live get the target plus every discovered name, and ports/tech/urls get
    the ALIVE set only.
    """
    rec = Recorder()
    specs = {
        "subs-fake": tool("subs-fake", Stage.SUBS),
        "dns-fake": tool("dns-fake", Stage.DNS),
        "live-fake": tool("live-fake", Stage.LIVE, mode=Mode.ACTIVE),
        "ports-fake": tool("ports-fake", Stage.PORTS, mode=Mode.ACTIVE),
        "tech-fake": tool("tech-fake", Stage.TECH, mode=Mode.ACTIVE),
        "urls-fake": tool("urls-fake", Stage.URLS, mode=Mode.ACTIVE),
    }
    adapters = {
        "subs-fake": adapter("subs-fake", Stage.SUBS, rec, records=[sub("a.example.com")]),
        "dns-fake": adapter("dns-fake", Stage.DNS, rec, records=[sub("a.example.com")]),
        "live-fake": adapter("live-fake", Stage.LIVE, rec, records=[alive("a.example.com")]),
        "ports-fake": adapter("ports-fake", Stage.PORTS, rec, records=[]),
        "tech-fake": adapter("tech-fake", Stage.TECH, rec, records=[]),
        "urls-fake": adapter("urls-fake", Stage.URLS, rec, records=[]),
    }
    engine = make_engine(tmp_path, specs, adapters)

    await engine.run(
        "example.com",
        ScanOptions(
            stages=(
                Stage.SUBS,
                Stage.DNS,
                Stage.LIVE,
                Stage.PORTS,
                Stage.TECH,
                Stage.URLS,
            ),
            active=True,
            no_scope=True,
            mock=True,
        ),
    )

    by_tool = dict(zip(rec.names, rec.hosts, strict=True))
    assert set(by_tool["subs-fake"]) == {"example.com"}
    assert set(by_tool["dns-fake"]) == {"example.com", "a.example.com"}
    assert set(by_tool["live-fake"]) == {"example.com", "a.example.com"}
    for later in ("ports-fake", "tech-fake", "urls-fake"):
        assert set(by_tool[later]) == {"a.example.com"}, later
