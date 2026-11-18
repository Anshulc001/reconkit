"""Part 6a: engine pipeline, selection, gating, env, timeout and redaction."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

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
    activity: Callable[[str], None] | None = None,
) -> Engine:
    config = load_config(CONFIG)
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
        ScanOptions(stages=(Stage.SUBS, Stage.LIVE, Stage.PORTS), active=True),
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
        ScanOptions(stages=(Stage.LIVE, Stage.URLS), active=True, mock=True),
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
    assert summary.stages[0].results == []
    row = engine.store._conn.execute("SELECT status, error FROM tool_runs").fetchone()
    assert (row["status"], row["error"]) == ("timeout", "phase timeout")


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
    await engine.run("example.com", ScanOptions(stages=(Stage.LIVE,), mock=True))
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
        "example.com", ScanOptions(stages=(Stage.SUBS,), mock=True)
    )
    assert summary.exit_code is ExitCode.SUCCESS


async def test_url_tools_receive_the_configured_runtime_bounds(tmp_path: Path) -> None:
    """2.2/2.3: the engine hands `config.yaml` `urls:` down as RunContext.limits.

    An adapter never reads config.yaml itself (docs/09 section 4a2b).
    """
    seen: dict[str, object] = {}

    class Urls(BaseToolAdapter):
        name = "urls-fake"
        stage = Stage.URLS

        async def run(self, ctx: RunContext) -> ToolResult:
            seen.update(ctx.limits)
            return ToolResult(tool=self.name, status=ToolStatus.OK)

        def parse_output(self, raw: str) -> list[Record]:
            return []

    specs = {"urls-fake": tool("urls-fake", Stage.URLS)}
    summary = await make_engine(tmp_path, specs, {"urls-fake": Urls}).run(
        "example.com", ScanOptions(stages=(Stage.URLS,), mock=True)
    )
    assert summary.exit_code is ExitCode.SUCCESS
    urlfinder = seen["urlfinder"]
    assert (urlfinder.max_s, urlfinder.idle_s, urlfinder.min_s) == (1800.0, 60.0, 180.0)
    assert seen["hakrawler"].max_s == 120.0
    assert seen["subjs"].max_s == 60.0


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
    engine = make_engine(tmp_path, specs, adapters, scope_text=None)
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
    """The sakec.ac.in 403 pair: same code, shared IP -> www is the duplicate."""
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
        "example.com", ScanOptions(stages=(Stage.SUBS,), mock=True)
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
        "example.com", ScanOptions(stages=(Stage.SUBS,), mock=True)
    )
    assert summary.exit_code is ExitCode.PARTIAL


async def test_an_external_service_gap_exits_zero_and_is_named_in_the_gaps(tmp_path: Path) -> None:
    """Owner ruling 2026-11-18: 429/quota/5xx is a gap, never exit 5.

    The sakec.ac.in case: every subs source was refused by its provider, the run
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
        "example.com", ScanOptions(stages=(Stage.SUBS,), mock=True)
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
        "example.com", ScanOptions(stages=(Stage.SUBS,), mock=True)
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


async def test_no_scope_file_runs_active_stages_unrestricted(tmp_path: Path) -> None:
    """Regression: 2026-11-17 - no scope file means unrestricted active scanning.

    The operator named the target explicitly; a missing scope file is not a
    restriction and not a refusal. Active stages run against the target and the
    hosts discovered under it, with no exit 3.
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

    assert rec.names == ["subs", "live", "ports"]
    live_hosts = rec.hosts[rec.names.index("live")]
    assert "www.example.com" in live_hosts
    assert "api.example.com" in live_hosts
    assert summary.scope_denied is False
    assert summary.exit_code is not ExitCode.SCOPE
    stage = next(item for item in summary.stages if item.stage is Stage.LIVE)
    assert stage.dropped_hosts == []


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
    The same run must also hand the active stage an allow-all `ip_allowed`,
    because there is no CIDR list to restrict against.
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

    assert summary.exit_code is not ExitCode.SCOPE
    assert rec.names == ["subs", "live"]
    assert len(predicates) == 1
    assert predicates[0] is not None
    assert predicates[0]("203.0.113.9") is True
    assert predicates[0]("10.0.0.1") is True
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


async def test_no_scope_file_runs_naabu_on_hostnames_unrestricted(tmp_path: Path) -> None:
    """(a) No scope file: naabu is an ordinary active tool, no resolve step."""
    rec = Recorder()
    resolved: list[str] = []

    async def resolve(host: str) -> list[str]:
        resolved.append(host)
        return ["203.0.113.5"]

    engine = ports_engine(tmp_path, rec, scope_text=None, resolve=resolve)
    summary = await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS, Stage.LIVE, Stage.PORTS), active=True, mock=True),
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
        "active": (Stage.SUBS, Stage.DNS, Stage.LIVE, Stage.TECH, Stage.URLS),
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
    engine = make_engine(tmp_path, specs, adapters, scope_text=None)

    summary = await engine.run("example.com", ScanOptions(active=True))

    assert [stage.stage for stage in summary.stages] == [
        Stage.SUBS,
        Stage.LIVE,
        Stage.TECH,
        Stage.URLS,
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
    engine = make_engine(tmp_path, specs, adapters, scope_text=None)

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
    assert len(MODE_STAGES["full"]) == 8
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
    engine = make_engine(tmp_path, specs, adapters, scope_text=None)
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
    engine = make_engine(tmp_path, specs, adapters, scope_text=None)

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
