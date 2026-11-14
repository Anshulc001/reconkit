"""Part 6a: engine pipeline, selection, gating, env, timeout and redaction."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from reconkit.adapters.base import BaseToolAdapter
from reconkit.adapters.dnspython import DnsOutcome, DnsResult
from reconkit.adapters.registry import ToolKey, ToolSpec
from reconkit.config import load_config
from reconkit.core.store import REDACTED, Store
from reconkit.engine import (
    STAGE_ORDER,
    DnsSignal,
    Engine,
    ExitCode,
    HostEvidence,
    ScanOptions,
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


async def no_sleep(_seconds: float) -> None:
    return None


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
            return ToolResult(
                tool=name,
                status=ToolStatus.OK,
                records=records or [],
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
) -> ToolSpec:
    return ToolSpec(
        name=name,
        stage=stage,
        kind="python",
        tier=tier,
        mode=mode,
        phase=2,
        keys=keys,
    )


def sub(fqdn: str) -> SubdomainRecord:
    return SubdomainRecord(fqdn=fqdn, source="fake")


def alive(fqdn: str) -> HostStatusRecord:
    return HostStatusRecord(fqdn=fqdn, source="fake", state=HostState.ALIVE)


def host(fqdn: str, state: HostState, source: str = "fake") -> HostStatusRecord:
    return HostStatusRecord(fqdn=fqdn, source=source, state=state)


def make_engine(
    tmp_path: Path,
    specs: Mapping[str, ToolSpec],
    adapters: Mapping[str, type[BaseToolAdapter]],
    *,
    env: dict[str, str] | None = None,
    store: Store | None = None,
    scope_text: str = SCOPE,
    now: Callable[[], str] | None = None,
    installed: Callable[[type[BaseToolAdapter]], bool] | None = None,
) -> Engine:
    config = load_config(CONFIG, speed="fast")
    tmp_path.mkdir(parents=True, exist_ok=True)
    store = store if store is not None else Store(tmp_path / "recon.db")
    scope = tmp_path / "scope.yaml"
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
        sleep=no_sleep,
        clock=lambda: 0.0,
        installed=installed,
        now=now,
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
    summary = await engine.run("example.com", ScanOptions(active=True, mock=True, speed="slow"))
    assert rec.names == [
        "subs-fake",
        "dns-fake",
        "live-fake",
        "ports-fake",
        "tech-fake",
        "urls-fake",
        "vulns-fake",
    ]
    assert [stage.stage for stage in summary.stages] == list(STAGE_ORDER)
    assert rec.built == []
    statuses = rows(engine.store, "SELECT tool, status FROM tool_runs ORDER BY id")
    assert [(row["tool"], row["status"]) for row in statuses] == [
        (name, "ok") for name in rec.names
    ]


async def test_tier_gating_and_explicit_intrusive_refusal(tmp_path: Path) -> None:
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
    await engine.run("example.com", ScanOptions(stages=(Stage.SUBS,), mock=True, speed="slow"))
    assert rec.names == ["core"]

    engine = make_engine(tmp_path / "second", specs, adapters)
    await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS,), include_noisy=True, mock=True, speed="slow"),
    )
    assert rec.names[-2:] == ["core", "noisy"]

    with pytest.raises(ConfigError, match="intrusive"):
        await make_engine(tmp_path / "third", specs, adapters).run(
            "example.com", ScanOptions(tools=("intrusive",), mock=True)
        )
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
    await engine.run(
        "example.com", ScanOptions(stages=(Stage.SUBS, Stage.LIVE), mock=True, speed="slow")
    )
    assert rec.names == ["subs"]
    assert rec.hosts == [["example.com"]]

    engine = make_engine(tmp_path / "active", specs, adapters)
    summary = await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS, Stage.LIVE), active=True, mock=True, speed="slow"),
    )
    assert "live" in rec.names
    live_hosts = rec.hosts[rec.names.index("live")]
    assert "api.example.com" not in live_hosts
    assert "www.example.com" in live_hosts
    live_stage = next(stage for stage in summary.stages if stage.stage is Stage.LIVE)
    assert live_stage.dropped_hosts == ["api.example.com"]


async def test_naabu_stays_blocked_because_it_resolves_inside_the_binary(
    tmp_path: Path,
) -> None:
    """Regression: 11c-G-7.

    `pyscan` enforces docs/05 rule 6 itself, so it is selectable. `naabu` resolves
    inside its own process, where no adapter can filter the address, so it must stay
    skipped at selection time with a clear reason instead of running unchecked.
    `--mock` connects to nothing, so fixture runs keep it selectable.
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
    assert [spec.name for spec, _ in selected] == ["pyscan"]
    assert [(spec.name, reason) for spec, reason in skipped] == [
        (
            "naabu",
            "blocked: resolves inside the binary, so in_scope_cidrs cannot be enforced (11c-G-7)",
        )
    ]

    selected, skipped = await engine._select(
        Stage.PORTS, ScanOptions(active=True, mock=True, tools=["pyscan", "naabu"])
    )
    assert {spec.name for spec, _ in selected} == {"pyscan", "naabu"}
    assert skipped == []


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
        ScanOptions(stages=(Stage.LIVE, Stage.PORTS), active=True, speed="slow"),
    )
    assert len(seen) == 1
    predicate = seen[0]
    assert predicate is not None, "the active ports stage must get a CIDR predicate"
    assert predicate("203.0.113.5") is True
    assert predicate("198.51.100.5") is False


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


async def test_phase_timeout_records_a_timeout_row(tmp_path: Path) -> None:
    rec = Recorder()
    specs = {"slow": tool("slow", Stage.SUBS)}
    adapters = {"slow": adapter("slow", Stage.SUBS, rec, wait=True)}
    engine = make_engine(tmp_path, specs, adapters)
    summary = await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS,), mock=True, speed="slow", phase_timeout=0.02),
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


async def test_slow_mode_runs_one_tool_at_a_time(tmp_path: Path) -> None:
    rec = Recorder()
    active = 0
    peak = 0

    specs = {"a": tool("a", Stage.SUBS), "b": tool("b", Stage.SUBS)}

    class Tracked(BaseToolAdapter):
        stage = Stage.SUBS

        async def run(self, ctx: RunContext) -> ToolResult:
            nonlocal active, peak
            rec.names.append("tracked")
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0)
            active -= 1
            return ToolResult(tool="tracked", status=ToolStatus.OK, records=[])

        def parse_output(self, raw: str) -> list[object]:
            return []

    engine = make_engine(tmp_path, specs, {"a": Tracked, "b": Tracked})
    await engine.run(
        "example.com",
        ScanOptions(stages=(Stage.SUBS,), mock=True, speed="slow"),
    )
    assert peak == 1


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
        "example.com", ScanOptions(stages=(Stage.SUBS, Stage.DNS), mock=True, speed="slow")
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
    await first_engine.run("example.com", ScanOptions(stages=(Stage.DNS,), mock=True, speed="slow"))
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
    summary = await second_engine.run(
        "example.com", ScanOptions(stages=(Stage.DNS,), mock=True, speed="slow")
    )
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
        summary = await engine.run(
            "example.com", ScanOptions(stages=(Stage.DNS,), mock=True, speed="slow")
        )
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
            ScanOptions(stages=(Stage.SUBS, Stage.DNS, Stage.LIVE), mock=True, speed="slow"),
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
            speed="slow",
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
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.DNS,), speed="fast"))
    assert len(probes) == 3
    assert all(probe.endswith(".example.com") and probe != "example.com" for probe in probes)
    assert summary.warnings == []
    assert stored_wildcard(engine) == {"www.example.com": 1, "own.example.com": 0}


async def test_wildcard_none_marks_nothing(tmp_path: Path) -> None:
    engine, probes = wildcard_setup(tmp_path, DnsResult(DnsOutcome.NXDOMAIN))
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.DNS,), speed="fast"))
    assert len(probes) == 3
    assert summary.warnings == []
    assert stored_wildcard(engine) == {"www.example.com": 0, "own.example.com": 0}


async def test_wildcard_unknown_warns_and_marks_nothing(tmp_path: Path) -> None:
    engine, probes = wildcard_setup(tmp_path, DnsResult(DnsOutcome.TIMEOUT))
    summary = await engine.run("example.com", ScanOptions(stages=(Stage.DNS,), speed="fast"))
    assert len(probes) == 3
    assert any("wildcard check inconclusive" in warning for warning in summary.warnings), (
        summary.warnings
    )
    assert stored_wildcard(engine) == {"www.example.com": 0, "own.example.com": 0}


async def test_wildcard_mark_reaches_the_subdomains_table(tmp_path: Path) -> None:
    engine, _probes = wildcard_setup(tmp_path, DnsResult(DnsOutcome.RESOLVED, ips=["1.2.3.4"]))
    await engine.run("example.com", ScanOptions(stages=(Stage.DNS,), speed="fast"))
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
    await engine.run("example.com", ScanOptions(stages=(Stage.DNS,), mock=True, speed="fast"))
    assert probes == []
    assert stored_wildcard(engine) == {"www.example.com": 0, "own.example.com": 0}
