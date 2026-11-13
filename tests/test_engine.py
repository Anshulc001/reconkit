"""Part 6a: engine pipeline, selection, gating, env, timeout and redaction."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from reconkit.adapters.base import BaseToolAdapter
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
    def uniform(self, low: float, _high: float) -> float:
        return low

    def shuffle(self, items: list[object]) -> None:
        return None


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
    assert ExitCode.ERROR == 1
    assert ExitCode.USAGE == 2
    assert ExitCode.INTERRUPTED == 130


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
