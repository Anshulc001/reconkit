"""Part 6a: engine pipeline, selection, gating, env, timeout and redaction."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path

import pytest

from reconkit.adapters.base import BaseToolAdapter
from reconkit.adapters.registry import ToolKey, ToolSpec
from reconkit.config import load_config
from reconkit.core.store import REDACTED, Store
from reconkit.engine import STAGE_ORDER, Engine, ScanOptions
from reconkit.errors import ConfigError
from reconkit.models import (
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


def make_engine(
    tmp_path: Path,
    specs: Mapping[str, ToolSpec],
    adapters: Mapping[str, type[BaseToolAdapter]],
    *,
    env: dict[str, str] | None = None,
) -> Engine:
    config = load_config(CONFIG, speed="fast")
    tmp_path.mkdir(parents=True, exist_ok=True)
    store = Store(tmp_path / "recon.db")
    scope = tmp_path / "scope.yaml"
    scope.write_text(SCOPE, encoding="utf-8")
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
