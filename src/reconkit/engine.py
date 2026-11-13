"""Stage orchestration, gating and the mock pipeline (docs/09 section 4).

The engine selects adapters from `tools.yaml`, applies tier/mode/scope gates,
builds a per-tool `RunContext`, runs stages in the documented order and records
one `tool_runs` row per tool. Consensus and host-state transitions are added in
Part 6b; this module keeps the pipeline and the safety gates.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from reconkit.adapters import ADAPTERS
from reconkit.adapters.base import BaseToolAdapter
from reconkit.adapters.registry import ToolSpec, load_tools
from reconkit.config import AppConfig, SpeedName, resolve_speed
from reconkit.core.pacing import Clock, Pacer, RateLimiter
from reconkit.core.runner import validate_host, validate_target
from reconkit.core.scope import load_scope, require_active
from reconkit.core.store import Store, redact
from reconkit.core.workspace import Workspace
from reconkit.errors import ConfigError, ScopeError
from reconkit.models import (
    FindingRecord,
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

STAGE_ORDER: tuple[Stage, ...] = (
    Stage.SUBS,
    Stage.DNS,
    Stage.LIVE,
    Stage.PORTS,
    Stage.TECH,
    Stage.URLS,
    Stage.VULNS,
)
SkipReason = str
Selected = list[tuple[ToolSpec, type[BaseToolAdapter]]]
Skipped = list[tuple[ToolSpec, SkipReason]]
Sleep = Callable[[float], Awaitable[None]]
InstalledCheck = Callable[[type[BaseToolAdapter]], bool]


@dataclass(frozen=True)
class ScanOptions:
    """The CLI's per-run switches, already parsed."""

    stages: tuple[Stage, ...] = STAGE_ORDER
    tools: tuple[str, ...] = ()
    exclude: frozenset[str] = frozenset()
    include_noisy: bool = False
    active: bool = False
    no_keys: bool = False
    mock: bool = False
    speed: SpeedName = "slow"
    phase_timeout: float | None = None


@dataclass
class StageOutcome:
    stage: Stage
    run_id: int
    results: list[ToolResult] = field(default_factory=list)
    dropped_hosts: list[str] = field(default_factory=list)


@dataclass
class ScanSummary:
    target: str
    target_id: int
    stages: list[StageOutcome] = field(default_factory=list)

    @property
    def results(self) -> list[ToolResult]:
        return [result for stage in self.stages for result in stage.results]


class Engine:
    """One target's pipeline. Built by the CLI, reusable across targets."""

    def __init__(
        self,
        config: AppConfig,
        store: Store,
        *,
        specs: Mapping[str, ToolSpec] | None = None,
        adapters: Mapping[str, type[BaseToolAdapter]] | None = None,
        scope_path: Path | str | None = None,
        workspace_root: Path | str | None = None,
        env: Mapping[str, str] | None = None,
        rng: Any = None,
        sleep: Sleep | None = None,
        clock: Clock | None = None,
        installed: InstalledCheck | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.specs = dict(specs) if specs is not None else load_tools()
        self.adapters = dict(adapters) if adapters is not None else dict(ADAPTERS)
        self.scope_path = scope_path
        self.workspace_root = (
            Path(workspace_root) if workspace_root is not None else Path(config.workspace_dir)
        )
        self.env = dict(env or {})
        self._rng = rng if rng is not None else secrets.SystemRandom()
        self._sleep = sleep if sleep is not None else asyncio.sleep
        self._clock = clock
        self._installed = installed
        self._secrets = tuple(value for value in self.env.values() if value)

    async def run(self, target: str, options: ScanOptions | None = None) -> ScanSummary:
        opts = options or ScanOptions()
        target = validate_target(target)
        if opts.speed not in ("slow", "normal", "fast"):
            raise ConfigError(f"invalid speed {opts.speed!r}; expected slow, normal or fast")
        if opts.phase_timeout is not None and opts.phase_timeout <= 0:
            raise ConfigError("phase timeout must be > 0")

        preset = resolve_speed(self.config, opts.speed)
        rate_flags = {
            name: spec.rate_flag for name, spec in self.specs.items() if spec.rate_flag is not None
        }
        pacer = Pacer(preset, rate_flags=rate_flags, rng=self._rng, sleep=self._sleep)
        workspace = Workspace.create(self.workspace_root, target, secrets=self._secrets)
        target_id = self.store.create_target(target)

        summary = ScanSummary(target=target, target_id=target_id)
        discovered: set[str] = set()
        alive: set[str] = set()
        for stage in STAGE_ORDER:
            if stage not in opts.stages:
                continue
            hosts = self._stage_hosts(stage, target, discovered, alive)
            selected, skipped = await self._select(stage, opts)
            if not selected and not skipped:
                continue
            if stage is Stage.PORTS and not hosts:
                continue

            dropped: list[str] = []
            if opts.active and any(spec.mode is Mode.ACTIVE for spec, _ in selected):
                hosts, dropped, scope_error = self._active_hosts(target, hosts, opts.speed)
                if scope_error is not None:
                    selected, skipped = self._skip_active(selected, skipped, scope_error)

            run_id = self.store.create_scan_run(
                target_id,
                stage.value,
                opts.speed,
                params=json.dumps(
                    {
                        "tools": [spec.name for spec, _ in selected],
                        "mock": opts.mock,
                        "active": opts.active,
                        "no_keys": opts.no_keys,
                    }
                ),
                secrets=self._secrets,
            )
            for spec, reason in skipped:
                self._record(run_id, spec.name, ToolStatus.SKIPPED, error=reason)

            timeout = opts.phase_timeout or self._stage_timeout(stage)
            results: list[ToolResult] = []
            done: set[str] = set()
            try:
                await asyncio.wait_for(
                    self._run_tools(
                        run_id,
                        target,
                        stage,
                        selected,
                        hosts,
                        workspace,
                        pacer,
                        opts,
                        results,
                        done,
                    ),
                    timeout=timeout,
                )
            except TimeoutError:
                for spec, _ in selected:
                    if spec.name not in done:
                        self._record(run_id, spec.name, ToolStatus.TIMEOUT, error="phase timeout")
                        done.add(spec.name)

            if results:
                with self.store.transaction():
                    for result in results:
                        if result.status is ToolStatus.OK:
                            self._persist(target_id, run_id, result)
            all_ok = all(result.status is ToolStatus.OK for result in results)
            self.store.finish_scan_run(run_id, "completed" if all_ok else "partial")

            for result in results:
                self._observe(result, discovered, alive, target)
            summary.stages.append(
                StageOutcome(stage=stage, run_id=run_id, results=results, dropped_hosts=dropped)
            )
        return summary

    def _stage_hosts(
        self, stage: Stage, target: str, discovered: set[str], alive: set[str]
    ) -> list[str]:
        if stage is Stage.SUBS:
            return [target]
        if stage in (Stage.DNS, Stage.LIVE):
            return self._clean_hosts([target, *discovered], target)
        return self._clean_hosts(alive, target)

    def _clean_hosts(self, hosts: Any, target: str) -> list[str]:
        kept: list[str] = []
        seen: set[str] = set()
        for raw in hosts:
            try:
                host = validate_host(raw)
            except (TypeError, ValueError):
                continue
            if host != target and not host.endswith(f".{target}"):
                continue
            if host not in seen:
                seen.add(host)
                kept.append(host)
        return kept

    def _active_hosts(
        self, target: str, hosts: list[str], speed: str
    ) -> tuple[list[str], list[str], str | None]:
        try:
            gate = load_scope(self.scope_path)
            allowed = [host for host in hosts if gate.allows(host)]
            dropped = [host for host in hosts if not gate.allows(host)]
            check = require_active(target, allowed, speed, path=self.scope_path)
        except ScopeError as exc:
            return hosts, [], str(exc)
        return check.hosts, dropped, None

    def _skip_active(
        self, selected: Selected, skipped: Skipped, reason: str
    ) -> tuple[Selected, Skipped]:
        kept: Selected = []
        extra: Skipped = []
        for spec, adapter in selected:
            if spec.mode is Mode.ACTIVE:
                extra.append((spec, reason))
            else:
                kept.append((spec, adapter))
        return kept, [*skipped, *extra]

    async def _select(self, stage: Stage, opts: ScanOptions) -> tuple[Selected, Skipped]:
        if opts.tools:
            unknown = [name for name in opts.tools if name not in self.specs]
            if unknown:
                raise ConfigError(f"unknown tool(s): {', '.join(unknown)}")
            intrusive = [name for name in opts.tools if self.specs[name].tier is Tier.INTRUSIVE]
            if intrusive:
                raise ConfigError(f"intrusive tool(s) are not available: {', '.join(intrusive)}")

        selected: Selected = []
        skipped: Skipped = []
        for name, spec in self.specs.items():
            if spec.stage is not stage:
                continue
            if opts.tools and name not in opts.tools:
                continue
            if name in opts.exclude:
                continue
            if spec.tier is Tier.INTRUSIVE:
                continue
            if spec.tier is Tier.OPT_IN and not opts.include_noisy and name not in opts.tools:
                continue
            adapter = self.adapters.get(name)
            if adapter is None:
                skipped.append((spec, f"no adapter yet (phase {spec.phase})"))
                continue
            if spec.mode is Mode.ACTIVE and not opts.active:
                skipped.append((spec, "requires --active"))
                continue
            if not opts.mock and not await asyncio.to_thread(self._is_installed, adapter):
                skipped.append((spec, "not installed"))
                continue
            selected.append((spec, adapter))
        return selected, skipped

    def _is_installed(self, adapter: type[BaseToolAdapter]) -> bool:
        if self._installed is not None:
            return self._installed(adapter)
        return adapter().check_installed().installed

    async def _run_tools(
        self,
        run_id: int,
        target: str,
        stage: Stage,
        selected: Selected,
        hosts: list[str],
        workspace: Workspace,
        pacer: Pacer,
        opts: ScanOptions,
        results: list[ToolResult],
        done: set[str],
    ) -> None:
        mode = (
            Mode.ACTIVE if any(spec.mode is Mode.ACTIVE for spec, _ in selected) else Mode.PASSIVE
        )
        rate = (
            pacer.preset.passive_requests_per_second
            if mode is Mode.PASSIVE
            else pacer.preset.active_requests_per_second
        )
        limiter = RateLimiter(rate, clock=self._clock, sleep=self._sleep)
        ctx = RunContext(
            target=target,
            hosts=hosts,
            ports=[],
            speed=opts.speed,
            pacer=pacer,
            limiter=limiter,
            timeout=self.config.timeouts.per_tool_default,
            workspace=workspace.directory,
            mock=opts.mock,
        )

        semaphore = asyncio.Semaphore(pacer.parallel_limit(mode.value))

        async def one(spec: ToolSpec, adapter: type[BaseToolAdapter]) -> None:
            async with semaphore:
                await pacer.before_tool(mode.value)
                tool_ctx = ctx.model_copy(update={"env": self._tool_env(spec, opts)})
                result = await self._run_one(run_id, adapter, tool_ctx)
            results.append(result)
            done.add(spec.name)

        pacer.reset()
        if opts.speed == "slow":
            for spec, adapter in selected:
                await one(spec, adapter)
            return
        await asyncio.gather(*(one(spec, adapter) for spec, adapter in selected))

    async def _run_one(
        self,
        run_id: int,
        adapter: type[BaseToolAdapter],
        ctx: RunContext,
    ) -> ToolResult:
        started = time.perf_counter()
        try:
            result = await asyncio.wait_for(adapter().run(ctx), timeout=ctx.timeout)
        except TimeoutError:
            result = ToolResult(
                tool=adapter.name,
                status=ToolStatus.TIMEOUT,
                error="timed out",
                duration_s=time.perf_counter() - started,
            )
        except Exception as exc:
            result = ToolResult(
                tool=adapter.name,
                status=ToolStatus.FAILED,
                error=redact(f"{type(exc).__name__}: {exc}", self._secrets),
                duration_s=time.perf_counter() - started,
            )
        self._record(
            run_id,
            adapter.name,
            result.status,
            item_count=len(result.records),
            duration_s=result.duration_s,
            error=result.error,
        )
        return result

    def _record(
        self,
        run_id: int,
        tool: str,
        status: ToolStatus,
        *,
        item_count: int = 0,
        duration_s: float | None = None,
        error: str | None = None,
    ) -> None:
        self.store.record_tool_run(
            run_id,
            tool,
            status.value,
            item_count=item_count,
            duration_s=duration_s,
            error=error,
            secrets=self._secrets,
        )

    def _tool_env(self, spec: ToolSpec, opts: ScanOptions) -> dict[str, str]:
        if opts.no_keys:
            return {}
        return {key.env: self.env[key.env] for key in spec.keys if self.env.get(key.env)}

    def _stage_timeout(self, stage: Stage) -> float:
        value = getattr(self.config.timeouts, stage.value, None)
        return float(value or self.config.timeouts.default_phase)

    def _observe(
        self, result: ToolResult, discovered: set[str], alive: set[str], target: str
    ) -> None:
        if result.status is not ToolStatus.OK:
            return
        for record in result.records:
            host = self._record_host(record)
            if host is None:
                continue
            for cleaned in self._clean_hosts([host], target):
                discovered.add(cleaned)
                if isinstance(record, HostStatusRecord) and record.state is HostState.ALIVE:
                    alive.add(cleaned)

    def _record_host(self, record: Record) -> str | None:
        if isinstance(record, (SubdomainRecord, HostStatusRecord, PortRecord, FindingRecord)):
            return record.fqdn
        if isinstance(record, UrlRecord):
            return urlsplit(record.url).hostname
        return None

    def _persist(self, target_id: int, run_id: int, result: ToolResult) -> None:
        for record in result.records:
            if isinstance(record, SubdomainRecord):
                sub_id = self.store.upsert_subdomain(target_id, record.fqdn, run_id=run_id)
                self.store.add_subdomain_source(sub_id, run_id, result.tool)
            elif isinstance(record, HostStatusRecord):
                sub_id = self.store.upsert_subdomain(
                    target_id, record.fqdn, run_id=run_id, state=record.state.value
                )
                self.store.append_host_status(
                    sub_id,
                    run_id,
                    record.state.value,
                    status_code=record.status_code,
                    title=record.title,
                    location=record.location,
                    ips=record.ips,
                    tech=record.tech,
                    waf=record.waf,
                    tools=[result.tool],
                )
            elif isinstance(record, PortRecord):
                sub_id = self.store.upsert_subdomain(target_id, record.fqdn, run_id=run_id)
                port_id = self.store.upsert_port(
                    sub_id,
                    record.ip,
                    record.port,
                    run_id=run_id,
                    state=record.state,
                    protocol=record.protocol,
                    service=record.service,
                    version=record.version,
                )
                self.store.add_port_source(port_id, run_id, result.tool, "run")
            elif isinstance(record, UrlRecord):
                self.store.upsert_url(target_id, record.url, run_id=run_id, source_count=1)
            elif isinstance(record, FindingRecord):
                # The findings table is deferred (docs/04); the result is kept in memory.
                continue
