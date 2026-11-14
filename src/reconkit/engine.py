"""Stage orchestration, confidence, host states and resume (docs/03, docs/09).

The engine selects adapters from `tools.yaml`, applies tier/mode/scope gates,
runs stages in the documented order, merges results by host, computes confidence
from distinct tools, applies the unconditional host-state rule, and records one
`tool_runs` row per tool. All consensus logic lives here; there is no
`core/consensus.py`.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import IntEnum, StrEnum
from functools import partial
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from dotenv import dotenv_values

from reconkit.adapters import ADAPTERS
from reconkit.adapters.base import BaseToolAdapter
from reconkit.adapters.registry import ToolSpec, load_tools
from reconkit.config import AppConfig, SpeedName, resolve_speed
from reconkit.core.pacing import Clock, Pacer, RateLimiter
from reconkit.core.runner import validate_host, validate_target
from reconkit.core.scope import load_scope, require_active
from reconkit.core.store import Store, redact, utc_now
from reconkit.core.wildcard import WildcardDetector, WildcardResult, WildcardStatus
from reconkit.core.workspace import Workspace
from reconkit.errors import ConfigError, ScopeError
from reconkit.models import (
    Confidence,
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
Now = Callable[[], str]


class ExitCode(IntEnum):
    """docs/02 exit codes. The CLI maps this; the engine never calls sys.exit."""

    SUCCESS = 0
    ERROR = 1
    USAGE = 2
    SCOPE = 3
    NO_TOOL = 4
    PARTIAL = 5
    ALL_FAILED = 6
    INTERRUPTED = 130


class DnsSignal(StrEnum):
    """Per-host DNS evidence; only NXDOMAIN may produce DEAD."""

    ABSENT = "absent"
    RESOLVED = "resolved"
    NXDOMAIN = "nxdomain"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True)
class HostEvidence:
    """All evidence for one host in one live/DNS pass."""

    web: tuple[tuple[str, HostState], ...] = ()
    dns: DnsSignal = DnsSignal.ABSENT
    dns_tools: tuple[str, ...] = ()
    dns_disagree: bool = False
    web_ok: bool = True
    dns_ok: bool = True
    cnames: tuple[str, ...] = ()


@dataclass(frozen=True)
class HostTransition:
    """The state rule's result; `persist` is false when nothing was observed."""

    state: HostState
    confidence: Confidence | None
    sources: tuple[str, ...]
    warnings: tuple[str, ...]
    persist: bool
    dangling_cname: str | None = None


def confidence_for(
    sources: Iterable[str],
    *,
    high_min: int,
    medium_min: int,
    disagree: bool = False,
) -> Confidence:
    """Confidence from DISTINCT tools, never from repeated results of one tool."""
    if disagree:
        return Confidence.UNCONFIRMED
    count = len(set(sources))
    if count >= high_min:
        return Confidence.HIGH
    if count >= medium_min:
        return Confidence.MEDIUM
    return Confidence.LOW


# Transition table (previous state x evidence). Only NXDOMAIN can yield DEAD.
# previous            ALIVE   DNS_ONLY   NXDOMAIN   timeout/SERVFAIL   no evidence
# None/UNKNOWN        ALIVE   DNS_ONLY   DEAD       UNKNOWN (warn)     UNKNOWN
# ALIVE               ALIVE   DNS_ONLY   SHUT_DOWN  ALIVE kept         ALIVE kept
# DNS_ONLY            ALIVE   DNS_ONLY   SHUT_DOWN  DNS_ONLY kept      DNS_ONLY kept
# SHUT_DOWN           ALIVE   DNS_ONLY   DEAD       SHUT_DOWN kept     SHUT_DOWN kept
# DEAD                ALIVE   DNS_ONLY   DEAD       DEAD kept          DEAD kept
def decide_host_state(
    previous: HostState | None,
    evidence: HostEvidence,
    *,
    target: str,
    high_min: int,
    medium_min: int,
) -> HostTransition:
    """Apply docs/09's state rule. Agreeing tools affect confidence, not state."""
    alive_tools = tuple(tool for tool, state in evidence.web if state is HostState.ALIVE)
    if alive_tools:
        sources = alive_tools
        disagree = evidence.dns is DnsSignal.NXDOMAIN or any(
            state is not HostState.ALIVE for _, state in evidence.web
        )
        return HostTransition(
            HostState.ALIVE,
            confidence_for(sources, high_min=high_min, medium_min=medium_min, disagree=disagree),
            sources,
            (),
            True,
        )

    if evidence.dns is DnsSignal.NXDOMAIN:
        state = (
            HostState.SHUT_DOWN
            if previous in (HostState.ALIVE, HostState.DNS_ONLY)
            else HostState.DEAD
        )
        sources = evidence.dns_tools or tuple(tool for tool, _ in evidence.web)
        warnings: list[str] = []
        dangling: str | None = None
        if state is HostState.SHUT_DOWN:
            outside = sorted(
                {
                    cname
                    for cname in evidence.cnames
                    if cname != target and not cname.endswith(f".{target}")
                }
            )
            if outside:
                dangling = outside[0]
                warnings.append(f"possible dangling CNAME: {dangling} (outside {target})")
        return HostTransition(
            state,
            confidence_for(
                sources,
                high_min=high_min,
                medium_min=medium_min,
                disagree=evidence.dns_disagree,
            ),
            sources,
            tuple(warnings),
            True,
            dangling_cname=dangling,
        )

    if evidence.dns is DnsSignal.RESOLVED:
        sources = (*evidence.dns_tools, *(tool for tool, _ in evidence.web))
        disagree = evidence.dns_disagree or any(
            state is HostState.DEAD for _, state in evidence.web
        )
        return HostTransition(
            HostState.DNS_ONLY,
            confidence_for(sources, high_min=high_min, medium_min=medium_min, disagree=disagree),
            sources,
            (),
            True,
        )

    if evidence.dns is DnsSignal.UNCERTAIN or not evidence.web_ok or not evidence.dns_ok:
        state = previous or HostState.UNKNOWN
        warning = (
            "DNS/probe inconclusive; kept previous state"
            if previous is not None
            else "DNS/probe inconclusive; state UNKNOWN"
        )
        sources = tuple(tool for tool, _ in evidence.web)
        return HostTransition(
            state,
            None if previous is not None else Confidence.LOW,
            sources,
            (warning,),
            previous is not None,
        )

    if evidence.web:
        state = previous or HostState.UNKNOWN
        sources = tuple(tool for tool, _ in evidence.web)
        warning = (
            "no conclusive web response; kept previous state"
            if previous is not None
            else "no conclusive web response; state UNKNOWN"
        )
        return HostTransition(
            state,
            None if previous is not None else Confidence.LOW,
            sources,
            (warning,),
            previous is not None,
        )

    return HostTransition(previous or HostState.UNKNOWN, None, (), (), False)


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
    min_sources: int = 1
    resume: bool = False


@dataclass
class StageOutcome:
    stage: Stage
    run_id: int
    results: list[ToolResult] = field(default_factory=list)
    dropped_hosts: list[str] = field(default_factory=list)
    resumed: bool = False


@dataclass
class ScanSummary:
    target: str
    target_id: int
    stages: list[StageOutcome] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    exit_code: ExitCode = ExitCode.SUCCESS
    resumed: bool = False
    scope_denied: bool = False

    @property
    def results(self) -> list[ToolResult]:
        return [result for stage in self.stages for result in stage.results]


@dataclass(frozen=True)
class HostSnapshot:
    """One stored host row, already decided by the engine (UI input)."""

    fqdn: str
    state: HostState
    confidence: Confidence
    sources: tuple[str, ...]
    status_code: int | None
    ports: tuple[int, ...]


@dataclass(frozen=True)
class DiffSnapshot:
    """Latest two same-kind runs; empty tuples mean nothing to compare."""

    target: str
    previous_run_id: int | None
    latest_run_id: int | None
    new: tuple[str, ...]
    gone: tuple[str, ...]
    state_changes: tuple[tuple[str, str, str], ...]
    ports_opened: tuple[tuple[str, int], ...]
    ports_closed: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class RunSnapshot:
    """Recent stage run for the status command."""

    id: int
    target: str
    stage: str
    speed: str
    status: str
    started_at: str
    finished_at: str | None


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
        now: Now | None = None,
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
        self._now = now if now is not None else utc_now
        self._secrets = tuple(value for value in self.env.values() if value)
        self._warnings: list[str] = []

    @classmethod
    def open(
        cls,
        config: AppConfig,
        *,
        db_path: Path | str | None = None,
        scope_path: Path | str | None = None,
        env_file: Path | str | None = None,
        **kwargs: Any,
    ) -> Engine:
        """Build the CLI-facing engine: open the store and load optional .env values."""
        env = kwargs.pop("env", None)
        if env is None:
            values = dotenv_values(env_file)
            env = {key: value for key, value in values.items() if value is not None}
        store = Store(db_path if db_path is not None else config.db_path)
        try:
            return cls(config, store, scope_path=scope_path, env=env, **kwargs)
        except BaseException:
            store.close()
            raise

    def close(self) -> None:
        """Close the store owned by this engine."""
        self.store.close()

    def host_rows(self, target_id: int) -> list[HostSnapshot]:
        """Read stored host rows for the UI without exposing Store to the CLI."""
        rows: list[HostSnapshot] = []
        for row in self.store.host_rows(target_id):
            raw_sources = cast(tuple[str, ...], row["sources"])
            raw_ports = cast(tuple[int, ...], row["ports"])
            raw_status = row["status_code"]
            rows.append(
                HostSnapshot(
                    fqdn=str(row["fqdn"]),
                    state=HostState(str(row["state"])),
                    confidence=Confidence(str(row["confidence"])),
                    sources=tuple(str(value) for value in raw_sources),
                    status_code=raw_status if isinstance(raw_status, int) else None,
                    ports=tuple(int(value) for value in raw_ports),
                )
            )
        return rows

    def recent_runs(self, limit: int = 20) -> list[RunSnapshot]:
        """Read recent stage runs for the status command."""
        return [
            RunSnapshot(
                id=cast(int, row["id"]),
                target=str(row["target"]),
                stage=str(row["stage"]),
                speed=str(row["speed"]),
                status=str(row["status"]),
                started_at=str(row["started_at"]),
                finished_at=None if row["finished_at"] is None else str(row["finished_at"]),
            )
            for row in self.store.recent_scan_runs(limit)
        ]

    def diff(self, target: str) -> DiffSnapshot:
        """Compare the latest two discovery runs and available status/port runs."""
        normalized = validate_target(target)
        target_id = self.store.get_target(normalized)
        if target_id is None:
            return DiffSnapshot(normalized, None, None, (), (), (), (), ())
        discovery = self.store.completed_run_ids(target_id, Stage.SUBS.value)
        latest = discovery[0] if discovery else None
        previous = discovery[1] if len(discovery) > 1 else None
        if latest is None or previous is None:
            return DiffSnapshot(normalized, previous, latest, (), (), (), (), ())
        live = self.store.completed_run_ids(target_id, Stage.LIVE.value)
        ports = self.store.completed_run_ids(target_id, Stage.PORTS.value)
        return DiffSnapshot(
            normalized,
            previous,
            latest,
            tuple(self.store.diff_new(latest)),
            tuple(self.store.diff_gone(previous, latest)),
            tuple(self.store.diff_state_changed(live[1], live[0])) if len(live) > 1 else (),
            tuple(self.store.diff_ports_opened(ports[1], ports[0])) if len(ports) > 1 else (),
            tuple(self.store.diff_ports_closed(ports[1], ports[0])) if len(ports) > 1 else (),
        )

    async def run(self, target: str, options: ScanOptions | None = None) -> ScanSummary:
        opts = options or ScanOptions()
        target = validate_target(target)
        if opts.speed not in ("slow", "normal", "fast"):
            raise ConfigError(f"invalid speed {opts.speed!r}; expected slow, normal or fast")
        if opts.phase_timeout is not None and opts.phase_timeout <= 0:
            raise ConfigError("phase timeout must be > 0")
        if opts.min_sources < 1:
            raise ConfigError("min_sources must be >= 1")

        preset = resolve_speed(self.config, opts.speed)
        rate_flags = {
            name: spec.rate_flag for name, spec in self.specs.items() if spec.rate_flag is not None
        }
        pacer = Pacer(preset, rate_flags=rate_flags, rng=self._rng, sleep=self._sleep)
        workspace = Workspace.create(self.workspace_root, target, secrets=self._secrets)
        target_id = self.store.create_target(target, created_at=self._now())
        self._warnings = []

        scan_key, completed, resumed = self._resume_plan(target_id, opts)
        summary = ScanSummary(target=target, target_id=target_id, resumed=resumed)
        discovered: set[str] = set()
        alive: set[str] = set()
        if resumed:
            self._seed_from_store(target_id, target, discovered, alive)

        dns_results: list[ToolResult] = []
        selected_total = 0
        failed_total = 0
        for stage in STAGE_ORDER:
            if stage not in opts.stages:
                continue
            if stage in completed:
                summary.stages.append(StageOutcome(stage, completed[stage], resumed=True))
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
                    summary.scope_denied = True
                    selected, skipped = self._skip_active(selected, skipped, scope_error)

            run_id = self.store.create_scan_run(
                target_id,
                stage.value,
                opts.speed,
                params=json.dumps(
                    {
                        "scan_key": scan_key,
                        "tools": [spec.name for spec, _ in selected],
                        "mock": opts.mock,
                        "active": opts.active,
                        "no_keys": opts.no_keys,
                        "min_sources": opts.min_sources,
                    }
                ),
                started_at=self._now(),
                secrets=self._secrets,
            )
            for spec, reason in skipped:
                self._record(run_id, spec.name, ToolStatus.SKIPPED, error=reason)

            timeout = opts.phase_timeout or self._stage_timeout(stage)
            results: list[ToolResult] = []
            done: set[str] = set()
            ctx: RunContext | None = None
            try:
                ctx = await asyncio.wait_for(
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
            except asyncio.CancelledError:
                self.store.finish_scan_run(run_id, "interrupted", finished_at=self._now())
                raise

            wildcard: WildcardResult | None = None
            if stage is Stage.DNS and ctx is not None and selected and not opts.mock:
                wildcard = await self._detect_wildcard(target, ctx)

            try:
                with self.store.transaction():
                    self._persist_stage(
                        target_id,
                        run_id,
                        stage,
                        results,
                        opts,
                        dns_results,
                        target,
                        hosts,
                        discovered,
                        alive,
                        wildcard=wildcard,
                    )
            except Exception:
                self.store.finish_scan_run(run_id, "failed", finished_at=self._now())
                raise

            selected_total += len(selected)
            failed_total += sum(1 for result in results if result.status is not ToolStatus.OK)
            failed_total += len(selected) - len(results)
            all_ok = len(results) == len(selected) and all(
                result.status is ToolStatus.OK for result in results
            )
            self.store.finish_scan_run(
                run_id, "completed" if all_ok else "partial", finished_at=self._now()
            )

            if stage is Stage.DNS:
                dns_results = list(results)
            self._update_discovered(stage, results, target, discovered, alive)
            summary.stages.append(
                StageOutcome(stage=stage, run_id=run_id, results=results, dropped_hosts=dropped)
            )

        summary.exit_code = self._exit_code(
            summary, selected_total=selected_total, failed_total=failed_total
        )
        summary.warnings = list(self._warnings)
        return summary

    def _exit_code(
        self, summary: ScanSummary, *, selected_total: int, failed_total: int
    ) -> ExitCode:
        if summary.scope_denied:
            return ExitCode.SCOPE
        new_stages = any(not stage.resumed for stage in summary.stages)
        if selected_total == 0:
            return ExitCode.NO_TOOL if new_stages else ExitCode.SUCCESS
        if failed_total == selected_total:
            return ExitCode.NO_TOOL
        if failed_total:
            return ExitCode.PARTIAL
        return ExitCode.SUCCESS

    def _resume_plan(self, target_id: int, opts: ScanOptions) -> tuple[str, dict[Stage, int], bool]:
        """Find the latest scan_key and the stages it already completed."""
        rows = self.store.scan_runs(target_id)
        if not opts.resume:
            return secrets.token_hex(8), {}, False
        key: str | None = None
        for row in reversed(rows):
            candidate = self._scan_key(row.get("params_json"))
            if candidate is not None:
                key = candidate
                break
        if key is None:
            return secrets.token_hex(8), {}, False
        completed: dict[Stage, int] = {}
        for row in rows:
            if self._scan_key(row.get("params_json")) != key:
                continue
            try:
                stage = Stage(str(row.get("stage")))
            except ValueError:
                continue
            status = str(row.get("status"))
            if status in ("completed", "partial"):
                completed[stage] = int(str(row.get("id")))
            elif status == "running":
                self.store.finish_scan_run(
                    int(str(row.get("id"))), "interrupted", finished_at=self._now()
                )
        return key, completed, True

    @staticmethod
    def _scan_key(params_json: object) -> str | None:
        try:
            data = json.loads(str(params_json))
        except (TypeError, ValueError):
            return None
        if isinstance(data, dict):
            key = data.get("scan_key")
            if isinstance(key, str):
                return key
        return None

    def _seed_from_store(
        self, target_id: int, target: str, discovered: set[str], alive: set[str]
    ) -> None:
        for row in self.store.subdomains(target_id):
            host = str(row.get("fqdn") or "")
            if host not in discovered:
                discovered.add(host)
            if str(row.get("state")) == HostState.ALIVE.value:
                alive.add(host)
        discovered.discard(target)

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

    async def _detect_wildcard(self, target: str, ctx: RunContext) -> WildcardResult | None:
        """Probe random labels with the dns stage's resolver context (docs/03 section 8)."""
        if not self.config.wildcard_check.enabled:
            return None
        adapter = self.adapters.get("dnspython")
        if adapter is None:
            return None
        resolver = cast(Any, adapter())
        detector = WildcardDetector(
            probe=partial(resolver.resolve_host, ctx),
            rng=self._rng,
            probes=self.config.wildcard_check.probes,
        )
        return await detector.detect(target)

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
    ) -> RunContext:
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
            return ctx
        await asyncio.gather(*(one(spec, adapter) for spec, adapter in selected))
        return ctx

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

    def _update_discovered(
        self,
        stage: Stage,
        results: list[ToolResult],
        target: str,
        discovered: set[str],
        alive: set[str],
    ) -> None:
        for result in results:
            if result.status is not ToolStatus.OK:
                continue
            for record in result.records:
                host = self._record_host(record)
                if host is None:
                    continue
                for cleaned in self._clean_hosts([host], target):
                    discovered.add(cleaned)
                    if (
                        stage is Stage.LIVE
                        and isinstance(record, HostStatusRecord)
                        and record.state is HostState.ALIVE
                    ):
                        alive.add(cleaned)

    def _record_host(self, record: Record) -> str | None:
        if isinstance(record, (SubdomainRecord, HostStatusRecord, PortRecord, FindingRecord)):
            return record.fqdn
        if isinstance(record, UrlRecord):
            return urlsplit(record.url).hostname
        return None

    def _persist_stage(
        self,
        target_id: int,
        run_id: int,
        stage: Stage,
        results: list[ToolResult],
        opts: ScanOptions,
        dns_results: list[ToolResult],
        target: str,
        hosts: list[str],
        discovered: set[str],
        alive: set[str],
        *,
        wildcard: WildcardResult | None = None,
    ) -> None:
        if stage is Stage.SUBS:
            self._persist_discovery(target_id, run_id, results, opts)
        elif stage is Stage.DNS:
            self._persist_dns(
                target_id,
                run_id,
                results,
                target,
                defer=Stage.LIVE in opts.stages,
                wildcard=wildcard,
            )
        elif stage is Stage.LIVE:
            self._persist_live(target_id, run_id, results, dns_results, target, hosts, opts, alive)
        elif stage is Stage.PORTS:
            self._persist_ports(target_id, run_id, results, opts)
        elif stage is Stage.URLS:
            self._persist_urls(target_id, run_id, results, opts)

    def _persist_discovery(
        self, target_id: int, run_id: int, results: list[ToolResult], opts: ScanOptions
    ) -> None:
        groups: dict[str, tuple[set[str], list[SubdomainRecord]]] = {}
        for result in results:
            if result.status is not ToolStatus.OK:
                continue
            for record in result.records:
                if not isinstance(record, SubdomainRecord):
                    continue
                tools, records = groups.setdefault(record.fqdn, (set(), []))
                tools.add(result.tool)
                records.append(record)
        for fqdn, (tools, _records) in groups.items():
            if len(tools) < opts.min_sources:
                continue
            confidence = confidence_for(
                tools,
                high_min=self.config.confidence.high_min_sources,
                medium_min=self.config.confidence.medium_min_sources,
            )
            sub_id = self.store.upsert_subdomain(
                target_id,
                fqdn,
                run_id=run_id,
                confidence=confidence.value,
                source_count=len(tools),
            )
            for tool in sorted(tools):
                self.store.add_subdomain_source(sub_id, run_id, tool)

    def _persist_urls(
        self, target_id: int, run_id: int, results: list[ToolResult], opts: ScanOptions
    ) -> None:
        groups: dict[str, set[str]] = {}
        for result in results:
            if result.status is not ToolStatus.OK:
                continue
            for record in result.records:
                if isinstance(record, UrlRecord):
                    groups.setdefault(record.url, set()).add(result.tool)
        for url, tools in groups.items():
            if len(tools) < opts.min_sources:
                continue
            self.store.upsert_url(target_id, url, run_id=run_id, source_count=len(tools))

    def _dns_facts(
        self, results: list[ToolResult], target: str
    ) -> tuple[
        dict[str, DnsSignal],
        dict[str, set[str]],
        dict[str, set[str]],
        dict[str, set[str]],
        set[str],
    ]:
        signals: dict[str, DnsSignal] = {}
        tools: dict[str, set[str]] = {}
        cnames: dict[str, set[str]] = {}
        ips: dict[str, set[str]] = {}
        disagree: set[str] = set()
        for result in results:
            if result.status is not ToolStatus.OK:
                continue
            for record in result.records:
                host = self._record_host(record)
                if host is None:
                    continue
                for cleaned in self._clean_hosts([host], target):
                    tools.setdefault(cleaned, set()).add(result.tool)
                    if isinstance(record, SubdomainRecord):
                        if signals.get(cleaned) is DnsSignal.NXDOMAIN:
                            disagree.add(cleaned)
                        signals[cleaned] = DnsSignal.RESOLVED
                        cnames.setdefault(cleaned, set()).update(record.cnames)
                        ips.setdefault(cleaned, set()).update(record.ips)
                    elif isinstance(record, HostStatusRecord) and record.state is HostState.DEAD:
                        if signals.get(cleaned) is DnsSignal.RESOLVED:
                            disagree.add(cleaned)
                        elif cleaned not in signals:
                            signals[cleaned] = DnsSignal.NXDOMAIN
        return signals, tools, cnames, ips, disagree

    def _persist_dns(
        self,
        target_id: int,
        run_id: int,
        results: list[ToolResult],
        target: str,
        *,
        defer: bool,
        wildcard: WildcardResult | None = None,
    ) -> None:
        signals, tools, cnames, ips, disagree = self._dns_facts(results, target)
        if wildcard is not None and wildcard.status is WildcardStatus.UNKNOWN:
            warning = f"wildcard check inconclusive for {target}; nothing marked wildcard"
            if warning not in self._warnings:
                self._warnings.append(warning)
        for host, signal in signals.items():
            if signal is DnsSignal.RESOLVED:
                # NONE and UNKNOWN never mark (PIT-21); UNKNOWN is warned above.
                marked = (
                    wildcard.matches(ips=ips.get(host, ()), cnames=cnames.get(host, ()))
                    if wildcard is not None and wildcard.status is WildcardStatus.PRESENT
                    else None
                )
                self.store.upsert_subdomain(target_id, host, run_id=run_id, is_wildcard=marked)
        if defer:
            return
        for host, signal in signals.items():
            previous, previous_cnames = self._previous_facts(target_id, host, run_id)
            current_cnames = tuple(sorted(cnames.get(host, set())))
            evidence_cnames = (
                current_cnames
                if current_cnames or signal is not DnsSignal.NXDOMAIN
                else previous_cnames
            )
            transition = decide_host_state(
                previous,
                HostEvidence(
                    dns=signal,
                    dns_tools=tuple(sorted(tools.get(host, set()))),
                    dns_disagree=host in disagree,
                    cnames=evidence_cnames,
                ),
                target=target,
                high_min=self.config.confidence.high_min_sources,
                medium_min=self.config.confidence.medium_min_sources,
            )
            if not transition.persist:
                continue
            self._write_host(
                target_id,
                run_id,
                host,
                transition,
                None,
                tuple(ips.get(host, ())),
                evidence_cnames,
            )
            for warning in transition.warnings:
                if warning not in self._warnings:
                    self._warnings.append(warning)

    def _persist_live(
        self,
        target_id: int,
        run_id: int,
        results: list[ToolResult],
        dns_results: list[ToolResult],
        target: str,
        hosts: list[str],
        opts: ScanOptions,
        alive: set[str],
    ) -> None:
        web: dict[str, list[tuple[str, HostStatusRecord]]] = {}
        for result in results:
            if result.status is not ToolStatus.OK:
                continue
            for record in result.records:
                if isinstance(record, HostStatusRecord):
                    web.setdefault(record.fqdn, []).append((result.tool, record))
        dns_signals, dns_tools, dns_cnames, dns_ips, dns_disagree = self._dns_facts(
            dns_results, target
        )
        dns_ran = bool(dns_results)
        dns_ok = any(result.status is ToolStatus.OK for result in dns_results) if dns_ran else True
        live_ok = any(result.status is ToolStatus.OK for result in results)
        for host in hosts:
            records = web.get(host, [])
            signal = dns_signals.get(host)
            if signal is None:
                signal = DnsSignal.UNCERTAIN if dns_ran else DnsSignal.ABSENT
            evidence = HostEvidence(
                web=tuple((tool, record.state) for tool, record in records),
                dns=signal,
                dns_tools=tuple(sorted(dns_tools.get(host, set()))),
                dns_disagree=host in dns_disagree,
                web_ok=live_ok,
                dns_ok=dns_ok,
                cnames=tuple(sorted(dns_cnames.get(host, set()))),
            )
            previous, previous_cnames = self._previous_facts(target_id, host, run_id)
            current_cnames = tuple(sorted(dns_cnames.get(host, set())))
            if signal is DnsSignal.NXDOMAIN and not current_cnames:
                evidence = replace(evidence, cnames=previous_cnames)
            transition = decide_host_state(
                previous,
                evidence,
                target=target,
                high_min=self.config.confidence.high_min_sources,
                medium_min=self.config.confidence.medium_min_sources,
            )
            if not transition.persist:
                continue
            best = next(
                (record for _, record in records if record.state is HostState.ALIVE),
                records[0][1] if records else None,
            )
            ips = tuple(sorted(dns_ips.get(host, set())))
            self._write_host(
                target_id,
                run_id,
                host,
                transition,
                best,
                ips,
                tuple(evidence.cnames),
            )
            if transition.state is HostState.ALIVE:
                alive.add(host)
            for warning in transition.warnings:
                if warning not in self._warnings:
                    self._warnings.append(warning)

    def _previous_facts(
        self, target_id: int, host: str, run_id: int
    ) -> tuple[HostState | None, tuple[str, ...]]:
        sub_id = self.store.upsert_subdomain(target_id, host, run_id=run_id)
        raw = self.store.previous_state(sub_id)
        previous = HostState(raw) if raw is not None else None
        return previous, self.store.latest_cnames(sub_id)

    def _write_host(
        self,
        target_id: int,
        run_id: int,
        host: str,
        transition: HostTransition,
        best: HostStatusRecord | None,
        ips: tuple[str, ...],
        cnames: tuple[str, ...],
    ) -> None:
        # `source_count` is defined by the rows in `subdomain_sources` (docs/04 section 5),
        # which only the discovery pass writes, so a dns/live pass must not supply it.
        # A state pass may still assert disagreement, and nothing is lost here because
        # the pass-local tools are already stored in `host_status_history.tools_json`.
        confidence = (
            Confidence.UNCONFIRMED.value
            if transition.confidence is Confidence.UNCONFIRMED
            else None
        )
        sub_id = self.store.upsert_subdomain(
            target_id,
            host,
            run_id=run_id,
            state=transition.state.value,
            confidence=confidence,
        )
        self.store.append_host_status(
            sub_id,
            run_id,
            transition.state.value,
            status_code=None if best is None else best.status_code,
            title=None if best is None else best.title,
            location=None if best is None else best.location,
            cnames=cnames,
            dangling_cname=transition.dangling_cname,
            ips=ips,
            tech=() if best is None else best.tech,
            waf=None if best is None else best.waf,
            tools=transition.sources,
            checked_at=self._now(),
        )

    def _persist_ports(
        self, target_id: int, run_id: int, results: list[ToolResult], opts: ScanOptions
    ) -> None:
        groups: dict[tuple[str, str, int], dict[str, list[str]]] = {}
        for result in results:
            if result.status is not ToolStatus.OK:
                continue
            for record in result.records:
                if not isinstance(record, PortRecord):
                    continue
                key = (record.fqdn, record.ip, record.port)
                groups.setdefault(key, {}).setdefault(result.tool, []).append(record.state)
        for (fqdn, ip, port), by_tool in groups.items():
            tools = set(by_tool)
            if len(tools) < opts.min_sources:
                continue
            seen = {state for states in by_tool.values() for state in states}
            state = "unconfirmed" if {"open", "closed"} <= seen else next(iter(seen))
            confidence = confidence_for(
                tools,
                high_min=self.config.confidence.high_min_sources,
                medium_min=self.config.confidence.medium_min_sources,
                disagree=state == "unconfirmed",
            )
            sub_id = self.store.upsert_subdomain(target_id, fqdn, run_id=run_id)
            port_id = self.store.upsert_port(
                sub_id,
                ip,
                port,
                run_id=run_id,
                state=state,
                confidence=confidence.value,
            )
            for tool, states in by_tool.items():
                self.store.add_port_source(port_id, run_id, tool, states[0])
