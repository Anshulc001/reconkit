"""Stage orchestration, confidence, host states and resume (docs/03, docs/09).

The engine selects adapters from `tools.yaml`, applies tier/mode/scope gates,
runs stages in the documented order, merges results by host, computes confidence
from distinct tools, applies the unconditional host-state rule, and records one
`tool_runs` row per tool. All consensus logic lives here; there is no
`core/consensus.py`.
"""

from __future__ import annotations

import asyncio
import ipaddress
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
from reconkit.adapters.base import BaseToolAdapter, running_as_root
from reconkit.adapters.pyscan import default_resolve
from reconkit.adapters.registry import ToolSpec, load_tools
from reconkit.config import AppConfig
from reconkit.core.runner import validate_host, validate_target
from reconkit.core.scope import load_scope, passive_warning, require_active, scope_present
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


@dataclass(frozen=True)
class ModeRules:
    """What one scan mode includes: tool modes plus tiers (docs/02, docs/03).

    `MODE_TOOLS` is the only place the tier/tool-mode rule lives; the CLI, the
    interactive prompt and every doc quote this table instead of restating it.
    """

    tool_modes: frozenset[Mode]
    tiers: frozenset[Tier]


# Scan-mode stages, the first of the two mode tables (docs/02 section 2).
# Every surface that needs "which stages does mode X run" reads this dict.
MODE_STAGES: dict[str, tuple[Stage, ...]] = {
    "passive": (Stage.SUBS, Stage.DNS, Stage.URLS),
    "active": (Stage.SUBS, Stage.DNS, Stage.LIVE, Stage.TECH, Stage.URLS),
    "full": STAGE_ORDER,
}

# Scan-mode tool modes and tiers, the second mode table. `opt_in` is added at
# selection time for `--include-noisy` (and always for full); it is not listed
# for passive/active because it is a flag, not a mode property.
MODE_TOOLS: dict[str, ModeRules] = {
    "passive": ModeRules(
        tool_modes=frozenset({Mode.PASSIVE}),
        tiers=frozenset({Tier.CORE}),
    ),
    "active": ModeRules(
        tool_modes=frozenset({Mode.PASSIVE, Mode.ACTIVE}),
        tiers=frozenset({Tier.CORE}),
    ),
    "full": ModeRules(
        tool_modes=frozenset({Mode.PASSIVE, Mode.ACTIVE}),
        tiers=frozenset({Tier.CORE, Tier.OPT_IN, Tier.INTRUSIVE}),
    ),
}


def allowed_tiers(mode: str, *, include_noisy: bool) -> frozenset[Tier]:
    """The tiers a mode may select; opt_in joins them for --include-noisy/full."""

    tiers = set(MODE_TOOLS[mode].tiers)
    if include_noisy or mode == "full":
        tiers.add(Tier.OPT_IN)
    return frozenset(tiers)


# Raw output goes to the stage's own workspace directory when there is one.
# `dns` has none - the layout is exactly the six documented directories - so it
# uses `meta`, like the phase-3 `vulns`/`shots` stages (docs/03 section 5, 12a).
RAW_OUTPUT_DIRS: dict[Stage, str] = {
    Stage.SUBS: "subs",
    Stage.DNS: "meta",
    Stage.LIVE: "live",
    Stage.PORTS: "ports",
    Stage.TECH: "tech",
    Stage.URLS: "urls",
    Stage.VULNS: "meta",
    Stage.SHOTS: "meta",
}
SkipReason = str
Selected = list[tuple[ToolSpec, type[BaseToolAdapter]]]
Skipped = list[tuple[ToolSpec, SkipReason]]
# docs/05 rule 6, naabu branch (2026-11-17): with a scope file present the engine
# resolves each in-scope target itself and hands naabu only verified addresses.
NAABU_NO_IPS = (
    "blocked: no in-scope IP for any target "
    "(resolution failed or the address is outside in_scope_cidrs)"
)
Resolve = Callable[[str], Awaitable[list[str]]]
InstalledCheck = Callable[[type[BaseToolAdapter]], bool]


def allow_all_ip(_ip: str) -> bool:
    """The docs/05 rule 6 predicate when there is no scope file (2026-11-17).

    No scope file means no CIDR list, so there is nothing to restrict: active
    scanning of the operator's targets is unrestricted. With a scope file the
    predicate is the loaded scope's `ip_allowed` instead.
    """
    return True


Now = Callable[[], str]
# One short progress line for the CLI to render on stderr (docs/03 section 5).
Progress = Callable[[str], None]


class ExitCode(IntEnum):
    """Scan-side subset of docs/02 section 6; the CLI maps it, the engine never exits.

    Code 6 is install/update only, from `installer.github_release.exit_code()`.
    A scan with every tool failed is NO_TOOL (4), never 6.
    """

    SUCCESS = 0
    ERROR = 1
    USAGE = 2
    SCOPE = 3
    NO_TOOL = 4
    PARTIAL = 5
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


# One level up, for a port an active tool fingerprinted (docs/09 section 5).
FINGERPRINT_BUMP = {Confidence.LOW: Confidence.MEDIUM, Confidence.MEDIUM: Confidence.HIGH}


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
    # docs/04 section 5: a probe was attempted when a live tool returned a record
    # for this host, ambiguous or not. It decides whether an inconclusive pass
    # with no previous state writes an `UNKNOWN` row (12e) instead of skipping.
    attempted = bool(evidence.web)
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
            previous is not None or attempted,
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
            previous is not None or attempted,
        )

    return HostTransition(previous or HostState.UNKNOWN, None, (), (), False)


@dataclass(frozen=True)
class ScanOptions:
    """The CLI's per-run switches, already parsed.

    `mode` is derived, never stored: the two tables above are the only place a
    mode's stages, tool modes and tiers are written down. `full` wins over
    `active` when a caller sets both.
    """

    stages: tuple[Stage, ...] = STAGE_ORDER
    tools: tuple[str, ...] = ()
    exclude: frozenset[str] = frozenset()
    include_noisy: bool = False
    active: bool = False
    full: bool = False
    no_scope: bool = False
    no_keys: bool = False
    mock: bool = False
    phase_timeout: float | None = None
    min_sources: int = 1
    resume: bool = False
    # Injectable scan parameters (docs/02 section 3). `headers` is a tuple of
    # (name, value) pairs so this frozen dataclass stays hashable.
    ports: tuple[int, ...] = ()
    status_codes: tuple[int, ...] = ()
    headers: tuple[tuple[str, str], ...] = ()
    user_agent: str | None = None
    redact_headers: bool = True
    # `--ffuf-wordlist` (D13): a user list replaces the packaged default.
    ffuf_wordlist: Path | None = None

    @property
    def mode(self) -> str:
        """The `MODE_STAGES`/`MODE_TOOLS` key for this invocation."""
        if self.full:
            return "full"
        return "active" if self.active else "passive"


@dataclass
class ToolSkip:
    """One tool the engine selected out before it ran (docs/02 section 5)."""

    tool: str
    reason: str


@dataclass(frozen=True)
class CompletionGap:
    """A requested stage that could not run anything because the tool was absent.

    docs/02 section 6 (owner ruling 2026-11-17): "no adapter yet (phase N)" and
    "not installed" mean the scan used every tool that was available - a gap,
    not a partial failure. Every other zero-tool cause stays a partial run.
    """

    stage: Stage
    reason: str
    skipped: int = 0


@dataclass
class StageOutcome:
    stage: Stage
    run_id: int
    results: list[ToolResult] = field(default_factory=list)
    dropped_hosts: list[str] = field(default_factory=list)
    skipped: list[ToolSkip] = field(default_factory=list)
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
    # enforced / no_file / unrestricted_flag (docs/04 section 4, schema 6).
    scope_mode: str = "no_file"
    # passive / active / full, for the gaps block headline (docs/02 section 6).
    mode: str = "passive"
    # Requested stages that ran nothing because no tool exists or none is installed.
    gaps: list[CompletionGap] = field(default_factory=list)

    @property
    def completion_status(self) -> str:
        """`complete` or `complete_with_gaps` (docs/02 section 5, `completion`)."""
        return "complete_with_gaps" if self.gaps else "complete"

    @property
    def results(self) -> list[ToolResult]:
        return [result for stage in self.stages for result in stage.results]

    @property
    def skipped(self) -> list[ToolSkip]:
        return [skip for stage in self.stages for skip in stage.skipped]


@dataclass(frozen=True)
class HostSnapshot:
    """One stored host row, already decided by the engine (UI input).

    The first seven fields are the documented table/`--json` shape. The rest are
    stored values the interactive report menu can include (docs/02 section 5);
    they default to empty so the table and the JSON document are unchanged.
    """

    fqdn: str
    state: HostState
    confidence: Confidence
    sources: tuple[str, ...]
    status_code: int | None
    ports: tuple[int, ...]
    detail: str | None = None
    source_count: int = 0
    ips: tuple[str, ...] = ()
    title: str | None = None
    location: str | None = None
    tech: tuple[str, ...] = ()


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
    pending_gone: tuple[str, ...] = ()
    baseline_run_id: int | None = None


@dataclass(frozen=True)
class RunSnapshot:
    """Recent stage run for the status command."""

    id: int
    target: str
    stage: str
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
        resolve: Resolve | None = None,
        installed: InstalledCheck | None = None,
        now: Now | None = None,
        progress: Progress | None = None,
    ) -> None:
        self.config = config
        self.store = store
        # Injected reporting callback (docs/03 section 5). The engine never prints
        # and never formats: it hands the CLI one short line, or nothing at all.
        self._progress_cb = progress
        self.specs = dict(specs) if specs is not None else load_tools()
        self.adapters = dict(adapters) if adapters is not None else dict(ADAPTERS)
        self.scope_path = scope_path
        self.workspace_root = (
            Path(workspace_root) if workspace_root is not None else Path(config.workspace_dir)
        )
        self.env = dict(env or {})
        self._rng = rng if rng is not None else secrets.SystemRandom()
        # docs/05 rule 6: the engine, not naabu, resolves names when a scope file
        # is present; injected so tests never touch DNS.
        self._resolve = resolve if resolve is not None else default_resolve
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

    def _progress(self, message: str) -> None:
        """Emit one progress line to the injected callback, if any."""
        if self._progress_cb is not None:
            self._progress_cb(message)

    def host_rows(self, target_id: int) -> list[HostSnapshot]:
        """Read stored host rows for the UI without exposing Store to the CLI."""
        rows: list[HostSnapshot] = []
        for row in self.store.host_rows(target_id):
            raw_sources = cast(tuple[str, ...], row["sources"])
            raw_ports = cast(tuple[int, ...], row["ports"])
            raw_status = row["status_code"]
            raw_detail = row["detail"]
            raw_title = row["title"]
            raw_location = row["location"]
            raw_count = row["source_count"]
            rows.append(
                HostSnapshot(
                    fqdn=str(row["fqdn"]),
                    state=HostState(str(row["state"])),
                    confidence=Confidence(str(row["confidence"])),
                    sources=tuple(str(value) for value in raw_sources),
                    status_code=raw_status if isinstance(raw_status, int) else None,
                    ports=tuple(int(value) for value in raw_ports),
                    detail=raw_detail if isinstance(raw_detail, str) else None,
                    source_count=raw_count if isinstance(raw_count, int) else 0,
                    ips=tuple(str(value) for value in cast(tuple[str, ...], row["ips"])),
                    title=raw_title if isinstance(raw_title, str) else None,
                    location=raw_location if isinstance(raw_location, str) else None,
                    tech=tuple(str(value) for value in cast(tuple[str, ...], row["tech"])),
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
        # docs/02: GONE needs two consecutive misses, so it also needs the run
        # before the previous one. Fewer than three runs confirms nothing gone.
        baseline = discovery[2] if len(discovery) > 2 else None
        if latest is None or previous is None:
            return DiffSnapshot(normalized, previous, latest, (), (), (), (), ())
        live = self.store.completed_run_ids(target_id, Stage.LIVE.value)
        ports = self.store.completed_run_ids(target_id, Stage.PORTS.value)
        return DiffSnapshot(
            normalized,
            previous,
            latest,
            tuple(self.store.diff_new(latest)),
            tuple(self.store.diff_gone(baseline, previous, latest)) if baseline is not None else (),
            tuple(self.store.diff_state_changed(live[1], live[0])) if len(live) > 1 else (),
            tuple(self.store.diff_ports_opened(ports[1], ports[0])) if len(ports) > 1 else (),
            tuple(self.store.diff_ports_closed(ports[1], ports[0])) if len(ports) > 1 else (),
            pending_gone=tuple(self.store.diff_pending_gone(previous, latest)),
            baseline_run_id=baseline,
        )

    async def run(self, target: str, options: ScanOptions | None = None) -> ScanSummary:
        opts = options or ScanOptions()
        target = validate_target(target)
        if opts.phase_timeout is not None and opts.phase_timeout <= 0:
            raise ConfigError("phase timeout must be > 0")
        if opts.min_sources < 1:
            raise ConfigError("min_sources must be >= 1")

        # docs/03 section 11: file I/O never runs on the loop; the SQLite block
        # below stays on it on purpose (single writer, thread-bound connection).
        workspace = await asyncio.to_thread(
            Workspace.create, self.workspace_root, target, secrets=self._secrets
        )
        target_id = self.store.create_target(target, created_at=self._now())
        self._warnings = []
        if not opts.active or opts.no_scope:
            self._note_passive_warning(target, opts)

        scan_key, completed, resumed = self._resume_plan(target_id, opts)
        summary = ScanSummary(
            target=target,
            target_id=target_id,
            resumed=resumed,
            scope_mode=self._scope_mode(opts),
            mode=opts.mode,
        )
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
            ip_allowed: Callable[[str], bool] | None = None
            if opts.active and any(spec.mode is Mode.ACTIVE for spec, _ in selected):
                hosts, dropped, scope_error = await asyncio.to_thread(
                    self._active_hosts, target, hosts, opts
                )
                if scope_error is not None:
                    summary.scope_denied = True
                    self._note_scope_refusal(target, scope_error)
                    selected, skipped = self._skip_active(selected, skipped, scope_error)
                else:
                    ip_allowed = await asyncio.to_thread(self._ip_allowed, opts)
            # docs/05 rule 6: with a scope file present, naabu receives only
            # addresses the engine resolved and verified; with no scope file it
            # runs unrestricted like every other active tool.
            tool_hosts: dict[str, list[str]] = {}
            # A `mode: passive` urls tool queries an archive by domain, so it gets
            # the discovered names; an active one crawls the alive hosts it was
            # handed (docs/02 section 1). Same override mechanism as naabu below.
            if stage is Stage.URLS:
                domains = self._clean_hosts([target, *discovered], target)
                for spec, _reason in selected:
                    if spec.mode is Mode.PASSIVE:
                        tool_hosts[spec.name] = domains
            if (
                stage is Stage.PORTS
                and not opts.mock
                and ip_allowed is not None
                and not opts.no_scope
                and scope_present(self.scope_path)
                and any(spec.name == "naabu" for spec, _ in selected)
            ):
                selected, skipped, tool_hosts = await self._naabu_verified_ips(
                    selected, skipped, hosts, ip_allowed
                )

            run_id = self.store.create_scan_run(
                target_id,
                stage.value,
                params=json.dumps(
                    {
                        "scan_key": scan_key,
                        "mode": opts.mode,
                        "tools": [spec.name for spec, _ in selected],
                        "mock": opts.mock,
                        "active": opts.active,
                        "no_keys": opts.no_keys,
                        "min_sources": opts.min_sources,
                    }
                ),
                started_at=self._now(),
                scope_mode=summary.scope_mode,
                secrets=self._secrets,
            )
            for spec, reason in skipped:
                self._record(run_id, spec.name, ToolStatus.SKIPPED, error=reason)

            self._progress(f"{stage.value}: running {len(selected)} tool(s)")
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
                        opts,
                        ip_allowed,
                        tool_hosts,
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

            self._progress(
                f"{stage.value}: finished {len(results)}/{len(selected)} tool(s), "
                f"{sum(len(result.records) for result in results)} item(s)"
            )
            if stage is Stage.DNS:
                dns_results = list(results)
            self._update_discovered(stage, results, target, discovered, alive)
            summary.stages.append(
                StageOutcome(
                    stage=stage,
                    run_id=run_id,
                    results=results,
                    dropped_hosts=dropped,
                    skipped=[ToolSkip(spec.name, reason) for spec, reason in skipped],
                )
            )
            if not results:
                self._note_empty_stage(stage, skipped)

        summary.gaps = self._completion_gaps(summary)
        summary.exit_code = self._exit_code(
            summary, selected_total=selected_total, failed_total=failed_total
        )
        summary.warnings = list(self._warnings)
        return summary

    def _exit_code(
        self, summary: ScanSummary, *, selected_total: int, failed_total: int
    ) -> ExitCode:
        """The one place the run's exit code is decided (docs/02 section 6).

        Precedence: scope (3) over no-usable-tool (4) over partial (5). A
        requested stage that executed zero tools is one more source of 5, never
        a replacement for the existing failed/timeout source - unless the only
        cause was an absent tool (no adapter, not installed). Those are
        `summary.gaps`: the run used every tool that was available, so it exits
        0 and the gaps block carries the honesty (owner ruling 2026-11-17).
        """
        if summary.scope_denied:
            return ExitCode.SCOPE
        new_stages = any(not stage.resumed for stage in summary.stages)
        if selected_total == 0:
            return ExitCode.NO_TOOL if new_stages else ExitCode.SUCCESS
        if failed_total == selected_total:
            return ExitCode.NO_TOOL
        explained = {gap.stage for gap in summary.gaps}
        unexplained = [stage for stage in self._empty_stages(summary) if stage not in explained]
        if failed_total or unexplained:
            return ExitCode.PARTIAL
        return ExitCode.SUCCESS

    @staticmethod
    def _is_gap_reason(reason: str) -> bool:
        """The two absence-only skip reasons (docs/02 section 6)."""
        return reason.startswith("no adapter") or reason == "not installed"

    def _completion_gaps(self, summary: ScanSummary) -> list[CompletionGap]:
        """Zero-tool stages whose only cause was an absent tool, one per stage.

        A stage emptied by `--tools`, `--exclude`, a tier/tool-mode rule, the
        exploitation rule or the scope gate is *not* a gap: those are deliberate
        exclusions, and the scope case is exit 3 anyway.
        """
        gaps: list[CompletionGap] = []
        for outcome in summary.stages:
            if outcome.resumed or outcome.results:
                continue
            absent = [skip for skip in outcome.skipped if self._is_gap_reason(skip.reason)]
            if absent:
                reasons = ", ".join(sorted({skip.reason for skip in absent}))
                gaps.append(CompletionGap(outcome.stage, reasons, len(absent)))
        return gaps

    @staticmethod
    def _empty_stages(summary: ScanSummary) -> list[Stage]:
        """Requested stages that executed zero tools; a resumed stage is not new work."""
        return [
            outcome.stage
            for outcome in summary.stages
            if not outcome.resumed and not outcome.results
        ]

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

    def _scope_mode(self, opts: ScanOptions) -> str:
        """The `scan_runs.scope_mode` value for this invocation (docs/04)."""
        if opts.no_scope:
            return "unrestricted_flag"
        return "enforced" if scope_present(self.scope_path) else "no_file"

    def _note_scope_refusal(self, target: str, reason: str) -> None:
        """docs/02 section 6: the exit-3 sentence an operator can act on."""
        if "not in scope" in reason or "out of scope" in reason:
            note = (
                f"active scan refused: {target} not in scope.yaml. "
                f"Re-run with --no-scope or add {target} to scope.yaml."
            )
        else:
            note = f"active scan refused: {reason} (re-run with --no-scope to ignore scope.yaml)"
        if note not in self._warnings:
            self._warnings.append(note)

    def _active_hosts(
        self, target: str, hosts: list[str], opts: ScanOptions
    ) -> tuple[list[str], list[str], str | None]:
        if opts.no_scope or not scope_present(self.scope_path):
            # docs/05 rule 2 (2026-11-17): no scope file means unrestricted
            # active scanning of the operator's targets and everything
            # discovered under them. `--no-scope` behaves exactly as if the file
            # were absent (docs/05 section 3). No scope object is loaded.
            return hosts, [], None
        try:
            gate = load_scope(self.scope_path)
            allowed = [host for host in hosts if gate.allows(host)]
            dropped = [host for host in hosts if not gate.allows(host)]
            check = require_active(target, allowed, path=self.scope_path)
        except ScopeError as exc:
            return hosts, [], str(exc)
        return check.hosts, dropped, None

    async def _naabu_verified_ips(
        self,
        selected: Selected,
        skipped: Skipped,
        hosts: list[str],
        ip_allowed: Callable[[str], bool],
    ) -> tuple[Selected, Skipped, dict[str, list[str]]]:
        """Resolve and verify naabu's input when a scope file is present.

        docs/05 rule 6 (2026-11-17): naabu resolves inside its own process, so
        the engine resolves each already-in-scope target itself, keeps every
        address `ip_allowed` accepts, and hands naabu only those addresses -
        never a bare domain. A target whose resolution fails or yields no
        in-scope address is left out of the scan; when nothing is left, naabu is
        removed from the selection with a `blocked:` reason.
        """
        naabu = next(((spec, adapter) for spec, adapter in selected if spec.name == "naabu"), None)
        tool_hosts: dict[str, list[str]] = {}
        if naabu is None:
            return selected, skipped, tool_hosts
        verified: list[str] = []
        seen: set[str] = set()
        dropped = 0
        for host in hosts:
            try:
                addresses = await self._resolve(host)
            except (OSError, ValueError):
                dropped += 1
                continue
            kept = 0
            for address in addresses:
                try:
                    ipaddress.ip_address(address)
                    permitted = ip_allowed(address)
                except (TypeError, ValueError):
                    continue
                if not permitted:
                    continue
                kept += 1
                if address not in seen:
                    seen.add(address)
                    verified.append(address)
            if kept == 0:
                dropped += 1
        if not verified:
            kept_selected = [(spec, adapter) for spec, adapter in selected if spec.name != "naabu"]
            return kept_selected, [*skipped, (naabu[0], NAABU_NO_IPS)], tool_hosts
        if dropped:
            note = (
                f"naabu scope check: {dropped} target(s) skipped "
                "(resolution failed or the address is outside in_scope_cidrs)"
            )
            if note not in self._warnings:
                self._warnings.append(note)
        tool_hosts["naabu"] = verified
        return selected, skipped, tool_hosts

    def _note_empty_stage(self, stage: Stage, skipped: Skipped) -> None:
        """docs/02 section 6: a stage that executed no tools says so, once."""
        reasons = sorted({reason for _spec, reason in skipped})
        detail = ", ".join(reasons) if reasons else "no adapter"
        note = f"{stage.value} stage executed no tools: {len(skipped)} tool(s) skipped ({detail})"
        if note not in self._warnings:
            self._warnings.append(note)

    def _note_passive_warning(self, target: str, opts: ScanOptions) -> None:
        """docs/05 rule 1: warn when a passive run targets outside an existing scope file.

        `scope.passive_warning()` returns one or two `warning:`-prefixed lines; the
        UI prefixes each entry itself, so the prefix is stripped here to avoid a
        doubled `warning: warning:`.
        """
        if opts.no_scope:
            return
        text = passive_warning(target, path=self.scope_path)
        if text is None:
            return
        for line in text.splitlines():
            note = line.strip()
            if note.startswith("warning:"):
                note = note[len("warning:") :].strip()
            if note and note not in self._warnings:
                self._warnings.append(note)

    def _ip_allowed(self, opts: ScanOptions) -> Callable[[str], bool] | None:
        """docs/05 rule 6 predicate, from the same scope file the active gate read.

        `None` means "no permission": an adapter that connects to a resolved
        address must treat it as a block, so an unreadable scope can only narrow
        what may be contacted, never widen it.
        """
        if opts.no_scope or not scope_present(self.scope_path):
            return allow_all_ip
        try:
            return load_scope(self.scope_path).ip_allowed
        except (ConfigError, ScopeError):
            return None

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
        """Apply the mode tables in one place (docs/03 section 5).

        Order matters and is documented: an explicit `--tools <name>` bypasses
        the tier gate (never the tool-mode gate), and an `exploitation: true`
        tool never fires automatically in any mode - not even `full`. That is
        the AGENTS "recon only" boundary expressed as a registry field.
        """
        if opts.tools:
            unknown = [name for name in opts.tools if name not in self.specs]
            if unknown:
                raise ConfigError(f"unknown tool(s): {', '.join(unknown)}")

        mode = opts.mode
        tiers = allowed_tiers(mode, include_noisy=opts.include_noisy)
        tool_modes = MODE_TOOLS[mode].tool_modes

        selected: Selected = []
        skipped: Skipped = []
        for name, spec in self.specs.items():
            if spec.stage is not stage:
                continue
            if opts.tools and name not in opts.tools:
                continue
            if name in opts.exclude:
                continue
            # 2026-11-17 pre-ruling: an exploitation-class tool is never
            # automatic, whatever the tier allowance says.
            if spec.exploitation and name not in opts.tools:
                skipped.append((spec, "exploitation tool requires explicit --tools"))
                continue
            if spec.tier not in tiers and name not in opts.tools:
                skipped.append((spec, f"tier not included in {mode} mode"))
                continue
            if spec.mode not in tool_modes:
                skipped.append((spec, f"tool mode not included in {mode} mode"))
                continue
            adapter = self.adapters.get(name)
            if adapter is None:
                skipped.append((spec, f"no adapter yet (phase {spec.phase})"))
                continue
            # `needs_root` (masscan): raw sockets are a process privilege, not a
            # tool property, so a non-root run skips it with a reason instead of
            # spawning it to fail (docs/09 section 4a6).
            if spec.needs_root and not running_as_root():
                skipped.append((spec, "requires root / sudo"))
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
        opts: ScanOptions,
        ip_allowed: Callable[[str], bool] | None,
        tool_hosts: dict[str, list[str]],
        results: list[ToolResult],
        done: set[str],
    ) -> RunContext:
        # Every tool in the stage starts at once and runs at its own natural
        # pace (2026-11-17, MASTER_PLAN D3).
        ctx = RunContext(
            target=target,
            hosts=hosts,
            ports=list(opts.ports),
            timeout=self.config.timeouts.per_tool_default,
            workspace=workspace.directory,
            mock=opts.mock,
            ip_allowed=ip_allowed,
            headers=dict(opts.headers),
            user_agent=opts.user_agent,
            ffuf_wordlist=opts.ffuf_wordlist,
        )

        async def one(spec: ToolSpec, adapter: type[BaseToolAdapter]) -> None:
            overrides: dict[str, object] = {"env": self._tool_env(spec, opts)}
            if spec.name in tool_hosts:
                # docs/05 rule 6: naabu's verified IPs replace the name list.
                overrides["hosts"] = tool_hosts[spec.name]
            tool_ctx = ctx.model_copy(update=overrides)
            result = await self._run_one(run_id, adapter, tool_ctx, workspace)
            results.append(result)
            done.add(spec.name)

        await asyncio.gather(*(one(spec, adapter) for spec, adapter in selected))
        return ctx

    async def _run_one(
        self,
        run_id: int,
        adapter: type[BaseToolAdapter],
        ctx: RunContext,
        workspace: Workspace,
    ) -> ToolResult:
        started = time.perf_counter()
        try:
            result = await asyncio.wait_for(adapter().run(ctx), timeout=ctx.timeout)
        except TimeoutError:
            result = ToolResult(tool=adapter.name, status=ToolStatus.TIMEOUT, error="timed out")
        except Exception as exc:
            result = ToolResult(
                tool=adapter.name,
                status=ToolStatus.FAILED,
                error=redact(f"{type(exc).__name__}: {exc}", self._secrets),
            )
        update: dict[str, object] = {
            "raw_path": self._write_raw(workspace, run_id, adapter, result)
        }
        if result.duration_s <= 0:
            # The adapter's own measurement is authoritative; this is the only
            # fallback site (docs/04 section 5) and it never overwrites one. A
            # crashed or timed-out adapter reports nothing, so it lands here.
            update["duration_s"] = time.perf_counter() - started
        result = result.model_copy(update=update)
        self._record(
            run_id,
            adapter.name,
            result.status,
            item_count=len(result.records),
            duration_s=result.duration_s,
            error=result.error,
        )
        self._progress(
            f"{adapter.stage.value}: {adapter.name} {result.status.value} "
            f"{len(result.records)} item(s)"
        )
        return result

    def _write_raw(
        self,
        workspace: Workspace,
        run_id: int,
        adapter: type[BaseToolAdapter],
        result: ToolResult,
    ) -> str | None:
        """Write one redacted, capped raw file per executed tool (docs/03 section 5).

        Raw capture is a diagnostic side channel: a write that fails (disk full,
        permissions, a rejected name) leaves `raw_path` empty and changes neither
        the tool result nor its `tool_runs` row.
        """
        try:
            path = workspace.write(
                RAW_OUTPUT_DIRS[adapter.stage],
                f"{run_id}-{adapter.name}.txt",
                result.raw_text or "",
            )
        except (OSError, ValueError, TypeError):
            return None
        return str(path)

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
        elif stage is Stage.TECH:
            self._persist_tech(target_id, run_id, results, target)
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
                provenance="subs",
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
        self._persist_live_discoveries(target_id, run_id, results, target, hosts, opts)

    def _persist_live_discoveries(
        self,
        target_id: int,
        run_id: int,
        results: list[ToolResult],
        target: str,
        hosts: list[str],
        opts: ScanOptions,
    ) -> None:
        """Persist subdomains a live-stage adapter discovered while probing.

        A live pass writes a row for each of its *input* hosts only, so a host an
        adapter found in passing (a certificate SAN, tlsx) used to stop at the
        in-memory `discovered` set and never reach `subdomains`. Records already
        known from the discovery pass or the input list keep their own row and
        source count (PIT-03), so this only creates the missing rows
        (Regression: PIT-49).
        """
        known = set(hosts) | {str(row["fqdn"]) for row in self.store.subdomains(target_id)}
        groups: dict[str, set[str]] = {}
        for result in results:
            if result.status is not ToolStatus.OK:
                continue
            for record in result.records:
                if not isinstance(record, SubdomainRecord):
                    continue
                for cleaned in self._clean_hosts([record.fqdn], target):
                    if cleaned not in known:
                        groups.setdefault(cleaned, set()).add(result.tool)
        for fqdn, tools in groups.items():
            if len(tools) < opts.min_sources:
                continue
            sub_id = self.store.upsert_subdomain(
                target_id,
                fqdn,
                run_id=run_id,
                confidence=confidence_for(
                    tools,
                    high_min=self.config.confidence.high_min_sources,
                    medium_min=self.config.confidence.medium_min_sources,
                ).value,
                source_count=len(tools),
                provenance="subs",
            )
            for tool in sorted(tools):
                self.store.add_subdomain_source(sub_id, run_id, tool)

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
        # A state pass may still record disagreement, and nothing is lost here because
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
            # Only the adapter's own reason, and only for the row it describes: a
            # later ALIVE pass supplies its own record (no detail), so an old
            # reason never reappears (docs/04 section 5). The store redacts and
            # bounds it with the run's secrets.
            detail=None if best is None else best.detail,
            ips=ips,
            tech=() if best is None else best.tech,
            waf=None if best is None else best.waf,
            tools=transition.sources,
            checked_at=self._now(),
            secrets=self._secrets,
        )

    def _persist_tech(
        self, target_id: int, run_id: int, results: list[ToolResult], target: str
    ) -> None:
        """Record technologies/WAF on the host's newest status row (D11).

        The tech stage adds facts to the row the live pass wrote: it never
        creates a status row and never touches `state`, because matching a
        technology says nothing about whether the host is up. Two tech tools
        contribute to one row, so the union of their findings is what is stored.

        The WAF is one string and merges by `waf_priority` (D12): the pass keeps
        its highest-priority detection, and a tie keeps the first record, so the
        value never depends on which tool happened to finish first.
        """
        groups: dict[str, dict[str, set[str] | str | int | None]] = {}
        for result in results:
            if result.status is not ToolStatus.OK:
                continue
            for record in result.records:
                if not isinstance(record, HostStatusRecord):
                    continue
                group = groups.setdefault(
                    record.fqdn, {"tech": set(), "waf": None, "waf_priority": -1}
                )
                tech = group["tech"]
                if isinstance(tech, set):
                    tech.update(record.tech)
                if record.waf is not None:
                    spec = self.specs.get(result.tool)
                    priority = spec.waf_priority if spec is not None else 0
                    raw = group["waf_priority"]
                    current = raw if isinstance(raw, int) else -1
                    if group["waf"] is None or priority > current:
                        group["waf"] = record.waf
                        group["waf_priority"] = priority
        for fqdn, group in groups.items():
            # Same target rule as every other stage: a record naming a host the
            # run did not ask about is dropped, not stored (docs/03 section 9).
            if not self._clean_hosts([fqdn], target):
                continue
            tech = group["tech"]
            waf = group["waf"]
            win_priority = group["waf_priority"]
            sub_id = self.store.upsert_subdomain(target_id, fqdn, run_id=run_id)
            self.store.update_host_extras(
                sub_id,
                tech=sorted(tech) if isinstance(tech, set) else [],
                waf=waf if isinstance(waf, str) else None,
                waf_priority=(
                    win_priority if isinstance(win_priority, int) and win_priority > 0 else 0
                ),
            )

    def _persist_ports(
        self, target_id: int, run_id: int, results: list[ToolResult], opts: ScanOptions
    ) -> None:
        groups: dict[tuple[str, str, int], dict[str, list[PortRecord]]] = {}
        for result in results:
            if result.status is not ToolStatus.OK:
                continue
            for record in result.records:
                if not isinstance(record, PortRecord):
                    continue
                key = (record.fqdn, record.ip, record.port)
                groups.setdefault(key, {}).setdefault(result.tool, []).append(record)
        for (fqdn, ip, port), by_tool in groups.items():
            tools = set(by_tool)
            if len(tools) < opts.min_sources:
                continue
            seen = {record.state for records in by_tool.values() for record in records}
            state = "unconfirmed" if {"open", "closed"} <= seen else next(iter(seen))
            confidence = confidence_for(
                tools,
                high_min=self.config.confidence.high_min_sources,
                medium_min=self.config.confidence.medium_min_sources,
                disagree=state == "unconfirmed",
            )
            service, version = _fingerprint(by_tool)
            # docs/09 section 5: an active tool's `-sV`/banner fingerprint raises
            # confidence by one level. Two tools that disagree on the service say
            # nothing, so the fields stay empty instead of picking a winner.
            if (service or version) and confidence in FINGERPRINT_BUMP:
                confidence = FINGERPRINT_BUMP[confidence]
            sub_id = self.store.upsert_subdomain(target_id, fqdn, run_id=run_id)
            port_id = self.store.upsert_port(
                sub_id,
                ip,
                port,
                run_id=run_id,
                state=state,
                service=service,
                version=version,
                confidence=confidence.value,
            )
            for tool, records in by_tool.items():
                self.store.add_port_source(port_id, run_id, tool, records[0].state)


def _fingerprint(by_tool: dict[str, list[PortRecord]]) -> tuple[str | None, str | None]:
    """The service/version an active tool reported, or nothing when tools disagree.

    `tcp/80` is `http` to nmap and `http?` to smap in the same collision, so only
    a single agreed value is stored; anything else is left empty rather than
    invented (docs/09 section 5).
    """
    services = {
        record.service for records in by_tool.values() for record in records if record.service
    }
    versions = {
        record.version for records in by_tool.values() for record in records if record.version
    }
    service = services.pop() if len(services) == 1 else None
    version = versions.pop() if len(versions) == 1 else None
    return service, version
