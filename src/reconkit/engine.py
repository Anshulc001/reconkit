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
import math
import secrets
import ssl
import threading
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from functools import partial
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import httpx
from dotenv import dotenv_values

from reconkit import __version__
from reconkit.adapters import ADAPTERS
from reconkit.adapters.base import USER_AGENT, BaseToolAdapter, normalize_url, running_as_root
from reconkit.adapters.pyscan import default_resolve
from reconkit.adapters.registry import ToolSpec, load_tools
from reconkit.config import AppConfig, UrlProbeConfig
from reconkit.core.runner import validate_host, validate_target
from reconkit.core.scope import (
    NO_SCOPE_MESSAGE,
    ScopeGate,
    load_scope,
    passive_warning,
    require_active,
    scope_present,
)
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
    ToolLimits,
    ToolResult,
    ToolStatus,
    UrlRecord,
)

# The `urls.status_code` values for a URL that has no HTTP status (D23). Both
# are stored answers, not missing ones: the probe never retries them.
#   UNREACHABLE - no answer at all: refused, timed out, DNS failed.
#   UNTRUSTED   - the server answered but its TLS certificate did not verify
#                 (hostname mismatch or untrusted chain). Kept apart from -1
#                 because "answers with a bad certificate" is a different fact
#                 from "does not answer", and the first is common on purpose
#                 (testfire.net is one). Verification is never disabled.
UNREACHABLE = -1
UNTRUSTED = -2
# D58: the `subdomain_sources` sentinel for a host first named by the URL pool.
# It is a source label, not a tool in `tools.yaml`, and it never runs on its own.
URL_DERIVED = "url-derived"

STAGE_ORDER: tuple[Stage, ...] = (
    Stage.SUBS,
    Stage.DNS,
    Stage.LIVE,
    Stage.PORTS,
    Stage.TECH,
    Stage.URLS,
    # The liveness probe follows the crawl: it needs the stored URLs (D23).
    Stage.URL_PROBE,
    # Screenshots come after URL discovery (they need alive hosts and the crawl
    # has already run) and before vulns, so a slow browser never delays the
    # findings stage (D19).
    Stage.SHOTS,
    Stage.VULNS,
)


@dataclass(frozen=True)
class ModeRules:
    """What one scan mode includes: tool modes plus tiers (docs/02, docs/03).

    `MODE_TOOLS` is the only place the tier/tool-mode rule lives; the CLI and
    every doc quote this table instead of restating it.
    """

    tool_modes: frozenset[Mode]
    tiers: frozenset[Tier]


# Scan-mode stages, the first of the two mode tables (docs/02 section 2).
# Every surface that needs "which stages does mode X run" reads this dict.
MODE_STAGES: dict[str, tuple[Stage, ...]] = {
    "passive": (Stage.SUBS, Stage.DNS, Stage.URLS),
    "active": (
        Stage.SUBS,
        Stage.DNS,
        Stage.LIVE,
        Stage.TECH,
        Stage.URLS,
        # Sends HTTP, so it is never a passive stage (D23).
        Stage.URL_PROBE,
    ),
    # `shots` is full-only (D19): it is in STAGE_ORDER, and therefore here, but
    # in neither tuple above. gowitness is `opt_in`/`active`, so the tier and
    # tool-mode rules in MODE_TOOLS still decide whether it runs.
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


def _is_2xx(status: object) -> bool:
    """A content answer: the name served the site itself."""
    return isinstance(status, int) and 200 <= status < 300


def _is_redirect(status: object) -> bool:
    """A redirect answer: the name points somewhere else (D22)."""
    return isinstance(status, int) and status in (301, 302, 303, 307, 308)


def _live_rank(record: HostStatusRecord) -> tuple[int, int]:
    """How good a live record's HTTP answer is, lower being better (D69).

    A 2xx is the site answering, a 3xx is a redirect, any other known code is
    weaker evidence, and no code at all is weakest. The code itself breaks a
    tie inside a class (`200` before `204`).
    """
    code = record.status_code
    if code is None:
        return (3, 0)
    if 200 <= code < 300:
        return (0, code)
    if 300 <= code < 400:
        return (1, code)
    return (2, code)


def _best_live_record(
    records: Sequence[tuple[str, HostStatusRecord]],
) -> HostStatusRecord | None:
    """The record whose fields a host row keeps (D69, 2026-11-19).

    The pool has adapters that never observe a status (`httprobe`, `tlsx`) and
    adapters that do (`pyprobe`, `httpx`). Taking the first ALIVE record in
    completion order let a statusless answer win at random, so a 200 was lost
    from `host_status_history.status_code` while the row kept the tech the
    `tech` stage wrote. Prefer ALIVE records, then the best status
    (`_live_rank`), then the tool name, so the result never depends on which
    tool finished first.
    """
    if not records:
        return None
    alive = [(tool, record) for tool, record in records if record.state is HostState.ALIVE]
    pool = alive or list(records)
    return min(pool, key=lambda item: (_live_rank(item[1]), item[0]))[1]


def _completed(status: ToolStatus) -> bool:
    """True for a tool that did all it could: `ok`, a `gap` from its upstream,
    or a `skipped` tool that was never given any input (R10, 2026-11-19).

    A skip is not a failure: it is the engine declining to run a tool against an
    empty list. The stage becomes a completion gap instead (exit 0).
    """
    # A `killed` tool is a deliberate stop (D52): it was silent past its idle or
    # the stage budget fired, and what it produced is kept. Like a skip, it is
    # not a failure and must not make a run exit 5.
    return status in (ToolStatus.OK, ToolStatus.GAP, ToolStatus.SKIPPED, ToolStatus.KILLED)


def allow_all_ip(_ip: str) -> bool:
    """The docs/05 rule 6 predicate under `--no-scope`.

    The explicit opt-out means no CIDR list, so there is nothing to restrict: active
    scanning of the operator's targets is unrestricted. With a scope file the
    predicate is the loaded scope's `ip_allowed` instead.
    """
    return True


# R10 (2026-11-19): the stages whose tools consume a host list. `subs` and
# `dns` get the target itself and are never input-less; `ports` already skips its
# whole stage when nothing is alive. `live` is listed because its list is
# `[target, *discovered]` - never empty, so the rule can never skip the apex.
HOST_INPUT_STAGES = frozenset({Stage.LIVE, Stage.TECH, Stage.URLS, Stage.VULNS})
NO_INPUT_HOSTS = "no input hosts"
# D50: seconds a tool must be running before its one "still running" line is
# printed. A tool that finishes sooner never produces one.
HEARTBEAT_AFTER_S = 10.0
# D52: how often the idle watchdog looks at the running tools, and how long a
# tool that was told to stop gets to return its partial output before its task is
# cancelled (an adapter that ignores the stop flag, e.g. a pure-Python one).
IDLE_WATCH_TICK_S = 0.1
KILL_GRACE_S = 0.25
# D52: the stage `asyncio.wait_for` keeps a small grace past the stage budget so
# the per-tool kill (which returns the partial output) fires first. The stage
# budget is still the bound; this only decides who reports it.
STAGE_KILL_GRACE_S = 2.0


def idle_for_tool(
    tool_name: str,
    config: AppConfig,
    *,
    specs: Mapping[str, ToolSpec] | None = None,
) -> float | None:
    """The silence window for one tool, or None when it has none (D52).

    One lookup, one number: a tool's own `idle_s:` in `tools.yaml` wins, else its
    `class:` window from `config.yaml` `runtime_idle:`. There is no runtime cap
    and no floor to intersect. A tool with neither runs until the stage budget
    fires. A class the config does not describe is a ConfigError, not a silent
    no-idle (docs/09 section 4a2b).
    """
    loaded = specs if specs is not None else load_tools()
    spec = loaded.get(tool_name)
    if spec is None:
        return None
    if spec.idle_s is not None:
        return float(spec.idle_s)
    if spec.class_ is None:
        return None
    runtime_class = config.runtime_idle.get(spec.class_)
    if runtime_class is None:
        raise ConfigError(
            f"tool {tool_name!r} uses runtime class {spec.class_!r}, "
            "which config.yaml does not define under runtime_idle"
        )
    return float(runtime_class.idle)


Now = Callable[[], str]
# One short progress line for the CLI to render on stderr (docs/03 section 5).
Progress = Callable[[str], None]
# A running-tool snapshot for the live status line: no newline, replaced in place
# (docs/02 section 5). Separate from `Progress`, whose lines are permanent.
Activity = Callable[[str], None]


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
    # D63: names the operator forced in with `--include`. They bypass the tier
    # gate and the tool-mode gate, and nothing else - exploitation tools still
    # need an explicit `--tools` name (AGENTS hard rule 6).
    include_tools: frozenset[str] = frozenset()
    # D63: `--include` forced a stage the requested mode would not run, so the
    # run contacts the target. It widens the scope gate (the D1 promise stays)
    # and never changes which tools a mode allows.
    forced_contact: bool = False
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
    # `--resolvers` (D16): a resolver list replaces the packaged default.
    resolvers: Path | None = None
    # `--skip-url-probe` (D23): leave every `urls.status_code` at NULL.
    skip_url_probe: bool = False
    # `--reprobe-urls`: probe every stored URL, not only the ones with no answer
    # yet, so a URL that has since gone dead is found (D24).
    reprobe_urls: bool = False

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
    # D56: scope facts a reader must see after the run (the report carries them
    # too, because a warning that only scrolls off is not a safety warning).
    scope_warnings: list[str] = field(default_factory=list)
    # D73: URLs that already carried a status when this run started, so the
    # report can say how much of its URL list came from earlier runs.
    urls_already_probed: int = 0
    # D78: what this run's `url_probe` actually sent, and what it skipped
    # because a stored answer already existed (`--reprobe-urls` sends those too).
    urls_probed_this_run: int = 0
    urls_skipped_already_probed: int = 0

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
    stored values the saved report can include (docs/02 section 5); they default
    to empty so the table and the JSON document are unchanged.
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
    # www/non-www metadata (D22): the canonical host when this row is a
    # duplicate, and the informational sibling note otherwise.
    duplicate_of: str | None = None
    www_note: str | None = None
    # D110: a CDN/WAF name means the host's listener is the edge, not the
    # origin, so its stored ports are not reportable (docs/05 rule 7).
    waf: str | None = None


def registry_tool_index() -> dict[str, tuple[Stage, Mode]]:
    """tools.yaml as `name -> (stage, tool mode)` for the CLI's D63 namespaces.

    `--include`/`--exclude` accept a stage name or an adapter name, so the CLI
    needs the registry's own names and each tool's stage. The CLI never imports
    `reconkit.adapters` (docs/03 section 9), so it asks the engine instead.
    """

    return {name: (spec.stage, spec.mode) for name, spec in load_tools().items()}


@dataclass(frozen=True)
class UrlSnapshot:
    """One stored URL with the state of the host that names it (D62).

    `host_state` is the host's latest stored state, or `UNKNOWN` when the host
    has no `subdomains` row at all (`Store.url_report_rows`).
    """

    url: str
    host: str
    status_code: int | None
    host_state: str
    # D76: the host is outside the target, so the report keeps the URL out of
    # `urls_by_host`, the `hosts/` tree and the probed pool.
    external: bool = False


def host_snapshots(store: Store, target_id: int) -> list[HostSnapshot]:
    """Stored host rows as report/display snapshots (one conversion, D65).

    Used by both a scan's own report and `reconkit report --from-db`, so a
    rebuilt report cannot drift from the one the run wrote.
    """
    rows: list[HostSnapshot] = []
    for row in store.host_rows(target_id):
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
                duplicate_of=(
                    str(row["duplicate_of"]) if isinstance(row["duplicate_of"], str) else None
                ),
                www_note=(str(row["www_note"]) if isinstance(row["www_note"], str) else None),
                waf=(str(row["waf"]) if isinstance(row["waf"], str) else None),
            )
        )
    return rows


def url_snapshots(store: Store, target_id: int) -> list[UrlSnapshot]:
    """Stored URLs as report snapshots (D62's columns, D65's second caller)."""
    return [
        UrlSnapshot(
            url=str(row["url"]),
            host=str(row["host"]),
            status_code=(row["status_code"] if isinstance(row["status_code"], int) else None),
            host_state=str(row["host_state"]),
            external=bool(row["external"]),
        )
        for row in store.url_report_rows(target_id)
    ]


@dataclass(frozen=True)
class StoredReport:
    """Everything a report needs, read from a stored run (D65).

    Nothing here is recomputed: the hosts are the latest stored state and the
    URLs are what the `urls` stage stored, which is the same input a scan's own
    report reads. `started_at` is the run the operator asked for, used for the
    output folder name when no `--out` is given.
    """

    target: str
    target_id: int
    run_id: int
    started_at: datetime
    hosts: tuple[HostSnapshot, ...]
    urls: tuple[UrlSnapshot, ...]


def load_stored_report(
    db_path: str | Path, target: str, *, run_id: int | None = None
) -> StoredReport:
    """Read one stored run for `reconkit report` - no network, no writes (D65).

    The connection is opened read-only (`Store.open_readonly`), so this function
    cannot change the database even by accident. A target or run that is not
    stored raises `ConfigError`, which the CLI turns into exit 2 without writing
    a partial report.
    """
    normalized = validate_target(target)
    store = Store.open_readonly(db_path)
    try:
        target_id = store.get_target(normalized)
        if target_id is None:
            raise ConfigError(f"no stored runs for {normalized} in {db_path}")
        stamp = store.run_stamp(target_id, run_id)
        if stamp is None:
            if run_id is None:
                raise ConfigError(f"no stored runs for {normalized} in {db_path}")
            raise ConfigError(f"run {run_id} does not belong to {normalized}")
        hosts = host_snapshots(store, target_id)
        urls = url_snapshots(store, target_id)
    finally:
        store.close()
    started = datetime.fromisoformat(str(stamp["started_at"]).replace("Z", "+00:00"))
    return StoredReport(
        target=normalized,
        target_id=target_id,
        run_id=cast(int, stamp["id"]),
        started_at=started.astimezone(UTC),
        hosts=tuple(hosts),
        urls=tuple(urls),
    )


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
        activity: Activity | None = None,
        url_probe_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        self.store = store
        # Injected reporting callback (docs/03 section 5). The engine never prints
        # and never formats: it hands the CLI one short line, or nothing at all.
        self._progress_cb = progress
        # Second, transient channel: the CLI renders it as a spinner, so it must
        # never be appended to a log or asserted on (docs/02 section 5).
        self._activity_cb = activity
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
        # The `url_probe` client's transport (D23), injectable for tests exactly
        # like the adapters' `transport` argument. `None` is a real connection.
        self._url_probe_transport = url_probe_transport
        self._installed = installed
        self._now = now if now is not None else utc_now
        self._secrets = tuple(value for value in self.env.values() if value)
        self._warnings: list[str] = []
        # D26: the last probe pass's bookkeeping, so a pass killed by its
        # deadline can still be finished with the counts it reached.
        self._url_probe_outcome: StageOutcome | None = None
        self._url_probe_progress: tuple[int, int] = (0, 0)
        self._url_probe_timeout: tuple[float, int, int] | None = None

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

    def _activity(self, message: str) -> None:
        """Emit one running-tool snapshot to the live-status callback, if any."""
        if self._activity_cb is not None:
            self._activity_cb(message)

    def host_rows(self, target_id: int) -> list[HostSnapshot]:
        """Read stored host rows for the UI without exposing Store to the CLI."""
        return host_snapshots(self.store, target_id)

    def url_rows(self, target_id: int) -> list[UrlSnapshot]:
        """Read the stored URLs for a report without exposing Store to the CLI."""
        return url_snapshots(self.store, target_id)

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
        # D26: cleared per run; only the timed-out pass sets them.
        self._url_probe_outcome = None
        self._url_probe_progress = (0, 0)
        self._url_probe_timeout = None
        if opts.no_scope or not (opts.active or opts.forced_contact):
            self._note_passive_warning(target, opts)
        cidr_warnings = await asyncio.to_thread(self._cidr_scope_warnings, opts)

        scan_key, completed, resumed = self._resume_plan(target_id, opts)
        summary = ScanSummary(
            target=target,
            target_id=target_id,
            resumed=resumed,
            scope_mode=self._scope_mode(opts),
            mode=opts.mode,
            scope_warnings=cidr_warnings,
        )
        for note in cidr_warnings:
            self._progress(note)
        # D73: counted before any stage runs, so a `url_probe` pass this run
        # cannot inflate the number the report calls "earlier runs".
        summary.urls_already_probed = sum(
            1
            for row in self.store.url_report_rows(target_id)
            if row["status_code"] is not None and not row["external"]
        )
        # D78: `--reprobe-urls` sends the stored answers again, so nothing is
        # "skipped because it already had a code" in that run.
        summary.urls_skipped_already_probed = (
            0 if opts.reprobe_urls else summary.urls_already_probed
        )
        discovered: set[str] = set()
        alive: set[str] = set()
        # A standalone stage command (`ports`, `tech`, `urls`, `vulns`, `shots`)
        # has no discovery stage in its own stage list, so the in-memory sets
        # would stay empty and the stage would silently scan nothing
        # (2026-11-20: `reconkit ports -d X` after a completed `--active` run
        # reported 0 tools and `Ports -`). Seed those runs from what earlier
        # runs stored. A run that includes subs/dns/live builds its own sets,
        # exactly as before, and `--resume` keeps its own seeding.
        discovery = {Stage.SUBS, Stage.DNS, Stage.LIVE}
        if resumed or not (discovery & set(opts.stages)):
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
            if stage is Stage.URL_PROBE:
                # Engine-owned, so it never goes through tool selection (D23).
                # D26: it gets the same deadline every tool stage has, from
                # --phase-timeout or `timeouts.url_probe` in config.yaml.
                probe_timeout = opts.phase_timeout or self._stage_timeout(Stage.URL_PROBE)
                try:
                    probe, scope_error = await asyncio.wait_for(
                        self._run_url_probe(target, target_id, opts, scan_key=scan_key),
                        timeout=probe_timeout,
                    )
                except TimeoutError:
                    probe, scope_error = self._url_probe_timed_out(probe_timeout), None
                if scope_error is not None:
                    summary.scope_denied = True
                    self._note_scope_refusal(target, scope_error)
                if probe is not None:
                    summary.stages.append(probe)
                # D78: `_url_probe_progress` is (done, total) and survives a
                # timeout, so the report can separate "probed now" from
                # "answered by an earlier run".
                summary.urls_probed_this_run = self._url_probe_progress[0]
                continue
            hosts = self._stage_hosts(stage, target, discovered, alive)
            selected, skipped = await self._select(stage, opts)
            if not selected and not skipped:
                continue
            if stage is Stage.PORTS and not hosts:
                # A standalone `ports` run with nothing stored would otherwise
                # look like a successful empty scan (2026-11-20, PIT-67).
                self._progress(
                    "ports: no ALIVE host from an earlier run; run `reconkit live` first"
                )
                continue
            if stage is Stage.PORTS:
                # docs/05 rule 7 (D110): a CDN/WAF edge answers on ports the
                # origin never opened, so scanning it stores the edge's
                # listeners as findings (Cloudflare answered 1, 3, 7, 9, 31337
                # and 65389 on 2026-11-21, ~3000 "open" ports per host).
                fronted = self.store.waf_fronted_hosts(target_id)
                skipped_fronted = [host for host in hosts if host in fronted]
                if skipped_fronted:
                    hosts = [host for host in hosts if host not in fronted]
                    self._progress(
                        f"ports: {len(skipped_fronted)} CDN/WAF-fronted host(s) skipped"
                        " (edge ports are not the origin's)"
                    )
                    if not hosts:
                        continue

            dropped: list[str] = []
            ip_allowed: Callable[[str], bool] | None = None
            if (opts.active or opts.forced_contact) and any(
                spec.mode is Mode.ACTIVE for spec, _ in selected
            ):
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
            # addresses the engine resolved and verified; under --no-scope it
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
                        stage_budget=timeout,
                    ),
                    # D52: the per-tool kill (idle or stage budget) fires first
                    # and returns the tool's partial output; this wait_for is the
                    # backstop for an adapter that ignores both, so it gets a
                    # small grace rather than racing the tool's own deadline.
                    timeout=timeout + STAGE_KILL_GRACE_S,
                )
            except TimeoutError:
                for spec, _ in selected:
                    if spec.name not in done:
                        detail = "phase timeout"
                        self._record(run_id, spec.name, ToolStatus.TIMEOUT, error=detail)
                        done.add(spec.name)
                        # The DB row alone is not enough: the summary counters and
                        # `--json` are built from `results`, so a tool killed by
                        # the stage deadline must appear there too.
                        results.append(
                            ToolResult(
                                tool=spec.name,
                                status=ToolStatus.TIMEOUT,
                                error=detail,
                            )
                        )
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

            # www/non-www deduplication (D22): a post-live metadata pass, before
            # tech/urls see the hosts. It never changes a state or a confidence.
            if stage is Stage.LIVE and results:
                self._dedupe_www_variants(target_id, hosts)

            selected_total += len(selected)
            # A gap is an external service refusing the tool, not a failure of the
            # run (owner ruling 2026-11-18); it never reaches exit 5.
            failed_total += sum(1 for result in results if not _completed(result.status))
            failed_total += len(selected) - len(results)
            all_ok = len(results) == len(selected) and all(
                _completed(result.status) for result in results
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
            # D58: one bounded pass for names only the URL pool found. It runs
            # after `urls` and before `url_probe` (the next stage in
            # STAGE_ORDER), so an active run's probe sees a real host state.
            if stage is Stage.URLS:
                await self._second_resolve(
                    target, target_id, opts, run_id, discovered, alive, workspace.directory
                )

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
    def _gap_reason(result: ToolResult) -> str:
        """`<tool>: <service message>`, without naming the tool twice.

        Every HTTP adapter already prefixes its own name (`otx: rate limited`),
        a binary's generic `exit N: ...` does not, so only the latter is labelled.
        """
        message = result.error or "external service problem"
        if message.startswith(f"{result.tool}:"):
            return message
        return f"{result.tool}: {message}"

    @staticmethod
    def _is_gap_reason(reason: str) -> bool:
        """The two absence-only skip reasons (docs/02 section 6)."""
        return reason.startswith("no adapter") or reason == "not installed"

    def _completion_gaps(self, summary: ScanSummary) -> list[CompletionGap]:
        """The stages that fell short for a reason that is nobody's fault here.

        Two causes are gaps: a stage whose only skips were an absent tool, and a
        stage where an executed tool was refused by an external service (429,
        quota, upstream 5xx - owner ruling 2026-11-18). A stage emptied by
        `--tools`, `--exclude`, a tier/tool-mode rule, the exploitation rule or
        the scope gate is *not* a gap: those are deliberate exclusions, and the
        scope case is exit 3 anyway.
        """
        gaps: list[CompletionGap] = []
        for outcome in summary.stages:
            if outcome.resumed:
                continue
            # An absent tool only matters when it left the stage with nothing to
            # run; a stage that ran other tools is not short because of it.
            absent = (
                []
                if outcome.results
                else [skip for skip in outcome.skipped if self._is_gap_reason(skip.reason)]
            )
            external = [result for result in outcome.results if result.status is ToolStatus.GAP]
            # R10: a stage whose tools were all handed an empty host list did not
            # get to work, but nothing is broken either - a gap, not a failure.
            idle = [result for result in outcome.results if result.status is ToolStatus.SKIPPED]
            if absent:
                reasons = ", ".join(sorted({skip.reason for skip in absent}))
                gaps.append(CompletionGap(outcome.stage, reasons, len(absent)))
            elif external:
                reasons = ", ".join(sorted(self._gap_reason(result) for result in external))
                gaps.append(CompletionGap(outcome.stage, reasons, 0))
            elif idle and len(idle) == len(outcome.results):
                gaps.append(CompletionGap(outcome.stage, NO_INPUT_HOSTS, len(idle)))
        if self._url_probe_timeout is not None:
            timeout, done, total = self._url_probe_timeout
            gaps.append(
                CompletionGap(
                    Stage.URL_PROBE,
                    f"timed out after {timeout:g}s ({done}/{total} URL(s) probed)",
                    0,
                )
            )
        return gaps

    @staticmethod
    def _empty_stages(summary: ScanSummary) -> list[Stage]:
        """Requested stages that executed zero tools; a resumed stage is not new work.

        `url_probe` is engine-owned and has no tools by design, so an empty
        result list there means "the probe ran", not "the stage was empty"
        (D23); it can never make a run partial.
        """
        return [
            outcome.stage
            for outcome in summary.stages
            if not outcome.resumed and not outcome.results and outcome.stage is not Stage.URL_PROBE
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

    @staticmethod
    def _within_scope(host: str, target: str) -> bool:
        """The target itself, or a name under it (D76).

        One predicate for the URL pool and the report: `target.example` is in
        scope, `*.target.example` is in scope, and `www.google.com` is not.
        """
        return host == target or host.endswith(f".{target}")

    def _clean_hosts(self, hosts: Any, target: str) -> list[str]:
        kept: list[str] = []
        seen: set[str] = set()
        for raw in hosts:
            try:
                host = validate_host(raw)
            except (TypeError, ValueError):
                continue
            if not self._within_scope(host, target):
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
        if reason == NO_SCOPE_MESSAGE:
            note = reason
        elif "not in scope" in reason or "out of scope" in reason:
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
        if opts.no_scope:
            # docs/05 rule 2 (2026-11-17, amended by D82 2026-11-19): no file
            # means active scanning is refused; only the explicit --no-scope
            # opt-out returns the host list untouched.
            return hosts, [], None
        if not scope_present(self.scope_path):
            # D82: fail closed. The CLI refuses before the engine starts; this
            # guard covers direct Engine callers and any future path.
            return hosts, [], NO_SCOPE_MESSAGE
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

    #: Tools whose child is handed addresses reconkit itself verified (docs/05
    #: rule 6). Every other active tool receives hostnames and resolves them
    #: inside the child, so an excluded CIDR cannot be applied to it (D56).
    _CIDR_GATED_TOOLS = frozenset({"pyscan", "naabu"})

    def _scope_gate(self, opts: ScanOptions) -> ScopeGate | None:
        """The scope file's gate, or `None` when there is nothing to enforce."""
        if opts.no_scope or not scope_present(self.scope_path):
            return None
        try:
            return load_scope(self.scope_path)
        except (ConfigError, ScopeError):
            return None

    def _cidr_ungated_tools(self, opts: ScanOptions) -> list[str]:
        """Active tools this run could select that resolve hostnames themselves.

        The rules mirror `_select` (tools, exclude, tier, tool mode, exploitation
        pre-ruling), because naming a tool that will not run would be noise.
        """
        tiers = allowed_tiers(opts.mode, include_noisy=opts.include_noisy)
        tool_modes = MODE_TOOLS[opts.mode].tool_modes
        names: list[str] = []
        for name, spec in self.specs.items():
            if spec.stage not in opts.stages or spec.mode is not Mode.ACTIVE:
                continue
            if name in self._CIDR_GATED_TOOLS or name in opts.exclude:
                continue
            if name not in self.adapters:
                continue
            if opts.tools and name not in opts.tools:
                continue
            if spec.exploitation and name not in opts.tools:
                continue
            if spec.tier not in tiers and name not in opts.tools:
                continue
            if spec.mode not in tool_modes:
                continue
            names.append(name)
        return sorted(names)

    def _cidr_scope_warnings(self, opts: ScanOptions) -> list[str]:
        """D56: say which selected tools cannot honour `exclude_cidrs`.

        Only a scope file with `exclude_cidrs` can produce this; `--no-scope` and
        a missing file have nothing to enforce and stay silent.
        """
        gate = self._scope_gate(opts)
        if gate is None or not gate.has_cidr_exclusions():
            return []
        tools = self._cidr_ungated_tools(opts)
        if not tools:
            return []
        return [
            f"exclude_cidrs is set, but {len(tools)} selected tool(s) resolve hostnames "
            f"inside the child and cannot be CIDR-gated: {', '.join(tools)} "
            "(pyscan and naabu are gated)"
        ]

    def _ip_allowed(self, opts: ScanOptions) -> Callable[[str], bool] | None:
        """docs/05 rule 6 predicate, from the same scope file the active gate read.

        `None` means "no permission": an adapter that connects to a resolved
        address must treat it as a block, so an unreadable scope can only narrow
        what may be contacted, never widen it. D56: the predicate is true only
        inside `in_scope_cidrs` and outside `exclude_cidrs`.
        """
        if opts.no_scope or not scope_present(self.scope_path):
            return allow_all_ip
        gate = self._scope_gate(opts)
        return None if gate is None else gate.ip_allowed

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
            if spec.tier not in tiers and name not in opts.tools and name not in opts.include_tools:
                skipped.append((spec, f"tier not included in {mode} mode"))
                continue
            # D63: `--include <adapter>` is the explicit override for this gate;
            # nothing else may put an active tool into a passive run.
            if spec.mode not in tool_modes and name not in opts.include_tools:
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
            # A tool that simply cannot run without a key (chaos,
            # github-subdomains) is skipped for the same reason: the binary would
            # start and exit, which is a failed result for a missing credential
            # the operator can supply (docs/09 section 4a7, pre-approved D18).
            required = getattr(adapter, "requires_env", ())
            if required and not opts.no_keys:
                absent = [name for name in required if not self.env.get(name)]
                if absent:
                    skipped.append((spec, f"requires {absent[0]}"))
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
        *,
        stage_budget: float,
    ) -> RunContext:
        # Every tool in the stage starts at once and runs at its own natural
        # pace (2026-11-17, MASTER_PLAN D3). D52: no tool gets a runtime cap. It
        # runs until it exits, until it has been silent past its class window
        # (killed, partial output kept), or until the stage budget fires.
        started_at = time.perf_counter()
        ctx = RunContext(
            target=target,
            hosts=hosts,
            ports=list(opts.ports),
            # D52: the stage budget is the only hard wall, so a tool's watchdog
            # ceiling is the time the stage has left, not a per-tool default.
            timeout=max(1.0, stage_budget),
            stage_started=started_at,
            workspace=workspace.directory,
            mock=opts.mock,
            ip_allowed=ip_allowed,
            headers=dict(opts.headers),
            user_agent=self._user_agent(opts.user_agent),
            ffuf_wordlist=opts.ffuf_wordlist,
            resolvers=opts.resolvers,
            results_dir=Path(self.config.results_dir),
            # D52: an idle window per classed tool; no max_s, no floor.
            limits=self._limits(selected),
        )

        total = len(selected)
        running: set[str] = set()
        # D52: idle bookkeeping. `last_output` is touched by the adapter (through
        # `RunContext.activity`) every time its child prints; `windows` is the
        # class idle for that tool; `killed` holds the sentence a killed tool
        # reports. `stops` is the flag a binary child watches so it can exit
        # with its partial output instead of being cancelled outright.
        last_output: dict[str, float] = {}
        windows: dict[str, float] = {}
        stops: dict[str, threading.Event] = {}
        tasks: dict[str, asyncio.Task[None]] = {}
        killed: dict[str, str] = {}
        stop_watch = asyncio.Event()
        # D50: one line per tool that is still running after this many seconds.
        # It is a "still working" signal, not progress: gau printing 1042 URLs in
        # one block has no meaningful percentage, and nothing here parses output.
        heartbeat_started: dict[str, float] = {}
        heartbeats: set[str] = set()
        stop_heartbeat = asyncio.Event()

        async def heartbeat() -> None:
            """Announce each long-running tool once, then stop (D50)."""
            while not stop_heartbeat.is_set():
                try:
                    await asyncio.wait_for(stop_heartbeat.wait(), timeout=HEARTBEAT_AFTER_S)
                except TimeoutError:
                    pass
                else:
                    return
                now = time.perf_counter()
                for name in sorted(running - heartbeats):
                    began = heartbeat_started.get(name)
                    if began is None:
                        continue
                    elapsed = now - began
                    if elapsed < HEARTBEAT_AFTER_S:
                        continue
                    heartbeats.add(name)
                    seconds = max(1, int(round(elapsed)))
                    self._progress(f"{stage.value}: {name} running ({seconds}s)")

        def snapshot() -> None:
            """The live line: how far the stage got and what is still in flight."""
            elapsed = time.perf_counter() - started_at
            names = ", ".join(sorted(running)) or "none"
            self._activity(
                f"{stage.value}: {len(done)}/{total} tool(s) done, "
                f"{elapsed:.0f}s elapsed - running: {names}"
            )

        def touch(name: str) -> None:
            """Record that a tool produced output (called from its child's thread)."""
            last_output[name] = time.perf_counter()

        def request_kill(name: str, elapsed: float) -> None:
            """Mark a tool for an idle kill and let a binary child exit cleanly.

            The stop flag is what a subprocess sees; an adapter that never looks
            at it (a pure-Python one) is cancelled after `KILL_GRACE_S`, so the
            stage still advances. Both paths produce a `killed` result with the
            same sentence.
            """
            if name in killed:
                return
            killed[name] = (
                f"killed after {windows[name]:g}s idle at stage {elapsed:.1f}s, 0 partial"
            )
            stop = stops.get(name)
            if stop is not None:
                stop.set()
            asyncio.create_task(cancel_later(name))

        async def cancel_later(name: str) -> None:
            await asyncio.sleep(KILL_GRACE_S)
            task = tasks.get(name)
            if task is not None and not task.done():
                task.cancel()

        async def watch_idle() -> None:
            """Kill tools that have gone quiet (D52).

            Two cases matter and neither needs a runtime cap: every running tool
            silent past its own window (nothing is producing - stop them all at
            the first window), and one running tool silent with every other tool
            in the stage already finished (it is alone and stuck).
            """
            while not stop_watch.is_set():
                try:
                    await asyncio.wait_for(stop_watch.wait(), timeout=IDLE_WATCH_TICK_S)
                except TimeoutError:
                    pass
                else:
                    return
                now = time.perf_counter()
                pending = [name for name in sorted(running) if name not in killed]
                if not pending:
                    continue
                silent = {name: now - last_output.get(name, now) for name in pending}
                all_idle = all(silent[name] >= windows[name] for name in pending)
                alone = len(pending) == 1 and silent[pending[0]] >= windows[pending[0]]
                if not (all_idle or alone):
                    continue
                for name in pending:
                    if silent[name] >= windows[name]:
                        request_kill(name, now - started_at)

        async def one(spec: ToolSpec, adapter: type[BaseToolAdapter]) -> None:
            stop = threading.Event()
            stops[spec.name] = stop
            overrides: dict[str, object] = {
                "env": self._tool_env(spec, opts),
                "stop": stop,
                "activity": partial(touch, spec.name),
            }
            if spec.name in tool_hosts:
                # docs/05 rule 6: naabu's verified IPs replace the name list.
                overrides["hosts"] = tool_hosts[spec.name]
            tool_ctx = ctx.model_copy(update=overrides)
            running.add(spec.name)
            last_output[spec.name] = time.perf_counter()
            idle = idle_for_tool(spec.name, self.config, specs=self.specs)
            windows[spec.name] = float(idle) if idle is not None else math.inf
            heartbeat_started[spec.name] = time.perf_counter()
            tasks[spec.name] = asyncio.current_task()  # type: ignore[assignment]
            snapshot()
            finished = False
            try:
                result = await self._run_one(run_id, adapter, tool_ctx, workspace)
                finished = True
            except asyncio.CancelledError:
                detail = killed.get(spec.name)
                if detail is None:
                    raise
                # The watchdog stopped this tool; it never produced a result of
                # its own, so the engine writes the row and reports the kill.
                duration = time.perf_counter() - started_at
                result = ToolResult(
                    tool=adapter.name,
                    status=ToolStatus.KILLED,
                    error=detail,
                    duration_s=duration,
                    last_output_s=last_output.get(spec.name, started_at) - started_at,
                )
                self._record(
                    run_id,
                    adapter.name,
                    ToolStatus.KILLED,
                    item_count=0,
                    duration_s=duration,
                    error=detail,
                )
                self._progress(f"{stage.value}: {adapter.name} killed 0 item(s)")
                finished = True
            finally:
                # Both sets move before the snapshot, or the line a finished tool
                # produces would still count it as running (found 2026-11-18). A
                # cancelled tool is not done: the phase-timeout bookkeeping reads
                # `done` to decide which tools get a timeout row.
                running.discard(spec.name)
                if finished:
                    done.add(spec.name)
                snapshot()
            results.append(result)

        # No durable-line sink (`--silent`) means no heartbeat task at all.
        beat_task = asyncio.create_task(heartbeat()) if self._progress_cb is not None else None
        watch_task = asyncio.create_task(watch_idle())
        try:
            await asyncio.gather(*(one(spec, adapter) for spec, adapter in selected))
        finally:
            stop_heartbeat.set()
            stop_watch.set()
            if beat_task is not None:
                await asyncio.gather(beat_task, return_exceptions=True)
            await asyncio.gather(watch_task, return_exceptions=True)
        return ctx

    def _limits(self, selected: Selected) -> dict[str, ToolLimits]:
        """The idle window per tool for one stage (docs/09 4a2b, D52).

        No `max_s` and no `min_s`: a tool runs until it exits, until it is silent
        past its window, or until the stage budget. A tool with no class and no
        `idle_s:` entry gets no window at all, so only the stage budget bounds
        it - the same shape every tool had before any of this existed.
        """
        limits: dict[str, ToolLimits] = {}
        for spec, _adapter in selected:
            idle = idle_for_tool(spec.name, self.config, specs=self.specs)
            if idle is None:
                continue
            limits[spec.name] = ToolLimits(idle_s=idle)
        return limits

    def _user_agent(self, override: str | None) -> str:
        """The effective User-Agent: flag, else config, with {version} filled."""
        value = override if override else self.config.user_agent
        return value.replace("{version}", __version__)

    async def _run_one(
        self,
        run_id: int,
        adapter: type[BaseToolAdapter],
        ctx: RunContext,
        workspace: Workspace,
    ) -> ToolResult:
        started = time.perf_counter()
        skipped_for_input = adapter.stage in HOST_INPUT_STAGES and not ctx.hosts
        if skipped_for_input:
            # R10 (2026-11-19): a stage tool handed no hosts has nothing to do.
            # Calling the adapter only to turn its own "no hosts to crawl" guard
            # into a failed result made a starved run read as nine broken tools
            # and exit 5. The tool never ran, so it is skipped, not failed, and
            # the stage becomes a completion gap (exit 0). `live` and `dns`
            # always receive the target itself, so this can never skip a tool
            # that legitimately works on the apex.
            result = ToolResult(tool=adapter.name, status=ToolStatus.SKIPPED, error=NO_INPUT_HOSTS)
        else:
            try:
                result = await asyncio.wait_for(adapter().run(ctx), timeout=ctx.timeout)
            except TimeoutError:
                # D52: the budget is the only hard wall left, and reaching it is
                # still `timeout` (R13/D45): a tool that did not finish in the
                # stage's time is a real signal. Only an idle kill is `killed`.
                result = ToolResult(
                    tool=adapter.name,
                    status=ToolStatus.TIMEOUT,
                    error=f"timed out at stage budget {ctx.timeout:g}s",
                )
            except Exception as exc:
                result = ToolResult(
                    tool=adapter.name,
                    status=ToolStatus.FAILED,
                    error=redact(f"{type(exc).__name__}: {exc}", self._secrets),
                )
        update: dict[str, object] = {
            # A tool that never ran has nothing to capture.
            "raw_path": None
            if skipped_for_input
            else self._write_raw(workspace, run_id, adapter, result)
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
            self._persist_discovery(target_id, run_id, results, opts, target)
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
            self._persist_ports(target_id, run_id, results, opts, target)
        elif stage is Stage.TECH:
            self._persist_tech(target_id, run_id, results, target)
        elif stage is Stage.URLS:
            self._persist_urls(target_id, run_id, results, opts, target)

    def _persist_discovery(
        self,
        target_id: int,
        run_id: int,
        results: list[ToolResult],
        opts: ScanOptions,
        target: str,
    ) -> None:
        """Store the union of discovery tools, one row per canonical host.

        An adapter's record is untrusted input: a source can print mixed case, a
        trailing dot or a `*.` prefix, and a broken or malicious parser can name
        a host outside the target. Canonicalizing here (not only in each adapter)
        means the `subdomains` unique key sees one spelling and a foreign name is
        never stored (PIT-69). `_clean_hosts` is the same gate every stage input
        passes.
        """
        groups: dict[str, tuple[set[str], list[SubdomainRecord]]] = {}
        for result in results:
            if result.status is not ToolStatus.OK:
                continue
            for record in result.records:
                if not isinstance(record, SubdomainRecord):
                    continue
                for fqdn in self._clean_hosts([record.fqdn], target):
                    tools, records = groups.setdefault(fqdn, (set(), []))
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
        self,
        target_id: int,
        run_id: int,
        results: list[ToolResult],
        opts: ScanOptions,
        target: str,
    ) -> None:
        """Store the URL pool, keeping third-party URLs apart (D76).

        A URL whose host is not the target or under it is still stored - an
        archive named it, and dropping it would lose evidence - but it carries
        `source = 'external'`, so it never becomes a `subdomains` row, a
        `hosts/<host>/` folder, or part of `urls_by_host`.

        D77: each `urls` tool also gets `unique_count`, the distinct URLs it
        contributed that the target did not already hold. The first result (in
        completion order) that reports a new URL gets the credit, so the sum
        over the stage is exactly the number of new rows a tool added.
        """
        groups: dict[str, set[str]] = {}
        for result in results:
            if result.status is not ToolStatus.OK:
                continue
            for record in result.records:
                if isinstance(record, UrlRecord):
                    url = normalize_url(record.url)
                    if url is not None:
                        groups.setdefault(url, set()).add(result.tool)
        # Compare canonical forms: a legacy row may be stored as the non-canonical
        # spelling (`https://host`), and its canonical twin must not be inserted
        # beside it (PIT-68).
        stored_urls = self.store.url_strings(target_id)
        known = {normalize_url(url) or url for url in stored_urls}
        spelling = {normalize_url(url) or url: url for url in stored_urls}
        credited: set[str] = set()
        for result in results:
            if result.status is not ToolStatus.OK:
                continue
            new = 0
            for record in result.records:
                if not isinstance(record, UrlRecord):
                    continue
                url = normalize_url(record.url)
                if url is None or url in known or url in credited:
                    continue
                if len(groups[url]) < opts.min_sources:
                    continue
                credited.add(url)
                new += 1
            result.unique_count = new
        for url, tools in groups.items():
            if len(tools) < opts.min_sources:
                continue
            host = self._url_host(url)
            source = "external" if host and not self._within_scope(host, target) else None
            # Update a legacy row under its own spelling instead of inserting its
            # canonical twin, so a re-scan neither duplicates nor freezes
            # `last_seen_run` (PIT-68).
            self.store.upsert_url(
                target_id,
                spelling.get(url, url),
                run_id=run_id,
                source_count=len(tools),
                source=source,
            )

    # ------------------------------------------------------- D58 second resolve

    async def _second_resolve(
        self,
        target: str,
        target_id: int,
        opts: ScanOptions,
        run_id: int,
        discovered: set[str],
        alive: set[str],
        workspace: Path,
    ) -> None:
        """One bounded pass for hostnames only the URL pool revealed (D58).

        A `urls` pass writes URLs, never hosts: a name an archive mentions but no
        subdomain source reports has no `subdomains` row, no state and no report
        line (measured 2026-11-19: 3 hosts carrying 43 URLs on target.example).
        This runs once, immediately after `urls`, and never re-extracts - the
        candidates come from the URL rows already stored, so its own output can
        never feed a second round.

        Passive resolves and stops: DNS queries already happen in a passive
        run's `dns` stage, while HTTP contact does not. Active/full additionally
        probes the new hosts, so `url_probe` finds their URLs on a host that has
        a real state instead of one nothing ever resolved.

        D75: in active/full the pass also picks up the hosts an earlier D58 pass
        created but never tech-scanned (`Store.url_derived_unprocessed()`). Those
        already have a `subdomains` row, so `url_only_hosts()` will never offer
        them again, and a fresh run does not seed `discovered` from the store -
        without this they stay orphaned forever. They are not re-resolved; they
        get the live probe and the tech pool only.

        Bounds: no new config key. The pass inherits a stage budget - `urls` in
        passive, `url_probe` in active/full, because that is the stage whose
        input the new state exists to serve. A pass that hits it leaves the rows
        as they were and says so; it never fails the run.
        """
        # The store is thread-bound (docs/03 section 11), so this read stays on
        # the loop like every other query, not in a worker thread.
        candidates = self._clean_hosts(self.store.url_only_hosts(target_id), target)
        hosts = list(dict.fromkeys(candidates))
        live = opts.active
        orphans: list[str] = []
        if live:
            orphans = [
                host
                for host in self._clean_hosts(self.store.url_derived_unprocessed(target_id), target)
                if host not in hosts
            ]
        if not hosts and not orphans:
            self._progress("urls: 0 host(s) found only in URLs; resolved")
            return
        budget = self._stage_timeout(Stage.URL_PROBE if live else Stage.URLS)
        try:
            now_alive = await asyncio.wait_for(
                self._second_resolve_pass(
                    target,
                    target_id,
                    opts,
                    run_id,
                    hosts,
                    orphans,
                    discovered,
                    alive,
                    workspace,
                    live=live,
                    budget=budget,
                ),
                timeout=budget,
            )
        except TimeoutError:
            self._progress(
                f"urls: second resolve timed out after {budget:g}s; "
                f"{len(hosts)} host(s) left as they were"
            )
            return
        if live:
            if hosts:
                self._progress(
                    f"urls: {len(hosts)} host(s) found only in URLs; "
                    f"resolved, {now_alive} now ALIVE"
                )
            if orphans:
                self._progress(
                    f"urls: {len(orphans)} url-derived host(s) already known; "
                    "tech-scanned on follow-up"
                )
        else:
            self._progress(f"urls: {len(hosts)} host(s) found only in URLs; resolved")

    async def _second_resolve_pass(
        self,
        target: str,
        target_id: int,
        opts: ScanOptions,
        run_id: int,
        hosts: list[str],
        orphans: list[str],
        discovered: set[str],
        alive: set[str],
        workspace: Path,
        *,
        live: bool,
        budget: float,
    ) -> int:
        """Resolve the candidates, label where they came from, optionally probe.

        Both steps call the adapters the `dns` and `live` stages already use
        (`dnspython`, `pyprobe`), through their normal `run(ctx)` - so `--mock`
        reads fixtures exactly like every other stage and no resolver is
        duplicated here. Missing adapters (a test that injects none) mean the
        pass does nothing rather than crash: 0 models available, 0 writes.
        """
        ctx = RunContext(
            target=target,
            hosts=hosts,
            ports=list(opts.ports),
            timeout=max(1.0, budget),
            workspace=workspace,
            mock=opts.mock,
            headers=dict(opts.headers),
            user_agent=self._user_agent(opts.user_agent),
            results_dir=Path(self.config.results_dir),
        )
        dns_results: list[ToolResult] = []
        if hosts:
            dns_results = await self._second_resolve_dns(ctx)
            self._label_url_derived(target_id, run_id, hosts)
            with self.store.transaction():
                self._persist_dns(target_id, run_id, dns_results, target, defer=live)
            discovered.update(hosts)
        if not live:
            return 0
        # D75: the orphans join the same pass, but never the DNS step - a host
        # that already has a state is not resolved again.
        targets = list(dict.fromkeys([*hosts, *orphans]))
        if not targets:
            return 0
        # Active contact needs the same gate as every other active stage, and
        # only for the hosts this pass would touch.
        allowed, _dropped, scope_error = await asyncio.to_thread(
            self._active_hosts, target, targets, opts
        )
        if scope_error is not None:
            self._progress(
                f"urls: live check of URL-only hosts refused by the scope gate ({scope_error})"
            )
            return 0
        if not allowed:
            return 0
        live_results = await self._second_resolve_live(ctx, allowed)
        with self.store.transaction():
            self._persist_live(
                target_id, run_id, live_results, dns_results, target, allowed, opts, alive
            )
        self._update_discovered(Stage.LIVE, live_results, target, discovered, alive)
        # D75: tech runs after live because `_persist_tech` merges into the
        # newest status row and never creates one (docs/04 section 5). Hosts this
        # pass discovers are handled on the next run, not fed back into this one.
        tech_results = await self._second_resolve_tech(ctx, allowed, opts)
        if tech_results:
            with self.store.transaction():
                self._persist_tech(target_id, run_id, tech_results, target)
        return sum(1 for host in allowed if host in alive)

    async def _second_resolve_dns(self, ctx: RunContext) -> list[ToolResult]:
        """The `dns` stage's own Python adapter, on this pass's ctx only."""
        adapter = self.adapters.get("dnspython")
        if adapter is None:
            return []
        return [await adapter().run(ctx)]

    async def _second_resolve_live(self, ctx: RunContext, hosts: list[str]) -> list[ToolResult]:
        """The `live` stage's Python probe, one adapter rather than the pool.

        One binary-free probe keeps the pass bounded (the pool would need four
        `tool_runs` rows under the `urls` run id) while `_persist_live` applies
        the same ALIVE/DNS_ONLY/UNKNOWN state rule the stage applies.
        """
        adapter = self.adapters.get("pyprobe")
        if adapter is None:
            return []
        probe_ctx = ctx.model_copy(update={"hosts": list(hosts)})
        return [await adapter().run(probe_ctx)]

    async def _second_resolve_tech(
        self, ctx: RunContext, hosts: list[str], opts: ScanOptions
    ) -> list[ToolResult]:
        """The `tech` stage's pool on this pass's ctx, for hosts that never got it (D75).

        The same adapters, `run(ctx)` and mock fixtures as the stage, so a
        follow-up run sees what `tech` would have seen. The results go through
        `_persist_tech`, which annotates each host's newest status row. One
        round only: a tech tool that names a new host starts nothing here.
        """
        selected, _skipped = await self._select(Stage.TECH, opts)
        if not selected:
            return []
        tech_ctx = ctx.model_copy(update={"hosts": list(hosts)})
        return [await adapter().run(tech_ctx) for _spec, adapter in selected]

    def _label_url_derived(self, target_id: int, run_id: int, hosts: list[str]) -> None:
        """Create the missing rows and name the URL pool as what found them.

        `provenance` stays `dns` - a DNS pass did create the row - and the one
        `subdomain_sources` entry carries the sentinel `url-derived`, so the
        report's sources column says where the name came from instead of
        showing a host with no origin. `source_count` follows the same rule as
        every other row: one distinct source in this run (docs/04 section 5).
        """
        for host in hosts:
            sub_id = self.store.upsert_subdomain(target_id, host, run_id=run_id, source_count=1)
            self.store.add_subdomain_source(sub_id, run_id, URL_DERIVED)

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

    async def _run_url_probe(
        self, target: str, target_id: int, opts: ScanOptions, *, scan_key: str
    ) -> tuple[StageOutcome | None, str | None]:
        """The `url_probe` stage (D23, 2026-11-18).

        Engine-owned: there is no adapter and no `tools.yaml` entry, so this pass
        sends the requests itself with the honest `reconkit/<version>` UA and
        writes `urls.status_code` - nothing else. A URL that does not answer is
        stored as `UNREACHABLE`, which is a *stored answer*, so a dead URL is
        paid for once and `NULL` keeps its one meaning: "not probed yet".

        Bounds come from `config.yaml` `url_probe:`. `--mock` never touches the
        network, so it leaves every `status_code` at `NULL` and says so instead
        of inventing answers. The scope gate is the same one every active stage
        goes through (docs/05 rule 2).
        """
        settings = self.config.url_probe
        limit = settings.max_urls + 1 if settings.max_urls else None
        plan = self.store.probe_candidates(target_id, limit=limit, reprobe=opts.reprobe_urls)
        rows = plan.rows
        if plan.skipped_unreachable:
            self._progress(
                f"url_probe: skipping {plan.skipped_unreachable} URL(s) whose host is unreachable"
            )
        if settings.max_urls and len(rows) > settings.max_urls:
            rows = rows[: settings.max_urls]
            note = (
                f"url_probe: probed the first {settings.max_urls} URL(s) only; "
                "re-run to probe the rest"
            )
            if note not in self._warnings:
                self._warnings.append(note)
        run_id = self.store.create_scan_run(
            target_id,
            Stage.URL_PROBE.value,
            params=json.dumps(
                {
                    "scan_key": scan_key,
                    "mode": opts.mode,
                    "tools": [],
                    "mock": opts.mock,
                    "active": opts.active,
                    "reprobe": opts.reprobe_urls,
                    "no_keys": opts.no_keys,
                    "min_sources": opts.min_sources,
                }
            ),
            started_at=self._now(),
            scope_mode=self._scope_mode(opts),
            secrets=self._secrets,
        )
        outcome = StageOutcome(stage=Stage.URL_PROBE, run_id=run_id)
        self._url_probe_outcome = outcome
        self._url_probe_progress = (0, 0)
        if not rows:
            self._progress("url_probe: nothing to probe")
            self.store.finish_scan_run(run_id, "completed", finished_at=self._now())
            return outcome, None
        if opts.mock:
            note = f"url_probe: skipped in --mock ({len(rows)} URL(s) left unprobed)"
            if note not in self._warnings:
                self._warnings.append(note)
            self._progress(note)
            self.store.finish_scan_run(run_id, "completed", finished_at=self._now())
            return outcome, None

        hosts = self._clean_hosts([self._url_host(str(row["url"])) for row in rows], target)
        allowed = set(hosts)
        if opts.active or opts.forced_contact:
            kept, _dropped, scope_error = await asyncio.to_thread(
                self._active_hosts, target, hosts, opts
            )
            if scope_error is not None:
                self.store.finish_scan_run(run_id, "completed", finished_at=self._now())
                return outcome, scope_error
            allowed = set(kept)
        pending = [row for row in rows if self._url_host(str(row["url"])) in allowed]
        self._url_probe_progress = (0, len(pending))
        if not pending:
            self._progress("url_probe: nothing to probe (no in-scope URL)")
            self.store.finish_scan_run(run_id, "completed", finished_at=self._now())
            return outcome, None

        self._progress(f"url_probe: probing {len(pending)} URL(s)")
        done = 0
        buffer: list[tuple[int, int]] = []

        def commit() -> None:
            """Flush finished answers; `batch_size` is the transaction size only."""
            nonlocal done
            if not buffer:
                return
            with self.store.transaction():
                for url_id, status in buffer:
                    self.store.set_url_status(url_id, status)
            done += len(buffer)
            buffer.clear()
            self._url_probe_progress = (done, len(pending))
            if done < len(pending):
                self._progress(f"url_probe: {done}/{len(pending)} URL(s) probed")

        # One client for the whole pass (D24). Results are committed as they
        # come in: a 200-URL gather used to make the slowest URL in each group
        # stall the next group, so one 10 s timeout cost the whole pass ~10 s.
        async with self._url_probe_client(settings) as client:
            semaphore = asyncio.Semaphore(settings.threads)

            async def probe(row: dict[str, object]) -> tuple[int, int]:
                async with semaphore:
                    return await self._probe_one(client, int(cast(int, row["id"])), str(row["url"]))

            tasks = [asyncio.create_task(probe(row)) for row in pending]
            try:
                for finished in asyncio.as_completed(tasks):
                    buffer.append(await finished)
                    if len(buffer) >= settings.batch_size:
                        commit()
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                # A pass killed by its deadline keeps every finished answer (D26).
                commit()
        self._progress(f"url_probe: finished {done} URL(s)")
        self.store.finish_scan_run(run_id, "completed", finished_at=self._now())
        return outcome, None

    def _url_probe_timed_out(self, timeout: float) -> StageOutcome:
        """Finish a probe pass that hit its deadline (D26, verification gap 4).

        Every completed batch is already committed, so the partial answers keep
        their place and the URLs that were never reached stay `NULL` for the
        next run. The pass is recorded as `partial`, the run keeps exit 0, and a
        completion gap names what was cut off - a timed-out probe is not a
        failed scan.
        """
        outcome = self._url_probe_outcome or StageOutcome(Stage.URL_PROBE, run_id=-1)
        done, total = self._url_probe_progress
        if outcome.run_id > 0:
            self.store.finish_scan_run(outcome.run_id, "partial", finished_at=self._now())
        note = f"url_probe: timed out after {timeout:g}s ({done}/{total} URL(s) probed)"
        if note not in self._warnings:
            self._warnings.append(note)
        self._progress(note)
        self._url_probe_timeout = (timeout, done, total)
        return outcome

    def _url_probe_client(self, settings: UrlProbeConfig) -> httpx.AsyncClient:
        """The one HTTP client a `url_probe` pass uses (D24).

        Default certificate verification stays on: a certificate that does not
        match the URL is an answer about that URL, and it is recorded as
        `UNTRUSTED` rather than hidden by turning verification off (which is
        also what PD httpx does by default - see docs/09 section 5).
        """
        return httpx.AsyncClient(
            limits=httpx.Limits(
                max_connections=settings.threads,
                max_keepalive_connections=settings.threads,
            ),
            timeout=httpx.Timeout(float(settings.timeout_s)),
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
            transport=self._url_probe_transport,
        )

    async def _probe_one(self, client: httpx.AsyncClient, url_id: int, url: str) -> tuple[int, int]:
        """One GET; an answer code, `UNREACHABLE` or `UNTRUSTED`."""
        try:
            response = await client.get(url)
        except (httpx.HTTPError, OSError, ValueError) as exc:
            if _certificate_not_verified(exc):
                return (url_id, UNTRUSTED)
            return (url_id, UNREACHABLE)
        return (url_id, int(response.status_code))

    @staticmethod
    def _url_host(url: str) -> str:
        return (urlsplit(url).hostname or "").lower()

    def _dedupe_www_variants(self, target_id: int, hosts: list[str]) -> None:
        """Mark a www/non-www pair as one website (D22, 2026-11-18).

        Metadata only: it reads the rows the `live` pass just stored and writes
        `duplicate_of`/`www_note` on the newest status row. Host state,
        confidence, `status_code` and every count query are untouched, and a
        pair that cannot be explained (different non-2xx codes) is left alone.

        Rules (docs/09 section 5):

        - one 3xx and one 2xx -> the 3xx name is the duplicate of the 2xx name;
        - both 2xx -> both serve content, neither is a duplicate (sibling note);
        - same **known** non-2xx status and a shared IP -> `www.X` is a duplicate
          of `X` (the bare name is the web convention for the canonical one);
          `NULL` is "no HTTP status observed", not a status the two names share,
          so a pair with no status on either side is never marked (D25);
        - same status, different IPs -> different servers, sibling note only;
        - one alive, one not -> nothing (a dead variant is not a duplicate of a
          live site, it is a name that does not resolve).
        """
        rows: dict[str, dict[str, object]] = {
            str(row["fqdn"]): row for row in self.store.host_rows(target_id)
        }
        current = set(hosts)
        for fqdn in sorted(rows):
            if not fqdn.startswith("www."):
                continue
            bare = fqdn[len("www.") :]
            other = rows.get(bare)
            if other is None or fqdn not in current or bare not in current:
                continue
            if rows[fqdn]["state"] != HostState.ALIVE.value:
                continue
            if other["state"] != HostState.ALIVE.value:
                continue
            www_status = rows[fqdn]["status_code"]
            bare_status = other["status_code"]
            www_ip = set(cast(tuple[str, ...], rows[fqdn]["ips"]))
            bare_ip = set(cast(tuple[str, ...], other["ips"]))
            duplicate: str | None = None
            canonical: str | None = None
            note: str | None = None
            if _is_redirect(bare_status) and _is_2xx(www_status):
                duplicate, canonical = bare, fqdn
            elif _is_redirect(www_status) and _is_2xx(bare_status):
                duplicate, canonical = fqdn, bare
            elif _is_2xx(bare_status) and _is_2xx(www_status):
                # Both names serve content: two sites, not a duplicate (rule 2).
                self.store.set_host_duplicate(
                    target_id, bare, duplicate_of=None, www_note=f"has www sibling at {fqdn}"
                )
                self.store.set_host_duplicate(
                    target_id, fqdn, duplicate_of=None, www_note=f"has www sibling at {bare}"
                )
                continue
            elif (
                www_status is not None
                and bare_status is not None
                and www_status == bare_status
                and www_ip & bare_ip
            ):
                # Both codes must be known: `NULL == NULL` is not evidence that
                # the two names answer the same way (D25, verification gap 2).
                duplicate, canonical = fqdn, bare
            elif www_status == bare_status and www_ip and bare_ip and not (www_ip & bare_ip):
                # Known and disjoint: two servers. With no DNS evidence for
                # either name we say nothing rather than guess.
                note = "www variant on a different server"
            if duplicate is not None and canonical is not None:
                self.store.set_host_duplicate(target_id, duplicate, duplicate_of=canonical)
            elif note is not None:
                self.store.set_host_duplicate(target_id, bare, duplicate_of=None, www_note=note)
                self.store.set_host_duplicate(target_id, fqdn, duplicate_of=None, www_note=note)

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
            best = _best_live_record(records)
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
        self,
        target_id: int,
        run_id: int,
        results: list[ToolResult],
        opts: ScanOptions,
        target: str,
    ) -> None:
        """Store one row per (host, address, port, protocol) the tools agree on.

        The natural key includes the protocol (docs/04 schema): `tcp/53` and
        `udp/53` are different findings, and storing a UDP observation as TCP is
        a false fact. The record's host is canonicalized and scope-filtered like
        every other persisted host, so an adapter naming a foreign host cannot
        create a row (PIT-70).
        """
        groups: dict[tuple[str, str, int, str], dict[str, list[PortRecord]]] = {}
        for result in results:
            if result.status is not ToolStatus.OK:
                continue
            for record in result.records:
                if not isinstance(record, PortRecord):
                    continue
                for fqdn in self._clean_hosts([record.fqdn], target):
                    key = (fqdn, record.ip, record.port, record.protocol)
                    groups.setdefault(key, {}).setdefault(result.tool, []).append(record)
        for (fqdn, ip, port, protocol), by_tool in groups.items():
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
                protocol=protocol,
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


def _certificate_not_verified(exc: BaseException) -> bool:
    """True when a probe failed because the TLS certificate did not verify.

    httpx wraps the stdlib error and httpcore re-raises it implicitly, so the
    ssl error hangs off `__context__` as often as off `__cause__`; the check walks
    both links (with a visited guard, because a chain can revisit an error)
    rather than matching on the message. Used only to tell
    `urls.status_code = -2` apart from `-1` (D23); verification itself is never
    turned off.
    """
    pending: list[BaseException] = [exc]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        pending.extend(
            link
            for link in (current.__cause__, current.__context__)
            if isinstance(link, BaseException)
        )
    return False
