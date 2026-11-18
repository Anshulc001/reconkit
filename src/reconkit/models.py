"""Pydantic models and enums shared across layers (docs/09_TOOL_CONTRACTS.md)."""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field


class Stage(StrEnum):
    SUBS = "subs"
    DNS = "dns"
    LIVE = "live"
    PORTS = "ports"
    TECH = "tech"
    URLS = "urls"
    # URL liveness probe (D23): engine-owned, no adapter, no tools.yaml entry.
    URL_PROBE = "url_probe"
    VULNS = "vulns"
    SHOTS = "shots"


class Tier(StrEnum):
    CORE = "core"
    OPT_IN = "opt_in"
    INTRUSIVE = "intrusive"


class Mode(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"


class HostState(StrEnum):
    ALIVE = "ALIVE"
    DNS_ONLY = "DNS_ONLY"
    SHUT_DOWN = "SHUT_DOWN"
    DEAD = "DEAD"
    UNKNOWN = "UNKNOWN"


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNCONFIRMED = "UNCONFIRMED"


class ToolStatus(StrEnum):
    OK = "ok"
    # The tool ran and an external service refused it (429, quota, upstream 5xx).
    # A completion gap, never a failure (owner ruling 2026-11-18, docs/02 s5-6).
    GAP = "gap"
    SKIPPED = "skipped"
    FAILED = "failed"
    TIMEOUT = "timeout"


class SubdomainRecord(BaseModel):
    fqdn: str
    source: str
    ips: list[str] = []
    cnames: list[str] = []


class HostStatusRecord(BaseModel):
    fqdn: str
    source: str
    state: HostState
    status_code: int | None = None
    title: str | None = None
    location: str | None = None
    # Why the pass could not decide a better state (UNKNOWN only). The store
    # bounds and redacts it before it reaches the database (docs/04 section 5).
    detail: str | None = None
    ips: list[str] = []
    tech: list[str] = []
    waf: str | None = None


class PortRecord(BaseModel):
    fqdn: str
    ip: str
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    state: Literal["open", "closed"]
    service: str | None = None
    version: str | None = None
    source: str


class UrlRecord(BaseModel):
    url: str
    source: str


class FindingRecord(BaseModel):
    fqdn: str
    kind: str
    # `unknown` is a real nuclei severity (42 installed templates declare it).
    severity: Literal["info", "low", "medium", "high", "critical", "unknown"]
    title: str
    evidence: str | None = None
    template_id: str | None = None
    source: str


Record: TypeAlias = SubdomainRecord | HostStatusRecord | PortRecord | UrlRecord | FindingRecord


class ToolResult(BaseModel):
    tool: str
    status: ToolStatus
    records: list[Record] = []
    duration_s: float = 0.0
    error: str | None = None
    raw_path: str | None = None
    # Captured output for the raw-output file (docs/09 section 3). It is
    # unredacted in memory and redacted only by Workspace.write, so it is
    # excluded from every serialization (`--json` included).
    raw_text: str | None = Field(default=None, exclude=True)


class InstallStatus(BaseModel):
    installed: bool
    version: str | None = None
    path: Path | None = None


class ToolLimits(BaseModel):
    """Per-tool runtime bounds the engine reads from `config.yaml` (`urls:`).

    `max_s` is a hard cap, `idle_s` kills a tool whose stdout has been silent
    that long and `min_s` is the floor below which idleness cannot kill. They
    reach an adapter through `RunContext.limits`, so an adapter never reads the
    config file itself (docs/09 sections 4a2b and 4a3).
    """

    max_s: float | None = None
    idle_s: float | None = None
    min_s: float | None = None
    note: str = ""


class RunContext(BaseModel):
    """Everything an adapter may read for one run. Built by the engine."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    target: str
    hosts: list[str] = []
    ports: list[int] = []
    timeout: float
    workspace: Path
    mock: bool = False
    env: dict[str, str] = {}
    # `--header` / `--user-agent` (docs/02 section 3). Adapters that can send a
    # header apply these; the rest ignore them and the engine warns once.
    headers: dict[str, str] = {}
    user_agent: str | None = None
    # `--ffuf-wordlist` (docs/02 section 3): a user-supplied list replaces the
    # packaged default for content discovery. `None` means "use the packaged one".
    ffuf_wordlist: Path | None = None
    # `--resolvers` (D16): a resolver list for massdns/puredns. `None` means the
    # packaged `src/reconkit/data/resolvers.txt`.
    resolvers: Path | None = None
    # The configured results root, so a per-run artifact adapter (gowitness,
    # D17) writes under the same `results/` the reports use.
    results_dir: Path | None = None
    # Runtime bounds per tool name, from `config.yaml` `urls:` (docs/09 4a2b).
    limits: dict[str, ToolLimits] = {}
    # docs/05 rule 6: the loaded scope's `in_scope_cidrs` check, handed down by the
    # engine so an adapter can refuse a resolved address without importing `scope`.
    # `None` means "no permission": an adapter that connects to a resolved address
    # must treat it as a block, never as an allow.
    ip_allowed: Callable[[str], bool] | None = None
