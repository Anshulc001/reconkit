"""Pydantic models and enums shared across layers (docs/09_TOOL_CONTRACTS.md)."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field

from reconkit.core.pacing import Pacer


class Stage(StrEnum):
    SUBS = "subs"
    DNS = "dns"
    LIVE = "live"
    PORTS = "ports"
    TECH = "tech"
    URLS = "urls"
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
    severity: Literal["info", "low", "medium", "high", "critical"]
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


class InstallStatus(BaseModel):
    installed: bool
    version: str | None = None
    path: Path | None = None


class RunContext(BaseModel):
    """Everything an adapter may read for one run. Built by the engine."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    target: str
    hosts: list[str] = []
    speed: Literal["slow", "normal", "fast"] = "slow"
    pacer: Pacer
    timeout: float
    workspace: Path
    mock: bool = False
    env: dict[str, str] = {}
