"""dnspython DNS adapter (docs/09_TOOL_CONTRACTS.md).

Resolves A/AAAA/CNAME per host. Only NXDOMAIN maps to DEAD: "no answer",
SERVFAIL and timeouts are counted, never turned into a false DEAD state.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from reconkit.adapters.base import BaseToolAdapter, records_output
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError
from reconkit.models import (
    HostState,
    HostStatusRecord,
    Record,
    RunContext,
    Stage,
    SubdomainRecord,
    ToolResult,
    ToolStatus,
)


class DnsOutcome(StrEnum):
    RESOLVED = "resolved"
    NXDOMAIN = "nxdomain"
    NOANSWER = "noanswer"
    SERVFAIL = "servfail"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class DnsResult:
    outcome: DnsOutcome
    ips: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)


class DnsPythonAdapter(BaseToolAdapter):
    name = "dnspython"
    stage = Stage.DNS

    def __init__(
        self,
        *,
        resolver: Any = None,
        lifetime: float = 5.0,
        fixtures_dir: Path | None = None,
    ) -> None:
        super().__init__(fixtures_dir=fixtures_dir)
        self._resolver = resolver
        self._lifetime = lifetime

    async def run(self, ctx: RunContext) -> ToolResult:
        started = time.perf_counter()
        if ctx.mock:
            fixture = ""
            try:
                fixture = self._read_fixture(ctx)
                mock_records = self.parse_output(fixture)
            except ParseError as exc:
                return ToolResult(
                    tool=self.name,
                    status=ToolStatus.FAILED,
                    error=str(exc),
                    duration_s=time.perf_counter() - started,
                    raw_text=fixture,
                )
            return ToolResult(
                tool=self.name,
                status=ToolStatus.OK,
                records=mock_records,
                duration_s=time.perf_counter() - started,
                raw_text=fixture,
            )

        hosts: list[str] = []
        invalid = 0
        for host in ctx.hosts:
            try:
                hosts.append(validate_host(host))
            except (TypeError, ValueError):
                invalid += 1
        results = await asyncio.gather(*(self.resolve_host(ctx, host) for host in hosts))
        records: list[Record] = []
        counts: dict[DnsOutcome, int] = {}
        for host, result in zip(hosts, results, strict=True):
            counts[result.outcome] = counts.get(result.outcome, 0) + 1
            if result.outcome is DnsOutcome.RESOLVED:
                records.append(
                    SubdomainRecord(
                        fqdn=host,
                        source=self.name,
                        ips=result.ips,
                        cnames=result.cnames,
                    )
                )
            elif result.outcome is DnsOutcome.NXDOMAIN:
                records.append(HostStatusRecord(fqdn=host, source=self.name, state=HostState.DEAD))
        problems = {
            outcome.value: count
            for outcome, count in counts.items()
            if outcome in (DnsOutcome.SERVFAIL, DnsOutcome.TIMEOUT, DnsOutcome.ERROR)
        }
        if invalid:
            problems["invalid"] = invalid
        error = None
        if problems:
            error = ", ".join(f"{name}={count}" for name, count in sorted(problems.items()))
        return ToolResult(
            tool=self.name,
            status=ToolStatus.OK,
            records=records,
            error=error,
            duration_s=time.perf_counter() - started,
            raw_text=records_output(records, error),
        )

    async def resolve_host(self, ctx: RunContext, host: str) -> DnsResult:
        """Resolve one host; every failure mode stays distinct."""
        try:
            host = validate_host(host)
        except (TypeError, ValueError):
            return DnsResult(DnsOutcome.ERROR)
        ips: list[str] = []
        cnames: list[str] = []
        try:
            ips.extend(await self._query(ctx, host, "A"))
            ips.extend(await self._query(ctx, host, "AAAA"))
            cnames.extend(await self._query(ctx, host, "CNAME"))
        except dns.resolver.NXDOMAIN:
            return DnsResult(DnsOutcome.NXDOMAIN)
        except dns.resolver.NoNameservers:
            return DnsResult(DnsOutcome.SERVFAIL)
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            return DnsResult(DnsOutcome.TIMEOUT)
        except dns.exception.DNSException:
            return DnsResult(DnsOutcome.ERROR)
        except Exception:
            # A resolver bug or an unexpected transport error must not kill the
            # whole DNS stage; it stays a per-host, structured failure.
            return DnsResult(DnsOutcome.ERROR)
        if not ips and not cnames:
            return DnsResult(DnsOutcome.NOANSWER)
        return DnsResult(DnsOutcome.RESOLVED, ips=ips, cnames=cnames)

    async def _query(self, ctx: RunContext, host: str, rtype: str) -> list[str]:
        resolver = self._get_resolver()
        answer = await resolver.resolve(
            host, rtype, lifetime=self._lifetime, raise_on_no_answer=False
        )
        if answer.rrset is None:
            return []
        values: list[str] = []
        for rdata in answer:
            if rtype == "CNAME":
                target = getattr(rdata, "target", None)
                values.append(str(target).rstrip(".") if target is not None else str(rdata))
            else:
                values.append(str(getattr(rdata, "address", rdata)))
        return values

    def _get_resolver(self) -> Any:
        if self._resolver is None:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = self._lifetime
            resolver.timeout = self._lifetime
            self._resolver = resolver
        return self._resolver

    def parse_output(self, raw: str) -> list[Record]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise ParseError("dnspython: invalid fixture JSON") from None
        if not isinstance(data, dict):
            raise ParseError("dnspython: fixture must map hostnames to results")
        records: list[Record] = []
        for fqdn, entry in data.items():
            if not isinstance(entry, dict):
                raise ParseError("dnspython: unexpected fixture entry")
            if entry.get("state") == "DEAD":
                records.append(HostStatusRecord(fqdn=fqdn, source=self.name, state=HostState.DEAD))
                continue
            ips = entry.get("ips", [])
            cnames = entry.get("cnames", [])
            if not isinstance(ips, list) or not isinstance(cnames, list):
                raise ParseError("dnspython: fixture ips/cnames must be lists")
            records.append(
                SubdomainRecord(
                    fqdn=fqdn,
                    source=self.name,
                    ips=[str(ip) for ip in ips],
                    cnames=[str(cname) for cname in cnames],
                )
            )
        return records
