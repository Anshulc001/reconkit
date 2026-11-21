"""pyscan TCP connect adapter (docs/09_TOOL_CONTRACTS.md).

Connect-only scan: sends no payload and reads no banner. Connection refused is
"closed"; a timeout is not proof of anything and is only counted. Every resolved
address is filtered through `ctx.ip_allowed` first (docs/05 rule 6): no predicate
or no allowed address means the host is skipped and counted as `blocked=`, never
probed, and never retried as a hostname.
"""

from __future__ import annotations

import asyncio
import json
import socket
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from reconkit.adapters.base import BaseToolAdapter, FixtureMissing, records_output
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError
from reconkit.models import PortRecord, Record, RunContext, Stage, ToolResult, ToolStatus

DEFAULT_PORTS = (80, 443, 22, 21, 25, 53, 110, 143, 3306, 3389, 8080, 8443)
# D53: one TCP connect gets this much time. A connection-level constant, never
# `ctx.timeout` (the stage budget): a 600 s connect timeout is a silent hang.
CONNECT_TIMEOUT_S = 5.0

Connect = Callable[[str, int], Awaitable[tuple[Any, Any]]]
Resolve = Callable[[str], Awaitable[list[str]]]


async def default_resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


class PyscanAdapter(BaseToolAdapter):
    name = "pyscan"
    stage = Stage.PORTS

    def __init__(
        self,
        *,
        connect: Connect | None = None,
        resolve: Resolve | None = None,
        fixtures_dir: Path | None = None,
    ) -> None:
        super().__init__(fixtures_dir=fixtures_dir)
        self._opener = connect if connect is not None else asyncio.open_connection
        self._resolve = resolve if resolve is not None else default_resolve

    async def run(self, ctx: RunContext) -> ToolResult:
        started = time.perf_counter()
        if ctx.mock:
            fixture = ""
            try:
                fixture = self._read_fixture(ctx)
                mock_records = self.parse_output(fixture)
            except FixtureMissing as exc:
                return ToolResult(
                    tool=self.name,
                    status=ToolStatus.SKIPPED,
                    error=str(exc),
                    duration_s=time.perf_counter() - started,
                    raw_text=fixture,
                )
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

        requested = [port for port in ctx.ports if 1 <= port <= 65535]
        ports = requested or list(DEFAULT_PORTS)
        records: list[Record] = []
        timeouts = 0
        failures = 0
        blocked = 0
        for raw_host in ctx.hosts:
            try:
                host = validate_host(raw_host)
            except (TypeError, ValueError):
                failures += 1
                continue
            try:
                addresses = await self._resolve(host)
            except OSError:
                failures += 1
                continue
            allowed = self._allowed_addresses(ctx, addresses)
            if not allowed:
                # docs/05 rule 6: an address outside in_scope_cidrs is never probed.
                # An empty answer is not permission to fall back to the hostname:
                # that would resolve a second time inside open_connection, bypassing
                # this filter.
                blocked += 1
                continue
            ip = allowed[0]
            outcomes = await asyncio.gather(*(self._probe(ctx, ip, port) for port in ports))
            for port, outcome in zip(ports, outcomes, strict=True):
                if outcome == "open":
                    records.append(
                        PortRecord(fqdn=host, ip=ip, port=port, state="open", source=self.name)
                    )
                elif outcome == "closed":
                    records.append(
                        PortRecord(fqdn=host, ip=ip, port=port, state="closed", source=self.name)
                    )
                elif outcome == "timeout":
                    timeouts += 1
                else:
                    failures += 1
        problems = []
        if timeouts:
            problems.append(f"timeouts={timeouts}")
        if failures:
            problems.append(f"errors={failures}")
        if blocked:
            problems.append(f"blocked={blocked}")
        error = ", ".join(problems) or None
        return ToolResult(
            tool=self.name,
            status=ToolStatus.OK,
            records=records,
            error=error,
            duration_s=time.perf_counter() - started,
            raw_text=records_output(records, error),
        )

    @staticmethod
    def _allowed_addresses(ctx: RunContext, addresses: list[str]) -> list[str]:
        """Keep only the resolved addresses docs/05 rule 6 allows this scan to probe."""
        if ctx.ip_allowed is None:
            return []
        allowed: list[str] = []
        for address in addresses:
            try:
                permitted = ctx.ip_allowed(address)
            except ValueError:
                continue
            if permitted:
                allowed.append(address)
        return allowed

    async def _probe(self, ctx: RunContext, ip: str, port: int) -> str:
        try:
            _reader, writer = await asyncio.wait_for(
                self._opener(ip, port), timeout=CONNECT_TIMEOUT_S
            )
        except ConnectionRefusedError:
            return "closed"
        except TimeoutError:
            return "timeout"
        except OSError:
            return "error"
        # `close()` is synchronous and runs before the first await, so a
        # cancellation while the socket drains can no longer leak it.
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return "open"

    def parse_output(self, raw: str) -> list[Record]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise ParseError("pyscan: invalid fixture JSON") from None
        if not isinstance(data, list):
            raise ParseError("pyscan: fixture must be a list of ports")
        records: list[Record] = []
        for entry in data:
            if not isinstance(entry, dict):
                raise ParseError("pyscan: unexpected fixture entry")
            try:
                record = PortRecord(
                    fqdn=str(entry["fqdn"]),
                    ip=str(entry["ip"]),
                    port=int(entry["port"]),
                    state=entry.get("state", "open"),
                    source=self.name,
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ParseError(f"pyscan: invalid fixture entry ({exc})") from None
            records.append(record)
        return records
