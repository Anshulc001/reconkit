"""pyprobe HTTP adapter (docs/09_TOOL_CONTRACTS.md).

Never follows redirects: a redirect may point out of scope, so the status code
and raw Location are recorded instead. The body read stops at TITLE_LIMIT.
"""

from __future__ import annotations

import asyncio
import html
import json
import re
import time
from pathlib import Path

import httpx

from reconkit.adapters.base import USER_AGENT, BaseToolAdapter, records_output
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError
from reconkit.models import (
    HostState,
    HostStatusRecord,
    Record,
    RunContext,
    Stage,
    ToolResult,
    ToolStatus,
)

TITLE_LIMIT = 256 * 1024
TITLE_MAX_CHARS = 200
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
SCHEMES = ("https", "http")


def extract_title(body: bytes) -> str | None:
    text = body.decode("utf-8", errors="replace")
    match = TITLE_RE.search(text)
    if match is None:
        return None
    title = " ".join(html.unescape(match.group(1)).split())
    return title[:TITLE_MAX_CHARS] or None


class PyprobeAdapter(BaseToolAdapter):
    name = "pyprobe"
    stage = Stage.LIVE

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        fixtures_dir: Path | None = None,
    ) -> None:
        super().__init__(fixtures_dir=fixtures_dir)
        self._transport = transport

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

        async with httpx.AsyncClient(
            timeout=ctx.timeout,
            headers={"User-Agent": USER_AGENT},
            transport=self._transport,
            follow_redirects=False,
        ) as client:
            outcomes = list(
                await asyncio.gather(*(self._probe(ctx, client, host) for host in ctx.hosts))
            )
        records: list[Record] = [record for record in outcomes if record is not None]
        unreachable = len(outcomes) - len(records)
        error = f"unreachable={unreachable}" if unreachable else None
        return ToolResult(
            tool=self.name,
            status=ToolStatus.OK,
            records=records,
            error=error,
            duration_s=time.perf_counter() - started,
            raw_text=records_output(records, error),
        )

    async def _probe(
        self,
        ctx: RunContext,
        client: httpx.AsyncClient,
        host: str,
    ) -> HostStatusRecord | None:
        try:
            host = validate_host(host)
        except (TypeError, ValueError):
            return None
        tls_error = False
        tls_detail: str | None = None
        for scheme in SCHEMES:
            try:
                async with client.stream("GET", f"{scheme}://{host}/") as response:
                    body = await self._read_prefix(response)
                    return HostStatusRecord(
                        fqdn=host,
                        source=self.name,
                        state=HostState.ALIVE,
                        status_code=response.status_code,
                        title=extract_title(body),
                        location=response.headers.get("location"),
                    )
            except httpx.ConnectError as exc:
                # Regression: 11d-findings-f. A TLS failure on `https` must not
                # end the probe: the host may still answer plain `http` (a
                # certificate that does not match the name is enough). Only a
                # TLS error with no working scheme is evidence of UNKNOWN.
                if self._is_tls_error(exc):
                    tls_error = True
                    # Keep the reason for the UNKNOWN record: the store bounds
                    # and redacts it (docs/04 section 5, part 12d).
                    tls_detail = str(exc)
                continue
            except (httpx.TimeoutException, httpx.HTTPError):
                continue
        if tls_error:
            return HostStatusRecord(
                fqdn=host, source=self.name, state=HostState.UNKNOWN, detail=tls_detail
            )
        return None

    @staticmethod
    async def _read_prefix(response: httpx.Response) -> bytes:
        body = b""
        async for chunk in response.aiter_bytes():
            body += chunk
            if len(body) >= TITLE_LIMIT:
                break
        return body[:TITLE_LIMIT]

    @staticmethod
    def _is_tls_error(exc: httpx.ConnectError) -> bool:
        message = str(exc).lower()
        return "ssl" in message or "certificate" in message

    def parse_output(self, raw: str) -> list[Record]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise ParseError("pyprobe: invalid fixture JSON") from None
        if not isinstance(data, dict):
            raise ParseError("pyprobe: fixture must map hostnames to results")
        records: list[Record] = []
        for fqdn, entry in data.items():
            if not isinstance(entry, dict):
                raise ParseError("pyprobe: unexpected fixture entry")
            status = entry.get("status_code")
            title = entry.get("title")
            location = entry.get("location")
            if status is not None and not isinstance(status, int):
                raise ParseError("pyprobe: status_code must be an integer")
            if title is not None and not isinstance(title, str):
                raise ParseError("pyprobe: title must be a string")
            if location is not None and not isinstance(location, str):
                raise ParseError("pyprobe: location must be a string")
            records.append(
                HostStatusRecord(
                    fqdn=fqdn,
                    source=self.name,
                    state=HostState.ALIVE if status is not None else HostState.UNKNOWN,
                    status_code=status,
                    title=title,
                    location=location,
                )
            )
        return records
