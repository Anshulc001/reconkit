"""subjs adapter (docs/09_TOOL_CONTRACTS.md).

subjs fetches each URL it is given and prints the JavaScript files the page
references. Real help on this box: `-c int` workers, `-i string` an input file,
`-t int` HTTP timeout, `-ua string`, `-version` (prints `subjs version: 1.0.1`).
It also reads plain URLs on stdin - verified with a local page that references
two scripts, which produced both URLs on stdout.

Input is the same https-then-http pair `hakrawler` gets, because the engine hands
the stage bare hostnames. No `.js` extension filter is applied on top of the
tool: subjs prints JavaScript files only, and filtering again would drop a
`.php`-suffixed script endpoint the tool deliberately reported.
"""

from __future__ import annotations

from reconkit.adapters.base import (
    USER_AGENT,
    BinaryAdapter,
    is_non_web_reference,
    normalize_url,
    strip_ansi,
)
from reconkit.adapters.hakrawler import crawl_urls
from reconkit.core.runner import validate_host
from reconkit.errors import ToolFailed
from reconkit.models import Record, RunContext, Stage, UrlRecord

WORKERS = 10
# D53: `-t` is the HTTP timeout in seconds, one request at a time, so it is a
# request-level constant and never `ctx.timeout` (the stage budget).
REQUEST_TIMEOUT_S = 10
# subjs fetches a handful of pages and prints script URLs; on the example.com
# scan it hit the phase budget with 0 items (2.2). D52: no hard cap - it carries
# `class: crawler`, so one minute of silence means it is stuck and a productive
# run is never cut short.


class SubjsAdapter(BinaryAdapter):
    name = "subjs"
    stage = Stage.URLS
    binary = "subjs"
    version_args = ["-version"]
    identity_markers = ("subjs version:",)
    needs_home = False

    def _hosts(self, ctx: RunContext) -> list[str]:
        hosts: list[str] = []
        seen: set[str] = set()
        for raw in ctx.hosts:
            try:
                host = validate_host(raw)
            except (TypeError, ValueError):
                continue
            if host not in seen:
                seen.add(host)
                hosts.append(host)
        return hosts

    def build_command(self, ctx: RunContext) -> list[str]:
        if not self._hosts(ctx):
            raise ToolFailed("subjs: no hosts to crawl")
        # Verified: `-c int` workers, `-t int` timeout in seconds, `-ua string`.
        # The honest User-Agent is sent because these are our own requests
        # (AGENTS hard rule 8); `--user-agent` from the CLI wins when given.
        return [
            self.binary_path() or self.binary,
            "-c",
            str(WORKERS),
            "-t",
            str(int(REQUEST_TIMEOUT_S)),
            "-ua",
            ctx.user_agent or USER_AGENT,
        ]

    def stdin_text(self, ctx: RunContext) -> str | None:
        urls = crawl_urls(self._hosts(ctx))
        return "".join(f"{url}\n" for url in urls) or None

    def parse_output(self, raw: str) -> list[Record]:
        records: list[Record] = []
        seen: set[str] = set()
        self.skipped_lines = []
        for line in strip_ansi(raw).splitlines():
            line = line.strip()
            if not line or is_non_web_reference(line):
                continue
            url = normalize_url(line)
            if url is None:
                # Unusable lines are counted, not fatal (PIT-58).
                self.skipped_lines.append(line)
                continue
            if url in seen:
                continue
            seen.add(url)
            records.append(UrlRecord(url=url, source=self.name))
        return records
