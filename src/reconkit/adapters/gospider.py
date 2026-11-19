"""gospider adapter (docs/09_TOOL_CONTRACTS.md).

gospider takes its targets from `-s/--site` (one string) or `-S/--sites` (a file),
never from stdin, so the adapter writes a sites file into the run workspace and
removes it in `finally`.

It has two output shapes, both verified on this box:

- `-q/--quiet` ("suppress all the output and only show URL"): one bare URL per line
- without `-q`: `[url] - [code-200] - https://host/` and `[href] - https://host/x`

The adapter runs `-q` and still strips a leading `[tag]` prefix, so a stray
verbose line can never become an unparseable record. It feeds each host as
`https://<host>/` and `http://<host>/`, the same order `pyprobe` uses: a host with
a certificate that does not cover its name still gets crawled over http.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from reconkit.adapters.base import BinaryAdapter, is_non_web_reference, normalize_url, strip_ansi
from reconkit.adapters.hakrawler import CRAWL_DEPTH, crawl_urls
from reconkit.core.runner import validate_host
from reconkit.errors import ToolFailed
from reconkit.models import Record, RunContext, Stage, UrlRecord

THREADS = 10
# D53: `-m/--timeout` is seconds per request, so it is a request-level constant,
# never `ctx.timeout` (the stage budget).
REQUEST_TIMEOUT_S = 10


class GospiderAdapter(BinaryAdapter):
    name = "gospider"
    stage = Stage.URLS
    binary = "gospider"
    # `--version` prints `Version: v1.1.6`, which does not name the program; `-h`
    # does, and the version regex still finds v1.1.6 in its banner line.
    version_args = ["-h"]
    identity_markers = ("fast web spider", "site to crawl")
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

    def _sites_file(self, ctx: RunContext) -> Path:
        return ctx.workspace / f"gospider-sites-{os.getpid()}.txt"

    @contextmanager
    def prepare(self, ctx: RunContext) -> Iterator[None]:
        """Write the `-S` file for this run and remove it afterwards."""
        path = self._sites_file(ctx)
        path.write_text(
            "".join(f"{url}\n" for url in crawl_urls(self._hosts(ctx))), encoding="utf-8"
        )
        try:
            yield
        finally:
            path.unlink(missing_ok=True)

    def build_command(self, ctx: RunContext) -> list[str]:
        if not self._hosts(ctx):
            raise ToolFailed("gospider: no hosts to crawl")
        # Verified: `-S, --sites string` (a file), `-d, --depth int`, `-q, --quiet`,
        # `-t, --threads int`, `-m, --timeout int` (seconds per request).
        return [
            self.binary_path() or self.binary,
            "-S",
            str(self._sites_file(ctx)),
            "-d",
            str(CRAWL_DEPTH),
            "-q",
            "-t",
            str(THREADS),
            "-m",
            str(int(REQUEST_TIMEOUT_S)),
        ]

    def parse_output(self, raw: str) -> list[Record]:
        records: list[Record] = []
        seen: set[str] = set()
        self.skipped_lines = []
        for line in strip_ansi(raw).splitlines():
            line = line.strip()
            if not line or is_non_web_reference(line):
                continue
            # A verbose line is `[tag] - [code-200] - URL`; everything up to the
            # first scheme is the prefix, and cutting there handles both shapes.
            start = min(
                (index for index in (line.find("http://"), line.find("https://")) if index >= 0),
                default=-1,
            )
            url = None if start < 0 else normalize_url(line[start:])
            if url is None:
                # A log line with no URL is counted, not fatal (PIT-58).
                self.skipped_lines.append(line)
                continue
            if url in seen:
                continue
            seen.add(url)
            records.append(UrlRecord(url=url, source=self.name))
        return records
