"""gau (getallurls) adapter (docs/09_TOOL_CONTRACTS.md).

A passive archive reader: it reads Wayback/CommonCrawl/OTX/urlscan indexes and
never touches the target. `--json` prints one `{"url": ...}` object per line;
plain URL lines are accepted too, because that is the output of older builds.
gau writes its "config file not found" notice to stderr, so only stdout is
parsed here.
"""

from __future__ import annotations

import json

from reconkit.adapters.base import BinaryAdapter, normalize_url, strip_ansi
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import Record, RunContext, Stage, UrlRecord

# gau's `--timeout` is its HTTP client timeout in seconds, and its own default is
# 45 (`gau --help`: "timeout (in seconds) for HTTP client (default 45)"). It is
# NOT a run budget: the adapter used to pass the per-tool budget (600 s) here, so
# a single stalled provider request could block for ten minutes and the tool was
# killed at the stage timeout with nothing found. Measured on 2026-11-18 with
# these values against testfire.net: 345 URLs in 31 s, where the 600 s run gave
# 0 items. `--threads` defaults to 1; five is enough to keep the four providers
# busy without hammering any single archive.
HTTP_TIMEOUT_S = 45
THREADS = 5
RETRIES = 1


class GauAdapter(BinaryAdapter):
    name = "gau"
    stage = Stage.URLS
    binary = "gau"
    version_args = ["--version"]
    identity_markers = ("gau version:",)
    needs_home = True

    def build_command(self, ctx: RunContext) -> list[str]:
        hosts: list[str] = []
        seen: set[str] = set()
        for raw in ctx.hosts:
            host = raw.strip().lower().rstrip(".")
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)
        if not hosts:
            raise ToolFailed("gau: no hosts to query")
        # Verified against the real binary: `--json`, `--timeout`, `--threads`,
        # `--retries`, `--providers` and `--subs` are the flags it documents, and
        # domains are positional arguments (it accepts several). gau has no
        # `-silent`/`-nc`/`-duc`. The HTTP timeout is capped by the run's own
        # budget so a short `--phase-timeout` is still respected.
        argv = [
            self.binary_path() or self.binary,
            "--json",
            f"--timeout={min(HTTP_TIMEOUT_S, max(1, int(ctx.timeout)))}",
            f"--threads={THREADS}",
            f"--retries={RETRIES}",
        ]
        return [*argv, *hosts]

    def parse_output(self, raw: str) -> list[Record]:
        records: list[Record] = []
        seen: set[str] = set()
        for line in strip_ansi(raw).splitlines():
            line = line.strip()
            if not line:
                continue
            value = line
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    raise ParseError("gau: invalid JSON line") from None
                if not isinstance(data, dict) or not isinstance(data.get("url"), str):
                    raise ParseError("gau: JSON line has no url")
                value = data["url"]
            url = normalize_url(value)
            if url is None or url in seen:
                continue
            seen.add(url)
            records.append(UrlRecord(url=url, source=self.name))
        return records
