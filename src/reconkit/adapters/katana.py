"""ProjectDiscovery katana adapter (docs/09_TOOL_CONTRACTS.md).

Katana crawls the alive hosts and prints one JSON line per request. A line that
carries a crawl error ("max depth reached") has no endpoint and is skipped: an
error is not a URL.

Not every line is JSON. A real scan failed the whole tool with
`katana: invalid JSON line` while katana was printing a warning on stdout, so a
line that does not parse is skipped and counted instead of failing the tool: the
lines that did parse are still the tool's output (PIT-58).
"""

from __future__ import annotations

import json

from reconkit.adapters.base import BinaryAdapter, normalize_url, strip_ansi
from reconkit.errors import ToolFailed
from reconkit.models import Record, RunContext, Stage, UrlRecord


class KatanaAdapter(BinaryAdapter):
    name = "katana"
    stage = Stage.URLS
    binary = "katana"
    version_args = ["-version"]
    identity_markers = ("projectdiscovery", "current version")
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
            raise ToolFailed("katana: no hosts to crawl")
        # Verified against the real binary: `-u, -list string[]` (repeatable),
        # `-j, -jsonl`, `-or, -omit-raw`, `-ob, -omit-body`, `-duc`, `-nc`.
        # Omitting raw and body keeps the JSON line small; neither is a record.
        argv = [
            self.binary_path() or self.binary,
            "-silent",
            "-jsonl",
            "-or",
            "-ob",
            "-duc",
            "-nc",
        ]
        for host in hosts:
            argv += ["-u", host]
        return argv

    def parse_output(self, raw: str) -> list[Record]:
        records: list[Record] = []
        seen: set[str] = set()
        self.skipped_lines = []
        for line in strip_ansi(raw).splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                # Warning text on stdout is not the tool failing (PIT-58).
                self.skipped_lines.append(line)
                continue
            if not isinstance(data, dict):
                self.skipped_lines.append(line)
                continue
            request = data.get("request")
            if not isinstance(request, dict):
                # `{"error": "max depth reached", ...}`: no request was made.
                continue
            endpoint = request.get("endpoint")
            if not isinstance(endpoint, str):
                continue
            url = normalize_url(endpoint)
            if url is None or url in seen:
                continue
            seen.add(url)
            records.append(UrlRecord(url=url, source=self.name))
        return records
