"""ProjectDiscovery katana adapter (docs/09_TOOL_CONTRACTS.md).

Katana crawls the alive hosts and prints one JSON line per request. A line that
carries a crawl error ("max depth reached") has no endpoint and is skipped: an
error is not a URL.
"""

from __future__ import annotations

import json

from reconkit.adapters.base import BinaryAdapter, normalize_url, strip_ansi
from reconkit.errors import ParseError, ToolFailed
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
        for line in strip_ansi(raw).splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                raise ParseError("katana: invalid JSON line") from None
            if not isinstance(data, dict):
                raise ParseError("katana: JSON line is not an object")
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
