"""waybackurls adapter (docs/09_TOOL_CONTRACTS.md).

A passive archive reader: it takes domains on stdin and prints archived URLs, one
per line, from the Wayback Machine (plus a couple of mirrors). It never touches
the target. It has no input flag and no `-version`, so the identity probe is `-h`.

Real flags (verified on this box, `waybackurls -h`): `-dates`, `-get-versions`,
`-no-subs`. The adapter passes none of them: `-no-subs` would silently drop the
subdomains the pipeline feeds it, and the date/version columns are not URLs.
"""

from __future__ import annotations

from reconkit.adapters.base import BinaryAdapter, normalize_url, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import Record, RunContext, Stage, UrlRecord


class WaybackurlsAdapter(BinaryAdapter):
    name = "waybackurls"
    stage = Stage.URLS
    binary = "waybackurls"
    version_args = ["-h"]
    identity_markers = ("-no-subs", "don't include subdomains")
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
            raise ToolFailed("waybackurls: no hosts to query")
        return [self.binary_path() or self.binary]

    def stdin_text(self, ctx: RunContext) -> str | None:
        hosts = self._hosts(ctx)
        return "".join(f"{host}\n" for host in hosts) or None

    def parse_output(self, raw: str) -> list[Record]:
        records: list[Record] = []
        seen: set[str] = set()
        for line in strip_ansi(raw).splitlines():
            line = line.strip()
            if not line:
                continue
            url = normalize_url(line)
            if url is None:
                raise ParseError(f"waybackurls: line is not a URL {line!r}")
            if url in seen:
                continue
            seen.add(url)
            records.append(UrlRecord(url=url, source=self.name))
        return records
