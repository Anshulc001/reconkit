"""waybackurls adapter (docs/09_TOOL_CONTRACTS.md).

A passive archive reader: it takes domains on stdin and prints archived URLs, one
per line, from the Wayback Machine (plus a couple of mirrors). It never touches
the target. It has no input flag and no `-version`, so the identity probe is `-h`.

Real flags (verified on this box, `waybackurls -h`): `-dates`, `-get-versions`,
`-no-subs`. The adapter passes none of them: `-no-subs` would silently drop the
subdomains the pipeline feeds it, and the date/version columns are not URLs.

**One query per root, not one per host (2026-11-18).** waybackurls reads a line
from stdin, asks the CDX API for `*.<line>/*` and prints what comes back; the
tool's own `-no-subs` help text ("don't include subdomains of the target domain")
is the proof that the default already covers subdomains. Feeding it all 42
hosts of a run therefore asked the same wildcard question 42 times in sequence,
which is where the 302 s in the 2026-11-18 10:14 run came from - against archive
organisation answers that were 503 that morning, so the wait bought nothing at
all. The adapter now feeds the apex once and passes through any host that is not
under it, so a scope with several domains still asks about each of them.
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

    @staticmethod
    def _query_roots(hosts: list[str], target: str) -> list[str]:
        """Collapse the hosts to the names waybackurls has to ask about.

        A host that is the target or sits under it is already covered by the
        target's `*.<target>/*` query; anything else (another domain named in a
        scope file) is kept as its own query line.
        """
        apex = target.strip().strip(".").lower()
        roots: list[str] = []
        seen: set[str] = set()
        for host in hosts:
            covered = host == apex or host.endswith(f".{apex}")
            line = apex if covered and apex else host
            if line not in seen:
                seen.add(line)
                roots.append(line)
        return roots

    def build_command(self, ctx: RunContext) -> list[str]:
        if not self._hosts(ctx):
            raise ToolFailed("waybackurls: no hosts to query")
        return [self.binary_path() or self.binary]

    def stdin_text(self, ctx: RunContext) -> str | None:
        roots = self._query_roots(self._hosts(ctx), ctx.target)
        return "".join(f"{host}\n" for host in roots) or None

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
