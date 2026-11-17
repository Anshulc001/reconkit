"""unfurl adapter (docs/09_TOOL_CONTRACTS.md).

unfurl is a URL formatter: it reads URLs on stdin and prints the parts you ask
for. Real `unfurl -h` (exit 0, usage on stderr) lists the modes `keys`, `values`,
`keypairs`, `domains`, `paths`, `apexes`, `json`, `format` and the `-u/--unique`
flag; there is no `-version` (`-version` -> `flag provided but not defined` plus
the usage, exit 2), so `-h` is the identity probe.

**Chosen extraction: `format '%s://%d%:%P%p?%q'` (option (b), full URL lines).**
That directive rebuilds the exact URL without its fragment - the same
normalization `normalize_url()` applies - so the adapter stores `UrlRecord`s and
nothing else. The component modes (`paths`, `keys`, `values`) would store bare
fragments that `UrlRecord` has no field for, which would need a new model field;
that is a docs change, not an adapter decision.

**Known limitation, reported not hidden:** the engine feeds a stage its alive
hostnames, and `RunContext` has no URL list, so unfurl receives only
`https://<host>/` and `http://<host>/` per host and returns those two canonical
roots. Its real value - canonicalizing URLs discovered by another tool - needs a
urls→urls hand-off the pipeline does not have (docs/03 section 5b), so today the
output is small by design.

`%?` is not conditional in practice: a URL with no query comes back with a bare
trailing `?` (`https://host/?`). `normalize_url()` drops it, because an empty
query serializes back with no `?`, so the stored URL is clean.
"""

from __future__ import annotations

from reconkit.adapters.base import BinaryAdapter, is_non_web_reference, normalize_url, strip_ansi
from reconkit.adapters.hakrawler import crawl_urls
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import Record, RunContext, Stage, UrlRecord

# Verified against the real binary: `%s` scheme, `%d` domain, `%:` colon before a
# port, `%P` port, `%p` path, `%?` question mark before a query, `%q` raw query.
FORMAT = "%s://%d%:%P%p?%q"


class UnfurlAdapter(BinaryAdapter):
    name = "unfurl"
    stage = Stage.URLS
    binary = "unfurl"
    # No version flag: the usage block is the identity probe.
    version_args = ["-h"]
    identity_markers = ("unfurl [options] [mode]", "format urls provided on stdin")
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
            raise ToolFailed("unfurl: no hosts to format")
        return [self.binary_path() or self.binary, "-u", "format", FORMAT]

    def stdin_text(self, ctx: RunContext) -> str | None:
        urls = crawl_urls(self._hosts(ctx))
        return "".join(f"{url}\n" for url in urls) or None

    def parse_output(self, raw: str) -> list[Record]:
        records: list[Record] = []
        seen: set[str] = set()
        for line in strip_ansi(raw).splitlines():
            line = line.strip()
            if not line or is_non_web_reference(line):
                continue
            url = normalize_url(line)
            if url is None:
                raise ParseError(f"unfurl: line is not a URL {line!r}")
            if url in seen:
                continue
            seen.add(url)
            records.append(UrlRecord(url=url, source=self.name))
        return records
