"""urlfinder (ProjectDiscovery) adapter (docs/09_TOOL_CONTRACTS.md).

urlfinder aggregates URLs for a domain from third-party archives, so it is a
passive reader that happens to sit in the active `urls` stage: it reads domains
on stdin (verified: `printf 'testfire.net\\n' | urlfinder -all -silent` prints
URLs with no `-d` flag) and never returns to the target.

Real help on this box: `-d, -list string[]` domains, `-all` every source,
`-silent` URLs only, `-timeout int` seconds per request, `-max-time int` minutes
for the whole enumeration, plus its own `-rl` rate limit. The adapter passes
`-all -silent -timeout` and nothing else - no `-rl` (there is no pacing in
reconkit, and the tool's per-source defaults stay as the project set them).

Two output facts the parser handles: a source failure does not fail the run
(exit stays 0 and the URLs found so far are printed), and archived rows can be
junk that is not a URL at all, for example a stored probe string containing
spaces (`http://host/path;curl d9q...oast.live`). A line with inner whitespace is
skipped, not stored: it is not a URL and it is not ours to interpret.
"""

from __future__ import annotations

from reconkit.adapters.base import BinaryAdapter, is_non_web_reference, normalize_url, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import Record, RunContext, Stage, UrlRecord

# `-timeout` is a per-request value in seconds (its documented default is 30) and
# `-max-time` is the whole enumeration in minutes (default 10). The adapter used
# to pass the per-tool budget (600 s) as `-timeout`, so every slow archive source
# was given ten minutes to answer one request. Measured on 2026-11-18 with these
# values against testfire.net: 996 URLs in 15 s, against 932 URLs in 554 s for the
# old command - faster and no worse. `-max-time` still comes from the run budget.
REQUEST_TIMEOUT_S = 30


class UrlfinderAdapter(BinaryAdapter):
    name = "urlfinder"
    stage = Stage.URLS
    binary = "urlfinder"
    version_args = ["-version"]
    identity_markers = ("current version", "urlfinder")
    needs_home = True

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
            raise ToolFailed("urlfinder: no hosts to query")
        # Verified: `-all`, `-silent`, `-timeout int`, `-max-time int`, `-nc`.
        # Both timeouts are capped by the run budget so `--phase-timeout` still
        # wins, and `-max-time` is rounded up so a 600 s budget stays 10 minutes.
        budget = max(1, int(ctx.timeout))
        return [
            self.binary_path() or self.binary,
            "-all",
            "-silent",
            "-nc",
            "-timeout",
            str(min(REQUEST_TIMEOUT_S, budget)),
            "-max-time",
            str(max(1, (budget + 59) // 60)),
        ]

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
            if any(char.isspace() for char in line) or is_non_web_reference(line):
                # Archived garbage (`...;curl d9q...oast.live`) or a `javascript:`
                # href; neither is an HTTP URL.
                continue
            url = normalize_url(line)
            if url is None:
                raise ParseError(f"urlfinder: line is not a URL {line!r}")
            if url in seen:
                continue
            seen.add(url)
            records.append(UrlRecord(url=url, source=self.name))
        return records
