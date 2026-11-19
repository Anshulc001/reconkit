"""hakrawler adapter (docs/09_TOOL_CONTRACTS.md).

hakrawler crawls the URLs it reads on stdin and prints every discovered URL, one
per line. It has no `-silent` flag (the wave-3 brief assumed one): the real help
lists `-d`, `-dr`, `-i`, `-insecure`, `-json`, `-proxy`, `-s`, `-size`, `-subs`,
`-t`, `-timeout`, `-u` and `-w`, and there is no `-version` either.

Two verified behaviours shape the adapter:

- it needs a **scheme** ("testfire.net" on stdin yields nothing), while the
  engine hands the stage bare hostnames, so each host is offered as
  `https://<host>/` and `http://<host>/` - the same https-then-http order
  `pyprobe` documents for liveness.
- it is strict about TLS: `https://testfire.net/` is skipped when the
  certificate does not cover the name (curl: `SSL: no alternative certificate
  subject name matches target hostname`), and the crawl of the `http://` form
  still works. `-insecure` is never passed: disabling verification would hide a
  real certificate problem from the operator.
"""

from __future__ import annotations

from reconkit.adapters.base import (
    BinaryAdapter,
    is_non_web_reference,
    normalize_url,
    strip_ansi,
)
from reconkit.core.runner import validate_host
from reconkit.errors import ToolFailed
from reconkit.models import Record, RunContext, Stage, UrlRecord

CRAWL_DEPTH = 2
# D53: `-timeout` is seconds per URL, so it is a request-level constant, never
# `ctx.timeout` (the stage budget). Before D53 this adapter passed 600 s per URL.
REQUEST_TIMEOUT_S = 10
# On the sakec.ac.in scan hakrawler hit the phase budget with 0 items and owned
# the whole urls stage. D52: no hard cap - it carries `class: crawler`, so a
# 60 s silence ends it and a productive crawl keeps going until it exits or the
# stage budget fires.


def crawl_urls(hosts: list[str]) -> list[str]:
    """The URLs to offer a crawler for each alive host: https first, then http."""
    urls: list[str] = []
    for host in hosts:
        urls.append(f"https://{host}/")
        urls.append(f"http://{host}/")
    return urls


class HakrawlerAdapter(BinaryAdapter):
    name = "hakrawler"
    stage = Stage.URLS
    binary = "hakrawler"
    # `-version` is not a flag: it prints the Go usage and exits 2, so the two
    # markers that name this program are what the identity check reads.
    version_args = ["-version"]
    identity_markers = ("depth to crawl", "show only unique urls")
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
            raise ToolFailed("hakrawler: no hosts to crawl")
        # Verified: `-d int` depth, `-u` unique URLs, `-timeout int` seconds per
        # URL. `-t` stays at its default 8 (threads are concurrency, not a pacer).
        return [
            self.binary_path() or self.binary,
            "-d",
            str(CRAWL_DEPTH),
            "-u",
            "-timeout",
            str(int(REQUEST_TIMEOUT_S)),
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
                # A `javascript:`/`mailto:` href is a link, not a URL we can store.
                continue
            url = normalize_url(line)
            if url is None:
                # Any other unusable line is skipped and counted, never fatal
                # for the whole crawl (PIT-58).
                self.skipped_lines.append(line)
                continue
            if url in seen:
                continue
            seen.add(url)
            records.append(UrlRecord(url=url, source=self.name))
        return records
