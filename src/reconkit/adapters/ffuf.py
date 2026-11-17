"""ffuf adapter (docs/09_TOOL_CONTRACTS.md).

ffuf is a content-discovery fuzzer, not a vulnerability scanner: it replaces
`FUZZ` with every wordlist line and reports the responses that match. What it
finds are **paths that exist**, so every record is `severity="info"` and the
operator decides what is interesting (docs/MASTER_PLAN.md D13).

Verified on this box (v2.3.0, `/usr/bin/ffuf`):

- `-V` prints `ffuf version: 2.3.0`.
- `-u` takes one URL, `-w` one wordlist and an optional `:KEYWORD`, `-mode`
  `clusterbomb` combines several wordlists, `-of json -o FILE` writes the
  machine-readable document, `-mc` picks the status codes to report, `-t`
  threads, `-s` silent, `-noninteractive` keeps it from opening its console.

Hosts travel as a second wordlist: `hosts.txt:FHOST` and
`common.txt:FFUF` with `-u FHOST/FFUF` (both keywords must be in the URL - a
real run taught this the hard way). That is one ffuf process for every host instead of one process
per host, and both schemes are offered (`https://<host>` then `http://<host>`,
the pyprobe order) because the engine hands the stage bare hostnames. No `-k`:
disabling TLS verification would hide a real certificate problem, and a root
that cannot be fetched simply produces no matches.

The wordlist is the packaged `data/wordlists/common.txt` (about 110 paths,
committed in the repository, D13). `--ffuf-wordlist PATH` replaces it; no
download ever happens at runtime.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from reconkit.adapters.base import BinaryAdapter, strip_ansi
from reconkit.adapters.hakrawler import crawl_urls
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import FindingRecord, Record, RunContext, Stage

DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "data" / "wordlists" / "common.txt"
MATCH_CODES = "200,204,301,302,307,401,403"
THREADS = 50


class FfufAdapter(BinaryAdapter):
    name = "ffuf"
    stage = Stage.VULNS
    binary = "ffuf"
    version_args = ["-V"]
    # `-V` prints only `ffuf version: 2.3.0`; the banner with the full name is
    # the `-h` header, which the probe does not run.
    identity_markers = ("ffuf version",)
    needs_home = True

    def _hosts(self, ctx: RunContext) -> list[str]:
        hosts: list[str] = []
        seen: set[str] = set()
        for raw in ctx.hosts:
            try:
                host = validate_host(raw)
            except (TypeError, ValueError):
                raise ToolFailed(f"ffuf: invalid host {raw!r}") from None
            if host not in seen:
                seen.add(host)
                hosts.append(host)
        return hosts

    def wordlist(self, ctx: RunContext) -> Path:
        """The `--ffuf-wordlist` file, or the packaged default (D13)."""
        path = ctx.ffuf_wordlist or DEFAULT_WORDLIST
        if not path.is_file():
            raise ToolFailed(f"ffuf: wordlist not found: {path}")
        return path

    def _hosts_file(self, ctx: RunContext) -> Path:
        return ctx.workspace / f"ffuf-hosts-{os.getpid()}.txt"

    def _output_file(self, ctx: RunContext) -> Path:
        return ctx.workspace / f"ffuf-output-{os.getpid()}.json"

    def _roots(self, ctx: RunContext) -> list[str]:
        """Scheme roots without a trailing slash: `FHOST/FFUF` joins literally.

        `crawl_urls()` returns `https://host/`, which produced `//admin` in a real
        run; the fuzz template supplies the separator.
        """
        return [url.rstrip("/") for url in crawl_urls(self._hosts(ctx))]

    @contextmanager
    def prepare(self, ctx: RunContext) -> Iterator[None]:
        """Write the `FHOST` wordlist and remove both per-run files afterwards."""
        hosts = self._hosts_file(ctx)
        output = self._output_file(ctx)
        hosts.write_text("".join(f"{root}\n" for root in self._roots(ctx)), encoding="utf-8")
        try:
            yield
        finally:
            hosts.unlink(missing_ok=True)
            output.unlink(missing_ok=True)

    def build_command(self, ctx: RunContext) -> list[str]:
        if not self._hosts(ctx):
            raise ToolFailed("ffuf: no hosts to fuzz")
        return [
            self.binary_path() or self.binary,
            # Both keywords must appear in the URL: a wordlist registered as
            # `:FFUF` and a URL using `FUZZ` makes ffuf exit 0 with
            # "Keyword FFUF defined, but not found in ..." and no results.
            "-u",
            "FHOST/FFUF",
            "-w",
            f"{self._hosts_file(ctx)}:FHOST",
            "-w",
            f"{self.wordlist(ctx)}:FFUF",
            "-mode",
            "clusterbomb",
            "-of",
            "json",
            "-o",
            str(self._output_file(ctx)),
            "-mc",
            MATCH_CODES,
            "-t",
            str(THREADS),
            "-s",
            "-noninteractive",
        ]

    def read_output(self, ctx: RunContext) -> str | None:
        """`-of json -o FILE` writes the matches there; stdout is progress only."""
        output = self._output_file(ctx)
        if not output.is_file():
            # ffuf writes no file at all when nothing matched.
            return "{}"
        return output.read_text(encoding="utf-8")

    def parse_output(self, raw: str) -> list[Record]:
        text = strip_ansi(raw).strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            raise ParseError("ffuf: output is not valid JSON") from None
        if not isinstance(data, dict):
            raise ParseError("ffuf: output is not a JSON object")
        results = data.get("results", [])
        if not isinstance(results, list):
            raise ParseError("ffuf: results is not a list")
        records: list[Record] = []
        for entry in results:
            if not isinstance(entry, dict):
                raise ParseError("ffuf: result entry is not an object")
            url = entry.get("url")
            if not isinstance(url, str) or not url:
                raise ParseError("ffuf: result has no url")
            host = urlsplit(url).hostname
            try:
                fqdn = validate_host(host or "")
            except (TypeError, ValueError):
                raise ParseError(f"ffuf: invalid host in {url!r}") from None
            status = entry.get("status")
            if not isinstance(status, int):
                raise ParseError(f"ffuf: result has no status code: {url!r}")
            path = urlsplit(url).path or "/"
            records.append(
                FindingRecord(
                    fqdn=fqdn,
                    kind="path",
                    severity="info",
                    title=f"{status} {path}",
                    evidence=url,
                    template_id=None,
                    source=self.name,
                )
            )
        return records


__all__ = ["DEFAULT_WORDLIST", "FfufAdapter"]
