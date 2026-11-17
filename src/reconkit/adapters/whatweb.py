"""whatweb adapter (docs/09_TOOL_CONTRACTS.md).

whatweb identifies the software behind a page by matching many small plugins
against the response. Verified against the real binary:

- `whatweb --version` -> `WhatWeb version 0.6.4
  ( https://morningstarsecurity.com/research/whatweb/ )`, exit 0.
- `--log-json=-` alone **fails**: whatweb writes the JSON log to stdout and then
  its one-line brief to the same closed stream, printing a Ruby traceback
  (`logging.rb:89:in 'write': closed stream (IOError)`) and exiting 1, which the
  base flow would report as a failed tool. Adding `--quiet` (real help:
  "Do not display brief logging to STDOUT.") removes that second write, so
  `--quiet --log-json=-` prints only the JSON array on stdout and exits 0.
- `--no-errors` keeps per-target failures off stderr, `--color=never` keeps the
  JSON free of ANSI codes, and `-a 1` is the single-request aggression level
  (whatweb's default is `1`; it is passed explicitly so a future default change
  cannot make every tech-stage run more aggressive silently).
- The document is a JSON array, one object per target:
  `{"target", "http_status", "request_config", "plugins": {Name: {...}}}`.
  A plugin name **is** the technology, so the keys of `plugins` are the tech
  list, minus the informational plugins listed in `NON_TECH_PLUGINS` (they
  describe the response - its IP, country, title, cookies - not the software).
"""

from __future__ import annotations

import json

from reconkit.adapters.base import BinaryAdapter, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import HostState, HostStatusRecord, Record, RunContext, Stage

# whatweb plugins that describe a response rather than the technology serving
# it. Every name here appears in the real testfire.net output captured in
# docs/tool_manuals/tech.md; keep this list to names of that kind.
NON_TECH_PLUGINS = frozenset(
    {
        "cookies",
        "country",
        "email",
        "html5",
        "htmltitle",
        "http_only",
        "httponly",
        "ip",
        "meta-refresh-redirect",
        "redirectlocation",
        "script",
        "title",
        "uncommonheaders",
        "x-frame-options",
    }
)


class WhatwebAdapter(BinaryAdapter):
    name = "whatweb"
    stage = Stage.TECH
    binary = "whatweb"
    version_args = ["--version"]
    identity_markers = ("whatweb version", "morningstarsecurity")
    needs_home = False

    def _urls(self, ctx: RunContext) -> list[str]:
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
        urls: list[str] = []
        for host in hosts:
            urls.append(f"https://{host}/")
            urls.append(f"http://{host}/")
        return urls

    def build_command(self, ctx: RunContext) -> list[str]:
        urls = self._urls(ctx)
        if not urls:
            raise ToolFailed("whatweb: no hosts to scan")
        return [
            self.binary_path() or self.binary,
            "--quiet",
            "--log-json=-",
            "--no-errors",
            "--color=never",
            "-a",
            "1",
            *urls,
        ]

    def parse_output(self, raw: str) -> list[Record]:
        text = strip_ansi(raw).strip()
        if not text:
            return []
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            raise ParseError("whatweb: invalid JSON document") from None
        if not isinstance(document, list):
            raise ParseError("whatweb: JSON document is not a list")
        records: list[Record] = []
        seen: set[str] = set()
        for entry in document:
            if not isinstance(entry, dict):
                raise ParseError("whatweb: JSON entry is not an object")
            target = entry.get("target")
            if not isinstance(target, str):
                raise ParseError("whatweb: JSON entry has no target")
            host = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            try:
                fqdn = validate_host(host)
            except (TypeError, ValueError):
                raise ParseError(f"whatweb: invalid target {target!r}") from None
            plugins = entry.get("plugins")
            tech: list[str] = []
            if isinstance(plugins, dict):
                for name in plugins:
                    if not isinstance(name, str):
                        continue
                    if name.strip().lower() in NON_TECH_PLUGINS:
                        continue
                    if name.strip() and name.strip() not in tech:
                        tech.append(name.strip())
            if fqdn in seen or not tech:
                continue
            seen.add(fqdn)
            records.append(
                HostStatusRecord(
                    fqdn=fqdn,
                    source=self.name,
                    state=HostState.UNKNOWN,
                    tech=sorted(tech),
                )
            )
        return records
