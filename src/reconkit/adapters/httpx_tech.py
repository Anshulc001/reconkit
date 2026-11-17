"""ProjectDiscovery httpx technology adapter (docs/09_TOOL_CONTRACTS.md).

Same binary as the live-stage `httpx` adapter, different job: the tech stage only
wants the `-td` technology list (and the `-cdn` name), so this class inherits
`build_command` from `HttpxAdapter`. That is the sharing itself - there is no
second copy of the flag list to drift, and `httpx_hosts()` / `httpx_fqdn()` in
`httpx_tool.py` are the shared helpers. If the builder ever needs a flag only
one caller wants, add a keyword argument there rather than overriding here.

The identity check is inherited unchanged from `HttpxAdapter`:
`version_args = ["-version"]` plus the `projectdiscovery` / `current version`
markers, which is what keeps the Python `httpx` client (a namesake with no such
banner) from counting as installed (01daa8b).
"""

from __future__ import annotations

import json

from reconkit.adapters.base import strip_ansi
from reconkit.adapters.httpx_tool import HttpxAdapter, httpx_fqdn
from reconkit.errors import ParseError
from reconkit.models import HostState, HostStatusRecord, Record, Stage


class HttpxTechAdapter(HttpxAdapter):
    name = "httpx_tech"
    stage = Stage.TECH

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
                raise ParseError("httpx_tech: invalid JSON line") from None
            if not isinstance(data, dict):
                raise ParseError("httpx_tech: JSON line is not an object")
            value = data.get("input") or data.get("url")
            if not isinstance(value, str) or not value:
                raise ParseError("httpx_tech: JSON line has no input/url")
            fqdn = httpx_fqdn(value, self.name)
            tech = data.get("tech") or []
            if not isinstance(tech, list):
                raise ParseError("httpx_tech: tech must be a list")
            waf = data.get("cdn_name")
            names = sorted({str(item).strip() for item in tech if str(item).strip()})
            waf_name = waf if isinstance(waf, str) and waf else None
            # A host with neither a technology nor a CDN/WAF name says nothing
            # about either column, so it is silence rather than an empty record.
            if fqdn in seen or (not names and waf_name is None):
                continue
            seen.add(fqdn)
            records.append(
                HostStatusRecord(
                    fqdn=fqdn,
                    source=self.name,
                    state=HostState.UNKNOWN,
                    tech=names,
                    waf=waf_name,
                )
            )
        return records


__all__ = ["HttpxTechAdapter"]
