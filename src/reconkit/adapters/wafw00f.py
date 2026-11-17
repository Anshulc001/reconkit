"""wafw00f adapter (docs/09_TOOL_CONTRACTS.md).

wafw00f fingerprints a web application firewall by sending probes and comparing
the responses with its signature list. Verified against the real binary:

- `wafw00f --version` prints a banner ending in
  `[+] The version of WAFW00F you have is v2.4.2`, exit 0.
- `-a` runs every detection plugin, `-f json` selects the JSON format and
  `-o -` writes that JSON to **stdout** (exit 0). Targets are positional and
  several are accepted in one run.
- The document is a JSON array, one entry per target, each
  `{"detected", "firewall", "manufacturer", "trigger_url", "url"}`.

Only `detected: true` produces a record: `firewall` becomes
`HostStatusRecord.waf` and the record's state is `UNKNOWN`, because a WAF
fingerprint never proves the host answers ordinary traffic any more than
cdncheck's range match does. A `detected: false` entry carries no fact, so it is
skipped rather than stored as an empty answer (same rule as cdncheck's silence).
`manufacturer` is not stored: `waf` is a single name, and the product name is the
one the operator acts on.
"""

from __future__ import annotations

import json

from reconkit.adapters.base import BinaryAdapter, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import HostState, HostStatusRecord, Record, RunContext, Stage


class Wafw00fAdapter(BinaryAdapter):
    name = "wafw00f"
    stage = Stage.TECH
    binary = "wafw00f"
    version_args = ["--version"]
    identity_markers = ("wafw00f", "the version of wafw00f you have is")
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
            raise ToolFailed("wafw00f: no hosts to test")
        # Verified against the real binary: `-a` all detection plugins,
        # `-f json` format, `-o -` write to stdout, targets positional.
        return [self.binary_path() or self.binary, "-a", "-f", "json", "-o", "-", *urls]

    def parse_output(self, raw: str) -> list[Record]:
        text = strip_ansi(raw).strip()
        if not text:
            return []
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            raise ParseError("wafw00f: invalid JSON document") from None
        if not isinstance(document, list):
            raise ParseError("wafw00f: JSON document is not a list")
        records: list[Record] = []
        seen: set[str] = set()
        for entry in document:
            if not isinstance(entry, dict):
                raise ParseError("wafw00f: JSON entry is not an object")
            target = entry.get("url")
            if not isinstance(target, str):
                raise ParseError("wafw00f: JSON entry has no url")
            host = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            try:
                fqdn = validate_host(host)
            except (TypeError, ValueError):
                raise ParseError(f"wafw00f: invalid url {target!r}") from None
            if entry.get("detected") is not True:
                continue
            name = entry.get("firewall")
            if not isinstance(name, str) or not name.strip() or name.strip() == "None":
                raise ParseError(f"wafw00f: detected entry for {fqdn} has no firewall name")
            if fqdn in seen:
                continue
            seen.add(fqdn)
            records.append(
                HostStatusRecord(
                    fqdn=fqdn,
                    source=self.name,
                    state=HostState.UNKNOWN,
                    waf=name.strip(),
                )
            )
        return records
