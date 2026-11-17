"""ProjectDiscovery cdncheck adapter (docs/09_TOOL_CONTRACTS.md).

cdncheck resolves each input and matches it against known CDN, cloud and WAF
ranges. A line means "this input matched", and the flags on the line say what:
`cdn`/`cdn_name`, `cloud`/`cloud_name`, `waf`/`waf_name`. Inputs that match
nothing print no line at all - silence is "no match", not a failure.

Semantics kept by the adapter: a WAF match becomes `HostStatusRecord.waf`
(the field the port pre-check reads, docs/09 section 5); a CDN or cloud match
becomes a technology entry, because neither changes the liveness verdict. The
record's state is `UNKNOWN`: cdncheck resolves a name and compares ranges, it
never proves the host answered HTTP, so it must not claim `ALIVE`.
"""

from __future__ import annotations

import json
from typing import Any

from reconkit.adapters.base import BinaryAdapter, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import HostState, HostStatusRecord, Record, RunContext, Stage


class CdncheckAdapter(BinaryAdapter):
    name = "cdncheck"
    stage = Stage.TECH
    binary = "cdncheck"
    version_args = ["-version"]
    identity_markers = ("projectdiscovery", "current version")
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
        hosts = self._hosts(ctx)
        if not hosts:
            raise ToolFailed("cdncheck: no hosts to scan")
        # Verified against the real binary: `-i, -input string[]` is repeatable,
        # `-silent` hides the banner, `-j, -jsonl` prints one object per match.
        argv = [self.binary_path() or self.binary, "-silent", "-jsonl"]
        for host in hosts:
            argv += ["-i", host]
        return argv

    def parse_output(self, raw: str) -> list[Record]:
        records: list[Record] = []
        seen: set[str] = set()
        for line in strip_ansi(raw).splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                raise ParseError("cdncheck: invalid JSON line") from None
            if not isinstance(data, dict):
                raise ParseError("cdncheck: JSON line is not an object")
            input_host = data.get("input")
            if not isinstance(input_host, str):
                raise ParseError("cdncheck: JSON line has no input")
            try:
                fqdn = validate_host(input_host)
            except (TypeError, ValueError):
                raise ParseError(f"cdncheck: invalid input {input_host!r}") from None
            tech = self._tech_names(data)
            waf = self._name(data, "waf", "waf_name")
            if fqdn in seen or (not tech and waf is None):
                continue
            seen.add(fqdn)
            records.append(
                HostStatusRecord(
                    fqdn=fqdn,
                    source=self.name,
                    state=HostState.UNKNOWN,
                    tech=tech,
                    waf=waf,
                )
            )
        return records

    @staticmethod
    def _name(data: dict[str, Any], flag: str, name_flag: str) -> str | None:
        """The provider name when its boolean flag is true, else None."""
        if data.get(flag) is not True:
            return None
        value = data.get(name_flag)
        return value.strip() if isinstance(value, str) and value.strip() else None

    def _tech_names(self, data: dict[str, Any]) -> list[str]:
        names: list[str] = []
        for flag, name_flag in (("cdn", "cdn_name"), ("cloud", "cloud_name")):
            name = self._name(data, flag, name_flag)
            if name is not None and name not in names:
                names.append(name)
        return sorted(names)
