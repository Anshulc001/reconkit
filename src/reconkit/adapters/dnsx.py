"""ProjectDiscovery dnsx adapter (docs/09_TOOL_CONTRACTS.md).

dnsx resolves the hosts the earlier stages discovered. Only an NXDOMAIN answer
becomes DEAD (PIT-01): a line with no A record, a missing status code and a
failed run all stay "no evidence" instead of a false death certificate.
"""

from __future__ import annotations

import json

from reconkit.adapters.base import BinaryAdapter, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import HostState, HostStatusRecord, Record, RunContext, Stage, SubdomainRecord


class DnsxAdapter(BinaryAdapter):
    name = "dnsx"
    stage = Stage.DNS
    binary = "dnsx"
    version_args = ["-version"]
    identity_markers = ("projectdiscovery", "current version")
    needs_home = True

    def build_command(self, ctx: RunContext) -> list[str]:
        hosts: list[str] = []
        seen: set[str] = set()
        for raw in ctx.hosts:
            try:
                host = validate_host(raw)
            except (TypeError, ValueError):
                raise ToolFailed(f"dnsx: invalid host {raw!r}") from None
            if host not in seen:
                seen.add(host)
                hosts.append(host)
        if not hosts:
            raise ToolFailed("dnsx: no hosts to resolve")
        # Verified against the real binary: dnsx has no repeated `-u`; its input
        # is `-l, -list string  list of sub(domains)/hosts to resolve (file or
        # comma separated or stdin)`. Every host is already validated, so the
        # comma-joined list can carry no separator or metacharacter.
        # `-or` omits the raw DNS packet, which no record uses.
        return [
            self.binary_path() or self.binary,
            "-silent",
            "-json",
            "-a",
            "-or",
            "-duc",
            "-nc",
            "-l",
            ",".join(hosts),
        ]

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
                raise ParseError("dnsx: invalid JSON line") from None
            if not isinstance(data, dict):
                raise ParseError("dnsx: JSON line is not an object")
            host = data.get("host")
            if not isinstance(host, str) or not host:
                raise ParseError("dnsx: JSON line has no host")
            try:
                fqdn = validate_host(host)
            except (TypeError, ValueError):
                raise ParseError(f"dnsx: invalid host {host!r}") from None
            if fqdn in seen:
                continue
            addresses = data.get("a") or []
            if not isinstance(addresses, list):
                raise ParseError("dnsx: 'a' must be a list")
            if addresses:
                seen.add(fqdn)
                records.append(
                    SubdomainRecord(
                        fqdn=fqdn,
                        source=self.name,
                        ips=[str(address) for address in addresses],
                    )
                )
            elif str(data.get("status_code", "")).upper() == "NXDOMAIN":
                seen.add(fqdn)
                records.append(HostStatusRecord(fqdn=fqdn, source=self.name, state=HostState.DEAD))
        return records
