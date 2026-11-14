"""naabu binary adapter (docs/09_TOOL_CONTRACTS.md).

Connect scan only (`-scan-type c`), so it works without root. Port order is the
engine's; naabu receives one validated host list and one port list.
"""

from __future__ import annotations

import ipaddress
import json

from reconkit.adapters.base import BinaryAdapter, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import PortRecord, Record, RunContext, Stage


class NaabuAdapter(BinaryAdapter):
    name = "naabu"
    stage = Stage.PORTS
    binary = "naabu"
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
                raise ToolFailed(f"naabu: invalid host {raw!r}") from None
            if host not in seen:
                seen.add(host)
                hosts.append(host)
        if not hosts:
            raise ToolFailed("naabu: no hosts to scan")
        ports = [port for port in ctx.ports if 1 <= port <= 65535]
        # The child gets only the env keys passed in, so it has no PATH: launch the
        # path binary_path() resolved (docs/09 adapter contract), never the bare name.
        argv = [
            self.binary_path() or self.binary,
            "-silent",
            "-json",
            "-no-stdin",
            "-duc",
            "-nc",
            "-scan-type",
            "c",
            "-host",
            ",".join(hosts),
        ]
        argv += ctx.pacer.tool_rate_args(self.name, "active")
        if ports:
            argv += ["-p", ",".join(str(port) for port in ports)]
        return argv

    def parse_output(self, raw: str) -> list[Record]:
        records: list[Record] = []
        seen: set[tuple[str, str, int]] = set()
        for line in strip_ansi(raw).splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                raise ParseError("naabu: invalid JSON line") from None
            if not isinstance(data, dict):
                raise ParseError("naabu: JSON line is not an object")
            ip = data.get("ip")
            port = data.get("port")
            if not isinstance(ip, str) or isinstance(port, bool) or not isinstance(port, int):
                raise ParseError("naabu: JSON line needs an ip and an integer port")
            try:
                ipaddress.ip_address(ip)
                record = PortRecord(
                    fqdn=_fqdn(data.get("host") or ip),
                    ip=ip,
                    port=port,
                    state="open",
                    source=self.name,
                )
            except (TypeError, ValueError) as exc:
                raise ParseError(f"naabu: invalid JSON line ({exc})") from None
            key = (record.fqdn, record.ip, record.port)
            if key not in seen:
                seen.add(key)
                records.append(record)
        return records


def _fqdn(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("missing host")
    if ":" in value:
        return str(ipaddress.ip_address(value))
    return validate_host(value)
