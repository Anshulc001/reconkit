"""ProjectDiscovery tlsx adapter (docs/09_TOOL_CONTRACTS.md).

Liveness-only by ruling: a line proves the host answered a TLS handshake and its
certificate names new hosts (SANs). Certificate metadata (expiry, issuer,
wildcard, self-signed) is deliberately not persisted yet - see docs/09.
"""

from __future__ import annotations

import json

from reconkit.adapters.base import BinaryAdapter, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import (
    HostState,
    HostStatusRecord,
    Record,
    RunContext,
    Stage,
    SubdomainRecord,
)

SAN_SOURCE = "tlsx:san"


class TlsxAdapter(BinaryAdapter):
    name = "tlsx"
    stage = Stage.LIVE
    binary = "tlsx"
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
                raise ToolFailed(f"tlsx: invalid host {raw!r}") from None
            if host not in seen:
                seen.add(host)
                hosts.append(host)
        if not hosts:
            raise ToolFailed("tlsx: no hosts to probe")
        # Verified against the real binary: `-u, -host string[]` (repeatable) and
        # `-san`/`-cn` add subject_an/subject_cn to the JSON line. `-duc` and
        # `-nc` keep the run offline and colour-free.
        argv = [
            self.binary_path() or self.binary,
            "-silent",
            "-json",
            "-san",
            "-duc",
            "-nc",
        ]
        for host in hosts:
            argv += ["-u", host]
        return argv

    def parse_output(self, raw: str) -> list[Record]:
        hosts: dict[str, HostStatusRecord] = {}
        sans: list[Record] = []
        seen_sans: set[str] = set()
        for line in strip_ansi(raw).splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                raise ParseError("tlsx: invalid JSON line") from None
            if not isinstance(data, dict):
                raise ParseError("tlsx: JSON line is not an object")
            host = data.get("host")
            if not isinstance(host, str) or not host:
                raise ParseError("tlsx: JSON line has no host")
            try:
                fqdn = validate_host(host)
            except (TypeError, ValueError):
                raise ParseError(f"tlsx: invalid host {host!r}") from None
            probed = data.get("probe_status") is True
            ip = data.get("ip")
            ip = ip if isinstance(ip, str) and ip else None
            record = hosts.get(fqdn)
            if record is None:
                hosts[fqdn] = HostStatusRecord(
                    fqdn=fqdn,
                    source=self.name,
                    state=HostState.ALIVE if probed else HostState.UNKNOWN,
                    # A failed handshake is the reason this pass cannot call the
                    # host ALIVE, which is exactly what `detail` documents.
                    detail=None if probed else "tls probe failed",
                    ips=[ip] if ip else [],
                )
            else:
                if probed and record.state is not HostState.ALIVE:
                    record.state = HostState.ALIVE
                    record.detail = None
                if ip is not None and ip not in record.ips:
                    record.ips.append(ip)
            names = data.get("subject_an") or []
            if not isinstance(names, list):
                raise ParseError("tlsx: subject_an must be a list")
            for name in names:
                if not isinstance(name, str):
                    continue
                # A wildcard SAN names the parent, which is the host worth
                # remembering; anything that is not a hostname is skipped
                # rather than failing the whole run on a certificate's text.
                candidate = name.strip().lower().removeprefix("*.")
                try:
                    san = validate_host(candidate)
                except (TypeError, ValueError):
                    continue
                if san not in seen_sans:
                    seen_sans.add(san)
                    sans.append(SubdomainRecord(fqdn=san, source=SAN_SOURCE))
        return [*hosts.values(), *sans]
