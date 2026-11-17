"""nmap adapter (docs/09_TOOL_CONTRACTS.md section 4a6).

`nmap` is the ports stage's verifier: `-sV` turns an open port into a
service/version fingerprint, which docs/09 section 5 says raises confidence.

Verified on this box (Nmap 7.991, `/usr/bin/nmap`):

- `nmap --version` prints `Nmap version 7.991 ( https://nmap.org )`.
- `-oX <file>` writes one `<nmaprun>` document; each `<host>` carries
  `<address addr=... addrtype="ipv4">`, optional `<hostnames>`, and `<ports>`
  with `<port protocol="tcp" portid="80"><state state="open"/><service name=
  "http" product="Apache Tomcat/Coyote JSP engine" version="1.1"/></port>`.
- `-p <list>` and `--top-ports <number>` both exist (`-p` takes
  `80,443,8000-8100`; `--top-ports 1000` is the documented default here).

No scan type is passed: unprivileged nmap does a `-sT` connect scan, which is
the scan docs/01 Feature 5 documents, and `-sS`/`-O`/scripts are never enabled
by the adapter. `-Pn` keeps the scan from depending on ICMP, because the live
stage already decided the host answers.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ElementTree
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from reconkit.adapters.base import BinaryAdapter
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import PortRecord, Record, RunContext, Stage

# 1000 is nmap's own `--top-ports` size and the set the ports stage documents.
TOP_PORTS = "1000"


class NmapAdapter(BinaryAdapter):
    name = "nmap"
    stage = Stage.PORTS
    binary = "nmap"
    version_args = ["--version"]
    identity_markers = ("nmap version", "nmap.org")

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

    def _output_file(self, ctx: RunContext) -> Path:
        return ctx.workspace / f"nmap-output-{os.getpid()}.xml"

    @contextmanager
    def prepare(self, ctx: RunContext) -> Iterator[None]:
        """Drop a stale XML file before the run and the new one afterwards."""
        output = self._output_file(ctx)
        output.unlink(missing_ok=True)
        try:
            yield
        finally:
            output.unlink(missing_ok=True)

    def build_command(self, ctx: RunContext) -> list[str]:
        hosts = self._hosts(ctx)
        if not hosts:
            raise ToolFailed("nmap: no hosts to scan")
        ports = [port for port in ctx.ports if 1 <= port <= 65535]
        argv = [
            self.binary_path() or self.binary,
            "-sV",
            "-Pn",
            "-oX",
            str(self._output_file(ctx)),
            "--open",
        ]
        # `--ports` replaces the top-ports set; it never adds to it, so a scan
        # covers exactly the ports the operator asked for.
        if ports:
            argv += ["-p", ",".join(str(port) for port in ports)]
        else:
            argv += ["--top-ports", TOP_PORTS]
        return [*argv, *hosts]

    def read_output(self, ctx: RunContext) -> str | None:
        """nmap writes XML to `-oX`; stdout only carries the interactive log."""
        output = self._output_file(ctx)
        if not output.is_file():
            raise ParseError("nmap: no -oX file was written")
        return output.read_text(encoding="utf-8", errors="replace")

    def parse_output(self, raw: str) -> list[Record]:
        try:
            root = ElementTree.fromstring(raw)
        except ElementTree.ParseError as exc:
            raise ParseError(f"nmap: invalid XML ({exc})") from None
        records: list[Record] = []
        seen: set[tuple[str, str, int]] = set()
        for host in root.iter("host"):
            address = _address(host)
            if address is None:
                raise ParseError("nmap: host element has no IP address")
            fqdn = _fqdn(host) or address
            for port_element in host.findall("./ports/port"):
                state = port_element.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = port_element.get("portid")
                try:
                    port = int(portid or "")
                    record = PortRecord(
                        fqdn=fqdn,
                        ip=address,
                        port=port,
                        protocol=_protocol(port_element.get("protocol")),
                        state="open",
                        service=_service(port_element),
                        version=_version(port_element),
                        source=self.name,
                    )
                except (TypeError, ValueError) as exc:
                    raise ParseError(f"nmap: invalid port element ({exc})") from None
                key = (record.fqdn, record.ip, record.port)
                if key not in seen:
                    seen.add(key)
                    records.append(record)
        return records


def _address(host: ElementTree.Element) -> str | None:
    """The host's IP: prefer ipv4, then ipv6; a MAC address is not a host."""
    for kind in ("ipv4", "ipv6"):
        for address in host.findall("./address"):
            if address.get("addrtype") == kind and address.get("addr"):
                return address.get("addr")
    return None


def _fqdn(host: ElementTree.Element) -> str | None:
    for hostname in host.findall("./hostnames/hostname"):
        name = hostname.get("name")
        if not name:
            continue
        try:
            return validate_host(name)
        except (TypeError, ValueError):
            continue
    return None


def _protocol(value: str | None) -> Literal["tcp", "udp"]:
    return "udp" if value == "udp" else "tcp"


def _service(port: ElementTree.Element) -> str | None:
    service = port.find("service")
    name = service.get("name") if service is not None else None
    return name or None


def _version(port: ElementTree.Element) -> str | None:
    """`product version` as one string, the `-sV` fingerprint docs/09 section 5 wants."""
    service = port.find("service")
    if service is None:
        return None
    parts = [service.get("product"), service.get("version")]
    text = " ".join(part.strip() for part in parts if part and part.strip())
    return text or None


__all__ = ["NmapAdapter", "TOP_PORTS"]
