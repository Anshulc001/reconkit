"""masscan adapter (docs/09_TOOL_CONTRACTS.md section 4a6).

`masscan` is `opt_in` and the one ports tool that needs root: it opens raw
sockets. Verified on this box (Masscan 1.3.2, `/usr/bin/masscan`), as `kali`:

```
$ masscan -p80 127.0.0.1 --output-format json -oJ /tmp/m.json --rate 100
[-] FAIL: permission denied
    [hint] need to sudo or run as root or something
```

so the adapter checks `os.geteuid()` **before** building the command and
returns `skipped (requires root / sudo)` when the process is not root. It never
runs `sudo` itself (AGENTS rule 1) and never sets capabilities on the binary:
`sudo reconkit run ...` or a one-time `setcap cap_net_raw+ep` is the operator's
decision.

Flags come from the installed tool, not from memory:

- `masscan --help`: `All single-dash parameters have a spelled out double-dash
  equivalent, so '-p80' is the same as '--ports 80'`.
- The manpage takes **IP addresses and ranges only** as targets ("anything on
  the command-line not prefixed with a '-' is assumed to be an IP address or
  range"), so `ctx.hosts` names are resolved here and only addresses
  `ctx.ip_allowed` permits are scanned (docs/05 rule 6); masscan is never handed
  a name to resolve a second time.
- `-oL <filename>` is the list format documented in
  `/usr/share/doc/masscan/README.md.gz`: `open tcp 80 XXX.XXX.XXX.XXX
  1390380064`. The JSON output (`-oJ`) needs a root scan to observe, which this
  build does not have, so the adapter writes the format whose example ships with
  the package instead of an unverified schema.
- `--rate 1000` is masscan's own transmit rate (its help calls 100 packets/s the
  default): a rate is mandatory for the tool and this is not reconkit pacing
  (D3).
"""

from __future__ import annotations

import ipaddress
import os
import socket
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from reconkit.adapters.base import BinaryAdapter, running_as_root, strip_ansi
from reconkit.adapters.pyscan import DEFAULT_PORTS
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import PortRecord, Record, RunContext, Stage, ToolResult, ToolStatus

RATE = "1000"
ROOT_REQUIRED = "requires root / sudo"
# Same question the engine's `needs_root` selection rule asks (base.py), kept as a
# module attribute so the adapter's own guard is the second line of defence.
is_root = running_as_root


class MasscanAdapter(BinaryAdapter):
    name = "masscan"
    stage = Stage.PORTS
    binary = "masscan"
    version_args = ["--version"]
    # `masscan --version` prints `Masscan version 1.3.2 ...` but exits 1 (PIT-35);
    # `check_installed` accepts a non-zero exit as long as the banner matches.
    identity_markers = ("masscan version",)

    def _output_file(self, ctx: RunContext) -> Path:
        return ctx.workspace / f"masscan-output-{os.getpid()}.list"

    @contextmanager
    def prepare(self, ctx: RunContext) -> Iterator[None]:
        output = self._output_file(ctx)
        output.unlink(missing_ok=True)
        try:
            yield
        finally:
            output.unlink(missing_ok=True)

    async def run(self, ctx: RunContext) -> ToolResult:
        if not is_root():
            # Runtime skip, not a failure: the binary is fine, this process may
            # not open raw sockets. Documented exception in docs/09 section 4a6.
            return ToolResult(tool=self.name, status=ToolStatus.SKIPPED, error=ROOT_REQUIRED)
        return await super().run(ctx)

    def _targets(self, ctx: RunContext) -> list[str]:
        """Resolve the stage's hosts to permitted IPs; masscan takes no names."""
        addresses: list[str] = []
        seen: set[str] = set()
        for raw in ctx.hosts:
            try:
                host = validate_host(raw)
            except (TypeError, ValueError):
                continue
            for address in _resolve(host):
                if ctx.ip_allowed is None:
                    # docs/05 rule 6: no predicate means no permission.
                    continue
                try:
                    permitted = ctx.ip_allowed(address)
                except ValueError:
                    permitted = False
                if permitted and address not in seen:
                    seen.add(address)
                    addresses.append(address)
        return addresses

    def build_command(self, ctx: RunContext) -> list[str]:
        targets = self._targets(ctx)
        if not targets:
            raise ToolFailed("masscan: no permitted IP addresses to scan")
        ports = [port for port in ctx.ports if 1 <= port <= 65535] or list(DEFAULT_PORTS)
        return [
            self.binary_path() or self.binary,
            ",".join(targets),
            f"-p{','.join(str(port) for port in ports)}",
            "--rate",
            RATE,
            "-oL",
            str(self._output_file(ctx)),
        ]

    def read_output(self, ctx: RunContext) -> str | None:
        """masscan writes the list format to `-oL`; stdout is its status summary."""
        output = self._output_file(ctx)
        if not output.is_file():
            raise ParseError("masscan: no -oL file was written")
        return output.read_text(encoding="utf-8", errors="replace")

    def parse_output(self, raw: str) -> list[Record]:
        records: list[Record] = []
        seen: set[tuple[str, str, int]] = set()
        for line in strip_ansi(raw).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                # `#masscan` and `#rate` banner lines are comments.
                continue
            fields = line.split()
            if len(fields) < 5:
                raise ParseError(f"masscan: unexpected output line {line!r}")
            state, protocol, port_text, address = fields[0], fields[1], fields[2], fields[3]
            if state != "open":
                continue
            try:
                record = PortRecord(
                    fqdn=address,
                    ip=address,
                    port=int(port_text),
                    protocol="udp" if protocol == "udp" else "tcp",
                    state="open",
                    source=self.name,
                )
            except (TypeError, ValueError) as exc:
                raise ParseError(f"masscan: invalid output line {line!r} ({exc})") from None
            key = (record.fqdn, record.ip, record.port)
            if key not in seen:
                seen.add(key)
                records.append(record)
        return records


def _resolve(host: str) -> list[str]:
    """Local resolution only: masscan is given addresses, never names."""
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        # Not a literal, so it is a name the OS resolver has to translate.
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    return sorted({str(info[4][0]) for info in infos})


__all__ = ["MasscanAdapter", "ROOT_REQUIRED", "is_root"]
