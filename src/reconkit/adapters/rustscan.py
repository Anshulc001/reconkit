"""rustscan adapter (docs/09_TOOL_CONTRACTS.md section 4a6).

Verified on this box (rustscan 2.3.0, `~/.reconkit/bin/rustscan`):

- `rustscan --version` prints `rustscan 2.3.0`.
- `-g, --greppable` is `Greppable mode. Only output the ports. No Nmap.` and one
  real run printed `65.61.137.117 -> [443,80,8080]`.
- `-a, --addresses` takes a comma-separated list, `-p` a comma-separated port
  list, `--top` the top 1000 ports, `-n/--no-config` skips a user config file and
  `-u/--ulimit` raises the open-file limit (5000 is the value rustscan's own docs
  recommend).
- **No nmap dependency in greppable mode:** the same command with `PATH` emptied
  of `nmap` still printed the address line, so there is no "requires nmap" skip
  to implement (2026-11-17). 2.3.0 has no `-- <nmap args>` passthrough, so the
  service fingerprint stays nmap's job (`nmap` adapter, `-sV`) instead of being
  faked here.

`-g` prints the **resolved address**, not the input name. With one host in the
stage that address can only belong to that host, so `run` rewrites `fqdn` to it;
with several hosts the printed address is kept, which is the same IP-keyed
fallback `naabu` documents for scope mode.
"""

from __future__ import annotations

import re

from reconkit.adapters.base import BinaryAdapter, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import PortRecord, Record, RunContext, Stage, ToolResult

ULIMIT = "5000"
_OPEN_PORTS = re.compile(r"^(?P<address>\S+)\s*->\s*\[(?P<ports>[0-9,\s]*)\]$")


class RustscanAdapter(BinaryAdapter):
    name = "rustscan"
    stage = Stage.PORTS
    binary = "rustscan"
    version_args = ["--version"]
    identity_markers = ("rustscan",)

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
            raise ToolFailed("rustscan: no hosts to scan")
        ports = [port for port in ctx.ports if 1 <= port <= 65535]
        argv = [
            self.binary_path() or self.binary,
            "-g",
            "-n",
            "--ulimit",
            ULIMIT,
            "-a",
            ",".join(hosts),
        ]
        # A real `--ports` list replaces the top-1000 default, exactly like nmap.
        if ports:
            argv += ["-p", ",".join(str(port) for port in ports)]
        else:
            argv += ["--top"]
        return argv

    async def run(self, ctx: RunContext) -> ToolResult:
        result = await super().run(ctx)
        hosts = self._hosts(ctx)
        if len(hosts) == 1 and result.records:
            # Greppable output names the resolved address; a single-host stage
            # can only have resolved that one host, so keep the name it knows.
            records = [
                record.model_copy(update={"fqdn": hosts[0]})
                if isinstance(record, PortRecord)
                else record
                for record in result.records
            ]
            result = result.model_copy(update={"records": records})
        return result

    def parse_output(self, raw: str) -> list[Record]:
        records: list[Record] = []
        seen: set[tuple[str, str, int]] = set()
        for line in strip_ansi(raw).splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                # rustscan's log lines start with `[` (`[!] ...`); the greppable
                # result line never does.
                continue
            match = _OPEN_PORTS.match(line)
            if match is None:
                raise ParseError(f"rustscan: unexpected output line {line!r}")
            address = match.group("address")
            for field in match.group("ports").replace(" ", "").split(","):
                if not field:
                    continue
                try:
                    record = PortRecord(
                        fqdn=address,
                        ip=address,
                        port=int(field),
                        state="open",
                        source=self.name,
                    )
                except (TypeError, ValueError) as exc:
                    raise ParseError(f"rustscan: invalid port {field!r} ({exc})") from None
                key = (record.fqdn, record.ip, record.port)
                if key not in seen:
                    seen.add(key)
                    records.append(record)
        return records


__all__ = ["RustscanAdapter"]
