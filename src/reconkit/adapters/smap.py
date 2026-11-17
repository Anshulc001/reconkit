"""smap adapter (docs/09_TOOL_CONTRACTS.md section 4a6).

`smap` is `mode: passive` in `tools.yaml`: it reads Shodan's public data, so no
packet reaches the target and the adapter needs no scope predicate of its own.

Verified on this box (Smap 1.0.0-beta, `~/.reconkit/bin/smap`):

- `smap -h` lists `-iL <filename>` (use `-` for stdin), `--concurrency <n>`
  (default 3) and `-oJ JSON` among the output flags; `smap testfire.net -oJ -`
  printed a JSON array.
- One array element is a host: `{"ip", "hostnames": [...], "user_hostname",
  "ports": [{"port": 80, "service": "http?", "protocol": "tcp", ...}], ...}`.
  `user_hostname` is the name the operator asked for, so it is what the record
  stores and a passive answer joins the same host rows the active tools write.
- `service` keeps smap's own uncertainty marker (`http?`), because dropping the
  `?` would turn "Shodan thinks" into "we verified".

**`--ports` filters, it cannot select.** smap has no port list to scan - it
reports what Shodan already observed - so `run` drops passive ports outside
`ctx.ports` after parsing. Dropping the filter instead would store ports the
operator explicitly excluded.
"""

from __future__ import annotations

import ipaddress
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from reconkit.adapters.base import BinaryAdapter, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import PortRecord, Record, RunContext, Stage, ToolResult


class SmapAdapter(BinaryAdapter):
    name = "smap"
    stage = Stage.PORTS
    binary = "smap"
    version_args = ["-h"]
    # `smap -h` opens with `Smap 1.0.0-beta` then `Usage: smap <targets here>`;
    # both are needed so a namesake that merely mentions smap is rejected.
    identity_markers = ("smap", "usage: smap")

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

    def _targets_file(self, ctx: RunContext) -> Path:
        return ctx.workspace / f"smap-targets-{os.getpid()}.txt"

    def _output_file(self, ctx: RunContext) -> Path:
        return ctx.workspace / f"smap-output-{os.getpid()}.json"

    @contextmanager
    def prepare(self, ctx: RunContext) -> Iterator[None]:
        """Write the `-iL` file and remove both per-run files afterwards."""
        targets = self._targets_file(ctx)
        output = self._output_file(ctx)
        targets.write_text("".join(f"{host}\n" for host in self._hosts(ctx)), encoding="utf-8")
        output.unlink(missing_ok=True)
        try:
            yield
        finally:
            targets.unlink(missing_ok=True)
            output.unlink(missing_ok=True)

    def build_command(self, ctx: RunContext) -> list[str]:
        if not self._hosts(ctx):
            raise ToolFailed("smap: no hosts to scan")
        # No `--concurrency`: the tool's own default stands, because reconkit adds
        # no pacing (docs/MASTER_PLAN.md D3).
        return [
            self.binary_path() or self.binary,
            "-iL",
            str(self._targets_file(ctx)),
            "-oJ",
            str(self._output_file(ctx)),
        ]

    def read_output(self, ctx: RunContext) -> str | None:
        """smap writes its JSON to `-oJ`; stdout carries its progress lines."""
        output = self._output_file(ctx)
        if not output.is_file():
            raise ParseError("smap: no -oJ file was written")
        return output.read_text(encoding="utf-8", errors="replace")

    async def run(self, ctx: RunContext) -> ToolResult:
        result = await super().run(ctx)
        wanted = {port for port in ctx.ports if 1 <= port <= 65535}
        if wanted:
            # `--ports` is an output filter here: smap reports what Shodan saw and
            # cannot be told which ports to scan.
            kept = [
                record
                for record in result.records
                if not isinstance(record, PortRecord) or record.port in wanted
            ]
            if len(kept) != len(result.records):
                result = result.model_copy(update={"records": kept})
        return result

    def parse_output(self, raw: str) -> list[Record]:
        text = strip_ansi(raw).strip()
        if not text:
            # Verified behaviour: an empty target list writes an empty document.
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            raise ParseError("smap: output is not valid JSON") from None
        if data is None:
            return []
        if not isinstance(data, list):
            raise ParseError("smap: output is not a JSON array")
        records: list[Record] = []
        seen: set[tuple[str, str, int]] = set()
        for entry in data:
            if not isinstance(entry, dict):
                raise ParseError("smap: entry is not an object")
            address = entry.get("ip")
            if not isinstance(address, str):
                raise ParseError("smap: entry has no ip")
            try:
                ipaddress.ip_address(address)
            except ValueError:
                raise ParseError(f"smap: invalid ip {address!r}") from None
            fqdn = _fqdn(entry, address)
            ports = entry.get("ports", [])
            if not isinstance(ports, list):
                raise ParseError("smap: entry ports is not a list")
            for item in ports:
                if not isinstance(item, dict):
                    raise ParseError("smap: port entry is not an object")
                raw_port = item.get("port")
                if not isinstance(raw_port, int) or isinstance(raw_port, bool):
                    raise ParseError("smap: port entry has no integer port")
                try:
                    record = PortRecord(
                        fqdn=fqdn,
                        ip=address,
                        port=raw_port,
                        protocol="udp" if item.get("protocol") == "udp" else "tcp",
                        state="open",
                        service=_service(item),
                        source=self.name,
                    )
                except (TypeError, ValueError) as exc:
                    raise ParseError(f"smap: invalid port entry ({exc})") from None
                key = (record.fqdn, record.ip, record.port)
                if key not in seen:
                    seen.add(key)
                    records.append(record)
        return records


def _fqdn(entry: dict[str, object], address: str) -> str:
    candidates = [entry.get("user_hostname")]
    hostnames = entry.get("hostnames")
    if isinstance(hostnames, list):
        candidates.extend(hostnames)
    for candidate in candidates:
        if not isinstance(candidate, str) or not candidate:
            continue
        try:
            return validate_host(candidate)
        except (TypeError, ValueError):
            continue
    return address


def _service(item: dict[str, object]) -> str | None:
    service = item.get("service")
    return service if isinstance(service, str) and service else None


__all__ = ["SmapAdapter"]
