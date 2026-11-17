"""massdns adapter (docs/09_TOOL_CONTRACTS.md).

Verified on this box (massdns 1.1.0, `/usr/bin/massdns`):

- `massdns --help` documents `-r/--resolvers` (a text file of resolvers),
  `-t/--type`, `-o/--output` and `-w/--outfile`; `--version` prints only
  `massdns ` (no number), so the identity probe is the help text.
- A real run
  `massdns -r <resolvers> -t A -o S -w out.txt hosts.txt` printed
  `demo.testfire.net. A 65.61.137.117`, `testfire.net. A 65.61.137.117` and
  `www.testfire.net. CNAME testfire.net.` - the `S` ("simple") format, one
  record per line, name and value with a trailing dot.
- The resolver list is the packaged `src/reconkit/data/resolvers.txt` (D16),
  overridable with `--resolvers PATH`. A missing file is a failed result, never
  a silent fallback to the system resolver: massdns has no other source.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from reconkit.adapters.base import BinaryAdapter, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import Record, RunContext, Stage, SubdomainRecord

DEFAULT_RESOLVERS = Path(__file__).resolve().parents[1] / "data" / "resolvers.txt"


def resolvers_path(ctx: RunContext) -> Path:
    """`--resolvers PATH` when given, else the packaged list (D16)."""
    path = ctx.resolvers if ctx.resolvers is not None else DEFAULT_RESOLVERS
    if not path.is_file():
        raise ToolFailed(f"{'resolvers'}: resolvers file not found: {path}")
    return path


class MassdnsAdapter(BinaryAdapter):
    name = "massdns"
    stage = Stage.DNS
    binary = "massdns"
    version_args = ["--help"]
    identity_markers = ("massdns", "resolvers")

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

    def _input_file(self, ctx: RunContext) -> Path:
        return ctx.workspace / f"massdns-hosts-{os.getpid()}.txt"

    def _output_file(self, ctx: RunContext) -> Path:
        return ctx.workspace / f"massdns-output-{os.getpid()}.txt"

    @contextmanager
    def prepare(self, ctx: RunContext) -> Iterator[None]:
        targets = self._input_file(ctx)
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
            raise ToolFailed("massdns: no hosts to resolve")
        return [
            self.binary_path() or self.binary,
            "-r",
            str(resolvers_path(ctx)),
            "-t",
            "A",
            "-o",
            "S",
            "-w",
            str(self._output_file(ctx)),
            str(self._input_file(ctx)),
        ]

    def read_output(self, ctx: RunContext) -> str | None:
        """massdns writes the `S` records to `-w`, not to stdout."""
        output = self._output_file(ctx)
        if not output.is_file():
            raise ParseError("massdns: no -w file was written")
        return output.read_text(encoding="utf-8", errors="replace")

    def parse_output(self, raw: str) -> list[Record]:
        found: dict[str, tuple[list[str], list[str]]] = {}
        for line in strip_ansi(raw).splitlines():
            text = line.strip()
            if not text:
                continue
            fields = text.split()
            if len(fields) < 3:
                raise ParseError(f"massdns: unexpected line {text!r}")
            name, record_type, value = fields[0], fields[1], fields[2]
            try:
                fqdn = validate_host(name)
            except (TypeError, ValueError):
                raise ParseError(f"massdns: invalid name {name!r}") from None
            ips, cnames = found.setdefault(fqdn, ([], []))
            if record_type in ("A", "AAAA"):
                try:
                    ips.append(str(ipaddress.ip_address(value.rstrip("."))))
                except ValueError:
                    raise ParseError(f"massdns: invalid address {value!r}") from None
            elif record_type == "CNAME":
                try:
                    cnames.append(validate_host(value))
                except (TypeError, ValueError):
                    raise ParseError(f"massdns: invalid CNAME {value!r}") from None
            else:
                raise ParseError(f"massdns: unexpected record type {record_type!r}")
        return [
            SubdomainRecord(
                fqdn=fqdn,
                source=self.name,
                ips=sorted(set(ips)),
                cnames=sorted(set(cnames)),
            )
            for fqdn, (ips, cnames) in found.items()
        ]


__all__ = ["DEFAULT_RESOLVERS", "MassdnsAdapter", "resolvers_path"]
