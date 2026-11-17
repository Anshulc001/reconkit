"""dig adapter (docs/09_TOOL_CONTRACTS.md).

Verified on this box (DiG 9.20.30-1-Debian, `/usr/bin/dig`):

- `dig -v` prints `DiG 9.20.30-1-Debian`.
- `dig +noall +answer -f <hosts file>` resolves every name in the file in one
  process and prints labelled answers:
  `testfire.net. 75048 IN A 65.61.137.117` and
  `www.testfire.net. 72983 IN CNAME testfire.net.`.
  Plain `+short` loses the name, so it can not attribute an address to a host.

**Why keep dig when dnspython exists?** dnspython is a resolver with a wildcard
probe and dangling-CNAME logic; `dig` is an independent second DNS source for
the same hosts, which is what raises a `DNS_ONLY` host's confidence from LOW to
MEDIUM (`docs/09` section 5). It is deliberately narrower: A/AAAA/CNAME only,
no MX/TXT/NS, and the adapter does not pretend otherwise.
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


class DigAdapter(BinaryAdapter):
    name = "dig"
    stage = Stage.DNS
    binary = "dig"
    version_args = ["-v"]
    identity_markers = ("dig",)

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
        return ctx.workspace / f"dig-hosts-{os.getpid()}.txt"

    @contextmanager
    def prepare(self, ctx: RunContext) -> Iterator[None]:
        target = self._input_file(ctx)
        target.write_text("".join(f"{host}\n" for host in self._hosts(ctx)), encoding="utf-8")
        try:
            yield
        finally:
            target.unlink(missing_ok=True)

    def build_command(self, ctx: RunContext) -> list[str]:
        hosts = self._hosts(ctx)
        if not hosts:
            raise ToolFailed("dig: no hosts to resolve")
        return [
            self.binary_path() or self.binary,
            "+noall",
            "+answer",
            "-f",
            str(self._input_file(ctx)),
        ]

    def parse_output(self, raw: str) -> list[Record]:
        found: dict[str, dict[str, list[str]]] = {}
        for line in strip_ansi(raw).splitlines():
            text = line.strip()
            if not text:
                continue
            fields = text.split()
            if len(fields) < 5 or "IN" not in fields:
                raise ParseError(f"dig: unexpected answer line {text!r}")
            name, record_type, value = fields[0], fields[3], fields[4]
            try:
                fqdn = validate_host(name)
            except (TypeError, ValueError):
                raise ParseError(f"dig: invalid host {name!r}") from None
            entry = found.setdefault(fqdn, {"ips": [], "cnames": []})
            if record_type in ("A", "AAAA"):
                entry["ips"].append(str(ipaddress.ip_address(value.rstrip("."))))
            elif record_type == "CNAME":
                try:
                    entry["cnames"].append(validate_host(value))
                except (TypeError, ValueError):
                    raise ParseError(f"dig: invalid CNAME target {value!r}") from None
            else:
                # The query is A-only; any other answer type is not expected.
                raise ParseError(f"dig: unexpected record type {record_type!r}")
        return [
            SubdomainRecord(fqdn=fqdn, source=self.name, ips=sorted(set(entry["ips"])))
            if not entry["cnames"]
            else SubdomainRecord(
                fqdn=fqdn,
                source=self.name,
                ips=sorted(set(entry["ips"])),
                cnames=sorted(set(entry["cnames"])),
            )
            for fqdn, entry in found.items()
        ]


__all__ = ["DigAdapter"]
