"""ProjectDiscovery httpx adapter (docs/09_TOOL_CONTRACTS.md).

The Python `httpx` CLI shares the binary name, so check_installed requires the
ProjectDiscovery banner/version text before the tool is used.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from reconkit.adapters.base import BinaryAdapter, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import HostState, HostStatusRecord, Record, RunContext, Stage


def _fqdn(value: str) -> str:
    host = urlsplit(value).hostname if "://" in value else value
    try:
        return validate_host(host or "")
    except (TypeError, ValueError):
        raise ParseError(f"httpx: invalid host {value!r}") from None


class HttpxAdapter(BinaryAdapter):
    name = "httpx"
    stage = Stage.LIVE
    binary = "httpx"
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
                raise ToolFailed(f"httpx: invalid host {raw!r}") from None
            if host not in seen:
                seen.add(host)
                hosts.append(host)
        if not hosts:
            raise ToolFailed("httpx: no hosts to probe")
        # The child gets only the env keys passed in, so it has no PATH: launch the
        # path binary_path() resolved (docs/09 adapter contract), never the bare name.
        argv = [
            self.binary_path() or self.binary,
            "-silent",
            "-json",
            "-no-stdin",
            "-duc",
            "-nc",
            "-sc",
            "-title",
            "-location",
            "-td",
            "-cdn",
        ]
        argv += ctx.pacer.tool_rate_args(self.name, "active")
        for host in hosts:
            argv += ["-u", host]
        return argv

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
                raise ParseError("httpx: invalid JSON line") from None
            if not isinstance(data, dict):
                raise ParseError("httpx: JSON line is not an object")
            value = data.get("input") or data.get("url")
            if not isinstance(value, str) or not value:
                raise ParseError("httpx: JSON line has no input/url")
            fqdn = _fqdn(value)
            status = data.get("status_code")
            if status is None:
                # A failed probe is not an HTTP response; httpx only prints a
                # line for it with -probe, which we do not pass.
                continue
            if not isinstance(status, int):
                raise ParseError("httpx: status_code must be an integer")
            title = data.get("title")
            location = data.get("location")
            if title is not None and not isinstance(title, str):
                raise ParseError("httpx: title must be a string")
            if location is not None and not isinstance(location, str):
                raise ParseError("httpx: location must be a string")
            tech = data.get("tech") or []
            if not isinstance(tech, list):
                raise ParseError("httpx: tech must be a list")
            waf = data.get("cdn_name")
            record = HostStatusRecord(
                fqdn=fqdn,
                source=self.name,
                state=HostState.ALIVE,
                status_code=status,
                title=title,
                location=location,
                tech=[str(item) for item in tech],
                waf=waf if isinstance(waf, str) and waf else None,
            )
            if fqdn not in seen:
                seen.add(fqdn)
                records.append(record)
        return records
