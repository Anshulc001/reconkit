"""dnsreaper adapter (docs/09_TOOL_CONTRACTS.md).

dnsreaper is a Python project with no console script: `main.py` plus
`requirements.txt`. `scripts/setup.sh` clones the pinned commit under
`~/.reconkit/opt/dnsreaper`, builds its own venv and writes the
`~/.reconkit/bin/dnsreaper` launcher, so from the adapter's side it is one
binary that takes arguments (D100).

Invocation verified against the real tool (commit c1588b2):

- `--help` prints the banner to stderr and exits 0; the banner names the tool
  and says what it does.
- `file --filename <path>` reads one name per line, which is how a host list is
  scanned in one run.
- `--out <path> --out-format json --nocolour` writes the findings to that file
  and leaves stdout for log lines. The writer emits `[` then one JSON object per
  finding, so an empty result is an empty file, not `[]`.
- Each object: `domain`, `signature`, `info`, `confidence`, `a_records`,
  `aaaa_records`, `cname_records`, `ns_records`, `more_info_url`.

`confidence` is `CONFIRMED`, `POTENTIAL` or `UNLIKELY`. UNLIKELY checks are off
by default, and the two remaining levels are the real difference between "this
can be taken over" and "this may be" - so they map to `high` and `medium`
instead of one flat severity. Only entries that actually matched become
findings; the tool has no "checked and clean" output.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from reconkit.adapters.base import BinaryAdapter, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import FindingRecord, Record, RunContext, Stage

Severity = Literal["info", "low", "medium", "high", "critical", "unknown"]

# The three levels the tool defines (detection_enums.CONFIDENCE).
SEVERITIES: dict[str, Severity] = {
    "CONFIRMED": "high",
    "POTENTIAL": "medium",
    "UNLIKELY": "low",
}


class DnsreaperAdapter(BinaryAdapter):
    name = "dnsreaper"
    stage = Stage.VULNS
    binary = "dnsreaper"
    # `--help` is the only flag that exits 0 without scanning; the banner is on
    # stderr and carries both markers below.
    version_args = ["--help"]
    identity_markers = ("dns reaper", "subdomain takeovers")
    needs_home = True

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

    def _hosts_file(self, ctx: RunContext) -> Path:
        return ctx.workspace / f"dnsreaper-hosts-{os.getpid()}.txt"

    def _output_file(self, ctx: RunContext) -> Path:
        return ctx.workspace / f"dnsreaper-output-{os.getpid()}.json"

    @contextmanager
    def prepare(self, ctx: RunContext) -> Iterator[None]:
        """Write the `--filename` list and remove both per-run files afterwards."""
        hosts = self._hosts_file(ctx)
        output = self._output_file(ctx)
        hosts.write_text("".join(f"{host}\n" for host in self._hosts(ctx)), encoding="utf-8")
        try:
            yield
        finally:
            hosts.unlink(missing_ok=True)
            output.unlink(missing_ok=True)

    def build_command(self, ctx: RunContext) -> list[str]:
        if not self._hosts(ctx):
            raise ToolFailed("dnsreaper: no hosts to check")
        # No `--parallelism`: the tool's own default stands, and reconkit adds no
        # pacing (docs/MASTER_PLAN.md D3).
        return [
            self.binary_path() or self.binary,
            "file",
            "--filename",
            str(self._hosts_file(ctx)),
            "--out",
            str(self._output_file(ctx)),
            "--out-format",
            "json",
            "--nocolour",
        ]

    def read_output(self, ctx: RunContext) -> str | None:
        """dnsreaper writes findings to `--out`, never to stdout."""
        output = self._output_file(ctx)
        if not output.is_file():
            raise ParseError("dnsreaper: no --out file was written")
        return output.read_text(encoding="utf-8")

    def parse_output(self, raw: str) -> list[Record]:
        text = strip_ansi(raw).strip()
        if not text:
            # The writer prints nothing when there is no finding, not `[]`.
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            raise ParseError("dnsreaper: output is not valid JSON") from None
        if not isinstance(data, list):
            raise ParseError("dnsreaper: output is not a JSON array")
        records: list[Record] = []
        for entry in data:
            if not isinstance(entry, dict):
                raise ParseError("dnsreaper: entry is not an object")
            host = entry.get("domain")
            if not isinstance(host, str) or not host:
                raise ParseError("dnsreaper: finding has no domain")
            try:
                fqdn = validate_host(host)
            except (TypeError, ValueError):
                raise ParseError(f"dnsreaper: invalid host {host!r}") from None
            raw_confidence = str(entry.get("confidence", "")).strip().upper()
            if raw_confidence not in SEVERITIES:
                raise ParseError(f"dnsreaper: unknown confidence {raw_confidence!r}")
            signature = entry.get("signature")
            if not isinstance(signature, str) or not signature.strip():
                raise ParseError("dnsreaper: finding has no signature")
            info = entry.get("info")
            cname = entry.get("cname_records")
            evidence_parts: list[str] = []
            if isinstance(cname, list) and cname:
                evidence_parts.append("CNAME: " + ", ".join(str(item) for item in cname))
            if isinstance(info, str) and info.strip():
                evidence_parts.append(info.strip())
            records.append(
                FindingRecord(
                    fqdn=fqdn,
                    kind="takeover",
                    severity=SEVERITIES[raw_confidence],
                    title=f"subdomain takeover: {signature.strip()}",
                    evidence="; ".join(evidence_parts) or None,
                    template_id=signature.strip(),
                    source=self.name,
                )
            )
        return records


__all__ = ["DnsreaperAdapter", "SEVERITIES"]
