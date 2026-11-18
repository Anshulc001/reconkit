"""nuclei adapter (docs/09_TOOL_CONTRACTS.md).

nuclei runs a template set against every host and reports one JSONL line per
match. Verified on this box (v3.11.1, `~/go/bin/nuclei`):

- `-version` prints `[INF] Nuclei Engine Version: v3.11.1`.
- `-l, -list` takes a **file**, so the adapter writes `nuclei-hosts-<pid>.txt`
  into the run workspace and removes it in `finally`.
- `-j, -jsonl` prints one JSON object per finding on stdout, `-silent` keeps the
  banner out of it, `-nc` drops ANSI codes, and `-duc` disables the automatic
  nuclei/templates update check - without it a scan can block on the network
  before it sends a single request.

The blast radius is bounded by tags, not severity: `tools.yaml` already says
`Run safe tags only (takeover, exposure, misconfig)`, so only those templates
run. No `-severity` filter is applied - the severity is stored on the finding,
and dropping findings in the adapter would discard evidence. No `-rl` either:
reconkit has no pacing (docs/MASTER_PLAN.md D3), so nuclei's own default rate
applies.

Output shape: `{"template-id", "info": {"name", "severity", ...}, "type",
"host", "matched-at", ...}`. `severity` is one of the five levels plus
`unknown` (42 installed templates use it), matching `FindingRecord`.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from reconkit.adapters.base import BinaryAdapter, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import FindingRecord, Record, RunContext, Stage

# tools.yaml notes: "Run safe tags only (takeover, exposure, misconfig)".
SAFE_TAGS = ("takeover", "exposure", "misconfig")
Severity = Literal["info", "low", "medium", "high", "critical", "unknown"]


# The whole vocabulary nuclei can emit; `unknown` is real (42 installed
# templates declare it) and FindingRecord accepts it.
def finding_host(value: str) -> str:
    """Hostname out of a nuclei `matched-at`/`host` value.

    Regression: PIT-53. The real scanner prints `host` as `host:port` when it
    probed a non-default port (`demo.testfire.net:443`), not as a URL, and a
    strict URL parse turned that into an invalid host and failed the whole tool.
    IPv6 literals keep their brackets removed and are handed to validate_host.
    """
    if "://" in value:
        return urlsplit(value).hostname or ""
    if value.startswith("["):
        end = value.find("]")
        return value[1:end] if end > 0 else value
    return value.split(":", 1)[0]


SEVERITIES: dict[str, Severity] = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "unknown",
}


class NucleiAdapter(BinaryAdapter):
    name = "nuclei"
    stage = Stage.VULNS
    binary = "nuclei"
    version_args = ["-version"]
    identity_markers = ("nuclei", "engine version")
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
        return ctx.workspace / f"nuclei-hosts-{os.getpid()}.txt"

    @contextmanager
    def prepare(self, ctx: RunContext) -> Iterator[None]:
        """Write the `-l` file for this run and remove it afterwards."""
        path = self._hosts_file(ctx)
        path.write_text("".join(f"{host}\n" for host in self._hosts(ctx)), encoding="utf-8")
        try:
            yield
        finally:
            path.unlink(missing_ok=True)

    def build_command(self, ctx: RunContext) -> list[str]:
        if not self._hosts(ctx):
            raise ToolFailed("nuclei: no hosts to scan")
        return [
            self.binary_path() or self.binary,
            "-l",
            str(self._hosts_file(ctx)),
            "-jsonl",
            "-silent",
            "-nc",
            "-duc",
            # The request/response pair is never parsed, and it is what pushed a
            # real run past the 1 MB stdout cap and truncated the last JSON line.
            "-or",
            "-tags",
            ",".join(SAFE_TAGS),
        ]

    def parse_output(self, raw: str) -> list[Record]:
        records: list[Record] = []
        for line in strip_ansi(raw).splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                # An `[INF]`/`[WRN]` log line is not a finding; `-silent` keeps
                # them rare, but a warning must not fail the tool.
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                raise ParseError("nuclei: invalid JSON line") from None
            if not isinstance(data, dict):
                raise ParseError("nuclei: JSON line is not an object")
            info = data.get("info")
            if not isinstance(info, dict):
                raise ParseError("nuclei: finding has no info object")
            raw_severity = str(info.get("severity", "")).strip().lower()
            if raw_severity not in SEVERITIES:
                raise ParseError(f"nuclei: unknown severity {raw_severity!r}")
            severity = SEVERITIES[raw_severity]
            title = info.get("name")
            if not isinstance(title, str) or not title.strip():
                raise ParseError("nuclei: finding has no info.name")
            evidence = data.get("matched-at")
            target = evidence if isinstance(evidence, str) and evidence else data.get("host")
            if not isinstance(target, str) or not target:
                raise ParseError("nuclei: finding has no matched-at/host")
            host = finding_host(target)
            try:
                fqdn = validate_host(host)
            except (TypeError, ValueError):
                raise ParseError(f"nuclei: invalid host {target!r}") from None
            kind = data.get("type")
            template_id = data.get("template-id")
            records.append(
                FindingRecord(
                    fqdn=fqdn,
                    kind=str(kind) if isinstance(kind, str) and kind else "vulnerability",
                    severity=severity,
                    title=title.strip(),
                    evidence=evidence if isinstance(evidence, str) else None,
                    template_id=(
                        str(template_id) if isinstance(template_id, str) and template_id else None
                    ),
                    source=self.name,
                )
            )
        return records


__all__ = ["NucleiAdapter", "SAFE_TAGS", "SEVERITIES"]
