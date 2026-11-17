"""subzy adapter (docs/09_TOOL_CONTRACTS.md).

subzy checks a host list for subdomain-takeover fingerprints. Verified on this
box (v1.2.0, `~/.reconkit/bin/subzy`):

- `subzy version` prints `subzy version: v1.2.0` (the probe is the `version`
  subcommand; there is no `--version` flag).
- `subzy run --help` lists `--targets` (file), `--target` (comma list),
  `--output` (JSON file), `--hide_fails`, `--concurrency`, `--timeout`,
  `--vuln`, `--https`, `--verify_ssl`.
- **Findings never reach stdout.** stdout is the run's log
  (`[ * ] Loaded 2 targets`, `[ * ] Saved output to "..."`); the JSON array lives
  in the `--output` file. The adapter therefore implements `read_output()`, so
  the base flow parses (and stores as raw output) the file instead of stdout.

The file is one object per checked name:
`{"subdomain", "status", "service", "documentation", "cname", "vulnerable"}`.
Only `vulnerable: true` becomes a finding: a checked-but-clean name is not a
result, and `--hide_fails` only suppresses those lines in the tool's own log.
Severity is `high` - a takeover is a real exposure of the name - and the title
names the service the fingerprint matched.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from reconkit.adapters.base import BinaryAdapter, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import FindingRecord, Record, RunContext, Stage


class SubzyAdapter(BinaryAdapter):
    name = "subzy"
    stage = Stage.VULNS
    binary = "subzy"
    # `--version` is not a flag; `version` is a subcommand. Its output names the
    # program, and "subdomain takeover" is in the tool's own description.
    version_args = ["version"]
    identity_markers = ("subzy version",)
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

    def _targets_file(self, ctx: RunContext) -> Path:
        return ctx.workspace / f"subzy-targets-{os.getpid()}.txt"

    def _output_file(self, ctx: RunContext) -> Path:
        return ctx.workspace / f"subzy-output-{os.getpid()}.json"

    @contextmanager
    def prepare(self, ctx: RunContext) -> Iterator[None]:
        """Write the `--targets` file and remove both per-run files afterwards."""
        targets = self._targets_file(ctx)
        output = self._output_file(ctx)
        targets.write_text("".join(f"{host}\n" for host in self._hosts(ctx)), encoding="utf-8")
        try:
            yield
        finally:
            targets.unlink(missing_ok=True)
            output.unlink(missing_ok=True)

    def build_command(self, ctx: RunContext) -> list[str]:
        if not self._hosts(ctx):
            raise ToolFailed("subzy: no hosts to check")
        # No `--concurrency`/`--timeout` flags: the tool's defaults stand, because
        # reconkit adds no pacing (docs/MASTER_PLAN.md D3).
        return [
            self.binary_path() or self.binary,
            "run",
            "--targets",
            str(self._targets_file(ctx)),
            "--hide_fails",
            "--output",
            str(self._output_file(ctx)),
        ]

    def read_output(self, ctx: RunContext) -> str | None:
        """subzy writes its findings to `--output`, never to stdout."""
        output = self._output_file(ctx)
        if not output.is_file():
            raise ParseError("subzy: no --output file was written")
        return output.read_text(encoding="utf-8")

    def parse_output(self, raw: str) -> list[Record]:
        text = strip_ansi(raw).strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            raise ParseError("subzy: output is not valid JSON") from None
        if data is None:
            # Verified on the real binary: with nothing to report it writes the
            # literal `null`, not `[]` (first real run failed on exactly this).
            return []
        if not isinstance(data, list):
            raise ParseError("subzy: output is not a JSON array")
        records: list[Record] = []
        for entry in data:
            if not isinstance(entry, dict):
                raise ParseError("subzy: entry is not an object")
            if not entry.get("vulnerable"):
                continue
            host = entry.get("subdomain")
            if not isinstance(host, str) or not host:
                raise ParseError("subzy: vulnerable entry has no subdomain")
            try:
                fqdn = validate_host(host)
            except (TypeError, ValueError):
                raise ParseError(f"subzy: invalid host {host!r}") from None
            service = entry.get("service")
            service_name = service.strip() if isinstance(service, str) else ""
            documentation = entry.get("documentation")
            evidence = documentation.strip() if isinstance(documentation, str) else None
            cname = entry.get("cname")
            if not evidence and isinstance(cname, str) and cname:
                evidence = f"cname: {cname}"
            records.append(
                FindingRecord(
                    fqdn=fqdn,
                    kind="takeover",
                    severity="high",
                    title=f"subdomain takeover: {service_name or 'unclaimed service'}",
                    evidence=evidence or None,
                    template_id=None,
                    source=self.name,
                )
            )
        return records


__all__ = ["SubzyAdapter"]
