"""nikto adapter (docs/09_TOOL_CONTRACTS.md).

Verified on this box (Nikto 2.6.1, `/usr/bin/nikto`):

- `nikto -Version` prints `Nikto 2.6.1 (LW 2.5)`.
- `nikto -h` lists `-Format+` with `json JSON Format`, so **the JSON path is the
  one taken** (the plain-text fallback the brief pre-approved is not needed).
- A real `nikto -h testfire.net -maxtime 60s -nointeractive -Format json -output
  out.json` exited 0 and wrote
  `[{"host", "ip", "port", "vulnerabilities": [{"id": "999967", "method",
  "msg", "references", "url"}]}]`.
- nikto takes **one host per run** (`-host+`), so the adapter runs it once per
  alive host and merges the JSON arrays; every finding is one `FindingRecord`
  with `severity="info"` and `kind="nikto"` - a Nikto message is a lead for the
  operator, not a confirmed exploit, and the tier is already `opt_in`.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

from reconkit.adapters.base import RAW_STDERR_MARK, BinaryAdapter, capture_output, strip_ansi
from reconkit.core.runner import run_exec, validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import FindingRecord, Record, RunContext, Stage, ToolResult, ToolStatus

MAX_ERROR_CHARS = 200


class NiktoAdapter(BinaryAdapter):
    name = "nikto"
    stage = Stage.VULNS
    binary = "nikto"
    version_args = ["-Version"]
    identity_markers = ("nikto",)

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

    def _output_file(self, ctx: RunContext, index: int) -> Path:
        return ctx.workspace / f"nikto-{os.getpid()}-{index}.json"

    def _command(self, ctx: RunContext, host: str, index: int, limit_s: float) -> list[str]:
        return [
            self.binary_path() or self.binary,
            "-h",
            host,
            "-nointeractive",
            # The tool's own limit stops it cleanly and writes its JSON just
            # before our kill timer would discard it (2026-11-18).
            "-maxtime",
            f"{max(1, int(limit_s))}s",
            "-Format",
            "json",
            "-output",
            str(self._output_file(ctx, index)),
        ]

    async def run(self, ctx: RunContext) -> ToolResult:
        """One nikto process per host: `-h` takes a single target."""
        started = time.perf_counter()
        hosts = self._hosts(ctx)
        if not hosts:
            raise ToolFailed("nikto: no hosts to scan")
        if ctx.mock:
            return await super().run(ctx)
        raw_parts: list[str] = []
        records: list[Record] = []
        failures: list[str] = []
        deadline = started + ctx.timeout
        for index, host in enumerate(hosts):
            output = self._output_file(ctx, index)
            output.unlink(missing_ok=True)
            # Each host gets an equal share of what is left of the stage budget,
            # so one slow host cannot use it all and get the tool cancelled.
            share = max(1.0, (deadline - time.perf_counter()) / (len(hosts) - index))
            outcome = await asyncio.to_thread(
                run_exec,
                self._command(ctx, host, index, share),
                timeout=share,
                env=self.child_env(ctx),
            )
            raw_parts.append(capture_output(outcome.stdout, outcome.stderr))
            if outcome.timed_out:
                failures.append(f"{host}: timed out")
                continue
            if outcome.returncode not in (0, None) and not output.is_file():
                detail = outcome.stderr.strip()[:MAX_ERROR_CHARS] or "no output"
                failures.append(f"{host}: exit {outcome.returncode}: {detail}")
                continue
            if not output.is_file():
                failures.append(f"{host}: no -output file was written")
                continue
            try:
                records.extend(self.parse_output(output.read_text(encoding="utf-8")))
            except ParseError as exc:
                failures.append(f"{host}: {exc}")
            finally:
                output.unlink(missing_ok=True)
        raw_text = "\n".join(part for part in raw_parts if part)
        error = "; ".join(failures) or None
        status = ToolStatus.OK if records or not failures else ToolStatus.FAILED
        return ToolResult(
            tool=self.name,
            status=status,
            records=records,
            error=error,
            duration_s=time.perf_counter() - started,
            raw_text=raw_text,
        )

    def parse_output(self, raw: str) -> list[Record]:
        text = strip_ansi(raw).strip()
        if not text:
            return []
        if RAW_STDERR_MARK in text:
            text = text.split(RAW_STDERR_MARK, 1)[0].strip()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            raise ParseError("nikto: output is not valid JSON") from None
        if not isinstance(data, list):
            raise ParseError("nikto: output is not a JSON array")
        records: list[Record] = []
        for entry in data:
            if not isinstance(entry, dict):
                raise ParseError("nikto: entry is not an object")
            host = entry.get("host")
            port = entry.get("port")
            if not isinstance(host, str) or not host:
                raise ParseError("nikto: entry has no host")
            try:
                fqdn = validate_host(host)
                port_text = f":{int(port)}" if isinstance(port, int) else ""
            except (TypeError, ValueError):
                raise ParseError(f"nikto: invalid host {host!r}") from None
            findings = entry.get("vulnerabilities", [])
            if not isinstance(findings, list):
                raise ParseError("nikto: vulnerabilities is not a list")
            for finding in findings:
                if not isinstance(finding, dict):
                    raise ParseError("nikto: vulnerability is not an object")
                message = finding.get("msg")
                if not isinstance(message, str) or not message.strip():
                    raise ParseError("nikto: vulnerability has no message")
                url = finding.get("url")
                identifier = finding.get("id")
                records.append(
                    FindingRecord(
                        fqdn=fqdn,
                        kind="nikto",
                        severity="info",
                        title=message.strip(),
                        evidence=f"{fqdn}{port_text}{url}" if isinstance(url, str) else None,
                        template_id=str(identifier) if identifier is not None else None,
                        source=self.name,
                    )
                )
        return records


__all__ = ["NiktoAdapter"]
