"""webanalyze adapter (docs/09_TOOL_CONTRACTS.md).

webanalyze fetches each host and matches the response against its technology
database. It takes the host list from a **file** (`-hosts`), so the adapter
writes one into the run workspace and removes it in `finally`; the whole host
list stays in one argv element, never in a shell string.

The technologies database is not shipped with the binary: `webanalyze -update`
writes `technologies.json` into the current directory. The adapter therefore
points `-apps` at the managed copy `~/.reconkit/technologies.json` when it exists
(one `-update` run there serves every directory) and falls back to
`./technologies.json`; with neither, webanalyze exits 1 with its own
`can not open apps file` message, which becomes the failed result unchanged.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from reconkit.adapters.base import BinaryAdapter, managed_bin_dir, strip_ansi
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import HostState, HostStatusRecord, Record, RunContext, Stage


class WebanalyzeAdapter(BinaryAdapter):
    name = "webanalyze"
    stage = Stage.TECH
    binary = "webanalyze"
    # No `-version` flag: it exits 2 with "flag provided but not defined".
    version_args = ["-h"]
    identity_markers = ("technologies definition file", "update technologies file")
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
        return ctx.workspace / f"webanalyze-hosts-{os.getpid()}.txt"

    def _apps_file(self) -> Path:
        managed = managed_bin_dir().parent / "technologies.json"
        return managed if managed.is_file() else Path.cwd() / "technologies.json"

    @contextmanager
    def prepare(self, ctx: RunContext) -> Iterator[None]:
        """Write the `-hosts` file for this run and remove it afterwards."""
        path = self._hosts_file(ctx)
        path.write_text("".join(f"{host}\n" for host in self._hosts(ctx)), encoding="utf-8")
        try:
            yield
        finally:
            path.unlink(missing_ok=True)

    def build_command(self, ctx: RunContext) -> list[str]:
        if not self._hosts(ctx):
            raise ToolFailed("webanalyze: no hosts to scan")
        # Verified against the real binary: `-hosts string` (a file),
        # `-output string` (stdout|csv|json), `-apps string`, `-silent`.
        return [
            self.binary_path() or self.binary,
            "-hosts",
            str(self._hosts_file(ctx)),
            "-output",
            "json",
            "-apps",
            str(self._apps_file()),
            "-silent",
        ]

    def parse_output(self, raw: str) -> list[Record]:
        records: list[Record] = []
        seen: set[str] = set()
        text = strip_ansi(raw).strip()
        decoder = json.JSONDecoder()
        index = 0
        while index < len(text):
            while index < len(text) and text[index] in " \t\r\n":
                index += 1
            if index >= len(text):
                break
            try:
                document, index = decoder.raw_decode(text, index)
            except json.JSONDecodeError:
                raise ParseError("webanalyze: invalid JSON document") from None
            if not isinstance(document, dict) or not isinstance(document.get("hostname"), str):
                raise ParseError("webanalyze: JSON document has no hostname")
            hostname = document["hostname"]
            host = hostname.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            try:
                fqdn = validate_host(host)
            except (TypeError, ValueError):
                raise ParseError(f"webanalyze: invalid hostname {hostname!r}") from None
            tech: list[str] = []
            matches = document.get("matches")
            if isinstance(matches, list):
                for match in matches:
                    if isinstance(match, dict) and isinstance(match.get("app_name"), str):
                        name = match["app_name"].strip()
                        if name and name not in tech:
                            tech.append(name)
            if fqdn in seen or not tech:
                # A host with no match carries no technology fact; storing an
                # empty list would only overwrite a better earlier answer.
                continue
            seen.add(fqdn)
            # webanalyze fetched the page, so the host answered: this is a
            # technology fact on an alive host, never a new liveness verdict.
            records.append(
                HostStatusRecord(
                    fqdn=fqdn,
                    source=self.name,
                    state=HostState.ALIVE,
                    tech=sorted(tech),
                )
            )
        return records
