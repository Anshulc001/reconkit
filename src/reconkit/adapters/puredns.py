"""puredns adapter (docs/09_TOOL_CONTRACTS.md).

Verified on this box (puredns v2.1.1, `~/.reconkit/bin/puredns`):

- `puredns --version` prints `puredns version v2.1.1`.
- `puredns resolve <file>` resolves a list; `-r/--resolvers` takes the public
  resolver file, `-w/--write` the output file and `-b/--bin` the massdns binary
  (default `massdns`, resolved through PATH).
- **It shells out to massdns**, and a child process here gets only the env keys
  the engine passes, so `-b` is always set to the absolute path the same lookup
  that finds any tool uses (`~/.reconkit/bin` first, then PATH). Without massdns
  the adapter fails with a clear message instead of letting puredns die on a
  bare name.
- The resolver list is the packaged `src/reconkit/data/resolvers.txt` (D16) or
  `--resolvers PATH`.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from shutil import which

from reconkit.adapters.base import BinaryAdapter, parse_subdomain_lines
from reconkit.adapters.massdns import resolvers_path
from reconkit.core.runner import validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import Record, RunContext, Stage


class PurednsAdapter(BinaryAdapter):
    name = "puredns"
    stage = Stage.DNS
    binary = "puredns"
    version_args = ["--version"]
    identity_markers = ("puredns",)
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

    def _input_file(self, ctx: RunContext) -> Path:
        return ctx.workspace / f"puredns-hosts-{os.getpid()}.txt"

    def _output_file(self, ctx: RunContext) -> Path:
        return ctx.workspace / f"puredns-output-{os.getpid()}.txt"

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
            raise ToolFailed("puredns: no hosts to resolve")
        massdns = which("massdns")
        if massdns is None:
            raise ToolFailed("puredns: massdns is required and was not found")
        return [
            self.binary_path() or self.binary,
            "resolve",
            str(self._input_file(ctx)),
            "-r",
            str(resolvers_path(ctx)),
            "-b",
            massdns,
            "-w",
            str(self._output_file(ctx)),
        ]

    def read_output(self, ctx: RunContext) -> str | None:
        """puredns writes the resolved names to `-w`; stdout is its progress log."""
        output = self._output_file(ctx)
        if not output.is_file():
            raise ParseError("puredns: no -w file was written")
        return output.read_text(encoding="utf-8", errors="replace")

    def parse_output(self, raw: str) -> list[Record]:
        return parse_subdomain_lines(raw, self.name)


__all__ = ["PurednsAdapter"]
