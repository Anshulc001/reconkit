"""github-subdomains adapter (docs/09_TOOL_CONTRACTS.md).

Verified on this box (`~/.reconkit/bin/github-subdomains`, no version flag):

- `github-subdomains -version` fails with `flag provided but not defined:
  -version`; `-h` prints the usage to stderr, which is what the identity probe
  reads (`-d string  domain you are looking for (required)`).
- `-d string` is one domain, `-t string` a token or token list, and `-o string`
  an output file whose **default is `<domain>.txt` in the current directory**.
  The adapter always passes `-o` with a workspace path so a scan never writes
  into the directory reconkit was started from, and reads the file through
  `read_output`.
- `GITHUB_TOKEN` is required (the tool only reads the env var when `-t` is
  absent, and exits without a token), so `requires_env` turns a tokenless run
  into a recorded selection skip with `requires GITHUB_TOKEN` (pre-approved).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from reconkit.adapters.base import BinaryAdapter, parse_subdomain_lines
from reconkit.core.runner import validate_target
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import Record, RunContext, Stage


class GithubSubdomainsAdapter(BinaryAdapter):
    name = "github_subdomains"
    stage = Stage.SUBS
    binary = "github-subdomains"
    version_args = ["-h"]
    identity_markers = ("domain you are looking for",)
    requires_env = ("GITHUB_TOKEN",)

    def _output_file(self, ctx: RunContext) -> Path:
        return ctx.workspace / f"github-subdomains-{os.getpid()}.txt"

    @contextmanager
    def prepare(self, ctx: RunContext) -> Iterator[None]:
        output = self._output_file(ctx)
        output.unlink(missing_ok=True)
        try:
            yield
        finally:
            output.unlink(missing_ok=True)

    def build_command(self, ctx: RunContext) -> list[str]:
        try:
            target = validate_target(ctx.target)
        except (TypeError, ValueError):
            raise ToolFailed(f"github_subdomains: invalid target {ctx.target!r}") from None
        return [
            self.binary_path() or self.binary,
            "-d",
            target,
            "-o",
            str(self._output_file(ctx)),
        ]

    def read_output(self, ctx: RunContext) -> str | None:
        """The findings are in `-o`, not on stdout (proven by the flag's default)."""
        output = self._output_file(ctx)
        if not output.is_file():
            raise ParseError("github_subdomains: no -o file was written")
        return output.read_text(encoding="utf-8", errors="replace")

    def parse_output(self, raw: str) -> list[Record]:
        return parse_subdomain_lines(raw, self.name)


__all__ = ["GithubSubdomainsAdapter"]
