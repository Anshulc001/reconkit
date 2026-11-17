"""Findomain adapter (docs/09_TOOL_CONTRACTS.md).

Verified on this box (findomain 11.0.0, `~/.reconkit/bin/findomain`):

- `findomain --version` prints `findomain 11.0.0`.
- `-t, --target <TARGET>` takes one host and `-q, --quiet` removes the
  informative messages; a real run `findomain -t testfire.net -q` printed bare
  subdomains, one per line, exit 0.
- Without `-o`/`-u` it writes no file, so the adapter passes neither: results
  stay on stdout and nothing lands in the current directory.
"""

from __future__ import annotations

from reconkit.adapters.base import BinaryAdapter, parse_subdomain_lines
from reconkit.core.runner import validate_target
from reconkit.errors import ToolFailed
from reconkit.models import Record, RunContext, Stage


class FindomainAdapter(BinaryAdapter):
    name = "findomain"
    stage = Stage.SUBS
    binary = "findomain"
    version_args = ["--version"]
    identity_markers = ("findomain",)

    def build_command(self, ctx: RunContext) -> list[str]:
        try:
            target = validate_target(ctx.target)
        except (TypeError, ValueError):
            raise ToolFailed(f"findomain: invalid target {ctx.target!r}") from None
        return [self.binary_path() or self.binary, "-t", target, "-q"]

    def parse_output(self, raw: str) -> list[Record]:
        return parse_subdomain_lines(raw, self.name)


__all__ = ["FindomainAdapter"]
