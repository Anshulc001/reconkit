"""ProjectDiscovery Chaos dataset adapter (docs/09_TOOL_CONTRACTS.md).

Verified on this box (chaos 0.5.2, `~/.reconkit/bin/chaos`):

- `chaos -version` prints `[INF] Current Version: 0.5.2` under its banner.
- `-d string` takes one domain, `-silent` prints only the names, `-duc` skips
  the automatic update check, and `-dL` exists for a domain file.
- Real run without a key: `chaos -d testfire.net -silent` exits **1** with
  `[FTL] PDCP_API_KEY not specified` (docs/tool_manuals/subs.md). The tool has no
  keyless path at all, so `requires_env` makes the engine skip it at selection
  with `requires PDCP_API_KEY` instead of spawning a tool that can only fail -
  the run continues and the reason is recorded (pre-approved, D18).
"""

from __future__ import annotations

from reconkit.adapters.base import BinaryAdapter, parse_subdomain_lines
from reconkit.core.runner import validate_target
from reconkit.errors import ToolFailed
from reconkit.models import Record, RunContext, Stage


class ChaosAdapter(BinaryAdapter):
    name = "chaos"
    stage = Stage.SUBS
    binary = "chaos"
    version_args = ["-version"]
    identity_markers = ("chaos", "current version")
    needs_home = True
    # No key means no query, by the tool's own design: skip, never fail.
    requires_env = ("PDCP_API_KEY",)

    def build_command(self, ctx: RunContext) -> list[str]:
        try:
            target = validate_target(ctx.target)
        except (TypeError, ValueError):
            raise ToolFailed(f"chaos: invalid target {ctx.target!r}") from None
        return [
            self.binary_path() or self.binary,
            "-d",
            target,
            "-silent",
            "-duc",
        ]

    def parse_output(self, raw: str) -> list[Record]:
        return parse_subdomain_lines(raw, self.name)


__all__ = ["ChaosAdapter"]
