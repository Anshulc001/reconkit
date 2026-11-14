"""assetfinder binary adapter (docs/09_TOOL_CONTRACTS.md)."""

from __future__ import annotations

from reconkit.adapters.base import BinaryAdapter, parse_subdomain_lines
from reconkit.core.runner import validate_target
from reconkit.errors import ToolFailed
from reconkit.models import Record, RunContext, Stage


class AssetfinderAdapter(BinaryAdapter):
    name = "assetfinder"
    stage = Stage.SUBS
    binary = "assetfinder"
    version_args = ["-h"]
    identity_markers = ("assetfinder",)

    def build_command(self, ctx: RunContext) -> list[str]:
        try:
            target = validate_target(ctx.target)
        except (TypeError, ValueError):
            raise ToolFailed("assetfinder: invalid target") from None
        # The child gets only the env keys passed in, so it has no PATH: launch the
        # path binary_path() resolved (docs/09 adapter contract), never the bare name.
        argv = [self.binary_path() or self.binary, "--subs-only", target]
        argv += ctx.pacer.tool_rate_args(self.name, "passive")
        return argv

    def parse_output(self, raw: str) -> list[Record]:
        return parse_subdomain_lines(raw, self.name)
