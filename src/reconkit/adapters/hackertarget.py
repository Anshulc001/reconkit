"""HackerTarget hostsearch adapter (docs/09_TOOL_CONTRACTS.md)."""

from __future__ import annotations

from reconkit.adapters.base import ExternalServiceGap, HttpAdapter, normalize_subdomains
from reconkit.errors import ParseError
from reconkit.models import Record, RunContext, Stage


class HackertargetAdapter(HttpAdapter):
    name = "hackertarget"
    stage = Stage.SUBS

    def url(self, ctx: RunContext) -> str:
        return "https://api.hackertarget.com/hostsearch/"

    def params(self, ctx: RunContext) -> dict[str, str]:
        return {"q": ctx.target}

    def headers(self, ctx: RunContext) -> dict[str, str]:
        headers = super().headers(ctx)
        headers["Accept"] = "text/plain"
        return headers

    def parse_output(self, raw: str) -> list[Record]:
        if "api count exceeded" in raw.lower():
            # HTTP 200 with a quota sentence: the free tier, not a broken tool.
            raise ExternalServiceGap("hackertarget: free quota exceeded")
        names: list[str] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            host, separator, _address = line.partition(",")
            if not separator or not host.strip():
                raise ParseError("hackertarget: unexpected response (not host,ip)")
            names.append(host.strip())
        return normalize_subdomains(names, self.name)
