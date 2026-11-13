"""AlienVault OTX passive DNS adapter (docs/09_TOOL_CONTRACTS.md)."""

from __future__ import annotations

import json

from reconkit.adapters.base import HttpAdapter, normalize_subdomains
from reconkit.errors import ParseError
from reconkit.models import Record, RunContext, Stage

API_KEY_ENV = "OTX_API_KEY"


class OtxAdapter(HttpAdapter):
    name = "otx"
    stage = Stage.SUBS

    def url(self, ctx: RunContext) -> str:
        return f"https://otx.alienvault.com/api/v1/indicators/domain/{ctx.target}/passive_dns"

    def headers(self, ctx: RunContext) -> dict[str, str]:
        headers = super().headers(ctx)
        key = ctx.env.get(API_KEY_ENV)
        if key:
            headers["X-OTX-API-KEY"] = key
        return headers

    def parse_output(self, raw: str) -> list[Record]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise ParseError("otx: invalid JSON") from None
        if not isinstance(data, dict):
            raise ParseError("otx: expected a JSON object")
        entries = data.get("passive_dns")
        if not isinstance(entries, list):
            raise ParseError("otx: expected passive_dns to be a list")
        names: list[str] = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ParseError("otx: unexpected entry shape")
            hostname = entry.get("hostname")
            if not isinstance(hostname, str):
                raise ParseError("otx: expected a hostname for every entry")
            names.append(hostname)
        return normalize_subdomains(names, self.name)
