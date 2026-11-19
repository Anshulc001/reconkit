"""crt.sh certificate transparency adapter (docs/09_TOOL_CONTRACTS.md)."""

from __future__ import annotations

import json

from reconkit.adapters.base import HttpAdapter, normalize_subdomains
from reconkit.errors import ParseError
from reconkit.models import Record, RunContext, Stage


class CrtshAdapter(HttpAdapter):
    name = "crtsh"
    stage = Stage.SUBS
    # crt.sh is a free third party with no SLA; its front end answers 404 for a
    # query it served a second earlier (D47), so a 404 here is a gap, not a
    # failure that makes every scan exit 5.
    external_api = True

    def url(self, ctx: RunContext) -> str:
        return "https://crt.sh/"

    def params(self, ctx: RunContext) -> dict[str, str]:
        return {"q": f"%.{ctx.target}", "output": "json"}

    def parse_output(self, raw: str) -> list[Record]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise ParseError("crtsh: invalid JSON") from None
        if not isinstance(data, list):
            raise ParseError("crtsh: expected a JSON array")
        names: list[str] = []
        for entry in data:
            if not isinstance(entry, dict):
                raise ParseError("crtsh: unexpected entry shape")
            for key in ("name_value", "common_name"):
                value = entry.get(key)
                if isinstance(value, str):
                    names.extend(value.splitlines())
        return normalize_subdomains(names, self.name)
