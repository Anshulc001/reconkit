"""Cert Spotter issuance API adapter (docs/09_TOOL_CONTRACTS.md)."""

from __future__ import annotations

import json

from reconkit.adapters.base import HttpAdapter, normalize_subdomains
from reconkit.errors import ParseError
from reconkit.models import Record, RunContext, Stage

API_KEY_ENV = "CERTSPOTTER_API_KEY"


class CertspotterAdapter(HttpAdapter):
    name = "certspotter"
    stage = Stage.SUBS

    def url(self, ctx: RunContext) -> str:
        return "https://api.certspotter.com/v1/issuances"

    def params(self, ctx: RunContext) -> dict[str, str]:
        return {
            "domain": ctx.target,
            "include_subdomains": "true",
            "expand": "dns_names",
        }

    def headers(self, ctx: RunContext) -> dict[str, str]:
        headers = super().headers(ctx)
        key = ctx.env.get(API_KEY_ENV)
        if key:
            headers["Authorization"] = f"Bearer {key}"
        return headers

    def parse_output(self, raw: str) -> list[Record]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise ParseError("certspotter: invalid JSON") from None
        if not isinstance(data, list):
            raise ParseError("certspotter: expected a JSON array")
        names: list[str] = []
        for entry in data:
            if not isinstance(entry, dict):
                raise ParseError("certspotter: unexpected entry shape")
            values = entry.get("dns_names")
            if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
                raise ParseError("certspotter: expected dns_names to be a list of names")
            names.extend(values)
        return normalize_subdomains(names, self.name)
