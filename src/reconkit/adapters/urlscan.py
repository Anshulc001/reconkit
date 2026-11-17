"""urlscan.io search adapter (docs/09_TOOL_CONTRACTS.md).

`urlscan` is `kind: http` in `tools.yaml` - no binary. The name on this box
(`/usr/bin/urlscan`) is the unrelated Python "parse and display URLs" CLI, which
is why the registry marks this row as needing no binary and why nothing here
touches `PATH`.

Real request (2026-11-17, unauthenticated, HTTP 200):

    https://urlscan.io/api/v1/search/?q=domain:testfire.net&size=2

returns `{"results": [...], "total": N}`; each result carries
`page.domain`/`page.url` and `task.domain`/`task.url`. `URLSCAN_API_KEY` is
documented in `tools.yaml` as needed for **submissions**, not for search, so the
key is optional: when it is set it travels in the `api-key` header, and a scan
without one still runs (the manual records the lower unauthenticated quota).
"""

from __future__ import annotations

import json

from reconkit.adapters.base import HttpAdapter, normalize_subdomains
from reconkit.errors import ParseError
from reconkit.models import Record, RunContext, Stage

API_KEY_ENV = "URLSCAN_API_KEY"
MAX_RESULTS = "100"


class UrlscanAdapter(HttpAdapter):
    name = "urlscan"
    stage = Stage.SUBS

    def url(self, ctx: RunContext) -> str:
        return "https://urlscan.io/api/v1/search/"

    def params(self, ctx: RunContext) -> dict[str, str]:
        return {"q": f"domain:{ctx.target}", "size": MAX_RESULTS}

    def headers(self, ctx: RunContext) -> dict[str, str]:
        headers = super().headers(ctx)
        key = ctx.env.get(API_KEY_ENV)
        if key:
            headers["api-key"] = key
        return headers

    def parse_output(self, raw: str) -> list[Record]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise ParseError("urlscan: invalid JSON") from None
        if not isinstance(data, dict):
            raise ParseError("urlscan: expected a JSON object")
        results = data.get("results")
        if not isinstance(results, list):
            raise ParseError("urlscan: expected results to be a list")
        names: list[str] = []
        for entry in results:
            if not isinstance(entry, dict):
                raise ParseError("urlscan: unexpected result shape")
            name = _domain(entry)
            if name is None:
                raise ParseError("urlscan: result has no page or task domain")
            names.append(name)
        return normalize_subdomains(names, self.name)


def _domain(entry: dict[str, object]) -> str | None:
    """The domain of one search result: page first, then task, as the manual says."""
    for section in ("page", "task"):
        block = entry.get(section)
        if not isinstance(block, dict):
            continue
        for key in ("domain", "url"):
            value = block.get(key)
            if isinstance(value, str) and value:
                return value
    return None


__all__ = ["UrlscanAdapter"]
