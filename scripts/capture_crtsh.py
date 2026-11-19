"""Run crtsh's real adapter once and print what it received (capture helper).

`crtsh` has no binary: it is reconkit's own HTTP call, so the only honest way to
capture it is to run the adapter itself, with a RunContext exactly like the one
the engine builds (honest User-Agent, real endpoint, real parser). The adapter's
raw response goes to stdout, one line per record the parser accepted, and the
status/error to stderr, so `scripts/capture_sakec.sh` can time it and keep the
output like every other tool's.

Usage: python scripts/capture_crtsh.py <domain>
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reconkit.adapters.crtsh import CrtshAdapter  # noqa: E402
from reconkit.core.runner import validate_target  # noqa: E402
from reconkit.models import RunContext  # noqa: E402


async def main(domain: str) -> int:
    target = validate_target(domain)
    ctx = RunContext(
        target=target,
        hosts=[target],
        timeout=300.0,
        workspace=Path(tempfile.mkdtemp(prefix="crtsh-capture-")),
        user_agent="reconkit/0.1",
    )
    result = await CrtshAdapter().run(ctx)
    # A subs record is a `SubdomainRecord` (fqdn); anything else is printed
    # through its own value field rather than silently dropped.
    for record in result.records:
        name = getattr(record, "fqdn", None) or getattr(record, "url", None)
        if name:
            print(name)
    print(
        f"crtsh: {result.status.value} {len(result.records)} item(s) in {result.duration_s:.1f}s"
        + (f" ({result.error})" if result.error else ""),
        file=sys.stderr,
    )
    return 0 if result.status.value in {"ok", "gap"} else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: capture_crtsh.py <domain>")
    raise SystemExit(asyncio.run(main(sys.argv[1])))
