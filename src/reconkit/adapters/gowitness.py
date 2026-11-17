"""gowitness adapter (docs/09_TOOL_CONTRACTS.md, D17).

Verified on this box (gowitness 3.2.2, `~/.reconkit/bin/gowitness`):

- `gowitness version` prints `gowitness: 3.2.2` under its banner (the identity
  marker); `--version` is not a flag.
- v3 is a command tree: `gowitness scan single -u <url> -s <dir>`. `-s` is
  `--screenshot-path` and `--write-*` flags persist metadata, but reconkit wants
  its own manifest, so none of them are passed.
- `--screenshot-format` is a **global** flag and defaults to `jpeg`, so the
  adapter passes `png` explicitly: D17 promises `.png` files, and a `*.png`
  glob over jpeg output would silently find nothing.
- A real run on this box reported `have-screenshot=false`: the probe answered
  (status 200, title "Altoro Mutual") but gowitness found no Chromium to drive.
  A screenshot needs a browser the tool can launch (`--chrome-path`); the
  adapter never guesses one, so on a box without one it honestly produces no
  PNG.

**Screenshots are files, not database rows (D17, pre-approved).** The adapter
writes `results/<target>/<UTC stamp>/screenshots/<file>.png` plus
`screenshots.jsonl` beside that folder, one
`{"url", "path", "timestamp"}` object per line. No table, no model, no schema
change: `reconkit status` and `reconkit diff` do not show screenshots, and the
files stay per-run artifacts.

**The `shots` stage is not reachable from the CLI yet.** `Stage.SHOTS` exists in
`models.py` and `RAW_OUTPUT_DIRS`, but it is in neither `STAGE_ORDER` nor a
`MODE_STAGES` row, so no mode and no `--tools` name runs it; wiring it in is a
mode-table change and needs an owner ruling. The adapter is complete and tested
so that wiring is a one-line change.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from reconkit.adapters.base import BinaryAdapter, capture_output
from reconkit.core.runner import run_exec, validate_host
from reconkit.models import Record, RunContext, Stage, ToolResult, ToolStatus, UrlRecord

MANIFEST_NAME = "screenshots.jsonl"


class GowitnessAdapter(BinaryAdapter):
    name = "gowitness"
    stage = Stage.SHOTS
    binary = "gowitness"
    version_args = ["version"]
    identity_markers = ("gowitness:",)
    needs_home = True

    def _hosts(self, ctx: RunContext) -> list[str]:
        hosts: list[str] = []
        seen: set[str] = set()
        for raw in ctx.hosts:
            try:
                host = validate_host(raw)
            except (TypeError, ValueError):
                continue
            if host not in seen:
                seen.add(host)
                hosts.append(host)
        return hosts

    def run_dir(self, ctx: RunContext) -> Path:
        """`results/<target>/<UTC stamp>/`, the same shape as a run report folder.

        The root comes from the engine (`RunContext.results_dir`, the configured
        `results_dir`), so `--config` and the reports agree; the adapter never
        reads the config file itself.
        """
        results_root = ctx.results_dir if ctx.results_dir is not None else Path("results")
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        return Path(results_root) / ctx.target / stamp

    def _command(self, ctx: RunContext, url: str, shots: Path) -> list[str]:
        return [
            self.binary_path() or self.binary,
            "scan",
            "single",
            "-u",
            url,
            "-s",
            str(shots),
            # Global flag; the tool default is jpeg (D17 files are .png).
            "--screenshot-format",
            "png",
        ]

    async def run(self, ctx: RunContext) -> ToolResult:
        started = time.perf_counter()
        hosts = self._hosts(ctx)
        if not hosts:
            return ToolResult(
                tool=self.name,
                status=ToolStatus.OK,
                duration_s=time.perf_counter() - started,
                raw_text="",
            )
        run_dir = self.run_dir(ctx)
        shots = run_dir / "screenshots"
        shots.mkdir(parents=True, exist_ok=True)
        manifest = run_dir / MANIFEST_NAME
        records: list[Record] = []
        lines: list[str] = []
        captured: list[str] = []
        failures: list[str] = []
        for host in hosts:
            for url in (f"https://{host}", f"http://{host}"):
                output = await asyncio.to_thread(
                    run_exec,
                    self._command(ctx, url, shots),
                    timeout=ctx.timeout,
                    env=self.child_env(ctx),
                )
                captured.append(capture_output(output.stdout, output.stderr))
                image = _new_image(shots, since=started)
                if image is None:
                    continue
                entry = {
                    "url": url,
                    "path": str(image),
                    "timestamp": datetime.now(UTC).isoformat(),
                }
                lines.append(json.dumps(entry, sort_keys=True))
                records.append(UrlRecord(url=url, source=self.name))
                break
            else:
                failures.append(f"{host}: no screenshot (no browser available?)")
        if lines:
            with manifest.open("a", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
        return ToolResult(
            tool=self.name,
            status=ToolStatus.OK,
            records=records,
            error="; ".join(failures) or None,
            duration_s=time.perf_counter() - started,
            raw_text="\n".join(part for part in captured if part),
        )

    def parse_output(self, raw: str) -> list[Record]:
        """Mock path: the fixture lists the URLs that produced a screenshot."""
        records: list[Record] = []
        for line in raw.splitlines():
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            records.append(UrlRecord(url=text, source=self.name))
        return records


def _new_image(directory: Path, *, since: float) -> Path | None:
    """The newest PNG this run created, if any (gowitness names it itself)."""
    best: Path | None = None
    for path in directory.glob("*.png"):
        try:
            modified = path.stat().st_mtime
        except OSError:
            continue
        if modified + 1.0 < since:
            continue
        if best is None or modified >= best.stat().st_mtime:
            best = path
    return best


__all__ = ["GowitnessAdapter", "MANIFEST_NAME"]
