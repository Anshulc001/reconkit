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

**The `shots` stage runs in full mode only (D19).** It is wired into
`MODE_STAGES` for `--full`, sits outside `STAGE_ORDER` so `--active` never runs
it, and the adapter is only selected when gowitness is installed (`opt_in`).
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from reconkit.adapters.base import BinaryAdapter, capture_output, normalize_url
from reconkit.core.runner import run_exec, validate_host
from reconkit.models import Record, RunContext, Stage, ToolResult, ToolStatus, UrlRecord

MANIFEST_NAME = "screenshots.jsonl"
# D53: one page's browser run gets this much time. A per-URL constant, never
# `ctx.timeout` (the stage budget): N hosts must not each receive 1800 s.
PAGE_TIMEOUT_S = 30.0

# gowitness 3.2.2 says one of these when it has no browser to drive. Matched only
# when a run produced zero screenshots, so a stray word in a page title cannot
# turn a working run into a gap (D35).
NO_BROWSER_MARKERS: tuple[str, ...] = (
    "failed to initialize chrome context",
    "chrome context",
    "no chrome",
    "chrome not found",
    "could not find chrome",
    "browser is not installed",
    "executable not found in $path",
)
NO_BROWSER_ERROR = "no chromium; 0 screenshots"


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
        # `--mock` reads the fixture through the base flow: no files, no manifest,
        # and a record per fixture line (the documented "ok N item(s)" proof).
        if ctx.mock:
            return await super().run(ctx)
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
                    timeout=PAGE_TIMEOUT_S,
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
                records.append(UrlRecord(url=normalize_url(url) or url, source=self.name))
                break
            else:
                failures.append(f"{host}: no screenshot (no browser available?)")
        if lines:
            with manifest.open("a", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
        raw_text = "\n".join(part for part in captured if part)
        # D35: no browser on this box is an absent dependency, not a broken tool.
        # A gap keeps the run at exit 0 and says why in the gaps block; the old
        # behaviour was `ok 0` with a per-host "no screenshot" note, which read
        # like a reconkit fault.
        if not records and _no_browser(raw_text):
            return ToolResult(
                tool=self.name,
                status=ToolStatus.GAP,
                records=records,
                error=NO_BROWSER_ERROR,
                duration_s=time.perf_counter() - started,
                raw_text=raw_text,
            )
        return ToolResult(
            tool=self.name,
            status=ToolStatus.OK,
            records=records,
            error="; ".join(failures) or None,
            duration_s=time.perf_counter() - started,
            raw_text=raw_text,
        )

    def parse_output(self, raw: str) -> list[Record]:
        """Mock path: the fixture lists the URLs that produced a screenshot."""
        records: list[Record] = []
        for line in raw.splitlines():
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            url = normalize_url(text)
            if url is None:
                continue
            records.append(UrlRecord(url=url, source=self.name))
        return records


def _no_browser(raw_text: str) -> bool:
    """True when gowitness's own output names a missing browser."""
    lowered = raw_text.lower()
    return any(marker in lowered for marker in NO_BROWSER_MARKERS)


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
