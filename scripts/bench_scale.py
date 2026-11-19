"""Benchmark a scale fixture: DB queries, per-tool limits, writes, stage loop.

No network, no tools: every adapter in the stage loop is a stand-in that returns
in about a millisecond. The point is to measure reconkit's own overhead on a DB
with tens of thousands of hosts, before and after a change - the numbers are
only comparable against the same box and the same fixture.

Measured, per database:

    probe_candidates   the whole 200k-NULL-URL list, ms + rows returned
    limits             per-tool idle/limit computation at N hosts, 100 passes
    writes             1 000 set_url_status calls, ms
    stage loop         four 1 ms mock tools over N hosts, wall clock
    peak RSS           resource.getrusage(RUSAGE_SELF).ru_maxrss

Usage:

    python scripts/bench_scale.py bench/scale_20k.db
    python scripts/bench_scale.py bench/scale_20k.db bench/scale_50k.db
"""

from __future__ import annotations

import argparse
import asyncio
import resource
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reconkit import engine as engine_module  # noqa: E402
from reconkit.adapters.base import BaseToolAdapter  # noqa: E402
from reconkit.adapters.registry import ToolSpec  # noqa: E402
from reconkit.config import load_config  # noqa: E402
from reconkit.core.store import Store  # noqa: E402
from reconkit.core.workspace import Workspace  # noqa: E402
from reconkit.engine import Engine, ScanOptions  # noqa: E402
from reconkit.models import Mode, Record, Stage, Tier, ToolResult, ToolStatus  # noqa: E402

TOOLS = ("fake-a", "fake-b", "fake-c", "fake-d")
LIMIT_PASSES = 100


def peak_rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def time_ms(fn) -> float:
    started = time.perf_counter()
    fn()
    return (time.perf_counter() - started) * 1000.0


def limits_ms(engine: Engine, hosts: list[str], specs, tool_hosts) -> float:
    """One pass over the classed tools' limits, repeated, in ms per pass."""
    limit_fn = engine_module.idle_for_tool
    tool_names = [spec.name for spec in specs]
    started = time.perf_counter()
    for _ in range(LIMIT_PASSES):
        for name in tool_names:
            limit_fn(name, engine.config, specs=engine.specs)
    return (time.perf_counter() - started) * 1000.0 / LIMIT_PASSES


def bench(path: Path) -> dict[str, object]:
    store = Store(path)
    try:
        target_id = store.get_target("scale.example")
        if target_id is None:
            raise SystemExit("fixture has no scale.example target")
        hosts = [str(row["fqdn"]) for row in store.subdomains(target_id)]
        url_count = store.count("urls")
        null_count = int(
            store._conn.execute("SELECT COUNT(*) FROM urls WHERE status_code IS NULL").fetchone()[0]
        )

        rows: list[dict[str, object]] = []
        probe_started = time.perf_counter()
        candidates = store.probe_candidates(target_id, limit=url_count).rows
        probe_ms = (time.perf_counter() - probe_started) * 1000.0
        rows.append({"metric": "probe_candidates", "value": probe_ms, "rows": len(candidates)})

        def write_1000() -> None:
            for item in candidates[:1000]:
                store.set_url_status(int(item["id"]), 200)

        rows.append({"metric": "1000 set_url_status", "value": time_ms(write_1000), "rows": 1000})

        config = load_config(Path("config.yaml"))
        engine = Engine(config, store)
        specs = [spec for spec in engine.specs.values() if spec.class_]
        rows.append(
            {
                "metric": "limits (per pass)",
                "value": limits_ms(engine, hosts, specs, {}),
                "rows": len(specs),
            }
        )

        class FastAdapter(BaseToolAdapter):
            name = "fake-a"
            stage = Stage.SUBS

            async def run(self, ctx) -> ToolResult:  # noqa: ANN001
                await asyncio.sleep(0.001)
                return ToolResult(
                    tool=self.name,
                    status=ToolStatus.OK,
                    records=[Record(kind="subdomain", value=f"x.{ctx.target}")],
                )

        adapters: dict[str, type[BaseToolAdapter]] = {}
        selected = []
        for index, name in enumerate(TOOLS):
            fake = type(
                f"FastAdapter{index}",
                (FastAdapter,),
                {"name": name, "stage": Stage.SUBS, "class_": "archive"},
            )
            adapters[name] = fake
            selected.append(
                (
                    ToolSpec(
                        name=name,
                        stage=Stage.SUBS,
                        kind="binary",
                        tier=Tier.CORE,
                        mode=Mode.PASSIVE,
                        phase=1,
                        class_="archive",
                    ),
                    fake,
                )
            )

        run_id = store.create_scan_run(target_id, "subs", params='{"bench": true}')
        results: list[ToolResult] = []
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Workspace.create(Path(tmp), "scale.example")
            canvas = engine._run_tools(
                run_id,
                "scale.example",
                Stage.SUBS,
                selected,
                hosts,
                workspace,
                ScanOptions(mock=True),
                None,
                {},
                results,
                set(),
                stage_budget=1800.0,
            )
            started = time.perf_counter()
            asyncio.run(canvas)
            stage_s = time.perf_counter() - started
        rows.append(
            {"metric": "stage loop (4 tools)", "value": stage_s * 1000.0, "rows": len(hosts)}
        )

        return {
            "path": str(path),
            "hosts": len(hosts),
            "urls": url_count,
            "urls_null": null_count,
            "rows": rows,
            "stage_s": round(stage_s, 3),
            "peak_rss_mb": round(peak_rss_mb(), 1),
            "store_mb": round(path.stat().st_size / 1e6, 1),
        }
    finally:
        store.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("db", nargs="+", type=Path)
    args = parser.parse_args()
    for path in args.db:
        if not path.exists():
            print(f"{path}: missing (run scripts/gen_scale_fixture.py first)")
            return 2
        result = bench(path)
        print(
            f"\n{result['path']}: {result['hosts']} hosts, {result['urls']} URLs"
            f" ({result['urls_null']} NULL), store {result['store_mb']} MB"
        )
        for row in result["rows"]:
            print(f"  {row['metric']:<22} {row['value']:9.2f} ms   ({row['rows']} row(s))")
        print(
            f"  {'stage loop':<22} {result['stage_s']:9.3f} s    "
            f"(peak RSS {result['peak_rss_mb']} MB)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
