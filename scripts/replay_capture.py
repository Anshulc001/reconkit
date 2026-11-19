"""Replay a real capture at 10x through the url_probe pass, no network.

Reads the capture files `scripts/capture_example.sh` wrote (`gau.txt`,
`katana.txt`), writes a 10x copy of each (every URL repeated with `?i=1..10`),
inserts the result into a throwaway database and runs the engine's real
url_probe pass against it with a mock transport that answers 200 in 1 ms.

The point is the shape of a real list: the archive output a real domain produces
is not a synthetic `/p0..p9` pattern, and 10x of it is what a bigger target
looks like. Nothing here scans anything.

Usage:

    python scripts/replay_capture.py captures/example --urls 200000
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

import httpx  # noqa: E402

from reconkit.config import load_config  # noqa: E402
from reconkit.core.store import Store  # noqa: E402
from reconkit.engine import Engine, ScanOptions  # noqa: E402

FACTOR = 10
# The target is the captured domain, not a synthetic one: the probe pass keeps
# only URLs whose host belongs to the target, so a `scale.example` target would
# silently drop every real capture row and bench the padding instead.
TARGET = "example.com"
PAD_HOST = f"pad.{TARGET}"


def read_urls(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(errors="replace").splitlines() if line.strip()]


def ten_x(urls: list[str]) -> list[str]:
    """Every URL repeated ten times, each copy distinguishable by its query."""
    out: list[str] = []
    for url in urls:
        joiner = "&" if "?" in url else "?"
        out.extend(f"{url}{joiner}i={index}" for index in range(1, FACTOR + 1))
    return out


def write_ten_x(source: Path, destination: Path) -> int:
    urls = ten_x(read_urls(source))
    destination.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")
    return len(urls)


def build_db(path: Path, urls: list[str], total: int) -> int:
    """Insert `urls`, padded deterministically to `total` rows; all NULL."""
    with Store(path) as store:
        target_id = store.create_target(TARGET)
        run_id = store.create_scan_run(target_id, "urls", params='{"replay": true}')
        rows = [(target_id, url, 1, run_id, run_id) for url in urls]
        pad = total - len(rows)
        rows.extend(
            (target_id, f"https://{PAD_HOST}/p{index}", 1, run_id, run_id)
            for index in range(max(0, pad))
        )
        with store.transaction():
            store._conn.executemany(
                "INSERT OR IGNORE INTO urls (target_id, url, source_count, first_seen_run,"
                " last_seen_run) VALUES (?, ?, ?, ?, ?)",
                rows,
            )
        store.finish_scan_run(run_id, "completed")
        return store.count("urls")


async def probe(db: Path) -> tuple[float, int]:
    config = load_config(Path("config.yaml"))
    config = config.model_copy(
        update={
            "url_probe": config.url_probe.model_copy(
                update={"max_urls": 1_000_000, "batch_size": 1000, "threads": 100}
            )
        }
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.001)
        return httpx.Response(200, request=request, text="ok")

    with Store(db) as store:
        engine = Engine(
            config,
            store,
            scope_path=None,
            url_probe_transport=httpx.MockTransport(handler),
        )
        target_id = store.get_target(TARGET)
        if target_id is None:
            raise SystemExit(f"no {TARGET} target in the replay store")
        started = time.perf_counter()
        # Not `active`: a real scope check would resolve the target over the
        # network, and this bench measures the probe pass, not DNS.
        outcome, error = await engine._run_url_probe(
            TARGET, target_id, ScanOptions(no_scope=True), scan_key="replay"
        )
        elapsed = time.perf_counter() - started
        probed = int(
            store._conn.execute(
                "SELECT COUNT(*) FROM urls WHERE status_code IS NOT NULL"
            ).fetchone()[0]
        )
        if error is not None or outcome is None:
            raise SystemExit(f"url_probe failed: {error}")
        return elapsed, probed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("capture_dir", type=Path, nargs="?", default=Path("captures/example"))
    parser.add_argument("--urls", type=int, default=200_000)
    args = parser.parse_args()

    gau = read_urls(args.capture_dir / "gau.txt")
    katana = read_urls(args.capture_dir / "katana.txt")
    if not gau and not katana:
        print(f"{args.capture_dir}: no gau.txt/katana.txt (run scripts/capture_example.sh first)")
        return 2
    gau_10x = write_ten_x(args.capture_dir / "gau.txt", args.capture_dir / "gau_10x.txt")
    katana_10x = write_ten_x(args.capture_dir / "katana.txt", args.capture_dir / "katana_10x.txt")
    urls = ten_x(gau) + ten_x(katana)
    unique = list(dict.fromkeys(urls))
    print(f"gau: {len(gau)} -> {gau_10x} URLs; katana: {len(katana)} -> {katana_10x}")
    print(f"replay list: {len(unique)} unique URLs, padded to {args.urls}")

    with tempfile.TemporaryDirectory(prefix="replay-") as tmp:
        db = Path(tmp) / "replay.db"
        rows = build_db(db, unique, args.urls)
        elapsed, probed = asyncio.run(probe(db))
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
        print(
            f"{rows} URL(s) in the DB, {probed} probed: {elapsed:.2f} s wall clock,"
            f" {probed / elapsed:,.0f} URL/s, peak RSS {peak:.1f} MB"
        )
        print(f"db {db.stat().st_size / 1e6:.1f} MB (temporary, deleted)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
