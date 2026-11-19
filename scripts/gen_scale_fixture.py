"""Build a synthetic reconkit database at scale (benchmark fixture, not a scan).

Shape, per the 2026-11-19 scale batch:

    one target, one scan_run
    N subdomains (`sub-<i>.scale.example`, deterministic)
    75% ALIVE with a 200, 25% DEAD
    10 URLs per host, 80% of them still NULL ("not probed"), 20% with a 200

The database is written through the real `Store` so the schema and every CHECK
constraint are the shipped ones; only the rows are synthetic. The file is never
committed (`.gitignore`: `bench/`), because a 50 000-host database is 500 000
rows of nothing anybody needs in git.

Usage:

    python scripts/gen_scale_fixture.py --hosts 20000 --out bench/scale_20k.db
    python scripts/gen_scale_fixture.py --hosts 50000 --out bench/scale_50k.db
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Run from a checkout without installing: the script imports the package it
# benchmarks, and `scripts/` is not on sys.path when it is called by path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reconkit.core.store import Store  # noqa: E402

TARGET = "scale.example"
ALIVE_RATIO = 0.75
URLS_PER_HOST = 10
URL_200_RATIO = 0.2


def build(hosts: int, out: Path, *, urls_per_host: int = URLS_PER_HOST) -> dict[str, int]:
    """Write one fixture; return the row counts actually inserted."""
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    for suffix in ("-wal", "-shm"):
        stale = out.with_name(out.name + suffix)
        if stale.exists():
            stale.unlink()

    started = time.perf_counter()
    with Store(out) as store:
        target_id = store.create_target(TARGET)
        run_id = store.create_scan_run(target_id, "subs", params='{"scale_fixture": true}')
        sub_rows: list[tuple[object, ...]] = []
        host_rows: list[tuple[object, ...]] = []
        url_rows: list[tuple[object, ...]] = []
        alive = int(hosts * ALIVE_RATIO)
        now = "2026-11-19T00:00:00Z"
        for index in range(hosts):
            fqdn = f"sub-{index}.{TARGET}"
            state = "ALIVE" if index < alive else "DEAD"
            status = 200 if state == "ALIVE" else 0
            confidence = "HIGH" if state == "ALIVE" else "LOW"
            sub_rows.append((target_id, fqdn, state, confidence, 2, 0, run_id, run_id))
            host_rows.append((index + 1, run_id, state, status or None, "[]", "[]", "[]", now))
            for slot in range(urls_per_host):
                url = f"https://{fqdn}/p{slot}"
                # 200 for the first URL_200_RATIO of each host's URLs, NULL for the rest.
                url_status = 200 if slot < int(urls_per_host * URL_200_RATIO) else None
                url_rows.append((target_id, url, 2, run_id, run_id, url_status))

        with store.transaction():
            cursor = store._conn
            cursor.executemany(
                "INSERT INTO subdomains (target_id, fqdn, state, confidence, source_count,"
                " is_wildcard, first_seen_run, last_seen_run)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                sub_rows,
            )
            cursor.executemany(
                "INSERT INTO host_status_history (subdomain_id, run_id, state, status_code,"
                " ips_json, tech_json, tools_json, checked_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                host_rows,
            )
            cursor.executemany(
                "INSERT INTO urls (target_id, url, source_count, first_seen_run, last_seen_run,"
                " status_code) VALUES (?, ?, ?, ?, ?, ?)",
                url_rows,
            )
        store.finish_scan_run(run_id, "completed", finished_at=now)
        counts = {
            "hosts": store.count("subdomains"),
            "host_status": store.count("host_status_history"),
            "urls": store.count("urls"),
            "urls_null": int(
                store._conn.execute(
                    "SELECT COUNT(*) FROM urls WHERE status_code IS NULL"
                ).fetchone()[0]
            ),
        }
    counts["seconds"] = int(time.perf_counter() - started)
    counts["bytes"] = out.stat().st_size
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--hosts", type=int, default=20_000)
    parser.add_argument("--urls-per-host", type=int, default=URLS_PER_HOST)
    parser.add_argument("--out", type=Path, default=Path("bench/scale_20k.db"))
    args = parser.parse_args()
    if args.hosts <= 0 or args.urls_per_host <= 0:
        parser.error("--hosts and --urls-per-host must be positive")
    counts = build(args.hosts, args.out, urls_per_host=args.urls_per_host)
    print(
        f"{args.out}: {counts['hosts']} hosts, {counts['urls']} URLs"
        f" ({counts['urls_null']} NULL), {counts['bytes'] / 1e6:.1f} MB,"
        f" built in {counts['seconds']}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
