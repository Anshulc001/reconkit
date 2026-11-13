"""Store tests: temp DBs only, every connection closed."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from reconkit.core.store import SCHEMA_VERSION, Store, redact
from reconkit.errors import ConfigError

SRC = Path(__file__).resolve().parents[1] / "src" / "reconkit"


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    db = Store(tmp_path / "recon.db")
    try:
        yield db
    finally:
        db.close()


def make_run(store: Store, domain: str = "example.com", speed: str = "slow") -> tuple[int, int]:
    target_id = store.create_target(domain)
    run_id = store.create_scan_run(target_id, "subs", speed)
    return target_id, run_id


def test_schema_tables_created(store: Store) -> None:
    names = {
        str(row["name"])
        for row in store._conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert {
        "schema_version",
        "targets",
        "scan_runs",
        "tool_runs",
        "subdomains",
        "subdomain_sources",
        "host_status_history",
        "ports",
        "port_sources",
        "urls",
    } <= names
    assert "findings" not in names
    assert "monitor_changes" not in names
    assert store.schema_version == SCHEMA_VERSION


def test_pragmas(store: Store) -> None:
    assert store._conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert store._conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert store._conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000


def test_migration_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "recon.db"
    first = Store(db_path)
    first.create_target("example.com")
    first.close()
    second = Store(db_path)
    try:
        assert second.schema_version == SCHEMA_VERSION
        assert second.count("targets") == 1
    finally:
        second.close()


def test_newer_schema_is_refused(tmp_path: Path) -> None:
    db_path = tmp_path / "recon.db"
    db = Store(db_path)
    db._conn.execute("UPDATE schema_version SET version = 99")
    db._conn.commit()
    db.close()
    with pytest.raises(ConfigError, match="newer than this build"):
        Store(db_path)


def test_foreign_keys_enforced(store: Store) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        store.upsert_subdomain(999, "orphan.example.com", run_id=1)
    assert store.count("subdomains") == 0


def test_create_target_is_idempotent(store: Store) -> None:
    assert store.create_target("example.com") == store.create_target("example.com")
    assert store.count("targets") == 1
    assert store.get_target("example.com") is not None


def test_scan_run_lifecycle(store: Store) -> None:
    _, run_id = make_run(store)
    store.finish_scan_run(run_id, "completed", finished_at="2026-11-13T10:00:00Z")
    row = store._conn.execute(
        "SELECT status, finished_at FROM scan_runs WHERE id = ?", (run_id,)
    ).fetchone()
    assert row["status"] == "completed"
    assert row["finished_at"] == "2026-11-13T10:00:00Z"


def test_upsert_subdomain_does_not_duplicate(store: Store) -> None:
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "api.example.com", run_id=run_a)
    again = store.upsert_subdomain(
        target_id, "api.example.com", run_id=run_b, state="ALIVE", source_count=2
    )
    assert sub_id == again
    assert store.count("subdomains") == 1
    row = store._conn.execute(
        "SELECT first_seen_run, last_seen_run, state FROM subdomains WHERE id = ?", (sub_id,)
    ).fetchone()
    assert row["first_seen_run"] == run_a
    assert row["last_seen_run"] == run_b
    assert row["state"] == "ALIVE"


def test_subdomain_sources_are_unique(store: Store) -> None:
    target_id, run_id = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "api.example.com", run_id=run_id)
    store.add_subdomain_source(sub_id, run_id, "crtsh")
    store.add_subdomain_source(sub_id, run_id, "crtsh")
    assert store.count("subdomain_sources") == 1


def test_host_status_history_order(store: Store) -> None:
    target_id, run_id = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "api.example.com", run_id=run_id)
    assert store.previous_state(sub_id) is None
    store.append_host_status(sub_id, run_id, "ALIVE", ips=["203.0.113.5"], waf="cloudflare")
    assert store.previous_state(sub_id) == "ALIVE"
    store.append_host_status(sub_id, run_id, "DEAD")
    assert store.previous_state(sub_id) == "DEAD"
    store.append_host_status(sub_id, run_id, "DNS_ONLY")
    assert store.previous_state(sub_id) == "DNS_ONLY"


def test_diff_new(store: Store) -> None:
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    a = store.upsert_subdomain(target_id, "a.example.com", run_id=run_a)
    store.add_subdomain_source(a, run_a, "crtsh")
    b = store.upsert_subdomain(target_id, "b.example.com", run_id=run_b)
    store.add_subdomain_source(b, run_b, "crtsh")
    assert store.diff_new(run_b) == ["b.example.com"]


def test_diff_gone(store: Store) -> None:
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    a = store.upsert_subdomain(target_id, "a.example.com", run_id=run_a)
    store.add_subdomain_source(a, run_a, "crtsh")
    b = store.upsert_subdomain(target_id, "b.example.com", run_id=run_b)
    store.add_subdomain_source(b, run_b, "crtsh")
    assert store.diff_gone(run_a, run_b) == ["a.example.com"]


def test_diff_state_changed(store: Store) -> None:
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "a.example.com", run_id=run_a)
    store.append_host_status(sub_id, run_a, "ALIVE")
    store.append_host_status(sub_id, run_b, "DEAD")
    assert store.diff_state_changed(run_a, run_b) == [("a.example.com", "ALIVE", "DEAD")]


def test_diff_ports_opened_and_closed(store: Store) -> None:
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "a.example.com", run_id=run_a)
    opened = store.upsert_port(sub_id, "203.0.113.5", 80, run_id=run_b, state="open")
    store.add_port_source(opened, run_b, "naabu", "open")
    closed = store.upsert_port(sub_id, "203.0.113.5", 443, run_id=run_a, state="open")
    store.add_port_source(closed, run_a, "naabu", "open")
    store.upsert_port(sub_id, "203.0.113.5", 443, run_id=run_b, state="closed")
    store.add_port_source(closed, run_b, "nmap", "closed")
    assert store.diff_ports_opened(run_a, run_b) == [("a.example.com", 80)]
    assert store.diff_ports_closed(run_a, run_b) == [("a.example.com", 443)]


def test_upsert_url_and_port_do_not_duplicate(store: Store) -> None:
    target_id, run_id = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "a.example.com", run_id=run_id)
    store.upsert_url(target_id, "https://a.example.com/x", run_id=run_id, category="html")
    store.upsert_url(target_id, "https://a.example.com/x", run_id=run_id, category="html")
    store.upsert_port(sub_id, "203.0.113.5", 80, run_id=run_id, state="open")
    store.upsert_port(sub_id, "203.0.113.5", 80, run_id=run_id, state="open")
    assert store.count("urls") == 1
    assert store.count("ports") == 1


def test_tool_run_error_is_redacted(store: Store) -> None:
    _, run_id = make_run(store)
    store.record_tool_run(
        run_id,
        "subfinder",
        "failed",
        error="api_key=abc123 env=sk-live-999",
        secrets=["sk-live-999"],
    )
    row = store._conn.execute("SELECT error FROM tool_runs WHERE run_id = ?", (run_id,)).fetchone()
    assert row["error"] == "api_key=*** env=***"


def test_scan_params_are_redacted(store: Store) -> None:
    target_id = store.create_target("example.com")
    run_id = store.create_scan_run(
        target_id, "subs", "slow", params='{"token": "abc123"}', secrets=["abc123"]
    )
    row = store._conn.execute(
        "SELECT params_json FROM scan_runs WHERE id = ?", (run_id,)
    ).fetchone()
    assert "abc123" not in row["params_json"]


def test_hostile_fqdn_is_stored_literally(store: Store) -> None:
    target_id, run_id = make_run(store)
    hostile = "a'; DROP TABLE subdomains;--"
    sub_id = store.upsert_subdomain(target_id, hostile, run_id=run_id)
    assert store.count("subdomains") == 1
    row = store._conn.execute("SELECT fqdn FROM subdomains WHERE id = ?", (sub_id,)).fetchone()
    assert row["fqdn"] == hostile


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("api_key=abc123", "api_key=***"),
        ("Authorization: Bearer sk-abc", "authorization: ***"),
        ("https://user:pass@example.com/x", "https://***:***@example.com/x"),
        ("https://x.example.com/?token=abc123", "https://x.example.com/?token=***"),
        ("password=hunter2&next=1", "password=***&next=1"),
        ("nothing secret here", "nothing secret here"),
    ],
)
def test_redact_cases(raw: str, expected: str) -> None:
    assert redact(raw) == expected


def test_redact_env_secret() -> None:
    assert redact("failed with sk-live-123", ["sk-live-123"]) == "failed with ***"


def test_only_store_imports_sqlite3() -> None:
    importers = [
        path.name
        for path in SRC.rglob("*.py")
        if "import sqlite3" in path.read_text(encoding="utf-8")
    ]
    assert importers == ["store.py"]
