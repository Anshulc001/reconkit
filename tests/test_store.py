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


def test_run_indexes_created(store: Store) -> None:
    names = {
        str(row["name"])
        for row in store._conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
    }
    assert {
        "idx_subdomain_sources_run",
        "idx_port_sources_run",
        "idx_hsh_run",
    } <= names


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


def test_v1_database_migrates_and_defaults_cname_columns(tmp_path: Path) -> None:
    db_path = tmp_path / "old.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version (version) VALUES (1);
        CREATE TABLE host_status_history (
          id           INTEGER PRIMARY KEY,
          subdomain_id INTEGER NOT NULL,
          run_id       INTEGER NOT NULL,
          state        TEXT NOT NULL,
          status_code  INTEGER,
          location     TEXT,
          title        TEXT,
          ips_json     TEXT NOT NULL DEFAULT '[]',
          tech_json    TEXT NOT NULL DEFAULT '[]',
          waf          TEXT,
          tools_json   TEXT NOT NULL DEFAULT '[]',
          checked_at   TEXT NOT NULL
        );
        INSERT INTO host_status_history
          (subdomain_id, run_id, state, checked_at)
          VALUES (1, 1, 'ALIVE', '2026-11-13T10:00:00Z');
        """
    )
    conn.close()

    migrated = Store(db_path)
    try:
        columns = {
            str(row["name"]): row
            for row in migrated._conn.execute("PRAGMA table_info(host_status_history)")
        }
        assert migrated.schema_version == SCHEMA_VERSION == 2
        assert "cnames_json" in columns
        assert "dangling_cname" in columns
        row = migrated._conn.execute(
            "SELECT cnames_json, dangling_cname FROM host_status_history"
        ).fetchone()
        assert row["cnames_json"] == "[]"
        assert row["dangling_cname"] is None
    finally:
        migrated.close()


def test_host_status_persists_cnames_and_latest_cnames(store: Store) -> None:
    target_id, run_id = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "old.example.com", run_id=run_id)
    store.append_host_status(
        sub_id,
        run_id,
        "SHUT_DOWN",
        cnames=["old.appspot.com"],
        dangling_cname="old.appspot.com",
    )
    assert store.latest_cnames(sub_id) == ("old.appspot.com",)
    row = store._conn.execute(
        "SELECT cnames_json, dangling_cname FROM host_status_history"
    ).fetchone()
    assert (row["cnames_json"], row["dangling_cname"]) == (
        '["old.appspot.com"]',
        "old.appspot.com",
    )


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


def test_upsert_subdomain_keeps_values_when_omitted(store: Store) -> None:
    """Regression: PIT-03 an omitted value keeps the stored value, not a column default."""
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    sub_id = store.upsert_subdomain(
        target_id,
        "api.example.com",
        run_id=run_a,
        state="ALIVE",
        confidence="HIGH",
        source_count=3,
        is_wildcard=True,
    )
    store.upsert_subdomain(target_id, "api.example.com", run_id=run_b)
    row = store._conn.execute(
        "SELECT state, confidence, source_count, is_wildcard, last_seen_run"
        " FROM subdomains WHERE id = ?",
        (sub_id,),
    ).fetchone()
    assert row["state"] == "ALIVE"
    assert row["confidence"] == "HIGH"
    assert row["source_count"] == 3
    assert row["is_wildcard"] == 1
    assert row["last_seen_run"] == run_b


def test_upsert_subdomain_explicit_state_overwrites(store: Store) -> None:
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "api.example.com", run_id=run_a, state="ALIVE")
    store.upsert_subdomain(target_id, "api.example.com", run_id=run_b, state="DEAD")
    row = store._conn.execute("SELECT state FROM subdomains WHERE id = ?", (sub_id,)).fetchone()
    assert row["state"] == "DEAD"


def test_upsert_subdomain_fresh_insert_uses_defaults(store: Store) -> None:
    target_id, run_id = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "api.example.com", run_id=run_id)
    row = store._conn.execute(
        "SELECT state, confidence, source_count, is_wildcard FROM subdomains WHERE id = ?",
        (sub_id,),
    ).fetchone()
    assert (row["state"], row["confidence"], row["source_count"], row["is_wildcard"]) == (
        "UNKNOWN",
        "LOW",
        0,
        0,
    )


def test_upsert_port_keeps_service_when_omitted(store: Store) -> None:
    """Regression: PIT-03 an omitted port service keeps the stored value."""
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "a.example.com", run_id=run_a)
    port_id = store.upsert_port(
        sub_id, "203.0.113.5", 443, run_id=run_a, state="open", service="https", version="1.1"
    )
    store.upsert_port(sub_id, "203.0.113.5", 443, run_id=run_b, state="open")
    row = store._conn.execute(
        "SELECT service, version FROM ports WHERE id = ?", (port_id,)
    ).fetchone()
    assert (row["service"], row["version"]) == ("https", "1.1")
    store.upsert_port(sub_id, "203.0.113.5", 443, run_id=run_b, state="open", service="http/ssl")
    row = store._conn.execute("SELECT service FROM ports WHERE id = ?", (port_id,)).fetchone()
    assert row["service"] == "http/ssl"


def test_upsert_port_keeps_confidence_when_omitted(store: Store) -> None:
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "a.example.com", run_id=run_a)
    port_id = store.upsert_port(
        sub_id, "203.0.113.5", 443, run_id=run_a, state="open", confidence="MEDIUM"
    )
    store.upsert_port(sub_id, "203.0.113.5", 443, run_id=run_b, state="open")
    row = store._conn.execute("SELECT confidence FROM ports WHERE id = ?", (port_id,)).fetchone()
    assert row["confidence"] == "MEDIUM"


def test_upsert_port_explicit_confidence_overwrites(store: Store) -> None:
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "a.example.com", run_id=run_a)
    port_id = store.upsert_port(
        sub_id, "203.0.113.5", 443, run_id=run_a, state="open", confidence="MEDIUM"
    )
    store.upsert_port(sub_id, "203.0.113.5", 443, run_id=run_b, state="open", confidence="HIGH")
    row = store._conn.execute("SELECT confidence FROM ports WHERE id = ?", (port_id,)).fetchone()
    assert row["confidence"] == "HIGH"


def test_upsert_port_fresh_insert_uses_defaults(store: Store) -> None:
    target_id, run_id = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "a.example.com", run_id=run_id)
    port_id = store.upsert_port(sub_id, "203.0.113.5", 443, run_id=run_id, state="open")
    row = store._conn.execute("SELECT confidence FROM ports WHERE id = ?", (port_id,)).fetchone()
    assert row["confidence"] == "LOW"


def test_upsert_url_keeps_source_count_when_omitted(store: Store) -> None:
    """Regression: PIT-03 an omitted URL source count keeps the stored value."""
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    url_id = store.upsert_url(target_id, "https://a.example.com/x", run_id=run_a, source_count=4)
    store.upsert_url(target_id, "https://a.example.com/x", run_id=run_b)
    row = store._conn.execute("SELECT source_count FROM urls WHERE id = ?", (url_id,)).fetchone()
    assert row["source_count"] == 4


def test_upsert_url_explicit_source_count_overwrites(store: Store) -> None:
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    url_id = store.upsert_url(target_id, "https://a.example.com/x", run_id=run_a, source_count=4)
    store.upsert_url(target_id, "https://a.example.com/x", run_id=run_b, source_count=7)
    row = store._conn.execute("SELECT source_count FROM urls WHERE id = ?", (url_id,)).fetchone()
    assert row["source_count"] == 7


def test_upsert_url_fresh_insert_uses_defaults(store: Store) -> None:
    target_id, run_id = make_run(store)
    url_id = store.upsert_url(target_id, "https://a.example.com/x", run_id=run_id)
    row = store._conn.execute("SELECT source_count FROM urls WHERE id = ?", (url_id,)).fetchone()
    assert row["source_count"] == 0


def test_upsert_url_keeps_category_when_omitted(store: Store) -> None:
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    url_id = store.upsert_url(
        target_id,
        "https://a.example.com/x",
        run_id=run_a,
        category="html",
        patterns=["xss"],
    )
    store.upsert_url(target_id, "https://a.example.com/x", run_id=run_b)
    row = store._conn.execute(
        "SELECT category, patterns_json FROM urls WHERE id = ?", (url_id,)
    ).fetchone()
    assert row["category"] == "html"
    assert row["patterns_json"] == '["xss"]'
    store.upsert_url(target_id, "https://a.example.com/x", run_id=run_b, category="json")
    row = store._conn.execute("SELECT category FROM urls WHERE id = ?", (url_id,)).fetchone()
    assert row["category"] == "json"


# `None` means "not supplied, keep the stored value"; 0 and "" are real values
# and must overwrite, otherwise a scan could never clear a previous value.


def test_upsert_subdomain_explicit_zero_overwrites(store: Store) -> None:
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    sub_id = store.upsert_subdomain(
        target_id, "api.example.com", run_id=run_a, source_count=3, is_wildcard=True
    )
    store.upsert_subdomain(
        target_id, "api.example.com", run_id=run_b, source_count=0, is_wildcard=False
    )
    row = store._conn.execute(
        "SELECT source_count, is_wildcard FROM subdomains WHERE id = ?", (sub_id,)
    ).fetchone()
    assert (row["source_count"], row["is_wildcard"]) == (0, 0)


def test_upsert_port_explicit_empty_service_overwrites(store: Store) -> None:
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "a.example.com", run_id=run_a)
    port_id = store.upsert_port(
        sub_id, "203.0.113.5", 443, run_id=run_a, state="open", service="https", version="1.1"
    )
    store.upsert_port(
        sub_id, "203.0.113.5", 443, run_id=run_b, state="open", service="", version=""
    )
    row = store._conn.execute(
        "SELECT service, version FROM ports WHERE id = ?", (port_id,)
    ).fetchone()
    assert (row["service"], row["version"]) == ("", "")


def test_upsert_url_explicit_zero_and_empty_overwrite(store: Store) -> None:
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    url_id = store.upsert_url(
        target_id,
        "https://a.example.com/x",
        run_id=run_a,
        category="html",
        patterns=["xss"],
        source_count=4,
    )
    store.upsert_url(
        target_id,
        "https://a.example.com/x",
        run_id=run_b,
        category="",
        patterns=[],
        source_count=0,
    )
    row = store._conn.execute(
        "SELECT category, patterns_json, source_count FROM urls WHERE id = ?", (url_id,)
    ).fetchone()
    assert (row["category"], row["patterns_json"], row["source_count"]) == ("", "[]", 0)


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
        ("Authorization: Bearer sk-abc", "Authorization: ***"),
        ("https://user:pass@example.com/x", "https://***:***@example.com/x"),
        ("https://x.example.com/?token=abc123", "https://x.example.com/?token=***"),
        ("password=hunter2&next=1", "password=***&next=1"),
        ("nuclei -u https://x --token abc123", "nuclei -u https://x --token ***"),
        ("tool -api-key abc123", "tool -api-key ***"),
        ("tool --password hunter2", "tool --password ***"),
        ("tool --secret 'two words'", "tool --secret ***"),
        ("Cookie: session=abc123; theme=dark", "Cookie: ***"),
        ("Set-Cookie: sid=abc123; Path=/", "Set-Cookie: ***"),
        ("nmap --delay 1.5", "nmap --delay 1.5"),
        ("nothing secret here", "nothing secret here"),
    ],
)
def test_redact_cases(raw: str, expected: str) -> None:
    """Regression: PIT-04 flag values and Cookie/Set-Cookie headers are masked."""
    assert redact(raw) == expected


def test_redact_env_secret() -> None:
    assert redact("failed with sk-live-123", ["sk-live-123"]) == "failed with ***"


def test_transaction_commits_once_and_rolls_back(store: Store) -> None:
    """Regression: PIT-03-adjacent batch writes must not leave half a stage."""
    with store.transaction():
        store.create_target("commit.example.com")
    assert store.get_target("commit.example.com") is not None

    with pytest.raises(RuntimeError):
        with store.transaction():
            store.create_target("rollback.example.com")
            raise RuntimeError("stage failed")
    assert store.get_target("rollback.example.com") is None


def test_only_store_imports_sqlite3() -> None:
    importers = [
        path.name
        for path in SRC.rglob("*.py")
        if "import sqlite3" in path.read_text(encoding="utf-8")
    ]
    assert importers == ["store.py"]
