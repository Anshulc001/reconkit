"""Store tests: temp DBs only, every connection closed."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from reconkit.core.store import (
    DETAIL_MAX_CHARS,
    REDACTED,
    SCHEMA_VERSION,
    Store,
    configure_redaction,
    redact,
)
from reconkit.errors import ConfigError

SRC = Path(__file__).resolve().parents[1] / "src" / "reconkit"


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    db = Store(tmp_path / "recon.db")
    try:
        yield db
    finally:
        db.close()


def make_run(store: Store, domain: str = "example.com") -> tuple[int, int]:
    target_id = store.create_target(domain)
    run_id = store.create_scan_run(target_id, "subs")
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
        -- A real database of this version has urls; schema 10 alters it.
        CREATE TABLE urls (
          id        INTEGER PRIMARY KEY,
          target_id INTEGER NOT NULL,
          url       TEXT NOT NULL
        );
        -- A real database of this version has tool_runs; schema 8 rebuilds it.
        CREATE TABLE tool_runs (
          id           INTEGER PRIMARY KEY,
          run_id       INTEGER NOT NULL,
          tool         TEXT NOT NULL,
          status       TEXT NOT NULL CHECK (status IN ('ok','skipped','failed','timeout')),
          item_count   INTEGER NOT NULL DEFAULT 0,
          duration_s   REAL,
          error        TEXT
        );
        CREATE TABLE scan_runs (
          id          INTEGER PRIMARY KEY,
          target_id   INTEGER NOT NULL,
          stage       TEXT NOT NULL,
          speed       TEXT NOT NULL CHECK (speed IN ('slow','normal','fast')),
          status      TEXT NOT NULL,
          started_at  TEXT NOT NULL,
          finished_at TEXT,
          params_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE subdomains (
          id INTEGER PRIMARY KEY,
          target_id INTEGER NOT NULL,
          fqdn TEXT NOT NULL,
          state TEXT NOT NULL DEFAULT 'UNKNOWN',
          confidence TEXT NOT NULL DEFAULT 'LOW',
          source_count INTEGER NOT NULL DEFAULT 0,
          is_wildcard INTEGER NOT NULL DEFAULT 0,
          first_seen_run INTEGER NOT NULL,
          last_seen_run INTEGER NOT NULL,
          UNIQUE (target_id, fqdn)
        );
        CREATE TABLE subdomain_sources (
          subdomain_id INTEGER NOT NULL,
          run_id INTEGER NOT NULL,
          tool TEXT NOT NULL,
          PRIMARY KEY (subdomain_id, run_id, tool)
        );
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
        assert migrated.schema_version == SCHEMA_VERSION == 10
        assert "cnames_json" in columns
        assert "dangling_cname" in columns
        assert "detail" in columns
        row = migrated._conn.execute(
            "SELECT cnames_json, dangling_cname, detail FROM host_status_history"
        ).fetchone()
        assert row["cnames_json"] == "[]"
        assert row["dangling_cname"] is None
        assert row["detail"] is None
    finally:
        migrated.close()


def test_v8_database_migrates_the_www_dedup_columns(tmp_path: Path) -> None:
    """D22: schema 9 adds duplicate_of/www_note, and old rows read as not duplicates."""
    db_path = tmp_path / "recon.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version (version) VALUES (8);
            -- A real database of this version has urls; schema 10 alters it.
            CREATE TABLE urls (
              id        INTEGER PRIMARY KEY,
              target_id INTEGER NOT NULL,
              url       TEXT NOT NULL
            );
            CREATE TABLE host_status_history (
              id           INTEGER PRIMARY KEY,
              subdomain_id INTEGER NOT NULL,
              run_id       INTEGER NOT NULL,
              state        TEXT NOT NULL,
              checked_at   TEXT NOT NULL
            );
            INSERT INTO host_status_history (subdomain_id, run_id, state, checked_at)
              VALUES (1, 1, 'ALIVE', '2026-11-17T10:00:00Z');
            """
        )
    finally:
        conn.close()

    migrated = Store(db_path)
    try:
        assert migrated.schema_version == SCHEMA_VERSION == 10
        columns = {
            str(row["name"]): row
            for row in migrated._conn.execute("PRAGMA table_info(host_status_history)")
        }
        assert {"duplicate_of", "www_note"} <= set(columns)
        row = migrated._conn.execute(
            "SELECT duplicate_of, www_note FROM host_status_history"
        ).fetchone()
        assert (row["duplicate_of"], row["www_note"]) == (None, None)
    finally:
        migrated.close()


def test_v9_database_migrates_the_url_status_column(tmp_path: Path) -> None:
    """D23: schema 10 adds urls.status_code; an existing URL reads NULL (not probed)."""
    db_path = tmp_path / "recon.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version (version) VALUES (9);
            CREATE TABLE urls (
              id        INTEGER PRIMARY KEY,
              target_id INTEGER NOT NULL,
              url       TEXT NOT NULL
            );
            INSERT INTO urls (target_id, url) VALUES (1, 'https://example.com/a');
            """
        )
    finally:
        conn.close()

    migrated = Store(db_path)
    try:
        assert migrated.schema_version == SCHEMA_VERSION == 10
        columns = {str(row["name"]) for row in migrated._conn.execute("PRAGMA table_info(urls)")}
        assert "status_code" in columns
        row = migrated._conn.execute("SELECT status_code FROM urls").fetchone()
        assert row["status_code"] is None
    finally:
        migrated.close()


def test_probe_candidates_and_set_url_status(store: Store) -> None:
    """`NULL` is the only "not probed" value; `-1` is a stored answer (D23)."""
    target_id, run_id = make_run(store)
    first = store.upsert_url(target_id, "https://example.com/a", run_id=run_id)
    second = store.upsert_url(target_id, "https://example.com/b", run_id=run_id)
    assert store.probe_candidates(target_id, limit=10) == [
        {"id": first, "url": "https://example.com/a"},
        {"id": second, "url": "https://example.com/b"},
    ]
    store.set_url_status(first, -1)
    store.set_url_status(second, 200)
    assert store.probe_candidates(target_id, limit=10) == []
    assert store.probe_candidates(target_id, limit=1) == []
    stored = [
        (str(row["url"]), row["status_code"])
        for row in store._conn.execute("SELECT url, status_code FROM urls ORDER BY id")
    ]
    assert stored == [("https://example.com/a", -1), ("https://example.com/b", 200)]


def test_probe_candidates_reprobe_returns_answered_rows(store: Store) -> None:
    """`--reprobe-urls` (D24) hands back URLs that already carry an answer."""
    target_id, run_id = make_run(store)
    first = store.upsert_url(target_id, "https://example.com/a", run_id=run_id)
    store.upsert_url(target_id, "https://example.com/b", run_id=run_id)
    store.set_url_status(first, 404)
    assert [row["url"] for row in store.probe_candidates(target_id, limit=10)] == [
        "https://example.com/b"
    ]
    assert [row["url"] for row in store.probe_candidates(target_id, limit=10, reprobe=True)] == [
        "https://example.com/a",
        "https://example.com/b",
    ]


def test_probe_candidates_is_bounded_by_the_limit(store: Store) -> None:
    target_id, run_id = make_run(store)
    for index in range(3):
        store.upsert_url(target_id, f"https://example.com/{index}", run_id=run_id)
    assert len(store.probe_candidates(target_id, limit=2)) == 2


def test_set_host_duplicate_updates_in_place_and_keeps_state(store: Store) -> None:
    """Metadata only: no new row, and state/status_code/checked_at are untouched."""
    target_id, run_id = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "www.example.com", run_id=run_id)
    store.append_host_status(
        sub_id, run_id, "ALIVE", status_code=301, checked_at="2026-11-18T09:00:00Z"
    )
    before = store.count("host_status_history")
    assert store.set_host_duplicate(target_id, "www.example.com", duplicate_of="example.com")
    assert store.count("host_status_history") == before
    row = store._conn.execute(
        "SELECT state, status_code, checked_at, duplicate_of, www_note FROM host_status_history"
    ).fetchone()
    assert (row["state"], row["status_code"], row["checked_at"]) == (
        "ALIVE",
        301,
        "2026-11-18T09:00:00Z",
    )
    assert (row["duplicate_of"], row["www_note"]) == ("example.com", None)


def test_set_host_duplicate_is_false_for_unknown_host_or_status(store: Store) -> None:
    target_id, run_id = make_run(store)
    assert not store.set_host_duplicate(target_id, "nope.example.com", duplicate_of="x")
    store.upsert_subdomain(target_id, "bare.example.com", run_id=run_id)
    assert not store.set_host_duplicate(target_id, "bare.example.com", duplicate_of="x")


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


def test_host_detail_is_redacted_bounded_and_one_line(store: Store) -> None:
    """12d: a raw reason never reaches the column as written.

    Regression: PIT-46 - the reason was discarded, and any reason that does get
    stored must be redacted with the same helper as every other stored text.
    """
    target_id, run_id = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "mystery.example.com", run_id=run_id)
    raw = (
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
        "provider-secret-value\nsecond line " + "x" * 400
    )
    store.append_host_status(
        sub_id, run_id, "UNKNOWN", detail=raw, secrets=("provider-secret-value",)
    )
    detail = str(store._conn.execute("SELECT detail FROM host_status_history").fetchone()[0])
    assert "provider-secret-value" not in detail
    assert REDACTED in detail
    assert "\n" not in detail
    assert "  " not in detail
    assert len(detail) == DETAIL_MAX_CHARS
    assert detail.startswith("[SSL: CERTIFICATE_VERIFY_FAILED]")


def test_blank_host_detail_is_stored_as_null(store: Store) -> None:
    target_id, run_id = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "mystery.example.com", run_id=run_id)
    store.append_host_status(sub_id, run_id, "UNKNOWN", detail="   \n\t ")
    assert store._conn.execute("SELECT detail FROM host_status_history").fetchone()[0] is None


def test_v3_database_migrates_the_additive_detail_column(tmp_path: Path) -> None:
    """An existing v3 database opens cleanly and gains a NULL detail column."""
    db_path = tmp_path / "v3.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version (version) VALUES (3);
        -- A real database of this version has urls; schema 10 alters it.
        CREATE TABLE urls (
          id        INTEGER PRIMARY KEY,
          target_id INTEGER NOT NULL,
          url       TEXT NOT NULL
        );
        -- A real database of this version has tool_runs; schema 8 rebuilds it.
        CREATE TABLE tool_runs (
          id           INTEGER PRIMARY KEY,
          run_id       INTEGER NOT NULL,
          tool         TEXT NOT NULL,
          status       TEXT NOT NULL CHECK (status IN ('ok','skipped','failed','timeout')),
          item_count   INTEGER NOT NULL DEFAULT 0,
          duration_s   REAL,
          error        TEXT
        );
        CREATE TABLE scan_runs (
          id          INTEGER PRIMARY KEY,
          target_id   INTEGER NOT NULL,
          stage       TEXT NOT NULL,
          speed       TEXT NOT NULL CHECK (speed IN ('slow','normal','fast')),
          status      TEXT NOT NULL,
          started_at  TEXT NOT NULL,
          finished_at TEXT,
          params_json TEXT NOT NULL DEFAULT '{}'
        );
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
          checked_at   TEXT NOT NULL,
          cnames_json  TEXT NOT NULL DEFAULT '[]',
          dangling_cname TEXT
        );
        INSERT INTO host_status_history (subdomain_id, run_id, state, checked_at)
          VALUES (1, 1, 'ALIVE', '2026-11-14T10:00:00Z');
        """
    )
    conn.close()

    migrated = Store(db_path)
    try:
        assert migrated.schema_version == SCHEMA_VERSION == 10
        columns = {
            str(row["name"])
            for row in migrated._conn.execute("PRAGMA table_info(host_status_history)")
        }
        assert "detail" in columns
        existing = migrated._conn.execute("SELECT detail FROM host_status_history").fetchone()
        assert existing["detail"] is None
        migrated.append_host_status(1, 1, "UNKNOWN", detail="tls: handshake rejected")
        newest = migrated._conn.execute(
            "SELECT detail FROM host_status_history ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert newest["detail"] == "tls: handshake rejected"
    finally:
        migrated.close()


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
    a = store.upsert_subdomain(target_id, "a.example.com", run_id=run_a, provenance="subs")
    store.add_subdomain_source(a, run_a, "crtsh")
    b = store.upsert_subdomain(target_id, "b.example.com", run_id=run_b, provenance="subs")
    store.add_subdomain_source(b, run_b, "crtsh")
    assert store.diff_new(run_b) == ["b.example.com"]


def provenance_of(store: Store, fqdn: str) -> str:
    row = store._conn.execute(
        "SELECT provenance FROM subdomains WHERE fqdn = ?", (fqdn,)
    ).fetchone()
    return str(row["provenance"])


def test_a_dns_created_row_is_never_new(store: Store) -> None:
    """12b: a row the dns stage created is not a discovery result."""
    target_id, run_id = make_run(store)
    store.upsert_subdomain(target_id, "alias.example.com", run_id=run_id)
    assert provenance_of(store, "alias.example.com") == "dns"
    assert store.diff_new(run_id) == []


def test_a_discovered_host_keeps_subs_provenance_and_is_new(store: Store) -> None:
    """Regression guard: the discovery path still writes subs and is still NEW."""
    target_id, run_id = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "www.example.com", run_id=run_id, provenance="subs")
    store.add_subdomain_source(sub_id, run_id, "crtsh")
    assert provenance_of(store, "www.example.com") == "subs"
    assert store.diff_new(run_id) == ["www.example.com"]


def test_provenance_upgrades_to_subs_and_becomes_new_at_that_run(store: Store) -> None:
    target_id, dns_run = make_run(store)
    _, subs_run = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "late.example.com", run_id=dns_run)
    assert store.diff_new(dns_run) == []
    same_id = store.upsert_subdomain(
        target_id, "late.example.com", run_id=subs_run, provenance="subs"
    )
    store.add_subdomain_source(same_id, subs_run, "subfinder")
    assert same_id == sub_id
    assert provenance_of(store, "late.example.com") == "subs"
    row = store._conn.execute(
        "SELECT first_seen_run FROM subdomains WHERE id = ?", (sub_id,)
    ).fetchone()
    assert row["first_seen_run"] == dns_run  # creation time is not rewritten
    assert store.diff_new(subs_run) == ["late.example.com"]


def test_provenance_never_downgrades(store: Store) -> None:
    target_id, first = make_run(store)
    _, later = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "kept.example.com", run_id=first, provenance="subs")
    store.add_subdomain_source(sub_id, first, "crtsh")
    store.upsert_subdomain(target_id, "kept.example.com", run_id=later)  # a dns pass
    assert provenance_of(store, "kept.example.com") == "subs"


def test_a_dns_only_host_stays_out_of_new_across_many_runs(store: Store) -> None:
    target_id, first = make_run(store)
    store.upsert_subdomain(target_id, "alias.example.com", run_id=first)
    runs = [first]
    for _ in range(3):
        _, run_id = make_run(store)
        runs.append(run_id)
        store.upsert_subdomain(target_id, "alias.example.com", run_id=run_id)
    assert [store.diff_new(run_id) for run_id in runs] == [[], [], [], []]


def test_v2_database_migrates_provenance_with_backfill(tmp_path: Path) -> None:
    db_path = tmp_path / "v2.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version (version) VALUES (2);
        -- A real database of this version has urls; schema 10 alters it.
        CREATE TABLE urls (
          id        INTEGER PRIMARY KEY,
          target_id INTEGER NOT NULL,
          url       TEXT NOT NULL
        );
        -- A real database of this version has tool_runs; schema 8 rebuilds it.
        CREATE TABLE tool_runs (
          id           INTEGER PRIMARY KEY,
          run_id       INTEGER NOT NULL,
          tool         TEXT NOT NULL,
          status       TEXT NOT NULL CHECK (status IN ('ok','skipped','failed','timeout')),
          item_count   INTEGER NOT NULL DEFAULT 0,
          duration_s   REAL,
          error        TEXT
        );
        CREATE TABLE scan_runs (
          id          INTEGER PRIMARY KEY,
          target_id   INTEGER NOT NULL,
          stage       TEXT NOT NULL,
          speed       TEXT NOT NULL CHECK (speed IN ('slow','normal','fast')),
          status      TEXT NOT NULL,
          started_at  TEXT NOT NULL,
          finished_at TEXT,
          params_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE subdomains (
          id INTEGER PRIMARY KEY,
          target_id INTEGER NOT NULL,
          fqdn TEXT NOT NULL,
          state TEXT NOT NULL DEFAULT 'UNKNOWN',
          confidence TEXT NOT NULL DEFAULT 'LOW',
          source_count INTEGER NOT NULL DEFAULT 0,
          is_wildcard INTEGER NOT NULL DEFAULT 0,
          first_seen_run INTEGER NOT NULL,
          last_seen_run INTEGER NOT NULL,
          UNIQUE (target_id, fqdn)
        );
        CREATE TABLE subdomain_sources (
          subdomain_id INTEGER NOT NULL,
          run_id INTEGER NOT NULL,
          tool TEXT NOT NULL,
          PRIMARY KEY (subdomain_id, run_id, tool)
        );
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
          checked_at   TEXT NOT NULL,
          cnames_json  TEXT NOT NULL DEFAULT '[]',
          dangling_cname TEXT
        );
        INSERT INTO subdomains (id, target_id, fqdn, first_seen_run, last_seen_run)
          VALUES (1, 1, 'www.example.com', 1, 1), (2, 1, 'alias.example.com', 1, 1);
        INSERT INTO subdomain_sources (subdomain_id, run_id, tool) VALUES (1, 1, 'crtsh');
        """
    )
    conn.close()

    migrated = Store(db_path)
    try:
        columns = {
            str(row["name"]) for row in migrated._conn.execute("PRAGMA table_info(subdomains)")
        }
        assert migrated.schema_version == SCHEMA_VERSION == 10
        assert "provenance" in columns
        rows = {
            str(row["fqdn"]): str(row["provenance"])
            for row in migrated._conn.execute("SELECT fqdn, provenance FROM subdomains")
        }
        assert rows == {"www.example.com": "subs", "alias.example.com": "dns"}
        # The resume query still reads the migrated rows.
        assert [row["fqdn"] for row in migrated.subdomains(1)] == [
            "alias.example.com",
            "www.example.com",
        ]
    finally:
        migrated.close()


def add_hosts(store: Store, target_id: int, run_id: int, names: list[str]) -> None:
    for name in names:
        sub_id = store.upsert_subdomain(target_id, name, run_id=run_id, provenance="subs")
        store.add_subdomain_source(sub_id, run_id, "subfinder")


def test_diff_pending_gone_is_a_single_miss(store: Store) -> None:
    target_id, run_a = make_run(store)
    _, run_b = make_run(store)
    add_hosts(store, target_id, run_a, ["a.example.com", "kept.example.com"])
    add_hosts(store, target_id, run_b, ["kept.example.com"])
    assert store.diff_pending_gone(run_a, run_b) == ["a.example.com"]


def test_regression_diff_gone_needs_two_consecutive_misses(store: Store) -> None:
    """Regression: the 2026-11-14 testfire.net finding (35 names, then 8).

    A single flaky discovery run reported 27 hosts as GONE even though nothing
    had been re-probed. docs/02: one miss is not a change.
    """
    target_id, run_1 = make_run(store)
    _, run_2 = make_run(store)
    _, run_3 = make_run(store)
    first = [f"h{index:02d}.example.com" for index in range(35)]
    second = first[:8]
    add_hosts(store, target_id, run_1, first)
    add_hosts(store, target_id, run_2, second)

    # One miss: the 27 are pending, never gone, and no baseline run exists yet.
    assert store.diff_pending_gone(run_1, run_2) == first[8:]

    add_hosts(store, target_id, run_3, second)
    assert store.diff_gone(run_1, run_2, run_3) == first[8:]
    assert store.diff_pending_gone(run_2, run_3) == []


def test_diff_gone_needs_the_baseline_run_not_just_two_empty_ones(store: Store) -> None:
    target_id, run_1 = make_run(store)
    _, run_2 = make_run(store)
    _, run_3 = make_run(store)
    _, run_4 = make_run(store)
    add_hosts(store, target_id, run_1, ["old.example.com"])
    # Absent from run_2, so run_2 cannot vouch for it as the baseline of 3 and 4.
    assert store.diff_gone(run_2, run_3, run_4) == []


def test_diff_gone_is_not_confirmed_when_the_host_reappears(store: Store) -> None:
    target_id, run_1 = make_run(store)
    _, run_2 = make_run(store)
    _, run_3 = make_run(store)
    add_hosts(store, target_id, run_1, ["flaky.example.com", "steady.example.com"])
    add_hosts(store, target_id, run_2, ["steady.example.com"])
    add_hosts(store, target_id, run_3, ["flaky.example.com", "steady.example.com"])
    assert store.diff_gone(run_1, run_2, run_3) == []
    assert store.diff_pending_gone(run_2, run_3) == []


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
        target_id, "subs", params='{"token": "abc123"}', secrets=["abc123"]
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


def test_redaction_keeps_a_jsonl_line_parseable() -> None:
    """Regression: PIT-54 a header value must stop at an escaped line end.

    nuclei prints one JSON object per line with the request/response embedded,
    so their newlines are the two characters `\\r\\n`. Redaction used to run to
    the next real newline, replacing the rest of the JSON line with `***` and
    making the whole tool fail with "invalid JSON line".
    """
    line = json.dumps(
        {
            "request": "GET / HTTP/1.1\r\nCookie: JSESSIONID=abc123; x=y\r\nAccept: */*\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\nSet-Cookie: sess=secretvalue; Path=/\r\n\r\nbody",
            "matched-at": "https://example.com/swagger/index.html",
        }
    )
    out = redact(line)
    parsed = json.loads(out)
    assert "abc123" not in out
    assert "secretvalue" not in out
    assert parsed["matched-at"] == "https://example.com/swagger/index.html"
    assert parsed["request"].endswith("Accept: */*\r\n\r\n")
    assert parsed["response"].endswith("\r\n\r\nbody")


def test_redact_env_secret() -> None:
    assert redact("failed with sk-live-123", ["sk-live-123"]) == "failed with ***"


def test_configure_redaction_replaces_values_and_ignores_short_ones() -> None:
    """12f: one process-wide value set, replaced - never a growing second list."""
    try:
        configure_redaction(["first-value"])
        assert redact("a first-value b") == "a *** b"
        configure_redaction(["second-value", "xy"])
        assert redact("a second-value xy") == "a *** xy"
        assert redact("a first-value b") == "a first-value b"
        # An explicit iterable still masks exactly that iterable, never the
        # configured set, so engine/workspace callers keep their per-run values.
        assert redact("a second-value b", ()) == "a second-value b"
    finally:
        configure_redaction(())


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


def test_diff_gone_needs_the_miss_to_be_consecutive(store: Store) -> None:
    """Seen in both baseline and previous, missing from the latest only: not GONE."""
    target_id, run_1 = make_run(store)
    _, run_2 = make_run(store)
    _, run_3 = make_run(store)
    add_hosts(store, target_id, run_1, ["a.example.com"])
    add_hosts(store, target_id, run_2, ["a.example.com"])
    assert store.diff_gone(run_1, run_2, run_3) == []
    assert store.diff_pending_gone(run_2, run_3) == ["a.example.com"]


def test_v4_database_migrates_by_removing_the_speed_column(tmp_path: Path) -> None:
    """Schema 5 drops `scan_runs.speed`; every other value of the row survives."""
    db_path = tmp_path / "v4.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version (version) VALUES (4);
        -- A real database of this version has urls; schema 10 alters it.
        CREATE TABLE urls (
          id        INTEGER PRIMARY KEY,
          target_id INTEGER NOT NULL,
          url       TEXT NOT NULL
        );
        -- A real database of this version has tool_runs; schema 8 rebuilds it.
        CREATE TABLE tool_runs (
          id           INTEGER PRIMARY KEY,
          run_id       INTEGER NOT NULL,
          tool         TEXT NOT NULL,
          status       TEXT NOT NULL CHECK (status IN ('ok','skipped','failed','timeout')),
          item_count   INTEGER NOT NULL DEFAULT 0,
          duration_s   REAL,
          error        TEXT
        );
        CREATE TABLE scan_runs (
          id          INTEGER PRIMARY KEY,
          target_id   INTEGER NOT NULL,
          stage       TEXT NOT NULL,
          speed       TEXT NOT NULL CHECK (speed IN ('slow','normal','fast')),
          status      TEXT NOT NULL,
          started_at  TEXT NOT NULL,
          finished_at TEXT,
          params_json TEXT NOT NULL DEFAULT '{}'
        );
        INSERT INTO scan_runs (id, target_id, stage, speed, status, started_at, params_json)
          VALUES (7, 1, 'subs', 'slow', 'completed', '2026-11-16T10:00:00Z', '{"scan_key":"k"}');
        -- A real v4 database has every v1 table; schema 7 alters this one.
        CREATE TABLE host_status_history (
          id           INTEGER PRIMARY KEY,
          subdomain_id INTEGER NOT NULL,
          run_id       INTEGER NOT NULL,
          state        TEXT NOT NULL,
          waf          TEXT,
          checked_at   TEXT NOT NULL
        );
        """
    )
    conn.close()

    migrated = Store(db_path)
    try:
        assert migrated.schema_version == SCHEMA_VERSION == 10
        columns = {
            str(row["name"]) for row in migrated._conn.execute("PRAGMA table_info(scan_runs)")
        }
        assert "speed" not in columns
        row = migrated._conn.execute(
            "SELECT id, target_id, stage, status, started_at, params_json FROM scan_runs"
        ).fetchone()
        assert (row["id"], row["stage"], row["status"]) == (7, "subs", "completed")
        assert row["params_json"] == '{"scan_key":"k"}'
    finally:
        migrated.close()


def test_v7_database_rebuilds_tool_runs_for_the_gap_status(tmp_path: Path) -> None:
    """Schema 8 accepts `gap`: an external service refusal is not a failure.

    SQLite cannot alter a CHECK constraint, so the migration rebuilds the table;
    every existing row must survive unchanged.
    """
    db_path = tmp_path / "v7.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version (version) VALUES (7);
        -- A real database of this version has urls; schema 10 alters it.
        CREATE TABLE urls (
          id        INTEGER PRIMARY KEY,
          target_id INTEGER NOT NULL,
          url       TEXT NOT NULL
        );
        CREATE TABLE scan_runs (
          id          INTEGER PRIMARY KEY,
          target_id   INTEGER NOT NULL,
          stage       TEXT NOT NULL,
          status      TEXT NOT NULL,
          started_at  TEXT NOT NULL,
          finished_at TEXT,
          params_json TEXT NOT NULL DEFAULT '{}',
          scope_mode  TEXT NOT NULL DEFAULT 'enforced'
        );
        INSERT INTO scan_runs (id, target_id, stage, status, started_at, params_json)
          VALUES (1, 1, 'subs', 'completed', '2026-11-18T10:00:00Z', '{}');
        CREATE TABLE tool_runs (
          id           INTEGER PRIMARY KEY,
          run_id       INTEGER NOT NULL,
          tool         TEXT NOT NULL,
          status       TEXT NOT NULL CHECK (status IN ('ok','skipped','failed','timeout')),
          item_count   INTEGER NOT NULL DEFAULT 0,
          duration_s   REAL,
          error        TEXT
        );
        INSERT INTO tool_runs (id, run_id, tool, status, item_count, duration_s, error)
          VALUES (3, 1, 'crtsh', 'failed', 0, 1.5, 'crtsh: server error (HTTP 502)');
        -- A real v7 database has it; schema 9 alters it.
        CREATE TABLE host_status_history (
          id           INTEGER PRIMARY KEY,
          subdomain_id INTEGER NOT NULL,
          run_id       INTEGER NOT NULL,
          state        TEXT NOT NULL,
          waf          TEXT,
          checked_at   TEXT NOT NULL
        );
        """
    )
    conn.close()

    migrated = Store(db_path)
    try:
        assert migrated.schema_version == SCHEMA_VERSION == 10
        row = migrated._conn.execute(
            "SELECT id, run_id, tool, status, item_count, duration_s, error FROM tool_runs"
        ).fetchone()
        assert (row["id"], row["run_id"], row["tool"], row["status"]) == (
            3,
            1,
            "crtsh",
            "failed",
        )
        assert row["item_count"] == 0
        assert row["duration_s"] == 1.5
        assert row["error"] == "crtsh: server error (HTTP 502)"
        # The rebuilt table accepts the new value, and still rejects a typo.
        migrated.record_tool_run(1, "otx", "gap", error="otx: rate limited (HTTP 429)")
        stored = migrated._conn.execute(
            "SELECT status FROM tool_runs WHERE tool = 'otx'"
        ).fetchone()
        assert stored["status"] == "gap"
        with pytest.raises(sqlite3.IntegrityError):
            migrated.record_tool_run(1, "otx", "nonsense")
    finally:
        migrated.close()


def test_create_scan_run_writes_no_speed_column(store: Store) -> None:
    target_id = store.create_target("example.com")
    run_id = store.create_scan_run(target_id, "subs")
    row = store._conn.execute("SELECT * FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
    assert "speed" not in row.keys()


def test_v6_database_migrates_the_waf_priority_column(tmp_path: Path) -> None:
    """Schema 7 adds the stored priority; rows written before it read 0 (D12)."""
    db_path = tmp_path / "v6.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version (version) VALUES (6);
        -- A real database of this version has urls; schema 10 alters it.
        CREATE TABLE urls (
          id        INTEGER PRIMARY KEY,
          target_id INTEGER NOT NULL,
          url       TEXT NOT NULL
        );
        CREATE TABLE scan_runs (
          id          INTEGER PRIMARY KEY,
          target_id   INTEGER NOT NULL,
          stage       TEXT NOT NULL,
          status      TEXT NOT NULL,
          started_at  TEXT NOT NULL,
          finished_at TEXT,
          params_json TEXT NOT NULL DEFAULT '{}'
        );
        -- A real database of this version has tool_runs; schema 8 rebuilds it.
        CREATE TABLE tool_runs (
          id           INTEGER PRIMARY KEY,
          run_id       INTEGER NOT NULL,
          tool         TEXT NOT NULL,
          status       TEXT NOT NULL CHECK (status IN ('ok','skipped','failed','timeout')),
          item_count   INTEGER NOT NULL DEFAULT 0,
          duration_s   REAL,
          error        TEXT
        );
        CREATE TABLE host_status_history (
          id           INTEGER PRIMARY KEY,
          subdomain_id INTEGER NOT NULL,
          run_id       INTEGER NOT NULL,
          state        TEXT NOT NULL,
          waf          TEXT,
          checked_at   TEXT NOT NULL
        );
        INSERT INTO host_status_history (id, subdomain_id, run_id, state, waf, checked_at)
          VALUES (4, 1, 1, 'ALIVE', 'cloudflare', '2026-11-17T10:00:00Z');
        """
    )
    conn.close()

    migrated = Store(db_path)
    try:
        assert migrated.schema_version == SCHEMA_VERSION == 10
        columns = {
            str(row["name"]): row
            for row in migrated._conn.execute("PRAGMA table_info(host_status_history)")
        }
        assert "waf_priority" in columns
        assert columns["waf_priority"]["dflt_value"] == "0"
        row = migrated._conn.execute("SELECT waf, waf_priority FROM host_status_history").fetchone()
        assert (row["waf"], row["waf_priority"]) == ("cloudflare", 0)
    finally:
        migrated.close()


def _waf_row(store: Store, sub_id: int) -> tuple[str | None, int]:
    row = store._conn.execute(
        "SELECT waf, waf_priority FROM host_status_history"
        " WHERE subdomain_id = ? ORDER BY id DESC LIMIT 1",
        (sub_id,),
    ).fetchone()
    return row["waf"], int(row["waf_priority"])


def test_waf_priority_zero_preserves_first_writer(store: Store) -> None:
    """D12: priority 0 fills an empty column but never overrides a detection.

    Regression: docs/MASTER_PLAN.md D12 - before the priority column any later
    write replaced the stored name, so the winner depended on completion order.
    """
    target_id, run_id = make_run(store)
    sub_id = store.upsert_subdomain(target_id, "a.example.com", run_id=run_id)
    store.append_host_status(sub_id, run_id, "ALIVE")

    # Nothing stored yet: even a priority-0 tool writes its own detection.
    assert store.update_host_extras(sub_id, waf="cloudflare", waf_priority=0) is True
    assert _waf_row(store, sub_id) == ("cloudflare", 0)

    # A higher priority replaces it and remembers its own priority.
    assert store.update_host_extras(sub_id, waf="Cloudflare", waf_priority=100) is True
    assert _waf_row(store, sub_id) == ("Cloudflare", 100)

    # A priority-0 tool and an equal-priority tool both leave the row alone.
    store.update_host_extras(sub_id, waf="akamai", waf_priority=0)
    assert _waf_row(store, sub_id) == ("Cloudflare", 100)
    store.update_host_extras(sub_id, waf="imperva", waf_priority=100)
    assert _waf_row(store, sub_id) == ("Cloudflare", 100)

    # Tech merging is unaffected by the priority rule.
    store.update_host_extras(sub_id, tech=["Java"], waf_priority=0)
    row = store._conn.execute(
        "SELECT tech_json, waf FROM host_status_history ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert (row["tech_json"], row["waf"]) == ('["Java"]', "Cloudflare")
