"""SQLite persistence and diff queries (docs/04_DATABASE.md).

Only this module imports sqlite3. It stores and queries; the engine decides
host states and confidence and passes the values in.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from reconkit.errors import ConfigError

SCHEMA_VERSION = 11
REDACTED = "***"
# docs/04 section 5: the stored reason is one line of at most this many characters.
DETAIL_MAX_CHARS = 200

_SCHEMA_V1 = """
CREATE TABLE targets (
  id         INTEGER PRIMARY KEY,
  domain     TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE scan_runs (
  id          INTEGER PRIMARY KEY,
  target_id   INTEGER NOT NULL REFERENCES targets(id),
  stage       TEXT NOT NULL,
  speed       TEXT NOT NULL CHECK (speed IN ('slow','normal','fast')),
  status      TEXT NOT NULL CHECK (status IN ('running','completed','partial','failed',
                                             'interrupted')),
  started_at  TEXT NOT NULL,
  finished_at TEXT,
  params_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_scan_runs_target ON scan_runs(target_id, id);

CREATE TABLE tool_runs (
  id           INTEGER PRIMARY KEY,
  run_id       INTEGER NOT NULL REFERENCES scan_runs(id),
  tool         TEXT NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('ok','skipped','failed','timeout')),
  item_count   INTEGER NOT NULL DEFAULT 0,
  duration_s   REAL,
  error        TEXT
);

CREATE TABLE subdomains (
  id            INTEGER PRIMARY KEY,
  target_id     INTEGER NOT NULL REFERENCES targets(id),
  fqdn          TEXT NOT NULL,
  state         TEXT NOT NULL DEFAULT 'UNKNOWN'
                CHECK (state IN ('ALIVE','DNS_ONLY','SHUT_DOWN','DEAD','UNKNOWN')),
  confidence    TEXT NOT NULL DEFAULT 'LOW'
                CHECK (confidence IN ('HIGH','MEDIUM','LOW','UNCONFIRMED')),
  source_count  INTEGER NOT NULL DEFAULT 0,
  is_wildcard   INTEGER NOT NULL DEFAULT 0,
  first_seen_run INTEGER NOT NULL REFERENCES scan_runs(id),
  last_seen_run  INTEGER NOT NULL REFERENCES scan_runs(id),
  UNIQUE (target_id, fqdn)
);

CREATE TABLE subdomain_sources (
  subdomain_id INTEGER NOT NULL REFERENCES subdomains(id),
  run_id       INTEGER NOT NULL REFERENCES scan_runs(id),
  tool         TEXT NOT NULL,
  PRIMARY KEY (subdomain_id, run_id, tool)
);
CREATE INDEX idx_subdomain_sources_run ON subdomain_sources(run_id);

CREATE TABLE host_status_history (
  id           INTEGER PRIMARY KEY,
  subdomain_id INTEGER NOT NULL REFERENCES subdomains(id),
  run_id       INTEGER NOT NULL REFERENCES scan_runs(id),
  state        TEXT NOT NULL CHECK (state IN ('ALIVE','DNS_ONLY','SHUT_DOWN','DEAD','UNKNOWN')),
  status_code  INTEGER,
  location     TEXT,
  title        TEXT,
  ips_json     TEXT NOT NULL DEFAULT '[]',
  tech_json    TEXT NOT NULL DEFAULT '[]',
  waf          TEXT,
  tools_json   TEXT NOT NULL DEFAULT '[]',
  checked_at   TEXT NOT NULL
);
CREATE INDEX idx_hsh_sub ON host_status_history(subdomain_id, id);
CREATE INDEX idx_hsh_run ON host_status_history(run_id);

CREATE TABLE ports (
  id            INTEGER PRIMARY KEY,
  subdomain_id  INTEGER NOT NULL REFERENCES subdomains(id),
  ip            TEXT NOT NULL,
  port          INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  protocol      TEXT NOT NULL DEFAULT 'tcp' CHECK (protocol IN ('tcp','udp')),
  state         TEXT NOT NULL CHECK (state IN ('open','unconfirmed','closed')),
  service       TEXT,
  version       TEXT,
  confidence    TEXT NOT NULL DEFAULT 'LOW'
                CHECK (confidence IN ('HIGH','MEDIUM','LOW','UNCONFIRMED')),
  first_seen_run INTEGER NOT NULL REFERENCES scan_runs(id),
  last_seen_run  INTEGER NOT NULL REFERENCES scan_runs(id),
  UNIQUE (subdomain_id, ip, port, protocol)
);

CREATE TABLE port_sources (
  port_id INTEGER NOT NULL REFERENCES ports(id),
  run_id  INTEGER NOT NULL REFERENCES scan_runs(id),
  tool    TEXT NOT NULL,
  seen    TEXT NOT NULL CHECK (seen IN ('open','closed')),
  PRIMARY KEY (port_id, run_id, tool)
);
CREATE INDEX idx_port_sources_run ON port_sources(run_id);

CREATE TABLE urls (
  id            INTEGER PRIMARY KEY,
  target_id     INTEGER NOT NULL REFERENCES targets(id),
  url           TEXT NOT NULL,
  category      TEXT,
  patterns_json TEXT NOT NULL DEFAULT '[]',
  source_count  INTEGER NOT NULL DEFAULT 0,
  first_seen_run INTEGER NOT NULL REFERENCES scan_runs(id),
  last_seen_run  INTEGER NOT NULL REFERENCES scan_runs(id),
  UNIQUE (target_id, url)
);
"""

_SCHEMA_V2 = """
ALTER TABLE host_status_history ADD COLUMN cnames_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE host_status_history ADD COLUMN dangling_cname TEXT;
"""

_SCHEMA_V3 = """
ALTER TABLE subdomains ADD COLUMN provenance TEXT NOT NULL DEFAULT 'dns'
  CHECK (provenance IN ('subs','dns'));
UPDATE subdomains SET provenance = 'subs'
  WHERE id IN (SELECT subdomain_id FROM subdomain_sources);
"""

_SCHEMA_V4 = """
ALTER TABLE host_status_history ADD COLUMN detail TEXT;
"""

# 2026-11-17 (MASTER_PLAN D3): speed control was removed, so the audit column
# that recorded the preset goes with it. No query ever filtered on it.
_SCHEMA_V5 = """
ALTER TABLE scan_runs DROP COLUMN speed;
"""

# docs/04 section 4 (2026-11-17): which scope rule a run used. Existing rows
# predate the column and read as `enforced`; every new run passes the value.
_SCHEMA_V6 = """
ALTER TABLE scan_runs ADD COLUMN scope_mode TEXT NOT NULL DEFAULT 'enforced';
"""

# docs/04 section 11 (2026-11-17, MASTER_PLAN D12): the priority of the tool
# whose detection the `waf` column holds, so a merge keeps the most
# authoritative name instead of the newest one. Existing rows read 0.
_SCHEMA_V7 = """
ALTER TABLE host_status_history ADD COLUMN waf_priority INTEGER NOT NULL DEFAULT 0;
"""

# docs/04 section 11 (2026-11-18, owner ruling): an external-service refusal
# (429, quota, upstream 5xx) is a `gap`, not a failure. SQLite cannot alter a
# CHECK constraint, so the table is rebuilt and every row copied unchanged; no
# other table references tool_runs.
_SCHEMA_V8 = """
CREATE TABLE tool_runs_new (
  id           INTEGER PRIMARY KEY,
  run_id       INTEGER NOT NULL REFERENCES scan_runs(id),
  tool         TEXT NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('ok','gap','skipped','failed','timeout')),
  item_count   INTEGER NOT NULL DEFAULT 0,
  duration_s   REAL,
  error        TEXT
);
INSERT INTO tool_runs_new (id, run_id, tool, status, item_count, duration_s, error)
  SELECT id, run_id, tool, status, item_count, duration_s, error FROM tool_runs;
DROP TABLE tool_runs;
ALTER TABLE tool_runs_new RENAME TO tool_runs;
"""

# docs/04 section 11 (2026-11-18, MASTER_PLAN D22): www/non-www deduplication
# metadata. Additive: every existing row reads NULL for both, which means "no
# duplicate information". No state, confidence or count query reads them.
_SCHEMA_V9 = """
ALTER TABLE host_status_history ADD COLUMN duplicate_of TEXT;
ALTER TABLE host_status_history ADD COLUMN www_note TEXT;
"""

# docs/04 section 11 (2026-11-18, MASTER_PLAN D23): the URL liveness answer.
# Additive: every existing URL reads NULL, which means "not probed yet".
_SCHEMA_V10 = """
ALTER TABLE urls ADD COLUMN status_code INTEGER;
"""

# docs/04 section 11 (2026-11-19, MASTER_PLAN D52): a tool the engine stopped
# (idle watchdog or stage budget) keeps its partial output, so its run is
# `killed` - not `failed` and not `timeout`. The CHECK is rebuilt once more;
# every existing row is copied unchanged and nothing references tool_runs.
_SCHEMA_V11 = """
CREATE TABLE tool_runs_new (
  id           INTEGER PRIMARY KEY,
  run_id       INTEGER NOT NULL REFERENCES scan_runs(id),
  tool         TEXT NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('ok','gap','skipped','failed','timeout',
                                              'killed')),
  item_count   INTEGER NOT NULL DEFAULT 0,
  duration_s   REAL,
  error        TEXT
);
INSERT INTO tool_runs_new (id, run_id, tool, status, item_count, duration_s, error)
  SELECT id, run_id, tool, status, item_count, duration_s, error FROM tool_runs;
DROP TABLE tool_runs;
ALTER TABLE tool_runs_new RENAME TO tool_runs;
"""

_MIGRATIONS: tuple[tuple[int, str], ...] = (
    (1, _SCHEMA_V1),
    (2, _SCHEMA_V2),
    (3, _SCHEMA_V3),
    (4, _SCHEMA_V4),
    (5, _SCHEMA_V5),
    (6, _SCHEMA_V6),
    (7, _SCHEMA_V7),
    (8, _SCHEMA_V8),
    (9, _SCHEMA_V9),
    (10, _SCHEMA_V10),
    (11, _SCHEMA_V11),
)

_COUNT_SQL: dict[str, str] = {
    "targets": "SELECT COUNT(*) FROM targets",
    "scan_runs": "SELECT COUNT(*) FROM scan_runs",
    "tool_runs": "SELECT COUNT(*) FROM tool_runs",
    "subdomains": "SELECT COUNT(*) FROM subdomains",
    "subdomain_sources": "SELECT COUNT(*) FROM subdomain_sources",
    "host_status_history": "SELECT COUNT(*) FROM host_status_history",
    "ports": "SELECT COUNT(*) FROM ports",
    "port_sources": "SELECT COUNT(*) FROM port_sources",
    "urls": "SELECT COUNT(*) FROM urls",
}

# A header value ends at a real line break or at the escaped `\\r`/`\\n` that a
# JSONL tool writes inside a string; without the second rule the value swallowed
# the rest of the JSON line, truncating it (PIT-54).
_HEADER_VALUE = r"(?:[^\\\r\n\"]|\\(?![rn]))*"
_AUTH_HEADER = re.compile(r"(?i)(authorization)\b(\s*[:=]\s*)(?:[^\\\r\n,\"]|\\(?![rn]))*")
_COOKIE_HEADER = re.compile(rf"(?i)((?:set-)?cookie)\b(\s*[:=]\s*){_HEADER_VALUE}")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_URL_CREDENTIALS = re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@")
_FLAG_VALUE = re.compile(
    r"(?i)(?<![\w-])(-{1,2}[a-z0-9][a-z0-9_-]*)(\s+)(\"[^\"]*\"|'[^']*'|(?:[^\s\\]|\\(?![rn]))+)"
)
_SECRET_FLAG_WORDS = (
    "token",
    "secret",
    "passw",
    "api-key",
    "api_key",
    "apikey",
    "cookie",
)
_SECRET_PAIR = re.compile(
    r"(?i)\b(api[_-]?key|apikey|token|access[_-]?token|secret|password|passwd|cookie)"
    r"(\s*[:=]\s*)(['\"]?)((?:[^\\\s'\",;&]|\\(?![rn]))+)"
)


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_now() -> str:
    """Public default for the engine's injected timestamp source."""
    return _utc_now()


def _mask_secret_flag(match: re.Match[str]) -> str:
    flag = match.group(1).lower()
    if not any(word in flag for word in _SECRET_FLAG_WORDS) and flag not in ("--key", "-key"):
        return match.group(0)
    return f"{match.group(1)}{match.group(2)}{REDACTED}"


def _secret_values(secrets: Iterable[str]) -> tuple[str, ...]:
    """Deduplicate secret values, longest first, ignoring chips under 3 chars."""
    return tuple(sorted({value for value in secrets if len(value) >= 3}, key=len, reverse=True))


# The process-wide value set the CLI fills once at startup (docs/03 section 5).
_configured_secrets: tuple[str, ...] = ()


def configure_redaction(secrets: Iterable[str]) -> None:
    """Replace the process-wide secret values `redact()` masks (docs/03 section 5).

    The CLI calls this once, at startup, with the values from `.env` - the same
    source that feeds `Engine._secrets` and therefore `Workspace.write` (12a).
    It replaces the set instead of appending, so a second call cannot grow a
    parallel list, and it adds no pattern list and no environment variable.
    """
    global _configured_secrets
    _configured_secrets = _secret_values(secrets)


def redact(text: str, secrets: Iterable[str] | None = None) -> str:
    """Mask credentials and secret values before text is stored or printed.

    `secrets=None` masks the process-wide values set by
    `configure_redaction()` (the CLI console path). An explicit iterable, even
    an empty one, masks exactly those values plus the shared patterns, so the
    engine/workspace callers keep their per-run set (docs/04 section 10).
    """
    result = text
    values = _configured_secrets if secrets is None else _secret_values(secrets)
    for value in values:
        result = result.replace(value, REDACTED)
    result = _AUTH_HEADER.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", result)
    result = _COOKIE_HEADER.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", result)
    result = _BEARER.sub(f"Bearer {REDACTED}", result)
    result = _URL_CREDENTIALS.sub(rf"\1{REDACTED}:{REDACTED}@", result)
    result = _FLAG_VALUE.sub(_mask_secret_flag, result)
    result = _SECRET_PAIR.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}{REDACTED}", result
    )
    return result


def _detail_value(detail: str | None, secrets: Iterable[str]) -> str | None:
    """One redacted, bounded line for `host_status_history.detail`.

    docs/04 section 5: redact first with the same helper as every other stored
    text, collapse whitespace so the value stays a single line, then cut to
    `DETAIL_MAX_CHARS`. Redacting before the cut means a truncated value can
    never leave a partial secret behind. An empty result is stored as NULL.
    """
    if detail is None:
        return None
    text = " ".join(redact(detail, secrets).split())
    return text[:DETAIL_MAX_CHARS] or None


def _text_list(raw: object) -> tuple[str, ...]:
    """Read one stored JSON string list (`ips_json`/`tech_json`).

    A missing row is `None` and a malformed value is treated the same way: an
    empty tuple, never an exception, because this feeds a report.
    """
    if not isinstance(raw, str) or not raw:
        return ()
    try:
        values = json.loads(raw)
    except ValueError:
        return ()
    if not isinstance(values, list):
        return ()
    return tuple(str(value) for value in values if isinstance(value, str))


def _url_host(url: str) -> str:
    """A stored URL's hostname, lowercased; `""` when it has none (D54)."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return ""
    return (host or "").lower().rstrip(".")


@dataclass(frozen=True)
class ProbeCandidates:
    """What the `url_probe` stage should send a request to (D23, D54, D55).

    `skipped_unreachable` is the number of URLs left out because their host is
    already known DEAD or DNS_ONLY. It never shrinks `rows`: the filter runs
    before the limit is filled, so a skipped row does not eat a probe slot.
    """

    rows: list[dict[str, object]]
    skipped_unreachable: int


class Store:
    """One SQLite database: schema migrations, writes and read queries."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._batch_depth = 0
        try:
            self._migrate()
        except Exception:
            self._conn.close()
            raise

    @classmethod
    def open_readonly(cls, path: str | Path) -> Store:
        """Open an existing database that this process may not write (D65).

        `reconkit report --from-db` only reads. `mode=ro` makes that a property
        of the connection instead of a promise: a stray INSERT or UPDATE raises
        `OperationalError` rather than changing the store. Migrations are skipped
        on purpose - the report reads two stable views (`subdomains`,
        `host_status_history`, `urls`, `scan_runs`), and a write would defeat the
        point. A missing file or table raises; the caller turns that into a
        usage error.
        """
        self = cls.__new__(cls)
        self.path = Path(path)
        self._conn = sqlite3.connect(f"file:{self.path.resolve().as_posix()}?mode=ro", uri=True)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._batch_depth = 0
        try:
            # One cheap read proves the file is a reconkit schema before the
            # caller turns a raw sqlite error into a traceback.
            self._conn.execute("SELECT id FROM scan_runs LIMIT 1").fetchone()
        except sqlite3.Error as exc:
            self._conn.close()
            raise ValueError(f"not a reconkit database: {self.path}") from exc
        return self

    def __enter__(self) -> Store:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    def _commit(self) -> None:
        """Commit unless an outer `transaction()` owns the commit."""
        if self._batch_depth == 0:
            self._conn.commit()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Batch writes into one commit; roll back the whole block on error.

        Nested blocks join the outermost transaction so an inner helper cannot
        commit half of a stage.
        """
        if self._batch_depth:
            self._batch_depth += 1
            try:
                yield
            finally:
                self._batch_depth -= 1
            return
        self._batch_depth = 1
        try:
            yield
        except BaseException:
            self._conn.rollback()
            raise
        else:
            self._commit()
        finally:
            self._batch_depth = 0

    @property
    def schema_version(self) -> int:
        row = self._conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
        return int(row[0]) if row[0] is not None else 0

    def _migrate(self) -> None:
        self._conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
        row = self._conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
        current = int(row[0]) if row[0] is not None else 0
        if current > SCHEMA_VERSION:
            raise ConfigError(
                f"database schema version {current} is newer than this build ({SCHEMA_VERSION})\n"
                "fix: upgrade reconkit or point --db at an older database"
            )
        has_row = self._conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0] > 0
        for version, script in _MIGRATIONS:
            if version <= current:
                continue
            self._conn.executescript(script)
            if has_row:
                self._conn.execute("UPDATE schema_version SET version = ?", (version,))
            else:
                self._conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
                has_row = True
            self._commit()

    def create_target(self, domain: str, *, created_at: str | None = None) -> int:
        self._conn.execute(
            "INSERT INTO targets (domain, created_at) VALUES (?, ?) ON CONFLICT(domain) DO NOTHING",
            (domain, created_at or _utc_now()),
        )
        self._commit()
        row = self._conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
        return int(row["id"])

    def get_target(self, domain: str) -> int | None:
        row = self._conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
        return None if row is None else int(row["id"])

    def scan_runs(self, target_id: int) -> list[dict[str, object]]:
        """Every stage row for one target, oldest first (engine resume)."""
        rows = self._conn.execute(
            "SELECT id, stage, status, params_json FROM scan_runs WHERE target_id = ? ORDER BY id",
            (target_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def run_stamp(self, target_id: int, run_id: int | None = None) -> dict[str, object] | None:
        """The run a report is rebuilt from: its id and start time (D65)."""
        if run_id is None:
            row = self._conn.execute(
                "SELECT id, started_at FROM scan_runs WHERE target_id = ? ORDER BY id DESC LIMIT 1",
                (target_id,),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT id, started_at FROM scan_runs WHERE target_id = ? AND id = ?",
                (target_id, run_id),
            ).fetchone()
        if row is None:
            return None
        return {"id": int(row["id"]), "started_at": str(row["started_at"])}

    def subdomains(self, target_id: int) -> list[dict[str, object]]:
        """Known hosts and states for one target (engine resume seeds)."""
        rows = self._conn.execute(
            "SELECT fqdn, state FROM subdomains WHERE target_id = ? ORDER BY fqdn",
            (target_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def host_rows(self, target_id: int) -> list[dict[str, object]]:
        """Latest host state, confidence, sources, status and open ports for the UI.

        Part 13 adds the stored title, location, IPs, technology list and the
        discovery source count from the same latest `host_status_history` row and
        from `subdomains`. Nothing new is computed here: every value is a stored
        column, so the report can never show a value the run did not observe.
        """
        rows = self._conn.execute(
            "SELECT s.fqdn, s.state, s.confidence, s.source_count,"
            " h.status_code, h.detail, h.title, h.location, h.ips_json, h.tech_json,"
            " h.duplicate_of, h.www_note,"
            " COALESCE((SELECT GROUP_CONCAT(DISTINCT x.tool) FROM subdomain_sources x"
            "  WHERE x.subdomain_id = s.id), '') AS sources,"
            " COALESCE((SELECT GROUP_CONCAT(DISTINCT p.port) FROM ports p"
            "  WHERE p.subdomain_id = s.id AND p.state = 'open'), '') AS ports"
            " FROM subdomains s"
            " LEFT JOIN host_status_history h ON h.id = ("
            "  SELECT MAX(latest.id) FROM host_status_history latest"
            "  WHERE latest.subdomain_id = s.id)"
            " WHERE s.target_id = ? ORDER BY s.fqdn",
            (target_id,),
        ).fetchall()
        result: list[dict[str, object]] = []
        for row in rows:
            sources = str(row["sources"] or "")
            ports = str(row["ports"] or "")
            result.append(
                {
                    "fqdn": str(row["fqdn"]),
                    "state": str(row["state"]),
                    "confidence": str(row["confidence"]),
                    "source_count": int(row["source_count"] or 0),
                    "status_code": None if row["status_code"] is None else int(row["status_code"]),
                    "detail": None if row["detail"] is None else str(row["detail"]),
                    "duplicate_of": (
                        None if row["duplicate_of"] is None else str(row["duplicate_of"])
                    ),
                    "www_note": None if row["www_note"] is None else str(row["www_note"]),
                    "title": None if row["title"] is None else str(row["title"]),
                    "location": None if row["location"] is None else str(row["location"]),
                    "ips": _text_list(row["ips_json"]),
                    "tech": _text_list(row["tech_json"]),
                    "sources": tuple(sorted(part for part in sources.split(",") if part)),
                    "ports": tuple(sorted(int(part) for part in ports.split(",") if part)),
                }
            )
        return result

    def recent_scan_runs(self, limit: int = 20) -> list[dict[str, object]]:
        """Recent stage runs joined to their target domain (status command)."""
        if limit < 1:
            return []
        rows = self._conn.execute(
            "SELECT r.id, t.domain AS target, r.stage, r.status,"
            " r.started_at, r.finished_at"
            " FROM scan_runs r JOIN targets t ON t.id = r.target_id"
            " ORDER BY r.id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def completed_run_ids(self, target_id: int, stage: str) -> list[int]:
        """Completed/partial run ids for one stage, newest first (diff command)."""
        rows = self._conn.execute(
            "SELECT id FROM scan_runs WHERE target_id = ? AND stage = ?"
            " AND status IN ('completed', 'partial') ORDER BY id DESC",
            (target_id, stage),
        ).fetchall()
        return [int(row["id"]) for row in rows]

    def create_scan_run(
        self,
        target_id: int,
        stage: str,
        *,
        params: str = "{}",
        scope_mode: str = "enforced",
        started_at: str | None = None,
        secrets: Sequence[str] = (),
    ) -> int:
        if scope_mode not in ("enforced", "no_file", "unrestricted_flag"):
            raise ValueError(f"invalid scope_mode {scope_mode!r}")
        cursor = self._conn.execute(
            "INSERT INTO scan_runs (target_id, stage, status, started_at, params_json, scope_mode)"
            " VALUES (?, ?, 'running', ?, ?, ?)",
            (target_id, stage, started_at or _utc_now(), redact(params, secrets), scope_mode),
        )
        self._commit()
        return int(cursor.lastrowid or 0)

    def finish_scan_run(self, run_id: int, status: str, *, finished_at: str | None = None) -> None:
        self._conn.execute(
            "UPDATE scan_runs SET status = ?, finished_at = ? WHERE id = ?",
            (status, finished_at or _utc_now(), run_id),
        )
        self._commit()

    def record_tool_run(
        self,
        run_id: int,
        tool: str,
        status: str,
        *,
        item_count: int = 0,
        duration_s: float | None = None,
        error: str | None = None,
        secrets: Sequence[str] = (),
    ) -> int:
        clean_error = None if error is None else redact(error, secrets)
        cursor = self._conn.execute(
            "INSERT INTO tool_runs (run_id, tool, status, item_count, duration_s, error)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (run_id, tool, status, item_count, duration_s, clean_error),
        )
        self._commit()
        return int(cursor.lastrowid or 0)

    def upsert_subdomain(
        self,
        target_id: int,
        fqdn: str,
        *,
        run_id: int,
        state: str | None = None,
        confidence: str | None = None,
        source_count: int | None = None,
        is_wildcard: bool | None = None,
        provenance: str | None = None,
    ) -> int:
        self._conn.execute(
            "INSERT INTO subdomains"
            " (target_id, fqdn, state, confidence, source_count, is_wildcard,"
            "  provenance, first_seen_run, last_seen_run)"
            " VALUES (:target_id, :fqdn, COALESCE(:state, 'UNKNOWN'),"
            "  COALESCE(:confidence, 'LOW'), COALESCE(:source_count, 0),"
            "  COALESCE(:is_wildcard, 0), COALESCE(:provenance, 'dns'),"
            "  :run_id, :run_id)"
            " ON CONFLICT(target_id, fqdn) DO UPDATE SET"
            "  last_seen_run = excluded.last_seen_run,"
            "  state = COALESCE(:state, subdomains.state),"
            "  confidence = COALESCE(:confidence, subdomains.confidence),"
            "  source_count = COALESCE(:source_count, subdomains.source_count),"
            "  is_wildcard = COALESCE(:is_wildcard, subdomains.is_wildcard),"
            "  provenance = CASE WHEN excluded.provenance = 'subs'"
            "   THEN 'subs' ELSE subdomains.provenance END",
            {
                "target_id": target_id,
                "fqdn": fqdn,
                "state": state,
                "confidence": confidence,
                "source_count": source_count,
                "is_wildcard": None if is_wildcard is None else int(is_wildcard),
                "provenance": provenance,
                "run_id": run_id,
            },
        )
        self._commit()
        row = self._conn.execute(
            "SELECT id FROM subdomains WHERE target_id = ? AND fqdn = ?", (target_id, fqdn)
        ).fetchone()
        return int(row["id"])

    def add_subdomain_source(self, subdomain_id: int, run_id: int, tool: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO subdomain_sources (subdomain_id, run_id, tool) VALUES (?, ?, ?)",
            (subdomain_id, run_id, tool),
        )
        self._commit()

    def append_host_status(
        self,
        subdomain_id: int,
        run_id: int,
        state: str,
        *,
        status_code: int | None = None,
        title: str | None = None,
        location: str | None = None,
        cnames: Sequence[str] = (),
        dangling_cname: str | None = None,
        detail: str | None = None,
        ips: Sequence[str] = (),
        tech: Sequence[str] = (),
        waf: str | None = None,
        tools: Sequence[str] = (),
        checked_at: str | None = None,
        secrets: Sequence[str] = (),
    ) -> int:
        cursor = self._conn.execute(
            "INSERT INTO host_status_history"
            " (subdomain_id, run_id, state, status_code, title, location, cnames_json,"
            "  dangling_cname, detail, ips_json, tech_json, waf, tools_json, checked_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                subdomain_id,
                run_id,
                state,
                status_code,
                title,
                location,
                json.dumps(list(cnames)),
                dangling_cname,
                _detail_value(detail, secrets),
                json.dumps(list(ips)),
                json.dumps(list(tech)),
                waf,
                json.dumps(list(tools)),
                checked_at or _utc_now(),
            ),
        )
        self._commit()
        return int(cursor.lastrowid or 0)

    def set_host_duplicate(
        self,
        target_id: int,
        fqdn: str,
        *,
        duplicate_of: str | None,
        www_note: str | None = None,
    ) -> bool:
        """Write the www/non-www metadata on the host's newest status row (D22).

        Metadata only: it never appends a row and never touches `state`,
        `status_code`, `confidence` or `checked_at`, so host state and every
        count query stay exactly what the live stage decided. Returns False when
        the host or its status row does not exist.
        """
        sub = self._conn.execute(
            "SELECT id FROM subdomains WHERE target_id = ? AND fqdn = ?", (target_id, fqdn)
        ).fetchone()
        if sub is None:
            return False
        row = self._conn.execute(
            "SELECT id FROM host_status_history WHERE subdomain_id = ? ORDER BY id DESC LIMIT 1",
            (int(sub["id"]),),
        ).fetchone()
        if row is None:
            return False
        self._conn.execute(
            "UPDATE host_status_history SET duplicate_of = ?, www_note = ? WHERE id = ?",
            (duplicate_of, www_note, int(row["id"])),
        )
        self._commit()
        return True

    def update_host_extras(
        self,
        subdomain_id: int,
        *,
        tech: Sequence[str] = (),
        waf: str | None = None,
        waf_priority: int = 0,
    ) -> bool:
        """Add technologies/WAF to the latest status row; never inserts a row.

        The `tech` stage annotates the newest pass instead of writing a state
        row of its own: a technology match is not a liveness verdict, so it must
        not create, replace or re-date one (docs/04 section 5). Returns True when
        a row was updated, False when the host has no status row yet.

        `waf` and `waf_priority` are merged together (docs/MASTER_PLAN.md D12):
        the stored name is only replaced by a strictly higher priority, and any
        first detection fills an empty column. Equal priorities keep the stored
        name, so completion order and rerun order can never change it.
        """
        if not tech and waf is None:
            return False
        row = self._conn.execute(
            "SELECT id, tech_json, waf, waf_priority FROM host_status_history"
            " WHERE subdomain_id = ? ORDER BY id DESC LIMIT 1",
            (subdomain_id,),
        ).fetchone()
        if row is None:
            return False
        merged = list(_text_list(row["tech_json"]))
        for name in tech:
            if name not in merged:
                merged.append(name)
        stored_waf = row["waf"]
        stored_priority = int(row["waf_priority"] or 0)
        if waf is not None and (stored_waf is None or waf_priority > stored_priority):
            stored_waf = waf
            stored_priority = waf_priority
        self._conn.execute(
            "UPDATE host_status_history SET tech_json = ?, waf = ?, waf_priority = ? WHERE id = ?",
            (json.dumps(merged), stored_waf, stored_priority, int(row["id"])),
        )
        self._commit()
        return True

    def upsert_port(
        self,
        subdomain_id: int,
        ip: str,
        port: int,
        *,
        run_id: int,
        state: str,
        protocol: str = "tcp",
        service: str | None = None,
        version: str | None = None,
        confidence: str | None = None,
    ) -> int:
        self._conn.execute(
            "INSERT INTO ports"
            " (subdomain_id, ip, port, protocol, state, service, version, confidence,"
            "  first_seen_run, last_seen_run)"
            " VALUES (:subdomain_id, :ip, :port, :protocol, :state, :service, :version,"
            "  COALESCE(:confidence, 'LOW'), :run_id, :run_id)"
            " ON CONFLICT(subdomain_id, ip, port, protocol) DO UPDATE SET"
            "  last_seen_run = excluded.last_seen_run,"
            "  state = excluded.state,"
            "  service = COALESCE(excluded.service, ports.service),"
            "  version = COALESCE(excluded.version, ports.version),"
            "  confidence = COALESCE(:confidence, ports.confidence)",
            {
                "subdomain_id": subdomain_id,
                "ip": ip,
                "port": port,
                "protocol": protocol,
                "state": state,
                "service": service,
                "version": version,
                "confidence": confidence,
                "run_id": run_id,
            },
        )
        self._commit()
        row = self._conn.execute(
            "SELECT id FROM ports WHERE subdomain_id = ? AND ip = ? AND port = ? AND protocol = ?",
            (subdomain_id, ip, port, protocol),
        ).fetchone()
        return int(row["id"])

    def add_port_source(self, port_id: int, run_id: int, tool: str, seen: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO port_sources (port_id, run_id, tool, seen) VALUES (?, ?, ?, ?)",
            (port_id, run_id, tool, seen),
        )
        self._commit()

    def upsert_url(
        self,
        target_id: int,
        url: str,
        *,
        run_id: int,
        category: str | None = None,
        patterns: Sequence[str] | None = None,
        source_count: int | None = None,
    ) -> int:
        self._conn.execute(
            "INSERT INTO urls"
            " (target_id, url, category, patterns_json, source_count,"
            "  first_seen_run, last_seen_run)"
            " VALUES (:target_id, :url, :category, COALESCE(:patterns_json, '[]'),"
            "  COALESCE(:source_count, 0), :run_id, :run_id)"
            " ON CONFLICT(target_id, url) DO UPDATE SET"
            "  last_seen_run = excluded.last_seen_run,"
            "  category = COALESCE(:category, urls.category),"
            "  patterns_json = COALESCE(:patterns_json, urls.patterns_json),"
            "  source_count = COALESCE(:source_count, urls.source_count)",
            {
                "target_id": target_id,
                "url": url,
                "category": category,
                "patterns_json": None if patterns is None else json.dumps(list(patterns)),
                "source_count": source_count,
                "run_id": run_id,
            },
        )
        self._commit()
        row = self._conn.execute(
            "SELECT id FROM urls WHERE target_id = ? AND url = ?", (target_id, url)
        ).fetchone()
        return int(row["id"])

    def probe_candidates(
        self, target_id: int, *, limit: int, reprobe: bool = False
    ) -> ProbeCandidates:
        """The target's URLs the `url_probe` stage should send a request to (D23).

        `NULL` is the only "not probed" value: a URL that did not answer is
        stored as `-1`, so by default it is never handed back here. `reprobe`
        (`--reprobe-urls`, D24) returns every URL, including ones that already
        carry an answer, so a live URL that has since gone dead can be found.

        D54/D55: a URL whose host the latest state pass recorded as `DEAD` or
        `DNS_ONLY` is not probed at all - a dead host went silent, and a
        DNS_ONLY host resolved but never served HTTP, so in both cases the URL
        can only be paid for and thrown away. Only those two **known** states
        are enough to skip: a URL whose host has no `subdomains` row (never
        resolved), whose host is ALIVE/SHUT_DOWN/UNKNOWN, or whose host cannot
        be parsed is kept. The filter runs before the limit is filled, so a
        skipped row never eats a probe slot.
        """
        if reprobe:
            sql = "SELECT id, url FROM urls WHERE target_id = ? ORDER BY id"
        else:
            sql = "SELECT id, url FROM urls WHERE target_id = ? AND status_code IS NULL ORDER BY id"
        unreachable = self._unreachable_fqdns(target_id)
        found: list[dict[str, object]] = []
        skipped = 0
        for row in self._conn.execute(sql, (target_id,)):
            url = str(row["url"])
            if unreachable and _url_host(url) in unreachable:
                skipped += 1
                continue
            found.append({"id": int(row["id"]), "url": url})
            if len(found) >= limit:
                break
        return ProbeCandidates(rows=found, skipped_unreachable=skipped)

    def url_only_hosts(self, target_id: int) -> list[str]:
        """Hostnames this target's URLs name that have no `subdomains` row (D58).

        A `urls` pass stores URLs, never hosts, so an archive can name a host no
        subdomain source reported and nothing downstream ever sees it. The
        comparison is the same `_url_host()` parser the D55 filter uses, so a
        URL with a port or no scheme is read identically in both places; a URL
        whose host cannot be parsed contributes nothing. Case is normalised, so
        `WWW.Example.com` and `www.example.com` are one candidate. Returns sorted
        names and never touches the network or another table.
        """
        rows = self._conn.execute(
            "SELECT url FROM urls WHERE target_id = ?", (target_id,)
        ).fetchall()
        known = {
            str(row["fqdn"])
            for row in self._conn.execute(
                "SELECT fqdn FROM subdomains WHERE target_id = ?", (target_id,)
            )
        }
        unknown: set[str] = set()
        for row in rows:
            host = _url_host(str(row["url"]))
            if host and host not in known:
                unknown.add(host)
        return sorted(unknown)

    def url_report_rows(self, target_id: int) -> list[dict[str, object]]:
        """Every stored URL of a target, with its host and that host's state (D62).

        Read-only: one row per URL with the URL as stored, its `status_code`
        (`None` when never probed), the hostname from the same `_url_host()`
        parser the D55 filter uses, and the host's latest `subdomains.state`
        (`UNKNOWN` when the host has no row at all). A URL whose host cannot be
        parsed contributes nothing, exactly like `url_only_hosts()`.
        """
        states = {
            str(row["fqdn"]): str(row["state"])
            for row in self._conn.execute(
                "SELECT fqdn, state FROM subdomains WHERE target_id = ?", (target_id,)
            )
        }
        rows: list[dict[str, object]] = []
        for row in self._conn.execute(
            "SELECT url, status_code FROM urls WHERE target_id = ? ORDER BY url", (target_id,)
        ):
            url = str(row["url"])
            host = _url_host(url)
            if not host:
                continue
            status = row["status_code"]
            rows.append(
                {
                    "url": url,
                    "host": host,
                    "status_code": status if isinstance(status, int) else None,
                    "host_state": states.get(host, "UNKNOWN"),
                }
            )
        return rows

    def _unreachable_fqdns(self, target_id: int) -> set[str]:
        """Hosts the latest state pass recorded as `DEAD` or `DNS_ONLY` (D54, D55)."""
        rows = self._conn.execute(
            "SELECT fqdn FROM subdomains WHERE target_id = ? AND state IN ('DEAD', 'DNS_ONLY')",
            (target_id,),
        ).fetchall()
        return {str(row["fqdn"]).lower().rstrip(".") for row in rows}

    def set_url_status(self, url_id: int, status_code: int) -> None:
        """Write the `url_probe` answer on the URL row (D23).

        Updates in place: no new row, and no other column is touched, so
        `first_seen_run`, `source_count` and `diff` see exactly what they saw
        before the probe existed.
        """
        self._conn.execute("UPDATE urls SET status_code = ? WHERE id = ?", (status_code, url_id))
        self._commit()

    def previous_state(self, subdomain_id: int) -> str | None:
        row = self._conn.execute(
            "SELECT state FROM host_status_history WHERE subdomain_id = ? ORDER BY id DESC LIMIT 1",
            (subdomain_id,),
        ).fetchone()
        return None if row is None else str(row["state"])

    def latest_cnames(self, subdomain_id: int) -> tuple[str, ...]:
        """CNAMEs from the latest status row, or an empty tuple when none exist."""
        row = self._conn.execute(
            "SELECT cnames_json FROM host_status_history"
            " WHERE subdomain_id = ? ORDER BY id DESC LIMIT 1",
            (subdomain_id,),
        ).fetchone()
        if row is None:
            return ()
        raw = json.loads(str(row["cnames_json"]))
        return tuple(str(value) for value in raw)

    def diff_new(self, latest_run_id: int) -> list[str]:
        rows = self._conn.execute(
            "SELECT s.fqdn FROM subdomains s"
            " WHERE s.target_id = (SELECT target_id FROM scan_runs WHERE id = ?)"
            "   AND s.provenance = 'subs'"
            "   AND NOT EXISTS (SELECT 1 FROM subdomain_sources x"
            "                   WHERE x.subdomain_id = s.id AND x.run_id < ?)"
            " ORDER BY s.fqdn",
            (latest_run_id, latest_run_id),
        ).fetchall()
        return [str(row["fqdn"]) for row in rows]

    def diff_gone(
        self, baseline_run_id: int, previous_run_id: int, latest_run_id: int
    ) -> list[str]:
        """Hosts absent from two consecutive runs, still present in the one before.

        docs/02 and docs/04 section 6: one miss is source flakiness, not a change.
        """
        rows = self._conn.execute(
            "SELECT s.fqdn FROM subdomains s"
            " WHERE s.target_id = (SELECT target_id FROM scan_runs WHERE id = ?)"
            "   AND EXISTS (SELECT 1 FROM subdomain_sources x"
            "               WHERE x.subdomain_id = s.id AND x.run_id = ?)"
            "   AND NOT EXISTS (SELECT 1 FROM subdomain_sources x"
            "                   WHERE x.subdomain_id = s.id AND x.run_id = ?)"
            "   AND NOT EXISTS (SELECT 1 FROM subdomain_sources x"
            "                   WHERE x.subdomain_id = s.id AND x.run_id = ?)"
            " ORDER BY s.fqdn",
            (latest_run_id, baseline_run_id, previous_run_id, latest_run_id),
        ).fetchall()
        return [str(row["fqdn"]) for row in rows]

    def diff_pending_gone(self, previous_run_id: int, latest_run_id: int) -> list[str]:
        """Hosts missing from the latest run only: not GONE, reported as pending."""
        rows = self._conn.execute(
            "SELECT s.fqdn FROM subdomains s"
            " WHERE s.target_id = (SELECT target_id FROM scan_runs WHERE id = ?)"
            "   AND EXISTS (SELECT 1 FROM subdomain_sources x"
            "               WHERE x.subdomain_id = s.id AND x.run_id = ?)"
            "   AND NOT EXISTS (SELECT 1 FROM subdomain_sources x"
            "                   WHERE x.subdomain_id = s.id AND x.run_id = ?)"
            " ORDER BY s.fqdn",
            (latest_run_id, previous_run_id, latest_run_id),
        ).fetchall()
        return [str(row["fqdn"]) for row in rows]

    def diff_state_changed(
        self, previous_run_id: int, latest_run_id: int
    ) -> list[tuple[str, str, str]]:
        rows = self._conn.execute(
            "SELECT s.fqdn, p.state AS old_state, c.state AS new_state"
            " FROM subdomains s"
            " JOIN host_status_history p ON p.id = ("
            "   SELECT id FROM host_status_history h"
            "   WHERE h.subdomain_id = s.id AND h.run_id = ? ORDER BY id DESC LIMIT 1)"
            " JOIN host_status_history c ON c.id = ("
            "   SELECT id FROM host_status_history h"
            "   WHERE h.subdomain_id = s.id AND h.run_id = ? ORDER BY id DESC LIMIT 1)"
            " WHERE s.target_id = (SELECT target_id FROM scan_runs WHERE id = ?)"
            "   AND p.state <> c.state"
            " ORDER BY s.fqdn",
            (previous_run_id, latest_run_id, latest_run_id),
        ).fetchall()
        return [(str(row["fqdn"]), str(row["old_state"]), str(row["new_state"])) for row in rows]

    def diff_ports_opened(self, previous_run_id: int, latest_run_id: int) -> list[tuple[str, int]]:
        rows = self._conn.execute(
            "SELECT DISTINCT s.fqdn, p.port"
            " FROM port_sources cur"
            " JOIN ports p ON p.id = cur.port_id"
            " JOIN subdomains s ON s.id = p.subdomain_id"
            " WHERE cur.run_id = ? AND cur.seen = 'open'"
            "   AND s.target_id = (SELECT target_id FROM scan_runs WHERE id = ?)"
            "   AND NOT EXISTS (SELECT 1 FROM port_sources old"
            "                   WHERE old.port_id = p.id AND old.run_id = ? AND old.seen = 'open')"
            " ORDER BY s.fqdn, p.port",
            (latest_run_id, latest_run_id, previous_run_id),
        ).fetchall()
        return [(str(row["fqdn"]), int(row["port"])) for row in rows]

    def diff_ports_closed(self, previous_run_id: int, latest_run_id: int) -> list[tuple[str, int]]:
        rows = self._conn.execute(
            "SELECT DISTINCT s.fqdn, p.port"
            " FROM port_sources cur"
            " JOIN ports p ON p.id = cur.port_id"
            " JOIN subdomains s ON s.id = p.subdomain_id"
            " WHERE cur.run_id = ? AND cur.seen = 'closed'"
            "   AND s.target_id = (SELECT target_id FROM scan_runs WHERE id = ?)"
            "   AND EXISTS (SELECT 1 FROM port_sources old"
            "               WHERE old.port_id = p.id AND old.run_id = ? AND old.seen = 'open')"
            " ORDER BY s.fqdn, p.port",
            (latest_run_id, latest_run_id, previous_run_id),
        ).fetchall()
        return [(str(row["fqdn"]), int(row["port"])) for row in rows]

    def count(self, table: str) -> int:
        sql = _COUNT_SQL.get(table)
        if sql is None:
            raise ValueError(f"unknown table {table!r}")
        row = self._conn.execute(sql).fetchone()
        return int(row[0])
