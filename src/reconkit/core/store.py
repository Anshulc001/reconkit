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
from datetime import UTC, datetime
from pathlib import Path

from reconkit.errors import ConfigError

SCHEMA_VERSION = 2
REDACTED = "***"

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

_MIGRATIONS: tuple[tuple[int, str], ...] = ((1, _SCHEMA_V1), (2, _SCHEMA_V2))

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

_AUTH_HEADER = re.compile(r"(?i)\b(authorization)\b(\s*[:=]\s*)[^\r\n,]+")
_COOKIE_HEADER = re.compile(r"(?i)\b((?:set-)?cookie)\b(\s*[:=]\s*)[^\r\n]+")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_URL_CREDENTIALS = re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@")
_FLAG_VALUE = re.compile(r"(?i)(?<![\w-])(-{1,2}[a-z0-9][a-z0-9_-]*)(\s+)(\"[^\"]*\"|'[^']*'|\S+)")
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
    r"(\s*[:=]\s*)(['\"]?)([^\s'\",;&]+)"
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


def redact(text: str, secrets: Iterable[str] = ()) -> str:
    """Mask credentials and secret values before text is stored (docs/04 section 10)."""
    result = text
    for secret in sorted({value for value in secrets if len(value) >= 3}, key=len, reverse=True):
        result = result.replace(secret, REDACTED)
    result = _AUTH_HEADER.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", result)
    result = _COOKIE_HEADER.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", result)
    result = _BEARER.sub(f"Bearer {REDACTED}", result)
    result = _URL_CREDENTIALS.sub(rf"\1{REDACTED}:{REDACTED}@", result)
    result = _FLAG_VALUE.sub(_mask_secret_flag, result)
    result = _SECRET_PAIR.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}{REDACTED}", result
    )
    return result


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

    def subdomains(self, target_id: int) -> list[dict[str, object]]:
        """Known hosts and states for one target (engine resume seeds)."""
        rows = self._conn.execute(
            "SELECT fqdn, state FROM subdomains WHERE target_id = ? ORDER BY fqdn",
            (target_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def host_rows(self, target_id: int) -> list[dict[str, object]]:
        """Latest host state, confidence, sources, status and open ports for the UI."""
        rows = self._conn.execute(
            "SELECT s.fqdn, s.state, s.confidence,"
            " (SELECT h.status_code FROM host_status_history h"
            "  WHERE h.subdomain_id = s.id ORDER BY h.id DESC LIMIT 1) AS status_code,"
            " COALESCE((SELECT GROUP_CONCAT(DISTINCT x.tool) FROM subdomain_sources x"
            "  WHERE x.subdomain_id = s.id), '') AS sources,"
            " COALESCE((SELECT GROUP_CONCAT(DISTINCT p.port) FROM ports p"
            "  WHERE p.subdomain_id = s.id AND p.state = 'open'), '') AS ports"
            " FROM subdomains s WHERE s.target_id = ? ORDER BY s.fqdn",
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
                    "status_code": None if row["status_code"] is None else int(row["status_code"]),
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
            "SELECT r.id, t.domain AS target, r.stage, r.speed, r.status,"
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
        speed: str,
        *,
        params: str = "{}",
        started_at: str | None = None,
        secrets: Sequence[str] = (),
    ) -> int:
        cursor = self._conn.execute(
            "INSERT INTO scan_runs (target_id, stage, speed, status, started_at, params_json)"
            " VALUES (?, ?, ?, 'running', ?, ?)",
            (target_id, stage, speed, started_at or _utc_now(), redact(params, secrets)),
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
    ) -> int:
        self._conn.execute(
            "INSERT INTO subdomains"
            " (target_id, fqdn, state, confidence, source_count, is_wildcard,"
            "  first_seen_run, last_seen_run)"
            " VALUES (:target_id, :fqdn, COALESCE(:state, 'UNKNOWN'),"
            "  COALESCE(:confidence, 'LOW'), COALESCE(:source_count, 0),"
            "  COALESCE(:is_wildcard, 0), :run_id, :run_id)"
            " ON CONFLICT(target_id, fqdn) DO UPDATE SET"
            "  last_seen_run = excluded.last_seen_run,"
            "  state = COALESCE(:state, subdomains.state),"
            "  confidence = COALESCE(:confidence, subdomains.confidence),"
            "  source_count = COALESCE(:source_count, subdomains.source_count),"
            "  is_wildcard = COALESCE(:is_wildcard, subdomains.is_wildcard)",
            {
                "target_id": target_id,
                "fqdn": fqdn,
                "state": state,
                "confidence": confidence,
                "source_count": source_count,
                "is_wildcard": None if is_wildcard is None else int(is_wildcard),
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
        ips: Sequence[str] = (),
        tech: Sequence[str] = (),
        waf: str | None = None,
        tools: Sequence[str] = (),
        checked_at: str | None = None,
    ) -> int:
        cursor = self._conn.execute(
            "INSERT INTO host_status_history"
            " (subdomain_id, run_id, state, status_code, title, location, cnames_json,"
            "  dangling_cname, ips_json, tech_json, waf, tools_json, checked_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                subdomain_id,
                run_id,
                state,
                status_code,
                title,
                location,
                json.dumps(list(cnames)),
                dangling_cname,
                json.dumps(list(ips)),
                json.dumps(list(tech)),
                waf,
                json.dumps(list(tools)),
                checked_at or _utc_now(),
            ),
        )
        self._commit()
        return int(cursor.lastrowid or 0)

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
            "SELECT fqdn FROM subdomains"
            " WHERE target_id = (SELECT target_id FROM scan_runs WHERE id = ?)"
            "   AND first_seen_run = ?"
            " ORDER BY fqdn",
            (latest_run_id, latest_run_id),
        ).fetchall()
        return [str(row["fqdn"]) for row in rows]

    def diff_gone(self, previous_run_id: int, latest_run_id: int) -> list[str]:
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
