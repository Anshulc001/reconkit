# Database

## 1. Engine

- **Database:** SQLite (single file, default `recon.db`, path from `config.yaml` or `--db`)
- **Hosting:** local file inside the project (`~/reconkit`, never `/mnt/c`)
- **Settings on connect:** `PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`
- **Access:** only through `core/store.py`. No SQL anywhere else.

## 2. Naming Conventions

- Tables: plural `snake_case`. Columns: `snake_case`.
- Primary keys: `id INTEGER PRIMARY KEY`.
- Foreign keys: `<singular>_id` (example `target_id`).
- Timestamps: ISO-8601 UTC text (`2026-11-13T10:15:00Z`), columns `*_at`.
- Enumerations stored as text in `CHECK` constraints.
- JSON data stored as text in columns ending `_json`.

## 3. Tables

```sql
CREATE TABLE schema_version (version INTEGER NOT NULL);

CREATE TABLE targets (
  id         INTEGER PRIMARY KEY,
  domain     TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE scan_runs (
  id          INTEGER PRIMARY KEY,
  target_id   INTEGER NOT NULL REFERENCES targets(id),
  stage       TEXT NOT NULL,                 -- subs|dns|live|ports|tech|urls|vulns|workflow
  speed       TEXT NOT NULL CHECK (speed IN ('slow','normal','fast')),
  status      TEXT NOT NULL CHECK (status IN ('running','completed','partial','failed','interrupted')),
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
  error        TEXT                            -- short, no secrets
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

CREATE TABLE host_status_history (
  id           INTEGER PRIMARY KEY,
  subdomain_id INTEGER NOT NULL REFERENCES subdomains(id),
  run_id       INTEGER NOT NULL REFERENCES scan_runs(id),
  state        TEXT NOT NULL CHECK (state IN ('ALIVE','DNS_ONLY','SHUT_DOWN','DEAD','UNKNOWN')),
  status_code  INTEGER,
  title        TEXT,
  ips_json     TEXT NOT NULL DEFAULT '[]',
  tech_json    TEXT NOT NULL DEFAULT '[]',
  waf          TEXT,                           -- CDN/WAF marker from httpx (Phase 2)
  tools_json   TEXT NOT NULL DEFAULT '[]',
  checked_at   TEXT NOT NULL
);
CREATE INDEX idx_hsh_sub ON host_status_history(subdomain_id, id);

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
  seen    TEXT NOT NULL CHECK (seen IN ('open','closed')),   -- what that tool reported
  PRIMARY KEY (port_id, run_id, tool)
);

CREATE TABLE urls (                       -- Phase 3
  id            INTEGER PRIMARY KEY,
  target_id     INTEGER NOT NULL REFERENCES targets(id),
  url           TEXT NOT NULL,
  category      TEXT,                     -- js|json|html|param|other
  patterns_json TEXT NOT NULL DEFAULT '[]',   -- xss|sqli|ssrf|lfi|redirect candidates
  source_count  INTEGER NOT NULL DEFAULT 0,
  first_seen_run INTEGER NOT NULL REFERENCES scan_runs(id),
  last_seen_run  INTEGER NOT NULL REFERENCES scan_runs(id),
  UNIQUE (target_id, url)
);

CREATE TABLE findings (                   -- Phase 3
  id            INTEGER PRIMARY KEY,
  target_id     INTEGER NOT NULL REFERENCES targets(id),
  subdomain_id  INTEGER REFERENCES subdomains(id),
  kind          TEXT NOT NULL,            -- takeover|exposure|misconfig|...
  severity      TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  title         TEXT NOT NULL,
  evidence      TEXT,
  template_id   TEXT,
  tool          TEXT NOT NULL,
  first_seen_run INTEGER NOT NULL REFERENCES scan_runs(id),
  last_seen_run  INTEGER NOT NULL REFERENCES scan_runs(id)
);

CREATE TABLE monitor_changes (            -- Phase 3
  id         INTEGER PRIMARY KEY,
  target_id  INTEGER NOT NULL REFERENCES targets(id),
  run_id     INTEGER NOT NULL REFERENCES scan_runs(id),
  change     TEXT NOT NULL,               -- new|now_alive|went_down|now_dead|port_opened|port_closed
  subject    TEXT NOT NULL,
  detail     TEXT,
  created_at TEXT NOT NULL
);
```

## 4. Relationships

- `targets` 1-N `scan_runs`, `subdomains`, `urls`, `findings`
- `scan_runs` 1-N `tool_runs`
- `subdomains` 1-N `subdomain_sources`, `host_status_history`, `ports`
- `ports` 1-N `port_sources`

## 5. Rules and Constraints

- A subdomain/port/url is **one row per target**; repeat scans update `last_seen_run` and add source rows. `first_seen_run` never changes.
- `source_count` = distinct tools in `*_sources` for the latest run in which the item was seen.
- Confidence from `source_count`: >=3 HIGH, 2 MEDIUM, 1 LOW (thresholds from `config.yaml`); `UNCONFIRMED` when tools disagree.
- No DNS answer (NXDOMAIN) means `DEAD`, unless the previous known state was `ALIVE` or `DNS_ONLY`, which makes it `SHUT_DOWN`. This state rule is unconditional; agreeing checks affect `confidence` only.
- `fqdn` stored lowercase, no trailing dot, validated before insert.

## 6. Diff Queries (core of `diff`)

- **NEW:** `first_seen_run = <latest run>`.
- **GONE:** seen in previous run, not in latest (for discovery stages).
- **NOW DEAD:** the latest `host_status_history` row for the subdomain is `DEAD` and the previous known state was not `DEAD`.
- **State change:** compare last two `host_status_history` rows per subdomain.
- **Port change:** compare `ports.state` and presence between runs.

## 7. Data Validation

- Pydantic models validate every record before it reaches the store.
- Store uses parameterized queries only (never string-built SQL).

## 8. Soft Delete

No soft delete. `db delete -d X` removes a target and its rows after confirmation.

## 9. Auditing

`scan_runs` and `tool_runs` are the audit trail (what ran, when, with which speed and result). No user accounts.

## 10. Sensitive Data

- Never stored: API keys, tokens, passwords, cookies.
- `tool_runs.error` must be redacted (strip tokens and URLs with secrets) before saving.
- DB and workspace may contain target info: both are git-ignored.

## 11. Migrations

- `schema_version` table + ordered migration functions in `core/store.py`.
- Every schema change: documented here, has a migration, has a test, never destroys existing data.

## 12. Seed Data

`tests/fixtures/` contains sample tool outputs. `--mock` loads them; there is no production seed data.
