# Database

## 1. Engine

- **Database:** SQLite (single file, default `recon.db`, path from `config.yaml` or `--db`)
- **Hosting:** local file inside the project checkout (never a `/mnt/c` path)
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
  duration_s   REAL,                            -- wall seconds the tool itself worked; see section 5
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
  provenance    TEXT NOT NULL DEFAULT 'dns'    -- how the row entered: 'subs' or 'dns'
                CHECK (provenance IN ('subs','dns')),
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
  cnames_json  TEXT NOT NULL DEFAULT '[]',     -- CNAMEs observed in this pass
  dangling_cname TEXT,                         -- first outside-target CNAME on SHUT_DOWN
  detail       TEXT,                           -- bounded, redacted reason; see section 5
  ips_json     TEXT NOT NULL DEFAULT '[]',
  tech_json    TEXT NOT NULL DEFAULT '[]',
  waf          TEXT,                           -- CDN/WAF marker from httpx (Phase 2)
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
  seen    TEXT NOT NULL CHECK (seen IN ('open','closed')),   -- what that tool reported
  PRIMARY KEY (port_id, run_id, tool)
);
CREATE INDEX idx_port_sources_run ON port_sources(run_id);

CREATE TABLE urls (                       -- created now; populated only by the Phase 3 urls stage
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

CREATE TABLE findings (                   -- Phase 3: not created in this build
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

CREATE TABLE monitor_changes (            -- Phase 3: not created in this build
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

- Engine-created timestamps (`targets.created_at`, `scan_runs.started_at/finished_at`, `host_status_history.checked_at`) come from the injected `Engine(now=...)` source; `store.utc_now()` is the default and tests inject a fixed value.
- Resume reads `scan_runs` for the target (newest first), groups rows by the `scan_key` stored in `params_json`, and skips stages whose row is `completed` or `partial`. A row left `running` by a crash is marked `interrupted`; a fresh row is created for that stage. Completed-stage rows are never duplicated.

- `tool_runs.duration_s` is **wall seconds of the tool's own work**, not harness overhead, and the adapter owns the measurement on every outcome: ok, failed (429/5xx/timeout/refused), parse error and mock, because a failure still took real time. For binary adapters this is `run_exec`'s measured child wall clock (`ExecResult.duration_s`, taken with `time.monotonic()` around spawn/wait), which is the tool's real work time and therefore **counts as adapter-reported** - the binary adapters are already compliant. `HttpAdapter` and the three python adapters (`dnspython`, `pyprobe`, `pyscan`) measure their own work with `time.perf_counter()`.
- `Engine._run_one` stores the adapter's value whenever it is positive and **only** substitutes its own wall clock when the adapter reported none. `ToolResult.duration_s` is a plain `float` defaulting to `0.0`, so "none" is exactly `0.0`; any non-positive value is treated the same way (a frozen clock can only produce `0.0`, never a negative one). That one fallback site measures the whole call with `perf_counter`, so a stored value is never negative, an adapter-reported time is never overwritten, and `0.0` can only mean "neither the adapter nor the harness measured".
- Mock mode does no network or process work, so its duration is the measured wall clock of reading the fixture and parsing it: small (well under a second), positive in practice, and deliberately not a constant. It exists so `--mock` evidence and real runs share one column meaning.
- A subdomain/port/url is **one row per target**; repeat scans update `last_seen_run` and add source rows. `first_seen_run` never changes.
- `source_count` = distinct tools in `*_sources` for the latest run in which the item was seen.
- Confidence from `source_count`: >=3 HIGH, 2 MEDIUM, 1 LOW (thresholds from `config.yaml`); `UNCONFIRMED` when tools disagree.
- No DNS answer (NXDOMAIN) means `DEAD`, unless the previous known state was `ALIVE` or `DNS_ONLY`, which makes it `SHUT_DOWN`. This state rule is unconditional; agreeing checks affect `confidence` only.
- `fqdn` stored lowercase, no trailing dot, validated before insert.
- `provenance` records how a row entered `subdomains`: `subs` when a discovery tool first reported it, `dns` when a `dns`/`live`/`ports` pass created the row first. A `dns` row has no `subdomain_sources` rows and `source_count` 0, so it is not a discovery result. A later discovery sighting upgrades it to `subs`, and the upgrade is never reversed; `first_seen_run` still records when the row was created and never changes.
- `Store.scan_runs(target_id)` and `Store.subdomains(target_id)` are read queries used by engine resume; both return plain dictionaries and never expose the connection.
- `Store.host_rows(target_id)` returns the latest host state/confidence, latest status code, distinct source tools and open ports for the UI. `Store.recent_scan_runs(limit)` returns recent stage runs joined to target domains for `status`. `Store.completed_run_ids(target_id, stage)` returns completed/partial run ids newest-first for `diff`; `Store.latest_cnames(subdomain_id)` returns the CNAMEs from the latest status row; all four are read-only and never expose the connection.
- `host_status_history.cnames_json` is written for every persisted status row and is never NULL. `dangling_cname` is NULL unless the row is `SHUT_DOWN` and the stored CNAME points outside the target. When a later NXDOMAIN pass has no CNAME of its own, the engine reuses `Store.latest_cnames()` so the takeover-relevant warning survives the process restart.
- `host_status_history.detail` is the short, human-readable reason a pass could not reach a conclusive web answer: it carries the adapter's own error text (today `pyprobe`'s TLS failure text), so "expired certificate", "untrusted CA" and "handshake rejected" can be told apart later without probing again. It is written only when the pass's web evidence was an `UNKNOWN` record and the pass persisted a row; that row's state is either `UNKNOWN` or the previously established state the state rule kept, because an inconclusive pass never invents a new state. It is bounded to `DETAIL_MAX_CHARS` (200) characters, whitespace-collapsed to one line, and passed through the same `redact()` helper as `tool_runs.error` with the run's secret values before it is stored - storage never receives the raw string. `NULL` means no reason was reported; a later conclusive pass writes its own row with `NULL`, so an old reason never reappears on a newer row. It is read with the latest status row only (`Store.host_rows`) and is not part of the default human table.
- `host_status_history` gains one row per host per status pass, not one row per NXDOMAIN. From the `dns` stage, `RESOLVED` writes `DNS_ONLY` and `NXDOMAIN` writes `SHUT_DOWN`/`DEAD`; SERVFAIL, timeout, no answer and error write no `dns` row. `previous_state()` therefore always reads the outcome of the immediately preceding pass, including a `DNS_ONLY` pass, which is what keeps the two-consecutive-NXDOMAIN rule intact.

## 6. Diff Queries (core of `diff`)

- **NEW:** the host's first discovery sighting is the latest discovery run: `provenance = 'subs'` and no `subdomain_sources` row for any earlier run. A row created by `dns`/`live`/`ports` (`provenance = 'dns'`) is never NEW; the run in which a discovery tool first reports it is the first run at which it can appear as NEW. NEW is therefore not `first_seen_run = <latest run>`: a host the `dns` stage resolved before any tool returned it would otherwise be reported new.
- **GONE:** seen in the run before the previous one, **and** missing from both the previous run and the latest run - two consecutive misses (for discovery stages). This needs the three latest completed discovery run ids; with fewer than three, `gone` is empty. No schema change is needed: presence per run is already recorded in `subdomain_sources.run_id`, so the query is the old "seen in X, not in Y" test applied twice.
- **Pending (not a change):** seen in the previous run, not in the latest. Not reported as `GONE`; surfaced as `pending_gone` so the user can see the rule working. It is the previous single-miss query under a new name.
- **NOW DEAD:** the latest `host_status_history` row for the subdomain is `DEAD` and the previous known state was not `DEAD`.
- **State change:** compare last two `host_status_history` rows per subdomain.
- **Port change:** compare `ports.state` and presence between runs.
- **Same kind only:** `diff_new`/`diff_gone`/`diff_pending_gone` rely on per-run `*_sources` rows, so diffs compare discovery runs with discovery runs and port runs with port runs. A single-stage run must never be compared with a run that covered different stages, or every unrelated host would look GONE.
- **No new table or column:** `diff_gone(baseline, previous, latest)` and `diff_pending_gone(previous, latest)` are read queries over `subdomains` + `subdomain_sources`; the existing `run_id` column on `subdomain_sources` is the whole history they need.

## 7. Data Validation

- Pydantic models validate every record before it reaches the store.
- Store uses parameterized queries only (never string-built SQL).

## 8. Soft Delete

No soft delete. This build has no delete command; removing a target's rows is a manual database operation until a delete command is documented in docs/02.

## 9. Auditing

`scan_runs` and `tool_runs` are the audit trail (what ran, when, with which speed and result). No user accounts.

## 10. Sensitive Data

- Never stored: API keys, tokens, passwords, cookies.
- `tool_runs.error` and `host_status_history.detail` must be redacted (strip tokens and URLs with secrets) before saving; both go through `store.redact()` inside the store, never through a second implementation.
- Bulk writes use `with store.transaction():`, which commits once at the end and rolls back the whole block on any exception. Per-row methods join the outer transaction instead of committing individually; nested `transaction()` blocks join the outermost one.
- DB and workspace may contain target info: both are git-ignored.

## 11. Migrations

- `schema_version` table + ordered migration scripts in `core/store.py`.
- Schema version 2 adds `host_status_history.cnames_json` (`NOT NULL DEFAULT '[]'`) and `dangling_cname` (`NULL`). Existing rows therefore get an empty list and no dangling value, never NULL for the list.
- Schema version 4 adds `host_status_history.detail` (`TEXT`, nullable, no default), the bounded redacted reason described in section 5. It is additive: every existing row gets `NULL`, and nothing is rewritten.
- Schema version 3 adds `subdomains.provenance` (`TEXT NOT NULL DEFAULT 'dns'`, `CHECK (provenance IN ('subs','dns'))`) and back-fills existing rows: any row with a `subdomain_sources` entry becomes `subs`, every other row stays `dns`. Nothing is destroyed; `first_seen_run` is untouched.
- Every schema change: documented here, has a migration, has a test, never destroys existing data.

## 12. Seed Data

`tests/fixtures/` contains sample tool outputs. `--mock` loads them; there is no production seed data.
