# Architecture

## 1. System Overview

reconkit is a single-process Python CLI. It does not reimplement recon: it **orchestrates** tools through small adapters, merges their output, scores confidence, and stores state in SQLite. External tools run as subprocesses; HTTP and Python adapters need no binary.

## 2. Architecture Pattern

- **Pattern:** Layered modular monolith with a plugin-style adapter layer.
- **Reason:** One local user, no server. Plugins keep each tool isolated so a new tool is one file.

## 3. Technology Stack

| Area | Choice |
|---|---|
| Language | Python 3.11+ |
| CLI | Typer |
| Terminal UI | Rich |
| Schemas | Pydantic v2 |
| Concurrency | asyncio (through the Pacer) |
| HTTP | httpx (Python library, async) |
| DNS | dnspython |
| Config | PyYAML (`safe_load` only) |
| Storage | SQLite (stdlib `sqlite3`) + workspace files |
| Tests / lint / types | pytest, ruff, mypy |
| Hosting | none (local CLI) |

## 4. Layers and Responsibilities

```
CLI (Typer)            parse flags, load config, call engine, render output
Engine (asyncio)       stage pipeline, adapter selection, pacing, merge, confidence, resume
Adapters (per tool)    check_installed / build_command / run / parse_output -> normalized records
Core services          scope gate, runner (subprocess), pacer, store (SQLite), workspace, installer, doctor
```

- **CLI:** no business logic. Validates input, calls the engine, prints results.
- **Engine:** picks adapters for a stage, asks the Pacer when to start each, collects `ToolResult`s, merges and scores, writes through the store.
- **Adapters:** know only one tool or source. They never touch the DB, the scope gate, or the UI.
- **Core:** shared, tested utilities.

## 5. Project Structure

```
reconkit/
  AGENTS.md  SETUP.md  README.md
  config.yaml  tools.yaml  scope.example.yaml  .env.example
  pyproject.toml
  docs/
  scripts/bootstrap.sh
  src/reconkit/
    cli.py            # Typer app, command wiring only
    config.py         # load config.yaml, merge flags
    models.py         # Pydantic models, enums (docs/09)
    errors.py         # exception types (docs/06 §6)
    engine.py         # stage orchestration + consensus
    ui.py             # Rich console, tables, theme, JSON output
    doctor.py
    core/
      runner.py       # run_exec(argv, timeout, ...) - the only subprocess entry
      pacing.py       # Pacer: delays, jitter, shuffling, parallel limits
      scope.py        # scope.yaml loader + gate
      store.py        # SQLite access + diff queries
      workspace.py    # workspaces/<target>/... raw files
      wildcard.py     # wildcard DNS detection
    adapters/
      base.py         # BaseToolAdapter
      registry.py     # loads tools.yaml, maps names to adapter classes
      crtsh.py certspotter.py otx.py hackertarget.py
      subfinder.py assetfinder.py dnspython.py
      pyprobe.py httpx_tool.py pyscan.py naabu.py
    installer/
      registry.py github_release.py go_install.py apt.py pipx.py verify.py
  tests/
    fixtures/<tool>/  conftest.py  test_*.py
  workspaces/         # generated (git-ignored)
```

Generated workspace, one directory per target (git-ignored):

```
workspaces/<domain>/
  subs/    raw output from subdomain sources
  live/    raw probe output
  ports/   raw scanner output
  urls/    raw URL/crawl output (Phase 3)
  tech/    raw technology/WAF output (Phase 3)
  meta/    run metadata and summaries
```

### Workspace API (`core/workspace.py`)

- `Workspace.create(root, target, secrets=...)` validates `target` with `validate_target()`, creates `workspaces/<domain>/` and exactly the six stage directories above (mode `0700`), and is idempotent.
- `workspace.path(stage, filename)` accepts only a documented stage and one plain filename. Traversal, absolute/UNC paths, `..`, trailing dot/space, hidden names and Windows device names (`CON`, `NUL`, `COM1`, ...) are rejected with `ValueError`. A target whose first label is a device name is rejected too, because Windows cannot create that directory.
- `workspace.write(stage, filename, text)` passes `text` through `store.redact()` with the run's secrets before any bytes reach disk, then writes a temporary file in the same directory and `os.replace()`s it (mode `0600`). A failure leaves the destination untouched and no temporary file behind. Writing the same filename again replaces it atomically.
- Raw tool output uses `subs`, `live`, `ports`, `urls` or `tech`; run metadata and summaries use `meta`. No other directory is created.

### Engine API (`engine.py`)

- `Engine.open(config, *, db_path=..., scope_path=..., env_file=..., ...)` is the CLI-facing factory: it creates the `Store`, loads optional `.env` values inside the engine, and returns an `Engine`. `close()` closes the store. The constructor remains injectable for tests.
- `Engine(config, store, now=...).run(target, ScanOptions(...))` runs the selected stages in the fixed order `subs, dns, live, ports, tech, urls, vulns`. `ScanOptions` carries `stages`, `tools`, `exclude`, `include_noisy`, `active`, `no_keys`, `mock`, `speed`, `phase_timeout`, `min_sources` and `resume`.
- `Engine.host_rows(target_id)` returns typed `HostSnapshot` rows (fqdn, state, confidence, sources, status code, open ports) for the UI; `Engine.diff(target)` returns the latest two same-kind run comparison; `Engine.recent_runs(limit)` returns recent stage runs for `status`.
- `now` is an injected timestamp source (default `store.utc_now`) used for `targets.created_at`, `scan_runs.started_at/finished_at` and `host_status_history.checked_at`; tests pass a fixed clock. The engine never calls `datetime.now()` or `time.time()` directly.
- `ScanSummary.exit_code` is a typed `ExitCode` (`0` success, `1` unexpected, `2` usage, `3` scope, `4` no usable tool, `5` partial, `130` interrupted). The engine never calls `sys.exit()`; the CLI maps the value.
- Tools are selected from `tools.yaml` once per run. A `--tools` name must exist; `intrusive` tools are refused, `opt_in` tools need `--include-noisy` or an explicit `--tools`, and `--exclude` always wins. Every selected or skipped tool gets a `tool_runs` row with its redacted error.
- Active tools run only when `--active` is set **and** `require_active()` passes. Discovered hosts are revalidated and re-checked against scope before they reach an active `RunContext`; dropped hosts are reported, never probed. A missing/unsafe scope skips the active tools instead of raising out of the stage.
- Each tool's `RunContext.env` contains only the env names in that tool's `keys` (none with `--no-keys`). One fresh `RateLimiter` is built per stage; `Pacer.reset()` runs at stage start; `slow` runs tools one at a time, other speeds use `pacer.parallel_limit()`.
- `--mock` reads only the fixtures, never calls `check_installed()`, the network or a subprocess. Stage asset writes are batched with `store.transaction()`; tool runs are recorded individually.

## 6. Data Flow (example: `reconkit live -d example.com --active`)

1. CLI parses flags (`--speed slow` default) and loads `config.yaml`.
2. Scope gate: `scope.yaml` must exist, not be expired, allow active, and match `example.com`; exit code 3 otherwise.
3. Engine reads known subdomains for the target from SQLite; each host is checked against scope again (out-of-scope removed).
4. Engine selects adapters for stage `live` that are installed and allowed by tier/flags.
5. Pacer orders hosts (shuffled in slow/normal) and schedules tools: one at a time with random delays in slow mode.
6. Each adapter runs (subprocess via `runner` or Python), returns `ToolResult` with normalized records.
7. Engine merges records per host, records which tools reported what, computes state and confidence, handles disagreements.
8. Store writes `scan_runs`, `tool_runs`, `host_status_history`, updates `subdomains`.
9. Workspace writes raw output files; UI prints the table and tool summary; exit code reflects success/partial.

## 7. Pacing Engine (`core/pacing.py`)

- Single `Pacer` object per run, built from the chosen speed preset plus `--delay` overrides.
- API: `await pacer.before_tool(mode)`, `await pacer.before_host()`, `pacer.order(items, kind="host"|"port")`, `pacer.parallel_limit(mode)`, `pacer.tool_rate_args(tool, mode)`, `pacer.next_pause_range(mode)` for the progress line, `pacer.reset()` per stage.
- `tool_rate_args(tool, mode)` uses `passive.requests_per_second` for passive tools and `active.requests_per_second` for active ones; `nmap -T<n>` and `masscan --max-rate` always use the active preset values. Whole-number rates print without `.0`.
- `before_host()` spaces **host dispatches** in active stages, and is awaited by the adapters that issue one request or connection per host: `pyscan` (a connect batch per host) and `pyprobe` (an HTTP probe per host). The pause is `active.host_delay` from the speed preset; the first host of a stage does not wait. `pyprobe` dispatches hosts sequentially when `parallel_limit("active")` is `1` (the `slow` preset), so the pause falls between real dispatches; at higher limits it keeps parallel dispatch (normal `host_delay` is `[0, 2]`, fast is `[0, 0]`).
- One-shot binary tools (`httpx`, `naabu`) are **exempt** from `before_host()`: they receive the whole host list in a single process and pace themselves through `-rl`/`-rate` from `tool_rate_args()`. No adapter may use `before_host()` as request pacing; it only spaces host dispatches.
- Randomness (`random.uniform`) and sleeping are **injected** (rng, sleep) so tests run instantly with a fake clock.
- Passive stages also use the Pacer (third-party APIs ban bursts).
- Per-source HTTP adapters share an async rate limiter (requests/second from the preset).

## 8. Consensus Engine

- **Discovery stages (subs, urls):** union of all adapters; `sources` list per item; confidence from source count.
- **Status stages (live, ports):** compare tools per host/port; agreement raises confidence; disagreement becomes `UNCONFIRMED`/`unconfirmed` and is stored.
- **Wildcard filter:** before accepting resolved subdomains, probe `wildcard_check.probes` random non-existent names with the DNS adapter's resolver (through the run's limiter); if they resolve, mark hosts whose addresses or CNAMEs match the wildcard answer as wildcard noise. Detection returns `present`, `none` or `unknown`: `none` only when every probe is NXDOMAIN, `unknown` when no probe resolved and at least one timed out, SERVFAILed, returned no answer or errored. `unknown` is never treated as `none`; the engine warns and skips the filter. `wildcard_check.enabled: false` skips the filter entirely, and the filter never runs under `--mock` (mock reads fixtures only).
- **Host-state machine (implemented in `engine.py`):** `previous` is the last `host_status_history.state` row (or `None`). Evidence is the set of live-tool states plus the DNS signal (`resolved`, `nxdomain`, `uncertain`, `absent`).

| previous | web ALIVE | DNS resolved, no web ALIVE | DNS NXDOMAIN | timeout/SERVFAIL/no answer | no evidence |
|---|---|---|---|---|---|
| `None` / `UNKNOWN` | `ALIVE` | `DNS_ONLY` | `DEAD` | `UNKNOWN` (warning) | `UNKNOWN` |
| `ALIVE` | `ALIVE` | `DNS_ONLY` | `SHUT_DOWN` | `ALIVE` kept (warning) | `ALIVE` kept |
| `DNS_ONLY` | `ALIVE` | `DNS_ONLY` | `SHUT_DOWN` | `DNS_ONLY` kept (warning) | `DNS_ONLY` kept |
| `SHUT_DOWN` | `ALIVE` | `DNS_ONLY` | `DEAD` | `SHUT_DOWN` kept (warning) | `SHUT_DOWN` kept |
| `DEAD` | `ALIVE` | `DNS_ONLY` | `DEAD` | `DEAD` kept (warning) | `DEAD` kept |

- Only NXDOMAIN can produce `DEAD`; timeout, SERVFAIL, no answer and resolver/tool errors keep the previous state and add a warning. A previously `ALIVE`/`DNS_ONLY` host therefore needs **two consecutive NXDOMAIN observations** before `DEAD`: the first becomes `SHUT_DOWN`, the second `DEAD`. A host with no previous state has no established service to confirm, so its first NXDOMAIN is `DEAD`. `SHUT_DOWN` is takeover-relevant: the engine warns when the host's known CNAME points outside the target. The CNAME set and the first outside-target CNAME are persisted on the status row, and a later NXDOMAIN with no CNAME of its own reuses the latest stored CNAME before deciding the warning; this keeps the evidence across process restarts. `host_status_history` is written only by the `dns` and `live` stages. The `dns` stage writes one status row per host it has a signal for, not only on NXDOMAIN: `RESOLVED` persists `DNS_ONLY` (carrying the CNAME evidence forward) and `NXDOMAIN` persists `SHUT_DOWN`/`DEAD`. A host with no DNS record (SERVFAIL, timeout, no answer, error) writes no `dns` row, and a live stage that consumes the deferred DNS results writes the row instead.
- **Wildcard API:** `WildcardDetector(probe=..., rng=..., probes=...)` is built per run. `probe` is the DNS adapter's `resolve_host` bound to the run context, so probes reuse that resolver and limiter; `rng` is injected; `probes` comes from `wildcard_check.probes`. `await detect(target)` returns `WildcardResult`, and `result.matches(ips=..., cnames=...)` decides `is_wildcard`.
- Exact rules: docs/09_TOOL_CONTRACTS.md.

## 8b. UI API (`ui.py`)

- `ui.render(summary, hosts, *, json_output=False, silent=False, no_color=False, stdout=None, stderr=None, console=None) -> int` writes the human tables/progress to stderr or the single JSON document to stdout, then returns `int(summary.exit_code)`.
- `ui.render_message(...)` writes one non-error line; `ui.render_diff(...)` and `ui.render_status(...)` render the `diff`/`status` documents to stderr or stdout JSON.
- `HostRow` is the plain input for the host table/JSON: `fqdn`, `state`, `confidence`, `sources`, `status_code`, `ports`. The engine or CLI supplies these precomputed values; `ui.py` never computes confidence or state.
- `ui.py` imports only Rich, the standard library and shared output types; it never imports `core.store`, `core.scope`, adapters or `cli.py`.

## 9. Dependency Rules

- CLI -> Engine -> (Adapters, Core). Never the reverse.
- Adapters must not import `store`, `scope`, `ui`, or `cli`.
- Only `core/runner.py` imports `subprocess`.
- Only `core/store.py` imports `sqlite3`.
- Only `ui.py` prints to the terminal (adapters and engine return data or raise).
- Registry (`tools.yaml`) is the only source of tool names, install sources and tiers.

## 10. Key Technical Decisions

| Decision | Reason | Alternative rejected |
|---|---|---|
| Python | Fast to write/fix with AI agents; simple parsing; Kali ships Python | Go (AutoAR's language): single binary, but slower to extend with AI for this use case |
| SQLite + workspace files | Diffing, resume, queries; plus human-browsable raw output | Flat files only (no history), Postgres (too heavy) |
| Native Linux checkout (Kali/Ubuntu), separate Windows checkout | Real Linux tools; fast disk; no CRLF/locking issues | WSL2-only workflow; `/mnt/c` |
| Slow-by-default pacing | Avoids API bans, WAF blocks, rate-limit violations | Max parallelism |
| Adapter + registry | Add a tool without touching core | Hard-coded pipelines |
| Own `~/.reconkit/bin` | No sudo, no global breakage, correct `httpx` | System PATH only |

## 11. Performance

- Slow mode trades time for politeness; progress and ETA are always shown.
- Bulk DB writes in one transaction per stage.
- Subprocess output streamed line by line (no loading huge output in memory).

## 12. Scalability

Single machine, thousands of hosts per target. Beyond that is out of scope (see PRD non-goals).

## 13. Failure Scenarios

| What if | Expected behavior |
|---|---|
| Tool missing | Skip, report `skipped (not installed)`; stage continues. This is the selection-time rule; a binary that was found at selection but cannot be spawned at run time is `failed` with its message instead |
| Tool crashes or exits non-zero | Record `failed` with stderr summary; keep other results |
| Tool timeout | Kill process group, keep partial output if parseable, record `timeout` |
| HTTP source returns 429/5xx | `failed` result carrying the status; no retry (only a connection error retries once) |
| No adapter available for a stage | Exit code 4 with install hint |
| `scope.yaml` missing/expired/mismatch | Refuse active stage, exit code 3 |
| DB locked or corrupt | Clear error; never silently continue; suggest `--db` path |
| Ctrl+C | Stop launching new tools, mark the stage run `interrupted`, exit 130 (resumable); a child already running is not explicitly killed in this build |
| Network down | Passive HTTP sources fail fast with one summary line |

## 14. Linux Workflow Rules

- Repo in a native Linux checkout (current path in PROGRESS "Environment"). Never `/mnt/c/...`.
- Terminal, venv and tools all live in that Linux checkout; VS Code may attach to it from Windows.
- Unit tests use fixtures and also pass on plain Windows (no tools needed).
- Real tool runs and integration smoke tests happen on Kali/Ubuntu.
- The current path, environment and check commands live in PROGRESS "Environment".
