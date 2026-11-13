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
      subfinder.py assetfinder.py dns_python.py
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
  meta/    run metadata, summaries, reconkit.log
```

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
- API: `await pacer.before_tool()`, `await pacer.before_host()`, `pacer.order(items)`, `pacer.parallel_limit`, `pacer.tool_rate_args(tool)`.
- Randomness (`random.uniform`) and sleeping are **injected** (rng, sleep) so tests run instantly with a fake clock.
- Passive stages also use the Pacer (third-party APIs ban bursts).
- Per-source HTTP adapters share an async rate limiter (requests/second from the preset).

## 8. Consensus Engine

- **Discovery stages (subs, urls):** union of all adapters; `sources` list per item; confidence from source count.
- **Status stages (live, ports):** compare tools per host/port; agreement raises confidence; disagreement becomes `UNCONFIRMED`/`unconfirmed` and is stored.
- **Wildcard filter:** before accepting resolved subdomains, probe random non-existent names; if they resolve, mark results that match the wildcard answer as wildcard noise.
- Exact rules: docs/09_TOOL_CONTRACTS.md.

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
| WSL2 Kali, project in `~/reconkit` | Real Linux tools; fast disk; no CRLF/locking issues | Native Windows, `/mnt/c` |
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
| Tool missing | Skip, report `skipped (not installed)`; stage continues |
| Tool crashes or exits non-zero | Record `failed` with stderr summary; keep other results |
| Tool timeout | Kill process group, keep partial output if parseable, record `timeout` |
| HTTP source returns 429/5xx | Back off once, then `skipped (rate limited)` |
| No adapter available for a stage | Exit code 4 with install hint |
| `scope.yaml` missing/expired/mismatch | Refuse active stage, exit code 3 |
| DB locked or corrupt | Clear error; never silently continue; suggest `--db` path |
| Ctrl+C | Stop launching tools, kill children, mark run `interrupted`, exit 130 (resumable) |
| Network down | Passive HTTP sources fail fast with one summary line |

## 14. WSL2 Workflow Rules

- Repo at `~/reconkit` in Kali. Never `/mnt/c/...`.
- Code in VS Code (Remote-WSL). Terminal, venv, tools all inside Kali.
- Unit tests use fixtures and also pass on plain Windows (no tools needed).
- Real tool runs and integration smoke tests happen in WSL2 Kali.
