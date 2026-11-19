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
| Concurrency | asyncio (no artificial throttling) |
| HTTP | httpx (Python library, async) |
| DNS | dnspython |
| Config | PyYAML (`safe_load` only) |
| Storage | SQLite (stdlib `sqlite3`) + workspace files |
| Tests / lint / types | pytest, ruff, mypy |
| Hosting | none (local CLI) |

## 4. Layers and Responsibilities

```
CLI (Typer)            parse flags, load config, call engine, render output
Engine (asyncio)       stage pipeline, adapter selection, merge, confidence, resume
Adapters (per tool)    check_installed / build_command / run / parse_output -> normalized records
Core services          scope gate, runner (subprocess), store (SQLite), workspace, toolcheck, doctor
```

- **CLI:** no business logic. Validates input, calls the engine, prints results. It configures console redaction once per process (`configure_redaction()` from `core/store.py`, seeded from `.env` the same way `Engine.open` loads it) and prints every error line through `redact()`, including the `-v` traceback (section 5, "Redaction API").
- **Engine:** picks adapters for a stage, starts them together, collects `ToolResult`s, merges and scores, writes through the store.
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
      scope.py        # scope.yaml loader + gate
      store.py        # SQLite access + diff queries + redact()/configure_redaction()
      workspace.py    # workspaces/<target>/... raw files
      wildcard.py     # wildcard DNS detection
      toolcheck.py    # installed_copy()/installed_version() - read-only tool probe
    adapters/
      base.py         # BaseToolAdapter
      registry.py     # loads tools.yaml, maps names to adapter classes
      crtsh.py certspotter.py otx.py hackertarget.py
      subfinder.py assetfinder.py dnspython.py
      pyprobe.py httpx_tool.py pyscan.py naabu.py
  # installer/ was deleted on 2026-11-17 (docs/MASTER_PLAN.md D4)
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
- `workspace.path(stage, filename)` accepts only a documented stage and one plain filename. Traversal, absolute/UNC paths, `..`, trailing dot/space and hidden names are rejected with `ValueError`.
- `workspace.write(stage, filename, text, *, secrets=None, max_bytes=MAX_OUTPUT_BYTES)` passes `text` through `store.redact()` with the run's secrets before any bytes reach disk, caps the result at `max_bytes` UTF-8 bytes, then writes a temporary file in the same directory and `os.replace()`s it (mode `0600`). A failure leaves the destination untouched and no temporary file behind. Writing the same filename again replaces it atomically. `MAX_OUTPUT_BYTES` is `core/runner.MAX_OUTPUT_BYTES` (1,000,000), the same limit `run_exec` applies to a child's output, so the cap has one definition and needs no config key. A longer text is cut at the cap, never dropped and never written unbounded; a multi-byte character split by the cut is dropped rather than written as a broken byte sequence. Redaction happens before the cap, so a secret that straddles the cut cannot survive as a prefix.
- Raw adapter output is written by the engine as `<stage>/<run_id>-<tool>.txt`: one file per executed tool per stage run (`run_id` is the `scan_runs` id), so two tools in one stage and the same tool in two runs never collide, and a rerun never overwrites an earlier run's evidence. The `dns` stage has no raw directory of its own - the workspace keeps exactly the six documented directories - so its files go to `meta/`, which also holds `vulns`/`shots` output when those phases exist. `write` returns the path and the engine stores it unchanged in `ToolResult.raw_path`, so it is relative while `workspace_dir` is relative (the shipped `config.yaml` value) and absolute when the caller passed an absolute root. The path is not shown in the human tables (docs/02) but does appear in `--json` under `stages[].results`, because that object is the docs/09 `ToolResult` schema.
- Raw tool output uses `subs`, `live`, `ports`, `urls` or `tech`; run metadata and summaries use `meta`. No other directory is created.

### Saved reports (`results/`, interactive mode only)

```
<results_dir>/<domain>/<YYYYmmddTHHMMSSZ>/
  report.txt  report.json
```

- `results_dir` is an `AppConfig` key (default `results`) read from `config.yaml`
  and overridden by `--config` like every other key. It is deliberately **not**
  inside `workspaces/<target>/`: that tree is fixed at six stage directories, and
  adding a seventh would break the `Workspace` contract above.
- `ui.report_directory(results_root, domain, run_at)` chooses the folder name from
  the run clock (UTC, second resolution) and, if that name already exists,
  appends `-2`, `-3`, ... so a previous run's folder is never reopened. It is the
  only place that names a report folder.
- `ui.write_field_report(directory, target, rows, fields, run_at)` writes both
  files atomically (temporary file plus `os.replace`, mode `0600`) and returns the
  paths. `rows` are the engine's `HostSnapshot` values already filtered to the
  selected fields; the writer never computes a state, a confidence or a value.
  A field the run did not observe is written as `not applicable`, never invented.
- Both helpers live in `ui.py` because they are output, not orchestration: `ui.py`
  already owns every rendering of the same snapshot rows and imports only the
  standard library, Rich and shared output types. A new module would have meant a
  new file outside docs/03, which G3 forbids.
- **Both paths call them** (changed 2026-11-18, D20). The interactive path
  (docs/02 section 2b) passes the fields the operator picked; a `-d`/`-l` run has
  no question to answer and passes every `REPORT_FIELDS` key. Until this change
  the call was gated on the interactive plan, so a flagged run saved no report at
  all - the inconsistency the owner reported from a real scan.

### Engine API (`engine.py`)

- `Engine.open(config, *, db_path=..., scope_path=..., env_file=..., ...)` is the CLI-facing factory: it creates the `Store`, loads optional `.env` values inside the engine, and returns an `Engine`. `close()` closes the store. The constructor remains injectable for tests.
- `Engine(config, store, now=...).run(target, ScanOptions(...))` runs the selected stages in the fixed order `subs, dns, live, ports, tech, urls, url_probe, shots, vulns` (D19, D23). `ScanOptions` carries `stages`, `tools`, `exclude`, `include_noisy`, `active`, `no_keys`, `mock`, `phase_timeout`, `min_sources` and `resume` (there is no `speed`; see section 7).
- `Engine(..., progress=callable)` is an optional injected reporting callback. The
  engine calls it with one short string at stage start, once per finished tool and
  once per finished stage; it never prints, formats or decides anything. `None`
  (the default, and what every test uses) makes it a no-op, so the engine's
  behaviour is unchanged when it is absent. `Engine.open(...)` forwards the same
  argument from the CLI.
- `Engine(..., activity=callable)` is a second, **transient** channel (added
  2026-11-18). While a stage runs, the engine calls it with a replaced-in-place
  snapshot - `<stage>: <done>/<total> tool(s) done, <n>s elapsed - running: a, b`
  - whenever a tool starts or finishes. Unlike `progress`, these lines are not
  meant to be kept: the CLI renders them as one spinner line on stderr and the
  tests treat `None` as a no-op. `done` is only advanced by a tool that actually
  finished, so a phase-timeout cancellation still leaves it out and gets its
  `timeout` row.
- `Engine.host_rows(target_id)` returns typed `HostSnapshot` rows (fqdn, state, confidence, sources, status code, open ports) for the UI; `HostSnapshot`
  also carries the extra stored values the interactive report menu needs -
  `source_count`, `ips`, `title`, `location`, `tech` - read from the existing
  `subdomains`/`host_status_history` columns. They are additive with defaults, so
  the human table and the `--json` document stay byte-identical. `Engine.diff(target)` returns the latest two same-kind run comparison; `Engine.recent_runs(limit)` returns recent stage runs for `status`.
- `now` is an injected timestamp source (default `store.utc_now`) used for `targets.created_at`, `scan_runs.started_at/finished_at` and `host_status_history.checked_at`; tests pass a fixed clock. The engine never calls `datetime.now()` or `time.time()` directly.
- **Tool status semantics (R8, 2026-11-18).** `ToolStatus` has five members: `ok`, `gap`, `skipped`, `failed`, `timeout`. `gap` is what the ruling calls **degraded** - a tool that ran and whose *upstream* refused it (HTTP 429, rate limit, quota, `too many requests`, `api count exceeded`, an upstream 5xx in an HTTP context). One classifier, `adapters.base.classify_external_gap()`, owns the signature list; `HttpAdapter`, the quota parsers and `BaseToolAdapter.run` all call it. A gap is excluded from the failure total, so a run whose only failures are gaps exits `0` with `completion: complete_with_gaps` and a gap entry naming the service message; it is stored as `tool_runs.status = 'gap'` (schema 8). A **local** fault - missing binary, crash, unparseable output, 401/403 - stays `failed` and still yields exit `5`. A new member was deliberately not added: `degraded` and `gap` would be the same state under two names, and a sixth `tool_runs.status` value would force another CHECK rebuild for no gain.
- **No input is a skip (R10, 2026-11-19).** A stage tool whose required input list is empty is recorded `skipped` with the detail `no input hosts`, and the adapter is never invoked: `Engine._run_one` checks `adapter.stage in HOST_INPUT_STAGES` (`live`, `tech`, `urls`, `vulns`) against an empty `RunContext.hosts` before calling `run()`. `subs` and `dns` always receive the target, and `live` receives `[target, *discovered]`, so the rule can never skip a tool that legitimately works on the apex; `ports` already skips its whole stage when nothing is alive. A `skipped` result counts as complete (`_completed()`), never as a failure, and a stage whose results are *all* skips becomes a `CompletionGap(stage, "no input hosts", n)` - so a scan whose discovery found nothing alive exits `0` with the stage named in the gaps block instead of reporting nine broken tools and `5`. One real failure anywhere still gives `5`.
- `ScanSummary.exit_code` is a typed `ExitCode` (`0` success, `1` unexpected, `2` usage, `3` scope, `4` no usable tool, `5` partial, `130` interrupted). The engine never calls `sys.exit()`; the CLI maps the value. `_exit_code()` is the single decision site; a requested stage that executed zero tools is one more source of `5` **unless** every one of its skips was an absence (`no adapter yet (phase N)`, `not installed`), in which case `Engine._completion_gaps()` records a `CompletionGap(stage, reason, skipped)` on `ScanSummary.gaps` and the run keeps `0` (docs/02 section 6). `ScanSummary.mode` and `ScanSummary.completion_status` (`complete` / `complete_with_gaps`) serve the gaps block and the `--json` `completion` object; `ui.render_completion_gaps()` prints the block on stderr and prints nothing when `gaps` is empty.
- Tools are selected from `tools.yaml` once per run. A `--tools` name must exist; `intrusive` tools are refused, `opt_in` tools need `--include-noisy` or an explicit `--tools`, and `--exclude` always wins. Every selected or skipped tool gets a `tool_runs` row with its redacted error.
- Active tools run only when `--active` is set. **A scope file is optional:** when the resolved path (default `./scope.yaml`, `--scope` overrides) does not exist, active and full scanning run unrestricted against the operator's targets and the hosts discovered under them - no scope object is constructed and nothing is derived from the target to restrict it (docs/05 rule 2). When a scope file **is** present, `require_active()` runs unchanged: discovered hosts are revalidated and re-checked against scope before they reach an active `RunContext`; dropped hosts are reported, never probed; and a denial skips the active tools (exit 3) instead of raising out of the stage. The file is only read.
- Each tool's `RunContext.env` contains only the env names in that tool's `keys` (none with `--no-keys`). Every tool selected for a stage starts together under `asyncio.gather`; there is no pacer, semaphore, rate limiter, delay or shuffling (section 7, 2026-11-17).
- `--mock` reads only the fixtures, never calls `check_installed()`, the network or a subprocess. Stage asset writes are batched with `store.transaction()`; tool runs are recorded individually.
- `_persist_stage` routes per stage: `subs` (discovery), `dns`, `live`, `ports`, `tech` and `urls`. `url_probe` has no adapter and therefore no `_persist_stage` branch: `Engine._run_url_probe()` writes `urls.status_code` itself (D23, docs/04 section 5). It runs through the same active-stage scope gate as every other active stage and creates its own tool-less `scan_runs` row, so it appears in `stages` and in a `--resume` plan. The `tech` branch is `_persist_tech`: it merges the pass's `tech`/`waf` into each host's newest `host_status_history` row through `Store.update_host_extras` and never appends a status row, because a technology match is not a liveness verdict (docs/04 section 5, D11).
- A binary child that takes its input list on stdin gets it through `runner.run_exec(..., stdin_text=...)`, fed from its own thread; the adapter side is the `stdin_text(ctx)` hook (httprobe, waybackurls). Everything else still passes argv lists and nothing else (docs/05 rule 1).

- `_run_one` writes the raw-output file for every executed tool, whatever its status: it takes the adapter's `ToolResult.raw_text` (docs/09 section 3), writes it through `Workspace.write` - redacted with the run's secrets, capped at `MAX_OUTPUT_BYTES`, into the stage's directory - and sets `raw_path` on the result only after the write returns. An empty capture still produces an empty file, so "one executed tool = one file" holds for a crash, a timeout and a quiet tool alike. A workspace write that raises (disk full, permissions, a rejected filename) is contained: the tool result and its `tool_runs` row are recorded unchanged and `raw_path` stays `None`. Raw capture is a diagnostic side channel; it never changes a status, an error or an exit code.

### Redaction API (`core/store.py`)

- There is exactly one redaction implementation: `core/store.py` owns `REDACTED`, the compiled pattern list (`Authorization`/`Cookie` headers, `Bearer`, URL credentials, secret-looking flags and `key=value` pairs) and `redact(text, secrets=None)`. `secrets=None` masks the process-wide values set by `configure_redaction()`; an explicit iterable (even `()`) masks exactly those values plus the same patterns. No module builds a second pattern list.
- `configure_redaction(secrets)` **replaces** the process-wide secret value set (deduplicated, values shorter than three characters ignored, longest first). It replaces rather than appends, so a second call cannot grow a parallel list, and it invents no environment variable: its input is the `.env` value set the engine already uses.
- **Startup order matters.** `Engine.open` loads `.env` (its `dotenv_values()` call) inside a command, which is too late for errors raised before it - `_targets()`, `load_config()` and the usage refusals all run first. The CLI therefore reads `.env` itself at the top of the Typer callback (`main`), with the same `dotenv_values()` call and no `os.environ` read, and calls `configure_redaction()` there. Click runs the callback before any subcommand body, so the values are set before `_report_error()` can fire; an unreadable `.env` is ignored here and left for the engine to report properly.
- Both console error paths go through it: `_report_error()` formats `traceback.format_exc()` for `-v` and then prints `redact(message)`, and the non-verbose branch is the same call, so a chained exception (`__cause__`/`__context__`) is rendered into the string before redaction. `--json` does not move errors to stdout; the redacted message still goes to stderr.

## 5b. Scan modes (single source of truth)

The engine owns the mode definition; nothing else restates it. `engine.py` has
two module-level tables and one helper:

- `MODE_STAGES`: `passive` = `(SUBS, DNS, URLS)`; `active` = `(SUBS, DNS,
  LIVE, TECH, URLS, URL_PROBE)`; `full` = all nine stages in `STAGE_ORDER`
  (the eight discovery stages plus `SHOTS`, which is full-only). Every tuple is
  in `STAGE_ORDER`, so help text and the interactive legend list the stages in
  the order they actually run; `URLS` always follows `LIVE` when `LIVE` runs.
  A mode's stage of a pipeline can therefore have no input: in `passive` the
  `urls` stage has no alive host, which is exactly why passive urls tools are fed
  the domain list (see the next bullet).
- `_run_tools` gives a tool its own input list through `RunContext.hosts`: for the
  `urls` stage a `mode: passive` tool (`gau`, `waybackurls`) receives
  `[target, *discovered]` filtered to hosts under the target, while a
  `mode: active` tool keeps the alive hosts. The override travels in the same
  `tool_hosts` map `naabu` uses, so there is one mechanism, not two.
- `MODE_TOOLS`: a `ModeRules(tool_modes, tiers)` per mode. `passive` =
  `{PASSIVE}` / `{CORE}`; `active` = `{PASSIVE, ACTIVE}` / `{CORE}`; `full` =
  `{PASSIVE, ACTIVE}` / `{CORE, OPT_IN, INTRUSIVE}`.
- `allowed_tiers(mode, include_noisy=...)` adds `OPT_IN` for `--include-noisy`
  (and always for `full`).

`_select()` applies them in this order: an explicit `--tools <name>` bypasses
the tier gate; an `exploitation: true` tool is skipped in every mode unless
named (`exploitation tool requires explicit --tools`); a tier outside
`allowed_tiers` is skipped (`tier not included in <mode> mode`); a tool whose
`mode:` is outside `MODE_TOOLS[mode].tool_modes` is skipped (`tool mode not
included in <mode> mode`, never bypassed); then no-adapter and not-installed
checks. `ScanOptions.mode` is derived (`full` wins over `active`, else
`passive`), so no caller can invent a fourth mode. The CLI's `_stages()` and
both help strings read `MODE_STAGES`; the interactive legend reads the same
tables, which is why the three surfaces cannot disagree.

## 6. Data Flow (example: `reconkit live -d example.com --active`)

1. CLI parses flags and loads `config.yaml`.
2. Scope gate: with `--no-scope` the file is ignored (`scope_mode` `unrestricted_flag`); otherwise, if `scope.yaml` exists it must not be expired, must allow active and must match `example.com` (exit code 3 otherwise). With no scope file at the resolved path the active stages run unrestricted against the named target (docs/05 rule 2).
3. Engine reads known subdomains for the target from SQLite; each host is checked against scope again (out-of-scope removed).
4. Engine selects adapters for stage `live` that are installed and allowed by `MODE_TOOLS` (section 5b) plus the `exploitation` rule.
5. Every selected adapter for the stage starts together; each one runs at its own natural pace.
6. Each adapter runs (subprocess via `runner` or Python), returns `ToolResult` with normalized records.
7. Engine merges records per host, records which tools reported what, computes state and confidence, handles disagreements.
8. Store writes `scan_runs`, `tool_runs`, `host_status_history`, updates `subdomains`.
9. Workspace writes one raw output file per executed tool (`<stage>/<run_id>-<tool>.txt`: stdout+stderr for a binary, the response body for an HTTP source, the per-host evidence document for a python adapter), redacted and capped, and `_run_one` sets `raw_path` on that result after the write returns; UI prints the table and tool summary; exit code reflects success/partial.

## 7. Concurrency (no pacing)

Speed control was removed on 2026-11-17 at the owner's request (docs/MASTER_PLAN.md D3, reason: "user-requested removal, no throttling desired"). `core/pacing.py`, the `Pacer`, the `RateLimiter`, the speed presets, `--speed`, `--delay`, the per-tool `rate_flag` (`-rl`/`-rate`/`-T`) and the typed `I AM AUTHORIZED` confirmation no longer exist. Leftovers that mention them are stale, not behaviour.

- **Tools.** Every adapter selected for a stage starts at once (`asyncio.gather`). There is no parallel limit, no inter-tool delay, no inter-host delay and no host or port shuffling.
- **Adapters.** `RunContext` carries `target`, `hosts`, `ports`, `timeout`, `workspace`, `mock`, `env`, `ip_allowed`, `headers` and `user_agent`. It has no `pacer`, `limiter` or `speed` field. `headers`/`user_agent` carry `--header`/`--user-agent`; only `httpx` and `pyprobe` apply them today. HTTP adapters make their request directly; Python adapters dispatch their per-host work directly.
- **Config.** `config.yaml` has no `speeds` block and no `default_speed`; `AppConfig` rejects those keys as unknown.
- **Scope.** `scope.yaml` `max_speed` is still accepted so an existing file keeps loading, and is ignored: there is no speed left to cap.
- **Persistence.** `scan_runs` has no `speed` column (schema version 6; migration 5 dropped it and migration 6 added `scope_mode`), and `status` no longer prints a Speed column or field.
- **Timeouts are not throttling** and remain: each stage has its phase timeout and each tool its per-tool timeout, both in `config.yaml`. The engine-owned `url_probe` stage is bounded by the same rule (D26): `--phase-timeout` or `timeouts.url_probe` (600 s) wraps `Engine._run_url_probe` in `asyncio.wait_for`; every finished batch is already committed, the pass row is closed as `partial`, and the timeout becomes a completion gap, not a failed run.
- **Randomness** survives only where it is functional: wildcard probe labels (injected RNG), never for scheduling.

## 8. Consensus Engine

- **Discovery stages (subs, urls):** union of all adapters; `sources` list per item; confidence from source count.
- **Status stages (live, ports):** compare tools per host/port; agreement raises confidence; disagreement becomes `UNCONFIRMED`/`unconfirmed` and is stored.
- **Wildcard filter:** before accepting resolved subdomains, probe `wildcard_check.probes` random non-existent names with the DNS adapter's resolver; if they resolve, mark hosts whose addresses or CNAMEs match the wildcard answer as wildcard noise. Detection returns `present`, `none` or `unknown`: `none` only when every probe is NXDOMAIN, `unknown` when no probe resolved and at least one timed out, SERVFAILed, returned no answer or errored. `unknown` is never treated as `none`; the engine warns and skips the filter. `wildcard_check.enabled: false` skips the filter entirely, and the filter never runs under `--mock` (mock reads fixtures only).
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
- `ui.render_progress(stage, tool, done, total, ...)` writes one progress line to
  stderr. It is wired into every scan (interactive and flag-based, `--json`
  included) and suppressed only by `--silent`; it never writes to stdout, so the
  one-document `--json` contract on stdout is untouched (docs/02 section 5).
  `Engine` receives it as an injected `progress` callback, so the engine still
  prints nothing itself.
- `ui.activity_spinner(console=..., *, enabled=...)` is a context manager that
  yields an updater for the live status line (the engine's `activity` snapshot),
  or a no-op updater when `enabled` is false or the console is not a terminal.
  The spinner is transient and never reaches stdout or a redirected stream.
- `ui.render_message(...)` writes one non-error line; `ui.render_diff(...)` and `ui.render_status(...)` render the `diff`/`status` documents to stderr or stdout JSON.
- `HostRow` is the plain input for the host table/JSON: `fqdn`, `state`, `confidence`, `sources`, `status_code`, `ports`, `detail`. The engine or CLI supplies these precomputed values; `ui.py` never computes confidence or state. `detail` is the stored, already-redacted reason from the latest status row (docs/04 section 5) and is emitted in `--json` only.
- `ui.py` imports only Rich, the standard library and shared output types; it never imports `core.store`, `core.scope`, adapters or `cli.py`. It does write the `results/` report files (docs/02 section 5): that is rendering to a file, it uses only `pathlib`/`json`/`os`, and every value comes from the engine's snapshots.

## 9. Dependency Rules

- CLI -> Engine -> (Adapters, Core). Never the reverse.
- Adapters must not import `store`, `scope`, `ui`, or `cli`.
- Only `core/runner.py` imports `subprocess`.
- Only `core/store.py` imports `sqlite3`.
- Redaction has one implementation and one value source (`core/store.py`). `cli.py` imports exactly the helpers `configure_redaction` and `redact` from `core.store` - never `Store`, never `sqlite3` - so console output and stored text are masked identically. A second pattern list or a second secret source is a bug.
- Only `ui.py` prints to the terminal (adapters and engine return data or raise).
- Registry (`tools.yaml`) is the only source of tool names, per-tool `source:` hints and tiers. reconkit installs nothing, so a `source:` string is documentation, never a command.

## 10. Key Technical Decisions

| Decision | Reason | Alternative rejected |
|---|---|---|
| Python | Fast to write/fix with AI agents; simple parsing; Kali ships Python | Go (AutoAR's language): single binary, but slower to extend with AI for this use case |
| SQLite + workspace files | Diffing, resume, queries; plus human-browsable raw output | Flat files only (no history), Postgres (too heavy) |
| Natural-pace execution | The owner asked for no throttling (2026-11-17, D3); every tool runs at its own rate | Speed presets, delays, shuffling, rate limiter |
| Adapter + registry | Add a tool without touching core | Hard-coded pipelines |
| Own `~/.reconkit/bin` (checked first) | No sudo, no global breakage, correct `httpx` | System PATH only |

## 11. Performance

- No throttling: stages start all their tools at once; progress is always shown.
- Bulk DB writes in one transaction per stage.
- Subprocess output streamed line by line (no loading huge output in memory).
- **File I/O never runs directly on the event loop.** The `scope.yaml` read (`scope.load_scope`, used by the active gate and by the `ip_allowed` predicate) and `Workspace.create`'s mkdir/chmod go through `asyncio.to_thread`, like `check_installed()` and every child process. They are kernel I/O on the single thread that also carries every tool's async work and the progress output, so a slow filesystem (a network share, a FUSE mount, an encrypted home) would otherwise freeze the whole run while it waited.
- **The SQLite persistence block stays on the event loop, deliberately.** `with store.transaction(): _persist_stage(...)` runs on the loop, one transaction per stage, and is awaited before the next stage starts, so stage order is fixed and there is exactly one writer. Moving it into a worker thread would need either a second connection or `sqlite3.connect(..., check_same_thread=False)`; `core/store.py` opens its connection on the main thread with the default `check_same_thread=True`, and SQLite refuses cross-thread use of that connection. The documented bound: one transaction per stage, holding only that stage's records, which is milliseconds on a local database - the ordering and single-writer guarantee is worth more than a gain nobody has measured on a local disk (12h).

## 12. Scalability

Single machine, thousands of hosts per target. Beyond that is out of scope (see PRD non-goals).

## 13. Failure Scenarios

| What if | Expected behavior |
|---|---|
| Tool missing | Skip, report `skipped (not installed)`; stage continues. This is the selection-time rule; a binary that was found at selection but cannot be spawned at run time is `failed` with its message instead |
| Adapter resolver lives inside the tool (`naabu`) | Scope-mode branch (docs/05 rule 6, 2026-11-17): no scope file - it runs unrestricted on hostnames; scope file present - the engine resolves and verifies each target itself and hands it only in-scope IPs, omitting targets whose resolution fails or resolves out of scope (all omitted = `blocked:` skip, stage continues) |
| Tool crashes or exits non-zero | Record `failed` with stderr summary; keep other results |
| Tool timeout | Kill process group, keep partial output if parseable, record `timeout` |
| HTTP source returns 429/5xx | `failed` result carrying the status; no retry (only a connection error retries once) |
| No adapter available for a stage | Exit code 4 (the message names the stage and its missing tools) |
| `scope.yaml` expired/mismatch (file present) | Refuse active stage, exit code 3 |
| `scope.yaml` absent | Active/full scanning runs unrestricted against the operator's targets and discovered hosts (docs/05 rule 2); no scope object is built |
| DB locked or corrupt | Clear error; never silently continue; suggest `--db` path |
| Ctrl+C | Stop launching new tools, mark the stage run `interrupted`, exit 130 (resumable); a child already running is not explicitly killed in this build |
| Network down | Passive HTTP sources fail fast with one summary line |

## 14. Linux Workflow Rules

- Repo in a native Linux checkout (current path in PROGRESS "Environment").
- Terminal, venv and tools all live in that Linux checkout.
- Unit tests use fixtures and need no installed tools.
- Real tool runs and integration smoke tests happen on Kali/Ubuntu.
- The current path, environment and check commands live in PROGRESS "Environment".
