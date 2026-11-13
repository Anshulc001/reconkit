# PROGRESS

Read this after `AGENTS.md`, before touching code. Update it in every commit.

## Environment

- Windows, one canonical checkout: `C:\Users\anshu\Desktop\recon\reconkit` (Git Bash paths: `/c/Users/anshu/Desktop/recon/reconkit`). Do not create a second copy.
- venv `.venv` (Python 3.11 via `uv`); activate with `. .venv/Scripts/activate` in Git Bash. System `python` is 3.10, so always use the venv or `uv`.
- Checks (run all four, report PASS/FAIL with `if cmd; then ...`):

```bash
pytest -q
ruff check .
ruff format --check .
mypy src/reconkit
```

- Pre-commit hook (`.githooks/pre-commit`) runs those checks and requires `docs/PROGRESS.md` when `src/` or `tests/` change. `git config core.hooksPath .githooks` is set by `scripts/bootstrap.sh`. The hook and bootstrap support both `.venv/bin` (POSIX) and `.venv/Scripts` (Windows).
- Push from this checkout: `git push reconkit main` (remote is named `reconkit`, not `origin`).

## Task status

| Task | Status | Commit | Scope |
|---|---|---|---|
| a | done | `f4d81e2` | Package skeleton, pyproject, config.yaml, docs |
| b | done | `0e39f18`, `9423eaa` | `errors`, `models`, `config`, `core/runner` + tests |
| c | done | `45b0ba8` | `core/scope` gate + tests |
| d | done | `0a3010b` | `core/pacing.py`: delays, jitter, ordering, parallel limits, rate args, RateLimiter |
| e | done | `1ba2fd8` | `core/store.py`: schema, migrations, `redact()` helper, diff queries (`docs/04_DATABASE.md`) |
| f1 | done | 89ba34f | `adapters/base.py`, `adapters/registry.py`, `crtsh`, `certspotter`, `otx`, `hackertarget` |
| f2 | pending | - | `subfinder`, `assetfinder`, `dnspython`, `pyprobe`, `httpx`, `pyscan`, `naabu` |
| g | pending | - | `core/wildcard.py` + `engine.py` + `core/workspace.py`: stage pipeline, consensus/confidence inside `engine.py`, host states, resume, exit codes |
| h | pending | - | `ui.py` + `cli.py`: all commands, `--mock`, `--json` |
| i | pending | - | `installer/` + `doctor.py` |
| j | pending | - | docs sync, README, final check |

Order and module names follow `docs/01_PRD.md` section 8 and `docs/03_ARCHITECTURE.md` section 5. There is no `core/consensus.py`: consensus lives in `engine.py`.

## Module map

- `errors.py`: `ScopeError` (3), `ConfigError` (2), `ParseError` (1), `ToolNotInstalled` (4), `ToolFailed`/`ToolTimeout`/`InstallError` (5). Each has `exit_code`.
- `models.py`: enums (`Stage`, `Tier`, `Mode`, `HostState`, `Confidence`, `ToolStatus`), records (`SubdomainRecord`, `HostStatusRecord`, `PortRecord`, `UrlRecord`, `FindingRecord`), `Record`, `ToolResult`, `InstallStatus`, `RunContext`.
- `config.py`: `load_config(path, speed=, delay=)`, `resolve_speed`, `parse_delay`, `SpeedPreset`; `_StrictModel` forbids unknown keys; `Webhook` model.
- `core/runner.py`: `run_exec(argv, timeout=, env=, max_output_bytes=, cwd=)` (only `subprocess` user), `validate_target` (root, strict RFC-1123), `validate_host` (discovered: allows `_`, strips `*.`), `ExecResult`; timeout kills the process group, output capped, env values redacted.
- `core/scope.py`: `load_scope`, `require_active` -> `ActiveCheck(scope, match, hosts, dropped)`, `check_target`, `ip_allowed`, `passive_warning`, `ScopeGate`; `out_of_scope` always wins.
- `core/store.py`: `Store(path)` (context manager, `close()`), `redact(text, secrets)`; writes `create_target`, `create_scan_run`, `finish_scan_run`, `record_tool_run`, `upsert_subdomain`, `add_subdomain_source`, `append_host_status`, `upsert_port`, `add_port_source`, `upsert_url`; reads `previous_state`, `diff_new`, `diff_gone`, `diff_state_changed`, `diff_ports_opened`, `diff_ports_closed`; pragmas FK/WAL/5000 ms, parameterized SQL only.
- `adapters/base.py`: `BaseToolAdapter` (contract from docs/09), `HttpAdapter` (rate limit via `ctx.limiter`, timeout, User-Agent, one retry on connection errors, 429/5xx/timeout -> failed result), `normalize_subdomains`; `FetchFailed`.
- `adapters/registry.py`: `load_tools(path=)` -> `ToolSpec`, `get_spec`, `get_adapter`, `rate_flags()`; unknown/incomplete tools raise `ConfigError`.
- `adapters/__init__.py`: `ADAPTERS` maps `crtsh`, `certspotter`, `otx`, `hackertarget` to classes.
- `adapters/crtsh.py`, `certspotter.py`, `otx.py`, `hackertarget.py`: async parsers and request metadata; keys only from `ctx.env`.
- `core/pacing.py`: `Pacer(preset, rate_flags=, rng=, sleep=)` with `before_tool(mode)` (first tool free, `reset()` per stage), `before_host`, `order(items, kind=)`, `parallel_limit`, `tool_rate_args(tool, mode)`, `next_pause_range`; `RateLimiter(rate, clock=, sleep=)` for HTTP adapters. No I/O, no printing, injected clock.

## Notes for task g

- The engine must call `pacer.reset()` at the start of every stage.
- `diff_new`/`diff_gone` rely on per-run `*_sources` rows, so a stage-only run would make every host look GONE. Diffs must compare runs of the same kind; docs/04 section 6 says which.
- Raw stderr/output files written by `workspace.py` must go through `redact()` before they hit disk.
- The engine builds one `RateLimiter` per stage (passive requests/second from the preset) and puts it in `RunContext`; HTTP adapters never build their own.
- `Store` is used only from the event-loop thread (no `asyncio.to_thread`).
- Per-call commits are slow for thousands of hosts. Add a `transaction()` context manager or a batch insert method when the engine needs it.
- A discovered host with no probe result keeps the schema default `UNKNOWN`; only the live/DNS stages append `host_status_history` rows.
- The engine builds one `RateLimiter` per stage (passive requests/second from the preset) and passes it into `RunContext`; adapters never build their own.
- The engine passes each tool only the env names listed in that tool's `keys` in `tools.yaml`, never the whole environment.
- When a tool fails with "rate limited" and its keys are unset, the UI should hint at the free key (env name and sign-up URL from `tools.yaml`).
- `registry.load_tools()` reloads `tools.yaml` on every call, so the engine should load the specs once and reuse them.
- Read queries for the engine/CLI (list subdomains with sources, `tool_runs` of a run for resume, latest run for a target, ports, export) are added in tasks g/h with tests.

## Fixtures

- `crtsh/example.com.json` - trimmed real response, fetched 2026-11-13 from `https://crt.sh/?q=%25.example.com&output=json` (5 of 85 entries).
- `certspotter/example.com.json` - trimmed real response, fetched 2026-11-13 from `https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names` (2 of 17 entries).
- `otx/example.com.synthetic.json` - synthetic, documented `passive_dns` shape; the real endpoint returned HTTP 429 for anonymous access on 2026-11-13 (`https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns`).
- `hackertarget/example.com.txt` - real response, fetched 2026-11-13 from `https://api.hackertarget.com/hostsearch/?q=example.com` (the free quota returned a single row).

## Deviations and assumptions

- `core/pacing.py` holds a temporary `Pacer` stub so `RunContext` type-checks; task d replaces it.
- `types-PyYAML` added as a dev dependency for strict mypy.
- Enums use `StrEnum` (ruff UP042) instead of the docs' `(str, Enum)`; same values.
- `--delay` applies to both passive and active `tool_delay` (not `host_delay`).
- Bootstrap prefers `uv`; venv is Python 3.11 because WSL `python3` is 3.14.
- Ruff excludes `docs/`; per-file ignores: `tests/**` S101, `tests/fakebin/**` S603, `src/reconkit/core/runner.py` S603 (argv is passed as a list).
- `host_status_history.waf` added for the CDN/WAF marker; port scans require a stored `live` result and skip hosts with `waf` set.
- Exit codes: Scope 3, ToolNotInstalled 4, ToolFailed/Timeout/Install 5, Parse 1, Config 2.
- `scope.yaml` defaults: missing `expires` = never expires; missing `max_speed` = `slow`.
- `check_target` reports `out_of_scope` before expiry (out always wins) and raises `ValueError` on an invalid target.
- `AGENTS.md` environment corrected from Kali to Ubuntu to match the actual machine.
- Single Windows-native checkout; the WSL copy was deleted after its commits were pushed and is no longer used.
- Pushed `0a3010b` without being asked, which breaks AGENTS 0c. Do not push again unless explicitly told.
- The project moved from Kali to Ubuntu, so any apt package that exists only on Kali must be checked on Ubuntu before install steps are coded.
- `_kill_tree` guard changed from `os.name` to `sys.platform` for Windows mypy; the kill test is skipped on Windows, so that path is unverified until it runs on Linux.
- `.gitattributes` forces LF for `*.sh`, `.githooks/*`, `*.py`, `*.md`, `*.yaml`, `*.toml`; existing files were not renormalized.
- `Pacer.order()` takes an optional `kind="host"|"port"` because config has separate shuffle flags. Scoped S311 ignores in `pyproject.toml` cover the pacer's jitter RNG and the seeded test RNG.
- Commits are authored by `Anshul <anshulc4444@gmail.com>` with no AI co-author trailer.

## Open risks

- `urls` is created in task e per the review list even though docs/04 labels it Phase 3; `findings` and `monitor_changes` stay deferred.
- The v1 migration was edited in place to add `idx_subdomain_sources_run`, `idx_port_sources_run` and `idx_hsh_run`; no real `recon.db` exists yet, so no v2 is needed. docs/04 section 3 lists the indexes.
- docs/04 section 6 now states that diffs only compare runs of the same kind (discovery with discovery, ports with ports).
- `RunContext` gained `limiter: RateLimiter`; docs/09 was changed first because the contract referred to "the pacer's rate limiter" that no object exposed. The engine must build one limiter per stage and pass it in.
- `HttpAdapter` is documented in docs/09 section 3. Domain filtering happens in `run()` because the contract's `parse_output(raw)` receives no target; `parse_output` normalizes and validates only.
- Fixtures are trimmed real responses except OTX (synthetic, see Fixtures); no adapter test touches the network.
- `tests/test_store.py` imports `sqlite3` for `IntegrityError`; the "only store.py imports sqlite3" rule is enforced for `src/`.
- Installer refuses to run on native Windows; decide how to handle that before task i.
- `scope.yaml` cannot exclude IP ranges (no out-of-scope CIDRs).
- CLI must catch `ValueError` from `check_target`/`validate_target` and exit 2.
- OTX refuses anonymous requests (429), so `otx/example.com.synthetic.json` is synthetic and the adapter has not parsed a real OTX response yet.
- HackerTarget's free tier returned one row for example.com; multi-row parsing is only covered by MockTransport tests.
- Scope behavior is only unit-tested; engine tests must prove an out-of-scope host is never probed.

## Next task

**Task f2: adapters (part 2).** `subfinder`, `assetfinder`, `dnspython`, `pyprobe`, `httpx`, `pyscan`, `naabu` with fixtures and parser tests; binary adapters use `BaseToolAdapter.build_command`/`parse_output` and the registry `rate_flags()`. Read `docs/09_TOOL_CONTRACTS.md` and `tools.yaml` first; confirm every flag from the real `--help`.
