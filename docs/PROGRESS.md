# PROGRESS

## RESUME HERE

- Status: Part 6b done; Part 7 (`ui.py`) next
- Last code commit: run `git log --oneline -1`; Part 6b is the newest `feat:` commit
- Baseline: 374 passed, 2 skipped; all four checks PASS (twice)
- Next action: implement Part 7 in `docs/MASTER_PLAN.md`: Rich tables/progress on stderr, one JSON document on stdout, silent/no-color modes, markup escaping and the key hint
- Already decided, do not reopen: no scope-bypass flag; consensus lives in engine.py; adapters never import store/scope/ui/cli; subjack replaced by subzy + nuclei takeover templates; installer targets Debian-family Linux only; free mode is default, keys only from .env; no push unless the user says so
- Do NOT: new dependencies; new modules/files/CLI commands not in docs/02-03; `assert` in src/; new lint/type suppressions; shell=True; whole environment to a child; adapters importing store/scope/ui/cli; consensus outside engine.py; pushing
- Known open bugs: none
- Read first: AGENTS.md, this block, last 3 REVIEW_LOG entries, current part in docs/MASTER_PLAN.md

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
| f2 | done | 80ddd93 | pure-Python adapters: `dnspython`, `pyprobe`, `pyscan` |
| f3 | done | ee06075 | remaining phase-2 tools: binary adapters `subfinder`, `assetfinder`, `httpx`, `naabu` |
| g | done | 36cd3a4, 6b hash in Part 7 | wildcard, workspace, engine, confidence, host states, resume, exit codes done |
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
- `adapters/dnspython.py` / `pyprobe.py` / `pyscan.py`: structured `DnsOutcome` (only NXDOMAIN -> DEAD), no-redirect probe that records `Location`, bounded TCP connect scan. All three validate hosts and count invalid ones.
- `core/pacing.py`: `Pacer(preset, rate_flags=, rng=, sleep=)` with `before_tool(mode)` (first tool free, `reset()` per stage), `before_host`, `order(items, kind=)`, `parallel_limit`, `tool_rate_args(tool, mode)`, `next_pause_range`; `RateLimiter(rate, clock=, sleep=)` for HTTP adapters. No I/O, no printing, injected clock.

## Notes for task g

- The engine must call `pacer.reset()` at the start of every stage.
- `diff_new`/`diff_gone` rely on per-run `*_sources` rows, so a stage-only run would make every host look GONE. Diffs must compare runs of the same kind; docs/04 section 6 says which.
- Raw stderr/output files written by `workspace.py` must go through `redact()` before they hit disk.
- The engine builds one `RateLimiter` per stage (passive requests/second from the preset) and puts it in `RunContext`; HTTP adapters never build their own.
- `Store` is used only from the event-loop thread (no `asyncio.to_thread`).
- Per-call commits are slow for thousands of hosts. Add a `transaction()` context manager or a batch insert method when the engine needs it.
- A discovered host with no probe result keeps the schema default `UNKNOWN`; only the live/DNS stages append `host_status_history` rows.
- The engine passes each tool only the env names listed in that tool's `keys` in `tools.yaml`, never the whole environment.
- When a tool fails with "rate limited" and its keys are unset, the UI should hint at the free key (env name and sign-up URL from `tools.yaml`).
- `registry.load_tools()` reloads `tools.yaml` on every call, so the engine should load the specs once and reuse them.
- Read queries for the engine/CLI (list subdomains with sources, `tool_runs` of a run for resume, latest run for a target, ports, export) are added in tasks g/h with tests.

## Fixtures

- `crtsh/example.com.json` - trimmed real response, fetched 2026-11-13 from `https://crt.sh/?q=%25.example.com&output=json` (5 of 85 entries).
- `certspotter/example.com.json` - trimmed real response, fetched 2026-11-13 from `https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names` (2 of 17 entries).
- `otx/example.com.synthetic.json` - synthetic, documented `passive_dns` shape; the real endpoint returned HTTP 429 for anonymous access on 2026-11-13 (`https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns`).
- `hackertarget/example.com.txt` - real response, fetched 2026-11-13 from `https://api.hackertarget.com/hostsearch/?q=example.com` (the free quota returned a single row).

## Key sources

- All fetched 2026-11-13.
- Cert Spotter API reference: `https://sslmate.com/help/reference/ct_search_api_v1`. An API key is a Bearer token (or Basic username); only unauthenticated per-hour limits are documented, and the docs give no number, so the old "100 queries/hour" claim was removed. Sign-up: `https://sslmate.com/ct_search_api`.
- OTX: `https://otx.alienvault.com/api` (`X-OTX-API-KEY`; a free account provides the key).
- assetfinder: `https://github.com/tomnomnom/assetfinder` (`VT_API_KEY`); VirusTotal Public API is free at 4 requests/minute and 500/day: `https://docs.virustotal.com/reference/public-vs-premium-api`.
- subfinder provider config: `https://docs.projectdiscovery.io/opensource/subfinder/install` (fetched 2026-11-13). Provider keys are stored only in `$HOME/.config/subfinder/provider-config.yaml`; no per-provider environment variable is documented. Providers the page says need a key: BeVigil, BinaryEdge, BufferOver, C99, Censys, CertSpotter, Chaos, Chinaz, DNSDB, Fofa, FullHunt, GitHub, Intelx, PassiveTotal, Profundis, quake, Robtex, SecurityTrails, Shodan, ThreatBook, VirusTotal, WhoisXML API, ZoomEye, dnsrepo, Hunter, Facebook, BuiltWith.
- urlscan API intro: `https://docs.urlscan.io/pages/api-intro` (account + API key; unauthenticated access has "minor quotas"). Sign-up: `https://urlscan.io/user/signup`.
- Chaos client README: `https://github.com/projectdiscovery/chaos-client`; the environment variable is `PDCP_API_KEY`, and the API allows 60 requests/minute/IP. Sign-up: `https://cloud.projectdiscovery.io`.
- github-subdomains README: `https://github.com/gwen001/github-subdomains`; it reads `GITHUB_TOKEN` when `-t` is absent. Token page: `https://github.com/settings/tokens`. GitHub REST limits: 60 requests/hour unauthenticated, 5,000/hour authenticated (`https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api`).

## Deviations and assumptions

- `types-PyYAML` added as a dev dependency for strict mypy.
- Enums use `StrEnum` (ruff UP042) instead of the docs' `(str, Enum)`; same values.
- `--delay` applies to both passive and active `tool_delay` (not `host_delay`).
- Bootstrap prefers `uv`; venv is Python 3.11 because WSL `python3` is 3.14.
- Ruff excludes `docs/`; per-file ignores: `tests/**` S101, `tests/fakebin/**` S603, `src/reconkit/core/runner.py` S603 (argv is passed as a list).
- `host_status_history.waf` added for the CDN/WAF marker; port scans require a stored `live` result and skip hosts with `waf` set.
- Exit codes: Scope 3, ToolNotInstalled 4, ToolFailed/Timeout/Install 5, Parse 1, Config 2.
- `scope.yaml` defaults: missing `expires` = never expires; missing `max_speed` = `slow`.
- `check_target` reports `out_of_scope` before expiry (out always wins) and raises `ValueError` on an invalid target.
- Single Windows-native checkout. Installer work must verify apt package names for both Kali and Ubuntu before coding.
- `_kill_tree` guard changed from `os.name` to `sys.platform` for Windows mypy; the kill test is skipped on Windows, so that path is unverified until it runs on Linux.
- `.gitattributes` forces LF for `*.sh`, `.githooks/*`, `*.py`, `*.md`, `*.yaml`, `*.toml`; existing files were not renormalized.
- `Pacer.order()` takes an optional `kind="host"|"port"` because config has separate shuffle flags. Scoped S311 ignores in `pyproject.toml` cover the pacer's jitter RNG and the seeded test RNG.
- Commits are authored by `Anshul <anshulc4444@gmail.com>` with no AI co-author trailer.
- `needs_key` was removed from `tools.yaml`; the loader now raises `ConfigError` for it so `keys` stays the single source of truth (docs/05 §6.1 updated first).
- Cert Spotter's `adds` text was corrected: the API docs do not promise 100 queries/hour to a key; that figure was the unauthenticated limit.
- Chaos's key env name was corrected from `CHAOS_API_KEY` to `PDCP_API_KEY` (chaos-client README). `urlscan` and `github_subdomains` migrated from `needs_key` to `keys` with verified URLs.
- Per-host adapters now normalize every input with `validate_host()`; an invalid or IDN host is skipped/counted instead of being used in a request. `dnspython` maps an unexpected resolver exception to the structured `error` outcome instead of aborting the stage.
- `pyscan` closes the connection before awaiting `wait_closed()`, so cancelling a stage cannot leak an open socket; the concurrency test pins the semaphore to the pacer limit.
- `subfinder` now carries four `keys` and the adapter writes them to a temporary `provider-config.yaml` (0600) passed with `-pc`, deleted in `finally`. This replaces the audit's earlier "no env bridge" decision because Part 4 requires the bridge.
- `chmod 0600` on the subfinder temp file is best-effort on Windows; the file is still deleted, and the open risk is recorded in REVIEW_LOG Part 4.
- Known pitfalls table + regression rules added by user addendum; `scripts/check.ps1` now warns on a `fix:` commit without a test change, and existing guards carry `Regression:` docstrings (no behavior change).
- Part 5 uses an injected, limiter-bound DNS probe and a required injected `rng` (no S311 default); `Workspace` rejects Windows-reserved target labels and chmods only its own dirs; `Workspace.write` is synchronous (`fsync` + `os.replace`), so the engine must offload large outputs.
- `src/reconkit/adapters/dns_python.py` is dead code: a 59-byte tracked stub created by `f4d81e2` from the docs/03 name; the real adapter is `dnspython.py` (`80ddd93`, updated in `75eb261`). Nothing imports it, but `docs/03_ARCHITECTURE.md:70` still names it. Kept pending the docs/03 fix (Part 11); do not use it.
- Part 6b adds `--resume` (docs/02); resume is stage-level and reruns an interrupted stage because asset writes are batched at stage end. State timestamps use the injected `now` source (default `store.utc_now()`); `Store.scan_runs()`/`subdomains()` are the resume reads. CNAME warnings stay in `ScanSummary.warnings` because the schema has no CNAME column. Double-confirmation is intentional: an established `ALIVE`/`DNS_ONLY` host has prior evidence, so one NXDOMAIN only means `SHUT_DOWN`; a second consecutive NXDOMAIN is required for `DEAD`. A never-probed host has no prior service to confirm, so its first NXDOMAIN is `DEAD`. This avoids one transient resolver failure erasing an established host while still recording genuine new non-existence.

## Open risks

- `RunContext` now carries `limiter` and `ports`, and `HostStatusRecord` carries `location`; all were documented in docs/09 before their code landed. The engine builds one limiter per stage.
- `dnspython` resolves A/AAAA/CNAME only: the record models have no NS/MX/TXT fields, and adding them would change the database schema. `pyscan` sends no payload and reads no banner (the banner read is optional).
- `HttpAdapter` is documented in docs/09 section 3. Domain filtering happens in `run()` because the contract's `parse_output(raw)` receives no target; `parse_output` normalizes and validates only.
- Seven fixtures are synthetic, written to the documented shapes: `tests/fixtures/{dnspython,pyprobe,pyscan}/example.com.synthetic.json`, `tests/fixtures/{subfinder,assetfinder}/example.com.synthetic.txt`, `tests/fixtures/{httpx,naabu}/example.com.synthetic.jsonl`. No adapter test touches the network or a real binary.
- Binary-adapter identity is based on the official banner/version text, not a live run: no real binary is installed here. `httpx` distinguishes ProjectDiscovery's tool from the Python CLI by requiring `projectdiscovery`/`current version`.
- `tests/test_store.py` imports `sqlite3` for `IntegrityError`; the "only store.py imports sqlite3" rule is enforced for `src/`.
- Installer refuses to run on native Windows; decide how to handle that before task i.
- `scope.yaml` cannot exclude IP ranges (no out-of-scope CIDRs).
- CLI must catch `ValueError` from `check_target`/`validate_target` and exit 2.
- OTX anonymous requests return 429 (synthetic fixture); HackerTarget's free tier returned one row for example.com, so multi-row parsing is only covered by MockTransport tests.
- subfinder keys are bridged by its adapter into a temporary 0600 `provider-config.yaml`; only certspotter, chaos, github and virustotal are configured. The other keyed providers' free tiers and sign-up URLs remain unverified, and no real subfinder has accepted the generated file yet.
- Part 6a: one `scan_runs` row per executed stage; `ScanOptions.speed` is `SpeedName`; `Store.transaction()` uses SQLite's implicit transaction (explicit `BEGIN` failed inside one); `check_installed()` runs via `asyncio.to_thread`; workspace/scope reads stay synchronous and short; `FindingRecord` is not persisted because the findings table is deferred.
- Wildcard detection is still not wired into the engine: `is_wildcard` stays 0 and no wildcard-unknown warning is emitted.
- Resume is stage-level; tools completed inside a crashed stage are rerun. CNAME dangling warnings are not persisted, and real NXDOMAIN/CNAME behavior has not been exercised.

## Fix backlog

1. **Persist dangling-CNAME evidence.** `host_status_history` has no CNAME/dangling column, so a takeover-relevant `SHUT_DOWN` warning exists only in `ScanSummary.warnings` and is lost on the next run. Add persistence when the schema is next migrated (Part 9).

## Next task

**Part 7: `ui.py`.** Follow docs/02: tables/progress on stderr, one valid JSON document on stdout, silent/no-color modes, Rich markup escaping, and the rate-limited-without-key hint. Do not import store/scope/adapters into UI functions.
