# PROGRESS

## RESUME HERE

- Status: 10f code is done and accepted (2026-11-13). The real non-dry `install --all`, `doctor` and `update --all` have run on Kali and every defect they found is fixed (non-TTY abort, `member`, `verify_checksums`, doctor plan probe, `dnsreaper`/`puredns`/`findomain`/`chaos` registry values). Part 10's gate is open on exactly one item: the sudo-authenticated apt install. That needs a human terminal where `sudo -v` succeeds; this box has no sudo password reachable by the agent, so the apt path has only ever been exercised as `skipped`.
- PIT-32 (new, after Part 10f): an A/B test confirmed that `run_exec`'s `start_new_session=True` hid a valid `sudo -v` ticket from children (sudo `tty_tickets` is session-scoped). `runner.py` now keeps POSIX children in the parent's session and gives each its own process group (`start_new_session=is_windows`, `process_group=0` on POSIX), with two regression tests. This does not close the gate; it is the prerequisite for the gate run.
- Deferred by ruling (not Part 10 blockers): `update` idempotency for `@latest` go_install tools (reporting gap, binaries byte-identical; needs a new version-probe mechanism and its own docs-first pass, docs/10 section 6) and authenticated GitHub release lookups (a Part 11 planning decision).
- Last code commit: run `git log --oneline -1`
- Baseline: 569 passed, 0 skipped on Linux (Python 3.14.8 here); ruff, ruff format and mypy clean
- Next action: the user runs `sudo -v` in a real terminal, then `reconkit install --all --no-color` is run and its output recorded, showing at least one real `apt-get install` end to end (confirmation -> sudo -> apt-get -> binary-on-PATH check -> version check passing). Then close the Part 10 gate and start Part 11. Hold here: do not start Part 11 before that output is recorded.
- Already decided, do not reopen: no scope-bypass flag; consensus lives in engine.py; adapters never import store/scope/ui/cli; subjack replaced by subzy + nuclei takeover templates; installer targets Debian-family Linux only; free mode is default, keys only from .env; no push unless the user says so
- Do NOT: new dependencies; new modules/files/CLI commands not in docs/02-03; `assert` in src/; new lint/type suppressions; shell=True; whole environment to a child; adapters importing store/scope/ui/cli; consensus outside engine.py; pushing
- Known open bugs: none
- Read first: AGENTS.md, this block, last 3 REVIEW_LOG entries, current part in docs/MASTER_PLAN.md

Read this after `AGENTS.md`, before touching code. Update it in every commit.

## Environment

- Windows, one canonical checkout: `C:\Users\anshu\Desktop\recon\reconkit` (Git Bash paths: `/c/Users/anshu/Desktop/recon/reconkit`). Do not create a second copy.
- venv `.venv` (Python 3.11 via `uv`); activate with `. .venv/Scripts/activate` in Git Bash. System `python` is 3.10, so always use the venv or `uv`.
- Part 10 runs on Kali Linux, checkout `/home/kali/Desktop/reconkit`, venv built with `python3 -m venv` (Python 3.14.8). The paths above describe the Windows machine; neither copy is generated from the other, and nothing is synced between them.
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
| h | done | Part 8 hash in Part 9 | `ui.py` + `cli.py`; installer/doctor stubs remain for i |
| i | partial | Part 10a commit | `doctor.py` done; `installer/` pending 10b+ |
| j | pending | - | docs sync, README, final check |

Order and module names follow `docs/01_PRD.md` section 8 and `docs/03_ARCHITECTURE.md` section 5. There is no `core/consensus.py`: consensus lives in `engine.py`.

## Module map

- `errors.py`: `ScopeError` (3), `ConfigError` (2), `ParseError` (1), `ToolNotInstalled` (4), `ToolFailed`/`ToolTimeout`/`InstallError` (5). Each has `exit_code`.
- `models.py`: enums (`Stage`, `Tier`, `Mode`, `HostState`, `Confidence`, `ToolStatus`), records (`SubdomainRecord`, `HostStatusRecord`, `PortRecord`, `UrlRecord`, `FindingRecord`), `Record`, `ToolResult`, `InstallStatus`, `RunContext`.
- `config.py`: `load_config(path, speed=, delay=)`, `resolve_speed`, `parse_delay`, `SpeedPreset`; `_StrictModel` forbids unknown keys; `Webhook` model.
- `core/runner.py`: `run_exec(argv, timeout=, env=, max_output_bytes=, cwd=)` (only `subprocess` user), `validate_target` (root, strict RFC-1123), `validate_host` (discovered: allows `_`, strips `*.`), `ExecResult`; POSIX children stay in the parent's session but lead their own process group (PIT-32), timeout kills that group, output capped, env values redacted.
- `core/scope.py`: `load_scope`, `require_active` -> `ActiveCheck(scope, match, hosts, dropped)`, `check_target`, `ip_allowed`, `passive_warning`, `ScopeGate`; `out_of_scope` always wins.
- `core/store.py`: `Store(path)` (context manager, `close()`), `redact(text, secrets)`; writes `create_target`, `create_scan_run`, `finish_scan_run`, `record_tool_run`, `upsert_subdomain`, `add_subdomain_source`, `append_host_status`, `upsert_port`, `add_port_source`, `upsert_url`; reads `previous_state`, `diff_new`, `diff_gone`, `diff_state_changed`, `diff_ports_opened`, `diff_ports_closed`; pragmas FK/WAL/5000 ms, parameterized SQL only.
- `adapters/base.py`: `managed_bin_dir()` (lazy import of `installer.registry.bin_dir`, one definition of the path)
- `doctor.py`: `key_checks()` (names only, used by the install keys prompt)
- `installer/registry.py`: `bin_dir(home=)` (`~/.reconkit/bin`), `tier` on `InstallPlan`, `load_plans(path=, versions=)` -> `InstallPlan` (`name`, `method`, `binary`, `package`, `repo`, `asset_pattern`, `checksums_pattern`, `asset_name`, `version`, `fallback`, `requires_apt`, `requires`), `plan_for`, `resolve_plan`; unknown method or missing package/repo raises `ConfigError`.
- `installer/apt.py`: `apt_env` (PATH/DEBIAN_FRONTEND/LC_ALL), `apt_argv` (`sudo -n apt-get install -y`), `apt_steps`, `apt_install_package`, `install_apt`; package names validated; a password-requiring sudo becomes `InstallSkipped`.
- `installer/go_install.py`: `go_env` (HOME/GOBIN/PATH), `go_spec`, `install_go`; builds into the managed bin dir and runs `version_cmd`.
- `installer/pipx.py`: `pipx_env` (HOME/PATH/PIPX_BIN_DIR/PIPX_HOME), `pipx_spec` (packages, pins and `git+https://` specs), `install_pipx_tool`; a missing pipx is a separate, separately confirmed apt step.
- `installer/github_release.py`: `install_selected` (idempotent install/update over a selection), `installed_copy`/`installed_version`, `desired_version`, `_refresh_templates` (`nuclei -ut`), `CHECKSUMS_LIMIT` (64 KiB cap on the checksums fetch), `release_for(plan, client=, arch=)`, `download`, `install_release(plan, client=, bin_dir, dry_run=, verify_checksums=, runner=)`, `install_plans` (per-tool isolation), `exit_code` (0/5/6), `host_arch`, `render_pattern`, `checked_https`; HTTPS GitHub hosts only, MockTransport in tests.
- `installer/verify.py`: `sha256_file`, `checksum_for`, `verify_checksum`, `extract_binary(archive, binary, dest_dir, archive_limit=, member_limit=)`; zip-slip refused, only the expected binary extracted, mode 0755; `ARCHIVE_LIMIT` 200 MiB, `MEMBER_LIMIT` 100 MiB.
- `doctor.py`: `collect_report(config, config_path=, env=, tools_path=, scope_path=, dpkg_status=, status_of=, python_version=)` -> `DoctorReport` of `ToolCheck`/`StageCoverage`/`PackageCheck`/`KeyCheck`; `default_status`, `installed_packages`, `db_writable`; reads files and version commands only, never installs.
- `adapters/base.py`: `BaseToolAdapter` (contract from docs/09), `HttpAdapter` (rate limit via `ctx.limiter`, timeout, User-Agent, one retry on connection errors, 429/5xx/timeout -> failed result), `normalize_subdomains`; `FetchFailed`.
- `adapters/registry.py`: `load_tools(path=)` -> `ToolSpec`, `load_system_packages(path=)`, `get_spec`, `get_adapter`, `rate_flags()`; unknown/incomplete tools raise `ConfigError`.
- `adapters/__init__.py`: `ADAPTERS` maps `crtsh`, `certspotter`, `otx`, `hackertarget` to classes.
- `adapters/crtsh.py`, `certspotter.py`, `otx.py`, `hackertarget.py`: async parsers and request metadata; keys only from `ctx.env`.
- `adapters/dnspython.py` / `pyprobe.py` / `pyscan.py`: structured `DnsOutcome` (only NXDOMAIN -> DEAD), no-redirect probe that records `Location`, bounded TCP connect scan. All three validate hosts and count invalid ones.
- `core/pacing.py`: `Pacer(preset, rate_flags=, rng=, sleep=)` with `before_tool(mode)` (first tool free, `reset()` per stage), `before_host`, `order(items, kind=)`, `parallel_limit`, `tool_rate_args(tool, mode)`, `next_pause_range`; `RateLimiter(rate, clock=, sleep=)` for HTTP adapters. No I/O, no printing, injected clock.

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
- Ruff excludes `docs/`; per-file ignores: `tests/**` S101, `tests/fakebin/**` S603, `tests/test_runner.py` S603 (the kill-tree test must hold a live `Popen` to call `_kill_tree`), `src/reconkit/core/runner.py` S603 (argv is passed as a list).
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
- Part 7: docs/09 said `--json` was JSONL, but the Part 7 requirement/master plan says ONE JSON document; docs/02 now defines that shape, docs/09 was aligned, and `ui.write_json` emits `type:summary` with `hosts`/`stages`/`summary`. `HostRow` is a UI input type populated by the CLI; `ui.py` does not compute confidence/state.
- Part 7: `ScanSummary` does not carry skipped tools, so the Tools table renders executed `ToolResult`s (ok/failed/timeout) only; skipped adapter rows remain in `tool_runs` and are a Part 8 wiring concern. The zero-tool empty state uses the explicit "skipped or excluded" line instead of docs/02's 3-tool example.
- Part 8: no command is shorthand for `lite`; `--json` accepts one target (multiple `-l` targets are rejected with exit 2); docs/02 now explicitly defers `--timeout-<stage>`, so only `--phase-timeout` sets a stage limit; `doctor`/`install`/`update` are Part 9 stubs, and `db list`, `db export`, `export` and `scope import` are explicit exit-1 stubs.
- Part 8: `Engine.open` loads `.env` values and the CLI has no `os.environ`/`getenv`; shell-exported key variables are therefore ignored. The active fast-mode typed confirmation runs outside `--mock`, where no traffic is possible.
- Part 9: schema v2 adds `host_status_history.cnames_json` and `dangling_cname`; DNS-only resolved hosts now get a status row so their CNAME survives a restart, and a later NXDOMAIN reuses the latest stored CNAME. The migration is additive and existing rows default to `[]`/NULL. This is also a row-frequency change: the `dns` stage now writes one status row per host with a signal (`RESOLVED` -> `DNS_ONLY`, `NXDOMAIN` -> `SHUT_DOWN`/`DEAD`) instead of only NXDOMAIN rows; docs/03 and docs/04 state it, and `test_dns_resolved_then_two_nxdomain_is_shut_down_then_dead` guards that the extra row does not break the two-consecutive-NXDOMAIN `DEAD` rule. Wildcard wiring and stage-level resume were triaged, not fixed, because this part was limited to the Fix backlog.

- Part 10 docs pre-fix (docs only): docs/10 now matches docs/02's install surface (`--stage`/`--yes` removed from the grammar), states that `doctor` runs on Windows while `install`/`update` exit 1 there, adds 3b prerequisites (jq, dnsutils via `dig`, Go/GOBIN, pipx-via-apt), 5a doctor output/exit rules, Go/PyPI download hosts, and defers the fixture-version doctor warning to Phase 3 pending per-tool metadata. Open for review: `--all` phase scope, the installer exit code when every tool fails, and where wordlists live.
- Part 10 scope decisions (docs only): `--all` stays "core tier, no phase filter" and MASTER_PLAN Part 4 now names only `masscan` as opt-in (`rustscan`/`nmap` are core-but-phase-3, and `phase` is build tracking, not a security gate). Exit code 6 was added to docs/02 section 6 for "every requested tool failed to install or update"; 4 and 5 keep their scan meanings. The doctor wordlists check was removed from docs/01 and docs/02 and logged under Open risks. No `src/`, `tests/`, `tools.yaml` or `config.yaml` change.
- Part 10a follow-up (PIT-30): the first real `doctor` run moved `~/.config/{subfinder,naabu}` into the repo root because `check_installed()` ran the version probe with `env={}`. The probe now passes `HOME`, the configs were restored to `~/.config`, and a regression test pins the child env. This bug affected scans too, not only doctor.
- Part 10a (doctor): `collect_report` reads tools.yaml once through `load_tools`/`load_system_packages`, asks each binary adapter's `check_installed()` and reads `/var/lib/dpkg/status` directly instead of running `dpkg-query`, so doctor executes only the adapters' version commands and never apt. `--fix` exits 1 with "not available yet" because the `install` CLI is not wired until 10e; docs/10 section 5a still promises `--fix`, so that line is true only after the installer lands. System packages are `system_packages` plus `requires_apt`; `dnsutils` (only in the `dig` install block) is not checked and docs/10 now says why. The `n/a (no binary required)` cells wrap in an 80-column table; the text matches docs/02 exactly.
- Part 10b: install plans parse the `install` block from tools.yaml directly because `ToolSpec` does not expose it; the tool set still comes from `load_tools()`, so the two loaders cannot disagree on which tools exist. `tool_versions` pin wiring landed in 10e (`_install_selection` passes `config.tool_versions`).
- Part 10f: `requires_apt` was parsed into every plan but **no installer backend consumed it**, so a clean box would have installed `naabu` without `libpcap-dev` while docs/10 section 3a promised "the installer installs dependencies first". Fixed in `github_release._install_required_packages`: each prerequisite is installed before the tool with its own confirmation line (`naabu: sudo apt-get install -y libpcap-dev (required by naabu)`), a declined prerequisite raises `InstallSkipped` for the tool, and `--dry-run` lists the step without starting a process. docs/10 section 3a also now states two consequences that were implicit: prerequisites do not run for an already-installed tool, and `requires` (puredns -> massdns) is still not auto-installed.
- Part 10f: the `.env` no-overwrite guard now has a test that copies the real `.env.example` beside a `.env` (`test_existing_env_is_not_overwritten_when_env_example_exists`); the older test could not fail on a real clobber because it had no example file. `InstallPlan` gained `member` (archive member when the release renames the binary; `chaos-client`) and `verify_checksums` (per-plan override, `false` only for `findomain`, which publishes no checksums). The field list lives only in docs/10 section 3c; docs/03 does not enumerate plan fields (it names the installer modules), so docs/03 needed no change. `doctor` now falls back to the plan probe for tools without an adapter, otherwise every phase-3 tool read `missing` after a clean install; docs/10 section 5a states it. `dnsreaper` is a `none` plan because the repository has no `setup.py`/`pyproject.toml` and no PyPI package, and `puredns` uses `--version` because it has no `version` subcommand (both verified 2026-11-13).
- Part 10f follow-up (massdns version display): `installed_version()` returned `str(copy)` whenever `version_args` was empty, so an apt package with no self-reported version (`massdns`) showed `/usr/bin/massdns` while every other apt row showed a version. `InstallPlan` now carries `version_command` from `version_cmd[0]`, but only when it names a different program than `binary`, so the managed-copy preference is unchanged for every existing tool; `installed_version` resolves and runs it, and the apt post-install check uses it. `massdns` now declares `[dpkg-query, -W, '-f=${Version}', massdns]`, and the idempotent row reads `(1.1.0-0kali2)` after a fresh install. `sqlmap` has the same gap and is deferred under Open risks. docs/10 defined the contract first (`66b117c`).

## Open risks

- `sqlmap` (apt, no `version_cmd` in `tools.yaml`) has the same gap massdns had: its install-table row and doctor display a bare path instead of a version. The `version_command` mechanism added for massdns applies unchanged (`[sqlmap, --version]`); this is deferred as a separate item because sqlmap is `intrusive` and outside Part 10's core-tool proof. No guard test enforces it yet.

- Windows subprocess arguments (PIT-32) are unverified: `run_exec` now passes `start_new_session=is_windows` and `process_group=None if is_windows else 0`, and CPython 3.11 accepts and ignores both on Windows (they reach the Windows `_execute_child` as `unused_start_new_session`/`unused_process_group`), but that was only read in the CPython source, not executed. On this Linux box `inspect.getsource(Popen._execute_child)` returns only the POSIX branch. A native Windows run of the runner/doctor must confirm the arguments are accepted before Part 11's Windows-refusal re-check closes. Not a Part 10 blocker.

- `SUDO_DENIAL_MARKERS` contains two substrings (`"no tty present"`, `"askpass"`) that were never reproduced against a live sudo; only `"a password is required"` was confirmed here. A different sudo/PAM wording would surface as `InstallError` instead of the friendlier `InstallSkipped` (low severity, but it will look like a failure rather than a skip).

- `_fetch_text`'s default 64 KiB cap has no dedicated test; the cap is only exercised through an explicit `max_bytes=64` argument in the test, so a regression in the default would pass the suite.
- Non-UTF-8 checksums-file rejection (`InstallError: checksums file is not UTF-8`) has no test.
- Accepted exception: `go_install` and `pipx` pass the parent process's `PATH` to their child (named in docs/10 section 3d with the reason). Every other child env is a fixed, explicit dict. Tests never exercise a custom parent `PATH`, so a change in that behaviour would not be caught by the suite.

- `doctor --fix` runs the `install --all` selection (10e) and never pretends to have fixed anything.
- `doctor` checks apt packages by reading `/var/lib/dpkg/status`; on a non-Debian system every package reports `unknown` instead of guessing. `dnsutils` is not covered because it appears only in the `dig` entry's `install` block.
- `rustscan` is excluded from the download path. Live check 2026-11-13 (tag 2.4.1 via the `bee-san/RustScan` redirect, now followed): assets are `x86-linux-rustscan.zip`, `x86_64-linux-rustscan.tar.gz.zip`, `aarch64-linux-rustscan.zip`, `rustscan.deb.zip` - none matches the `amd64`/`arm64` `{arch}` values, and there is no checksums asset. `tools.yaml` keeps the literal placeholder, so it still fails (`has no asset`) once the API quota is available; today it fails earlier with HTTP 403.
- `requires_apt` is only reached when the tool itself is installed. On this box `naabu` is already present from `/usr/bin`, so `install --all` does **not** install `libpcap-dev`. Review ruling: that is not a gate item. The prerequisite *orchestration* is verified by four unit tests plus two mutation proofs, and the prerequisite *apt mechanism* is the same `apt.apt_install_package` call site that `massdns` proves live, so `massdns` alone is the accepted live proof. A live `libpcap-dev` run is only reachable via `update naabu` when its lookup says not-current, or a box without naabu, and is not worth forcing destructively. Low functional stakes anyway: the naabu adapter always uses `-scan-type c`, which does not need libpcap.
- `requires` (puredns -> massdns) is parsed but not auto-installed; a user must install the named tool. Deferred to a future part and stated in docs/10 section 3a.
- The sudo-authenticated half of the install path has never been run end to end: `sudo -n true` and `sudo -v` both report that a password is required and this box has no NOPASSWD rule, so `massdns`, `amass`, `dig`, `nmap`, `whatweb` and `libpcap-dev` have only ever been exercised as `skipped`. `install_apt`'s `shutil.which` check and its `check_version` call have therefore never seen a real successful `apt-get`.
- GitHub release lookups are unauthenticated: 60 requests/hour per source IP for 13 `github_release` tools, and `release_for` sends no token (there is no `GITHUB_TOKEN` support for release lookups; the registry's `GITHUB_TOKEN` key is for `github_subdomains`). On 2026-11-13 the quota was exhausted (core `remaining 0`, `reset` 21:57 UTC) and every `github_release` tool failed with HTTP 403 while the run continued. Deferred to Part 11 planning as a feature decision: either add authenticated lookups and recommend `GITHUB_TOKEN` in docs/10, or keep the wait-and-retry rule now documented there. Not built in 10f.
- `update` re-runs `go install` for every `@latest` go_install tool and reports `installed` rather than `up to date`, because there is no installed-version metadata to compare. The re-run is byte-identical (Go build cache; measured on `assetfinder`, `subjs`, `gau`), so it is a reporting/idempotency-of-message gap, not a corrupting reinstall. docs/10 section 6 states it and marks the proper fix (module-proxy lookup vs installed build metadata) as deferred to a future part; the ruling is that this does not block the Part 10 gate.
- `doctor` does not check wordlists: no Phase-2 adapter consumes one, and no wordlist path exists in `tools.yaml` or `config.yaml`. Only the phase-3 DNS-bruteforce tools (`puredns`, `massdns`, `amass`, `findomain`, `dnsx`) would need one. Revisit when any of those gets an adapter.
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
- Part 9 triage: wildcard detection is still not wired into the engine; `is_wildcard` stays 0 and no wildcard-unknown warning is emitted. This is not a Fix backlog item and needs engine integration, so it remains open for a later part.
- Part 9 triage: resume remains stage-level; tools completed inside a crashed stage are rerun. Per-tool checkpointing is a larger engine change, so this stays a documented limitation. Real NXDOMAIN/CNAME behavior remains unverified.
- Part 9: the dangling warning can reuse only a CNAME stored by an earlier resolved pass; `dnspython`'s NXDOMAIN path returns no CNAME in that pass.
- Part 7 rendering is tested with `StringIO`/fake TTY only; real terminal widths and the CLI's `HostRow` source are unverified until Part 8.
- `docs/09_TOOL_CONTRACTS.md` has now contradicted docs/02 twice (the earlier `needs_key` registry issue and Part 7's JSONL-vs-single-document contract), so it needs a full fresh-eyes pass against docs/02 before the Part 11 final docs sync; do not treat docs/09 as authoritative until then.
- Part 8: `db list`/`db export`/`export` are command stubs, and `diff` compares only the latest two completed `subs` runs plus matched `live`/`ports` runs; real tools, real terminals and the stubs remain unverified.
- Part 8: `--timeout-<stage>` is explicitly deferred in docs/02; `--phase-timeout` is the only stage-timeout flag, and multi-target `--json` is rejected pending a batch document shape.

## Fix backlog

No open items. Part 9 fixed the dangling-CNAME persistence gap with schema version 2 and a restart regression test.
