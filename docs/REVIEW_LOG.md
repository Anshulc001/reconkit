# Review log

Per-part evidence log for this repository. Each entry follows the template in
`docs/MASTER_PLAN.md`. Hashes are filled by the next commit, because a commit
cannot contain its own hash.

## Known pitfalls (read before coding)

Check every new change against this table before writing code. A future fix must
add a `test_regression_<slug>` test (or a docstring starting `Regression: PIT-xx`),
show it failing, then passing, and add its row in the same commit. A trap that
cannot be tested is marked UNTESTED and listed under "Not verified".

| ID | Symptom | Root cause | Rule going forward | Guarding test |
|---|---|---|---|---|
| PIT-01 | A host with a DNS timeout/SERVFAIL became DEAD | Every resolver exception collapsed into NXDOMAIN | Only NXDOMAIN may yield DEAD; timeout/SERVFAIL stay structured and warn | `test_dnspython_nxdomain_timeout_servfail_are_distinct` |
| PIT-02 | Passive tools were paced at the active rate | `tool_rate_args` ignored the mode | Passive uses passive rps; active uses active rps; nmap/masscan always active | `test_tool_rate_args_slow_passive_vs_active` |
| PIT-03 | Upserts reset stored subdomain/port/url values to defaults | Unconditional update on conflict | `None` keeps, explicit `0`/`""` overwrites, for all three tables | `test_upsert_subdomain_keeps_values_when_omitted`, `test_upsert_port_keeps_service_when_omitted`, `test_upsert_url_keeps_source_count_when_omitted` |
| PIT-04 | Secrets in `--flag VALUE` and Cookie headers survived redaction | Regexes covered pairs and Bearer only | Flag-value plus Cookie/Set-Cookie matchers | `test_redact_cases` |
| PIT-05 | Timing test flaked on Windows | Too-tight duration bound | Assert a lower bound only (`>= 0.25`) | `test_timeout_keeps_partial_output` |
| PIT-06 | `os.killpg` missing on Windows | POSIX-only API | `sys.platform` guard; kill test skipped | `test_timeout_kills_child` (skipped on Windows; UNTESTED on Linux) |
| PIT-07 | OTX 429 treated as an empty result | Anonymous API refuses requests | Synthetic fixture; 429 is an error, never data | n/a (synthetic fixture; `test_otx_sends_key_in_header_and_never_leaks_it`) |
| PIT-08 | `grep` missing in PowerShell | Two different shells | `Select-String` in PowerShell, `grep` in Git Bash | n/a (tooling) |
| PIT-09 | An invented `core/consensus.py` appeared | Assumed a module from the feature name | Consensus stays in `engine.py` | n/a (architecture) |
| PIT-10 | Copied output was claimed as evidence | Hand-written diff | Paste raw command output only | n/a (process) |
| PIT-11 | A workspace write escaped the target directory or hit a device name | Filename taken without validation | Regex + one segment + `resolve()` containment + device-name reject | `test_workspace_rejects_unsafe_filenames` |
| PIT-12 | The pre-commit hook passed while tests failed | Hook only checks PROGRESS.md | Run `scripts/check.ps1`; hook now warns on a `fix:` commit without tests | n/a (tooling; `check.ps1` WARN) |
| PIT-13 | `random.Random()` in `src/` tripped S311 | Convenience default RNG | Inject the RNG, no default, never suppress S311 | `test_wildcard_labels_are_unique_valid_and_under_the_target` |
| PIT-14 | The Python `httpx` CLI was accepted as ProjectDiscovery httpx | Identity checked by filename | Match the tool's own banner/version markers | `test_python_httpx_cli_is_rejected` |
| PIT-15 | A failed httpx probe was stored as ALIVE | No distinction between a response and a failed probe | Skip JSON lines without an integer `status_code` | `test_httpx_parser_skips_lines_without_a_status` |
| PIT-16 | A runner `RuntimeError` escaped an adapter | Only parse/fetch errors were mapped | Map it to `FAILED` with `runner error: ...` | `test_run_runner_error_is_a_failed_result` |
| PIT-17 | A subfinder provider file survived a YAML failure | Only `OSError` was caught | Catch `yaml.YAMLError` and unlink in `finally` | UNTESTED (inspection; needs a PyYAML fault injection) |
| PIT-18 | A provider key could reach argv or the result | No bridge existed | 0600 temp file, argv holds only its path, delete in `finally` | `test_subfinder_writes_and_deletes_provider_config` |
| PIT-19 | `needs_key` and `keys` disagreed | Two sources of truth | `keys` only; the loader rejects `needs_key` | `test_tools_yaml_has_no_legacy_needs_key` |
| PIT-20 | The body cap was bypassed by chunked or lying Content-Length | Trusted the header / buffered the whole body | Stream and cap actual bytes | `test_lying_small_content_length_is_still_capped` |
| PIT-21 | A wildcard timeout was read as "no wildcard" | Status collapsed to none | Any failed probe with no resolution is UNKNOWN, never NONE | `test_wildcard_unknown_is_not_none` |
| PIT-22 | The workspace wrote unredacted or partial output | Raw write in place | Redact before `mkstemp`, then `os.replace`; unlink on failure | `test_workspace_redacts_two_secrets_and_a_bearer_token` |
| PIT-23 | `Workspace.create` chmodded a caller-owned parent dir | `chmod(self.root)` | Chmod only the target and stage directories | UNTESTED (review fix) |
| PIT-24 | Target `con.example.com` mapped to a reserved Windows directory | `validate_target` accepts it | Reject a reserved first label in `Workspace` | `test_workspace_rejects_invalid_targets` |
| PIT-25 | Key and quota metadata was guessed from memory | No source check | Cite the URL and fetch date; list unverified items under Open risks | n/a (docs; see "Key sources") |
| PIT-26 | A `fix:` commit landed with no test | No gate step checked it | `scripts/check.ps1` prints a WARN | n/a (tooling; added with this addendum) |
| PIT-27 | `store.transaction()` raised "cannot start a transaction within a transaction" | Explicit `BEGIN` on a connection already inside SQLite's implicit transaction | Use SQLite's implicit transaction; commit/rollback at block exit | `test_transaction_commits_once_and_rolls_back` |
| PIT-28 | A resumed `live` stage saw only the target, not hosts persisted by completed stages | Resume skipped stages but the in-memory discovered/alive sets were not reseeded from SQLite | Seed both sets from `Store.subdomains()` on resume | `test_resume_skips_completed_stages_and_continues` |
| PIT-30 | `doctor`/scans moved subfinder and naabu config dirs from `~/.config` into the current directory | `BinaryAdapter.check_installed()` ran the version probe with `env={}`, so the child had no `HOME` and the tools wrote their config beside the CWD | Pass `HOME` to the identity probe | `test_identity_probe_passes_home` |
| PIT-31 | The `nuclei -ut` template refresh reported `templates not refreshed` on a working install, because nuclei lives under `$HOME/go/bin` | `_refresh_templates` passed `env={"HOME"}`; `Popen`/`execvpe` resolves a bare program name with the `PATH` inside the env it is given, falling back to `os.defpath` (`/bin:/usr/bin`) | A `runner(...)` call with a custom `env=` that names a bare binary must pass `PATH` too (the documented exception in docs/10 section 3d); where the caller already has an absolute path, pass the absolute path instead | `test_regression_custom_env_without_path_cannot_resolve_binary`, `test_nuclei_templates_are_refreshed_after_a_change` |
| PIT-32 | `sudo -n` fails inside reconkit (`sudo: a password is required`, exit 1) despite a valid `sudo -v` ticket in the same shell; a direct subprocess call succeeds | `run_exec` passed `start_new_session=True`, so the child called `setsid()` and sudo's `tty_tickets` scoping could not see the ticket cached against the parent's controlling terminal | POSIX children must stay in the parent's session: use `process_group=0` to give the timeout kill its own group, never `start_new_session=True` on POSIX. Windows keeps its old path (both arguments are ignored there) | `test_regression_child_shares_parent_session_but_not_pgid`, `test_regression_kill_tree_kills_only_the_child_group` |
| PIT-29 | A dangling-CNAME warning disappeared after restart | `host_status_history` had no CNAME columns and DNS-only resolved hosts were not persisted | Store `cnames_json` plus `dangling_cname`; reuse `Store.latest_cnames()` on a later NXDOMAIN | `test_regression_dangling_cname_survives_restart`, `test_dns_resolved_then_two_nxdomain_is_shut_down_then_dead`; migration tests in `test_store.py` |
| PIT-34 | A port scan resolved a host and connected to `addresses[0]` without checking `in_scope_cidrs`, and an empty resolution fell back to the hostname (a second, unchecked resolution) | docs/05 rule 6's predicate existed but had zero call sites, and an adapter could not reach the loaded scope by design (no `scope` import) | An adapter that resolves and then connects must refuse every address the injected `ip_allowed` predicate does not allow, treat `None` as deny (never allow-all), and never retry a hostname; a resolver that lives inside the binary (`naabu`) is skipped at selection time | `test_pyscan_probes_only_an_address_inside_in_scope_cidrs`, `test_pyscan_skips_a_host_whose_address_is_outside_in_scope_cidrs`, `test_pyscan_without_cidrs_probes_no_addresses`, `test_pyscan_never_falls_back_to_the_hostname`, `test_active_ports_stage_receives_the_cidr_predicate`, `test_naabu_stays_blocked_because_it_resolves_inside_the_binary` |
| PIT-35 | A tool printed a valid version banner and exited nonzero (`masscan --version` exits 1), so the installer's identity probe called a real, working binary "wrong program" and doctor refused it | `installed_version()` returned `None` for any nonzero exit; exit code was treated as the identity signal instead of the program name in the output | A version probe may accept a nonzero exit only when the output names the program (`plan.binary` case-insensitive); any other failing probe stays not-usable | `test_masscan_version_counts_even_though_its_exit_code_is_1`, `test_a_nonzero_version_probe_with_unrelated_text_is_not_installed` |
| PIT-33 | Three real docs-only commits (`cc70b15`, `722b2d1`, `046e0a2`) closed named Part 11 work but updated neither PROGRESS nor REVIEW_LOG; the RESUME block still read "11a is next" long after 11a shipped, and no 11c findings were ever logged | `.githooks/pre-commit` requires `docs/PROGRESS.md` only when `src/` or `tests/` change, so a docs-only commit is never forced to update the source of truth | Any commit that closes or advances a named task updates `docs/PROGRESS.md` in the same commit, docs-only included, and any finding gets a REVIEW_LOG entry whether or not code changed | n/a (tooling/process; the Part 11 findings backfill entry is the correction) |
| PIT-36 | `reconkit -d X --active ...` ran subs+dns only and exited as if the requested active scan had run | The bare form is the `lite` shorthand, `_stages("lite", active)` ignores `active` by design, and no command rejected a flag it cannot honour | A flag a command cannot honour is a usage error (exit 2) whose message names the command that can honour it; never accept and ignore it | `test_bare_command_rejects_active_instead_of_running_lite`, `test_passive_only_commands_reject_active` |
| PIT-37 | Every host ProjectDiscovery `httpx` got 200 on came back `UNKNOWN` from `pyprobe`, so 8 of 8 live hosts looked like two tools disagreeing | `_probe` returned a `UNKNOWN` record from inside the scheme loop on the first TLS `ConnectError`, so the `http` attempt never happened | A per-scheme failure must not end a multi-scheme probe; `UNKNOWN` requires "no scheme answered" plus a TLS error | `test_pyprobe_tls_failure_still_tries_http` |
| PIT-38 | A stage whose whole pool had no adapter reported `results: []` and `tools_skipped: 0`, indistinguishable from "ran and found nothing" | The summary counted only executed `ToolResult`s and `StageOutcome` dropped the selection-time skip list | Selection-time skips belong to the stage outcome and the totals (`stages[].skipped`, `summary.tools_skipped`), not only to `tool_runs` | `test_a_stage_with_no_adapter_reports_its_skips` |

| PIT-39 | `diff` reported 27 hosts as `GONE` after a single flaky discovery run (`subfinder` 35 names, then 8), none of them re-probed | `diff_gone` compared one run against the next and treated any absence as a removal, so passive-source variance became infrastructure change | `GONE` requires two consecutive misses plus a sighting in the run before them; a single miss is `pending_gone`, never a change; fewer than three discovery runs confirm nothing | `test_regression_diff_gone_needs_two_consecutive_misses`, `test_diff_gone_needs_the_miss_to_be_consecutive`, `test_diff_gone_needs_the_baseline_run_not_just_two_empty_ones`, `test_diff_gone_is_not_confirmed_when_the_host_reappears`, `test_diff_with_two_runs_reports_pending_and_no_gone` |


## Commit map

- Step 1 (`docs: add master plan, review log, check script, resume block`): `09a5bce`
- Part 3-AUDIT (`fix: close the phase-2 review gaps in store, keys and adapters`): `75eb261`
- Part 0 (`docs: record the Part 0 baseline and f1 review`): `e675079`
- Part 4 (`feat: add the phase-2 binary adapters`): `ee06075`
- Part 5 code (`wip: add wildcard detection and the target workspace`): `d9cf6c7`
- Regression/pitfalls addendum (`docs: add regression and pitfalls rules`): `49c68ae`
- Part 5 review (`docs: record the Part 5 review`): `7eb6b3f`
- Part 6a (`feat: add the staged engine and safety gates`): `36cd3a4`
- Part 6b (`feat: add confidence, host states, resume and exit codes`): `fffd5ea`
- Part 7 (`feat: add UI rendering, JSON and color safety`): `17d0412`
- Part 8 (`feat: add the Typer CLI, flags and mock wiring`): `c69aac5`
- Part 8 fix (`fix: align CLI timeout docs and mock help`): `83edd03`
- Part 9 (`fix: persist dangling CNAME evidence across restarts`): `83f3b85`
- Entries A, B and C below are the Part 3-AUDIT evidence. That audit was
  committed before Step 1 and Part 0 because the audit instruction arrived
  first; the ordering inversion is logged in the Step 1 entry and in Part 0.

## Step 1: save the plan, check script, resume block

- Docs read / goal: `AGENTS.md`, `docs/PROGRESS.md`, the pasted master plan. Make the plan permanent and give every session one read-only gate and one resume block.
- Decisions and assumptions: `docs/REVIEW_LOG.md` already existed from the Part 3-AUDIT; it was kept and extended rather than recreated. `scripts/check.ps1` is new because `scripts/` had only `bootstrap.sh`, not a check script. The script uses `.venv\Scripts\python.exe` and falls back to `python` only when the venv is absent.
- Decisions for user review (things the user may want to overrule): the fallback to bare `python` will run the checks on 3.10 and fail; that is deliberate so a missing venv is visible rather than silently skipped.
- Docs changed first: created `docs/MASTER_PLAN.md` (verbatim from AUTONOMY RULES through Part 11), prepended the session-start block to `AGENTS.md`, added both new docs to the AGENTS docs map, added the RESUME block to `docs/PROGRESS.md`, and trimmed PROGRESS history to stay under the 150-line cap.
- Deviations: Part 3-AUDIT was completed and committed as `75eb261` before Step 1/Part 0, contrary to the requested order. No work was discarded; Part 0 records the baseline normally.
- Files touched: `docs/MASTER_PLAN.md` (new), `docs/REVIEW_LOG.md`, `docs/PROGRESS.md`, `AGENTS.md`, `scripts/check.ps1` (new).
- Requirement -> test table: no product behavior in Step 1. Gate evidence: the failure path was proved with a temporary `tests/test_zz_gate_probe.py` containing `assert False`; `scripts/check.ps1` printed `pytest=FAIL`, `ruff-check=FAIL`, `CHECKS FAILED` and exited 1. The file was deleted and the same script then printed `ALL CHECKS PASS` and exited 0.
- Self-review findings (S2 lists, S3 raw output): no `src/` changes, so the S2 lists are empty. `check.ps1` runs only the four checks, writes nothing, and sets `$ErrorActionPreference = "Stop"`. Raw failing gate (tail): `pytest=FAIL`, `ruff-check=FAIL`, `ruff-format=PASS`, `mypy=PASS`, `CHECKS FAILED`, script exit 1.
- Bugs found: none.
- Mutation proofs: not applicable (no behavior under test); the gate's FAIL branch was exercised as above.
- Raw check output (last lines of scripts/check.ps1): `238 passed, 1 skipped`, `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`, `ALL CHECKS PASS`, exit 0.
- Not verified: `check.ps1` on a machine without PowerShell or without the venv.
- Next part must know: Part 0 records the baseline and the f1 retro entry; the audit commit already exists, so do not redo it.

## Part 0: baseline

- Docs read / goal: `AGENTS.md`, `docs/MASTER_PLAN.md` Part 0, `docs/PROGRESS.md`. Record the real starting point before Part 4.
- Decisions and assumptions: `docs/PROGRESS.md` is already 146 lines with the RESUME block, under the 150-line cap. The Part 3-AUDIT work is treated as finished history, not redone.
- Decisions for user review (things the user may want to overrule): none new. The local branch is 8 commits ahead of `reconkit/main` and is not pushed, as instructed.
- Docs changed first: no product docs changed; this commit is evidence only.
- Deviations: the Part 3-AUDIT commit (`75eb261`) landed before Step 1 and Part 0 because its instruction arrived first. It is recorded here instead of being replayed.
- Files touched: `docs/REVIEW_LOG.md`, `docs/PROGRESS.md`, `tests/test_python_adapters.py` (removed one suppression added by the audit).
- Requirement -> test table: Part 0 has evidence requirements, not feature requirements. `0a`: raw git/remote/fixture/ignore output below. `0b`: `scripts/check.ps1` twice, 238 passed / 1 skipped, S3 scans below. `0c`: f1 entry below. `0d`: S1/S3/S7 only.
- Self-review findings (S2 lists, S3 raw output):
  - S2: no `src/` diff in this part. The only code-adjacent edit was deleting a `# type: ignore[method-assign]` in a test; no broad except, blocking call, secret path or escaping exception was introduced.
  - S3 raw (PowerShell): `assert` no hits; `shell=True` no hits; `TODO|FIXME|XXX|HACK` only matches the word `Hackertarget`/`hackertarget` (case-insensitive false positive, no real marker); `print(` no hits; `subprocess` only `core/runner.py` plus one docstring in `adapters/base.py`; `sqlite3` only `core/store.py`; `os.environ` no hits; broad except: `adapters/dnspython.py:130` (unexpected resolver error must stay a structured per-host ERROR, not abort the DNS stage) and `core/store.py:202` (`__init__` closes the connection and re-raises the migration error); `noqa|type: ignore` count = 3, all pre-existing in tests; adapter imports of store/scope/ui/cli: no hits.
- Bugs found: one self-inflicted suppression from the audit (`tests/test_python_adapters.py`, `# type: ignore[method-assign]`). Root cause: added defensively although mypy does not check tests and ruff accepts the assignment. Fix: removed the comment. Guarding test: the S3 suppression count is back to the 3 pre-existing entries, and `test_pyscan_respects_the_pacer_parallel_limit` still passes.
- Mutation proofs: not applicable to Part 0.
- Raw check output (last lines of scripts/check.ps1, run twice): both runs ended `238 passed, 1 skipped`, `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`, `ALL CHECKS PASS`, exit 0.
- Raw 0a evidence: `git status --short` empty; `git log --oneline -8` starts `09a5bce`, `75eb261`, `80ddd93`, `e40091d`, `d03a231`, `89ba34f`, `2cb24e4`, `1ba2fd8`; `git ls-remote reconkit main` = `5fd1d9aa0d4a2ed9fc5ef2e9d0934abdd04e7b5a` (remote behind local); fixtures: certspotter 596, crtsh 1577, dnspython 172, hackertarget 31, otx 591, pyprobe 185, pyscan 168 bytes; `git check-ignore -v .env` = `.gitignore:3:.env`; `.tmpfetch` absent.
- Not verified: nothing about real tools or network; the remote was read, never pushed.
- Next part must know: Part 4 is f3, the four remaining phase-2 binary adapters. The 3 existing suppressions are the baseline; do not add a fourth.

## f1 (retroactive): 89ba34f `feat: add HTTP subdomain adapters and tool registry`

- Docs read / goal: docs/09 adapter contract and stage registry, docs/05 secrets, `tools.yaml`. Build `adapters/base.py`, `adapters/registry.py` and the crt.sh, Cert Spotter, OTX and HackerTarget HTTP adapters.
- Decisions and assumptions: one shared `HttpAdapter` for rate limiting, timeout, User-Agent, one connect retry and 429/5xx mapping; `parse_output` stays pure and target-unaware, so domain filtering lives in `run()`; keys are read from `ctx.env` only.
- Decisions for user review: none outstanding. The later audit corrected key facts; see entry B.
- Docs changed first: docs/09 sections 2-3 and the tool registry table.
- Deviations: OTX had no real response (HTTP 429 anonymous), so its fixture is synthetic and the parser has only seen the documented shape.
- Files touched: `src/reconkit/adapters/{base,registry,__init__,crtsh,certspotter,otx,hackertarget}.py`, `tests/test_adapters.py`, `tests/test_registry.py`, four fixtures, docs/09, tools.yaml.
- Requirement -> test table: normal shapes -> `test_real_fixture_shapes`; malformed -> `test_malformed_responses_fail_without_raising`; 429/5xx -> `test_429_is_failed_and_not_retried`, `test_500_is_failed_and_not_retried`; connection retry -> `test_connection_error_retries_once_with_injected_sleep`; mock -> `test_mock_mode_reads_fixture_and_skips_network`; keys never leak -> `test_certspotter_sends_key_in_header_and_never_leaks_it`, `test_otx_sends_key_in_header_and_never_leaks_it`; dependency rule -> `test_adapters_import_no_forbidden_modules`.
- Self-review findings (S2 lists, S3 raw output): no broad except in the adapter files; external input is the HTTP body, validated by each parser; keys stay in headers, never in URLs, errors or `ToolResult`; no blocking calls in async code; no unfinished path known.
- Bugs found: none at f1. The Part 3 audit later found unverified key metadata and corrected it in `75eb261`.
- Mutation proofs: not part of the Part 0 retro loop.
- Raw check output: same Part 0 baseline, `238 passed, 1 skipped`, all four checks PASS.
- Not verified: OTX real response (anonymous 429); the free-tier provider names for subfinder; the pre-commit hook can still be bypassed with `--no-verify` and does not check REVIEW_LOG content; domain filtering is covered only through `run()` tests, not a dedicated `_within_target` unit test.
- Next part must know: f1's key metadata was superseded by `75eb261` (`keys` is the only key field); do not restore `needs_key`.

---

## Part 3-AUDIT: phase-2 commit review

One entry per phase-2 commit reviewed in the Part 3 audit. The loop used for each
entry is S1 diff integrity, S2 contract/correctness, S3 tests and edge cases,
S4 docs, S5 security and hard rules, S6 mutation proof, S7 gate.

Chain confirmed with `git log --oneline -8`:

```
80ddd93 feat: add dnspython, pyprobe and pyscan adapters
e40091d feat: define the free-first API key policy and registry keys
d03a231 fix: keep stored port/url values and cap HTTP response bodies
89ba34f feat: add HTTP subdomain adapters and tool registry
```

Full hashes:

- A = `d03a231ff31df205d9c5e7819b542300a695bd22`
- B = `e40091d6c279ba3c77f44441a59fdd9063787386`
- C = `80ddd936a3870d6cf0500395efc3519cc3c0aa26`
- f1 base = `89ba34feee08aaccb0d9f8beb0197b4b6c4caade`

Baseline before the audit (working tree clean at 80ddd93): `218 passed, 1 skipped`;
`ruff check .`, `ruff format --check .` and `mypy src/reconkit` all passed.

## A - d03a231 `fix: keep stored port/url values and cap HTTP response bodies`

S1 - The commit changes `store.py`, `adapters/base.py`, `adapters/hackertarget.py`,
their tests and docs/09. No unrelated files.

S2 - Every writer in `store.py` was re-audited for a defaulted column being reset
on conflict:

| Method | Conflict-updated columns | Verdict |
|---|---|---|
| `upsert_subdomain` | `last_seen_run` (always), `state`, `confidence`, `source_count`, `is_wildcard` (COALESCE) | keeps omitted values; explicit `0`/`False` overwrite |
| `upsert_port` | `last_seen_run` (always), `state` (always), `service`, `version`, `confidence` (COALESCE) | `state` is required, not defaulted, so updating it is intended; no reset |
| `upsert_url` | `last_seen_run` (always), `category`, `patterns_json`, `source_count` (COALESCE) | keeps omitted values; explicit `""`/`[]`/`0` overwrite |
| `add_subdomain_source`, `add_port_source` | `INSERT OR IGNORE`, composite primary key | no defaulted column is updated. First `seen` value wins per `(port, run, tool)`; cross-run diffs are unaffected |
| `append_host_status`, `record_tool_run`, `create_scan_run` | insert-only | no conflict path |
| `create_target` | `ON CONFLICT DO NOTHING` | `created_at` preserved |

No other reset was found. `insert` defaults use `COALESCE(:x, ...)` too, so a fresh
row and a conflict row agree on what `None` means.

S3 - Tests added: explicit `source_count=0` and `is_wildcard=False` overwrite;
explicit `service=""`/`version=""` overwrite; explicit `category=""`,
`patterns=[]` and `source_count=0` overwrite; body exactly at `MAX_BODY_BYTES`
passes; body at `MAX_BODY_BYTES + 1` fails; chunked body with no
`Content-Length` is capped; a lying small `Content-Length` with a large body is
capped. Mixed-case quota text (`API count Exceeded`) was already covered.

S4 - docs/09 already states the 10 MiB stream cap and the failed `ToolResult`
behaviour; no doc change was needed for the tests.

S5 - No new subprocess, scope, secret or pacing path. The body cap is a memory
safety control and stays enforced while streaming.

S6 - Mutations (each temporarily applied to `src/`, then restored):

- `source_count = COALESCE(:source_count, subdomains.source_count)` -> `..., 0)`:
  `test_upsert_subdomain_keeps_values_when_omitted` failed (`assert 0 == 3`).
- `if size > MAX_BODY_BYTES:` -> `if size > MAX_BODY_BYTES * 1000:`: the +1,
  chunked and lying-length tests failed.
- quota check deleted: `test_hackertarget_free_quota_is_reported` failed with
  `hackertarget: unexpected response (not host,ip)`.

S7 - Gate at the end of the audit: see "Gate" below.

## B - e40091d `feat: define the free-first API key policy and registry keys`

S1 - Adds the docs/05 6.1 key policy, `keys` parsing/validation, `ToolSpec.keys`,
`tools.yaml` entries and registry tests.

S2 - Corrections made after fetching the official pages (all on 2026-11-13):

- **Cert Spotter.** `https://sslmate.com/help/reference/ct_search_api_v1` says an
  API key is a Bearer token (or Basic username) and that only *unauthenticated*
  "List Issuances" queries are limited per hour, for evaluation. It gives no
  number and no authenticated quota. The old `adds` text ("free ... 100
  queries/hour") mixed the anonymous limit into the key entry; it now says the
  key authenticates queries and the unauthenticated limit is for evaluation.
  The API defines no environment variable name, so `CERTSPOTTER_API_KEY` stays
  reconkit's own name.
- **subfinder.** `https://docs.projectdiscovery.io/opensource/subfinder/install`
  lists 27 providers that need keys, but states they are stored only in
  `$HOME/.config/subfinder/provider-config.yaml`. No per-provider environment
  variable is documented, so a `keys` entry would pass an env var the child
  ignores. No `keys` entry was invented; the provider list, the file-based
  mechanism and the unverified free tiers are recorded under Open risks in
  PROGRESS. Doctor cannot hint at these keys until a provider-config bridge is
  designed.
- **`needs_key` vs `keys`.** `keys` is now the only per-tool key field.
  `urlscan`, `chaos` and `github_subdomains` were migrated, `needs_key` was
  removed from `tools.yaml`, and `registry._spec()` raises `ConfigError` if it
  reappears. docs/05 6.1 and docs/09 section 1 were updated first.
- **Chaos env name.** The chaos-client README documents `PDCP_API_KEY`, not
  `CHAOS_API_KEY`; the registry now uses the real name.
- **urlscan / github_subdomains.** Verified free account + API key
  (`https://urlscan.io/user/signup`) and `GITHUB_TOKEN` (read by the tool,
  `https://github.com/settings/tokens`; 60/hour anonymous, 5,000/hour
  authenticated per GitHub's REST rate-limit docs).

S3 - Tests: every `keys` env must appear in `.env.example`; malformed `keys`
(lowercase env, non-https, missing `adds`, non-list, non-mapping) raise
`ConfigError`; `tools.yaml` must contain no `needs_key`; an entry that still
uses `needs_key` raises `ConfigError`; the Cert Spotter text no longer claims
100 queries/hour; Chaos/urlscan/github env names are asserted.

S4 - docs/05 6.1 (single source of truth, subfinder exception), docs/05 7
(active env names), docs/09 section 1 and the tools.yaml header were updated
before the code.

S5 - The loader still enforces `https` URLs and `^[A-Z][A-Z0-9_]*$` env names;
no key value is stored or printed, and `.env.example` lists names only.

S6 - Mutations:

- https check -> `if False:`: both "must be https" cases failed.
- env regex -> `if False:`: the lowercase-env case failed.
- `PDCP_API_KEY` deleted from `.env.example`:
  `test_every_key_env_is_in_env_example` failed with
  `PDCP_API_KEY missing from .env.example`.

S7 - Gate at the end of the audit: see "Gate" below.

## C - 80ddd93 `feat: add dnspython, pyprobe and pyscan adapters`

S1 - Touches adapters, models, store, docs/09 and docs/04, three JSON fixtures and
one test file. `RunContext.ports` and `HostStatusRecord.location` are the model
changes.

S2 - The docs/09 text for per-host input is (as of this commit, section 3):

> Per-host adapters (`python` kind) read their inputs from `ctx.hosts` (and
> `ctx.ports` for port scanners); both are already scope-checked by the engine.
> `pyscan` calls `ctx.pacer.order(ctx.ports, kind="port")` itself because it
> owns the scan loop; the engine only fills the lists.

and the schema says `ports: list[int] = []  # port-scan input; empty = adapter
default list`. `RunContext` did gain `ports` in this commit, and docs/09 was
updated in the same commit, so the engine does not have to guess. The code and
docs agree; nothing was changed for this item.

`DnsResult` already had a structured `DnsOutcome` (`resolved`, `nxdomain`,
`noanswer`, `servfail`, `timeout`, `error`), so timeout and
SERVFAIL/NoNameservers are distinct values, not only an error string. No-answer
stays distinct from NXDOMAIN, and only NXDOMAIN produces `DEAD`. Audit fixes:

- An unexpected resolver exception was not caught (`RuntimeError` escaped
  `resolve_host` and aborted the stage). It now maps to `DnsOutcome.ERROR`.
- Per-host adapters did not normalize their input. Every per-host adapter now
  calls `validate_host()`; uppercase names are lowercased and IDN/invalid names
  are skipped and counted instead of being put in a request.
- `pyscan` closed the socket only after `wait_closed()` could be cancelled. It
  now calls `close()` (synchronous) before the first await, so cancellation
  cannot leak the connection.

S3 - Tests added for all four required DNS outcomes plus `resolved` and `error`
(asserted with distinct enum values), CNAME loop -> `error` not `DEAD`,
unexpected resolver exception -> `error` not a crash, uppercase host
normalization and IDN rejection in all three adapters, empty inputs for all
three, out-of-range ports (`0`, `-1`, `65536`, `70000` are not dialled), the
pyscan semaphore bound, binary banner bytes never read, cancellation closing the
writer, and the existing "Location to an out-of-scope host is recorded but not
followed" test (`outside.example.net`, exactly one request).

S4 - docs/09 now records the structured DNS outcomes and the per-host
`validate_host()` rule. The three synthetic fixtures are listed explicitly under
Open risks in PROGRESS.

S5 - No adapter imports `store`, `scope`, `ui` or `cli`; the dependency test
still covers all three files. No payload is sent, no banner is read, and
`pyprobe` still does not follow redirects.

S6 - Mutations:

- TIMEOUT -> NXDOMAIN: `test_dnspython_nxdomain_timeout_servfail_are_distinct`
  failed (`assert <DnsOutcome.NXDOMAIN> is <DnsOutcome.TIMEOUT>`).
- `follow_redirects=False` -> `True`: the redirect test failed (no record after
  `TooManyRedirects`).
- pyscan semaphore -> `Semaphore(999)`: the bound test failed (`assert 10 == 2`).
- `writer.close()` removed: the cancellation test failed
  (`assert False is True`).
- the `except Exception` branch removed: the unexpected-exception test failed
  with `RuntimeError: resolver bug`.

S7 - Gate at the end of the audit: see below.

## Gate

Run from the canonical checkout with the venv activated, after all audit changes:

```
pytest -q                    238 passed, 1 skipped in 7.33s
ruff check .                 All checks passed!
ruff format --check .        57 files already formatted
mypy src/reconkit            Success: no issues found in 37 source files
```

The 1 skipped test is the existing Windows-only process-group kill test.

## Part 4: binary adapters f3

- Docs read / goal: `docs/09_TOOL_CONTRACTS.md`, `docs/03_ARCHITECTURE.md` (adapter file names), `docs/05_SECURITY.md` 4-6, `tools.yaml`, and the official pages for subfinder, assetfinder, ProjectDiscovery httpx and naabu. Implement every remaining phase-2 binary adapter: subfinder, assetfinder, httpx, naabu.
- Decisions and assumptions: a shared `BinaryAdapter` in `adapters/base.py` resolves `~/.reconkit/bin` before `PATH` and verifies identity from the registry `version_cmd` output. subfinder provider keys are bridged to a temporary `provider-config.yaml` because Part 4 requires it and subfinder has no env-var reader. httpx JSON lines without `status_code` are failed probes and are skipped, not marked ALIVE. Empty host lists are a failed command, not an empty argv. naabu always uses `-scan-type c`.
- Decisions for user review (things the user may want to overrule): subfinder now lists four keys (certspotter, chaos, github, virustotal) and the adapter writes them to a temp file; this reverses the audit's "no env bridge" open risk. A wrong binary and a missing binary both return `installed=False`, but a wrong binary also sets `path` so doctor can show it. `chmod 0600` on the temp config is best-effort on Windows.
- Docs changed first: `docs/09` section 3 (BinaryAdapter, identity, missing/exit/timeout, subfinder bridge, httpx/naabu flags), `docs/05` 6.1 (subfinder exception replaced by the bridge), `tools.yaml` (`keys` for subfinder, note updated).
- Deviations: the provider config is written synchronously in the event-loop thread (bounded, under 1 KiB, local disk). Fixtures are synthetic because none of the four binaries is installed. The rate-cap mutation target does not apply to f3: all four tools are `core`, and no opt-in tool is in this part.
- Files touched: `src/reconkit/adapters/{base,subfinder,assetfinder,httpx_tool,naabu,__init__}.py`, `tests/test_binary_adapters.py`, four synthetic fixtures, `tools.yaml`, `docs/05`, `docs/09`, `docs/PROGRESS.md`.
- Requirement -> test table:
  - adapter for every remaining phase-2 tool -> `test_binary_adapters_are_registered`
  - identity check, not name only -> `test_projectdiscovery_httpx_identity_is_accepted`, `test_python_httpx_cli_is_rejected`, `test_assetfinder_usage_identity`, `test_identity_timeout_is_not_installed`
  - argv list, no shell, validated hosts, leading `-` rejected -> `test_subfinder_command_and_rate_flag`, `test_assetfinder_command`, `test_httpx_command_dedupes_and_lowercases_hosts`, `test_naabu_command_and_ports`, `test_flag_like_host_is_rejected_before_argv`, `test_flag_like_target_is_rejected`, `test_empty_host_list_is_a_failed_command`
  - key never in argv; temp file deleted on success/failure/timeout -> `test_subfinder_writes_and_deletes_provider_config`, `test_subfinder_deletes_provider_config_on_parse_failure`, `test_subfinder_deletes_provider_config_on_timeout`, `test_subfinder_without_keys_has_no_provider_flag`, `test_subfinder_provider_envs_are_registry_keys`
  - parse normal/empty/malformed -> `test_subfinder_and_assetfinder_parse_fixtures`, `test_httpx_parse_fixture`, `test_naabu_parse_fixture`, `test_empty_output_is_ok`, `test_malformed_output_fails_without_raising`
  - missing binary / non-zero / timeout distinct -> `test_run_missing_binary_is_distinct`, `test_run_nonzero_exit_is_distinct`, `test_run_timeout_is_distinct`, `test_run_runner_error_is_a_failed_result`
  - no secret in result -> `test_subfinder_writes_and_deletes_provider_config`
  - AST import rule -> `test_binary_adapters_import_no_forbidden_modules`
  - mock mode -> `test_mock_mode_reads_fixture`
  - adversarial: ANSI, duplicates, stderr noise, truncation, empty vs partial, uppercase, IPv6 -> `test_ansi_and_log_noise_are_ignored`, `test_duplicate_httpx_and_naabu_lines_are_merged`, `test_run_truncated_output_is_reported`, `test_httpx_parser_skips_lines_without_a_status`, `test_httpx_parser_handles_url_input`, `test_naabu_parser_accepts_ipv6`
- Self-review findings (S2 lists, S3 raw output):
  - Broad except: none added. Specific handlers only: `(TypeError, ValueError)` for validation, `OSError`/`yaml.YAMLError` for the temp file, `RuntimeError` for runner pipe failure.
  - External input: `ctx.target` -> `validate_target`; `ctx.hosts` -> `validate_host`; `ctx.ports` -> `1..65535`; tool stdout -> strict per-line parser; version output -> identity markers; fixture files -> the same parser.
  - Secrets: key values only enter the 0600 temp file and the child env; argv holds only the temp path; `runner` redacts env values in stdout/stderr before the adapter sees them; tests assert no secret in argv/result.
  - Blocking call in async: one synchronous YAML write in `SubfinderAdapter.prepare` (bounded, local, no network); recorded above.
  - Escaping exceptions: parsers raise `ParseError`, `prepare` raises `ToolFailed`, `run_exec` `RuntimeError` is mapped; `asyncio.CancelledError` still propagates, and `prepare`'s `finally` deletes the temp file.
  - Unfinished path: engine wiring (`ctx.env` from `keys`, tool selection) is Part 6; real binaries are not installed, so identity markers are based on official docs, not a live run.
  - S3 raw: `assert` none; `shell=True` none; `TODO|FIXME|XXX|HACK` none; `print(` none; `subprocess` only `core/runner.py` plus the `base.py` docstring; `sqlite3` only `core/store.py`; `os.environ` none; broad except only the two justified earlier (`dnspython.py:130`, `store.py:202`); suppressions = 3, all pre-existing; adapter imports of store/scope/ui/cli none.
- Bugs found:
  1. httpx identity: name-only resolution would accept the Python `httpx` CLI. Root cause: no identity check in the base. Fix: `BinaryAdapter.check_installed` matches the tool's own banner/version text. Guard: `test_python_httpx_cli_is_rejected`.
  2. httpx JSON without `status_code` would have been stored as `ALIVE`. Root cause: no distinction between a response and a failed probe. Fix: skip status-less lines. Guard: `test_httpx_parser_skips_lines_without_a_status`.
  3. `run_exec` `RuntimeError` could escape an adapter. Root cause: only parse/fetch errors were mapped. Fix: map it to a failed result. Guard: `test_run_runner_error_is_a_failed_result`.
  4. `yaml.safe_dump` failure could leave the provider file behind. Root cause: only `OSError` was caught. Fix: catch `yaml.YAMLError` and unlink. Not separately testable without monkeypatching PyYAML; covered by inspection.
- Mutation proofs: key-in-argv -> `test_subfinder_writes_and_deletes_provider_config` failed on `assert all("secret" not in arg ...)`; identity check -> `test_python_httpx_cli_is_rejected` failed with `installed=True`; rate-cap refusal -> not applicable (no opt-in tool in f3, recorded above). `git status --short` after restore showed only the intended Part 4 changes.
- Raw check output (twice): `295 passed, 1 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`, `ALL CHECKS PASS`, exit 0 (both runs).
- Not verified: real subfinder/assetfinder/httpx/naabu binaries and their exact version banners; whether real subfinder accepts the generated provider-config on all versions; chmod on Windows; JSON fields beyond the official docs; rate flags against live binaries; installer-provided binary paths.
- Next part must know: `ADAPTERS` now covers every phase-2 tool. Engine work must pass only the tool's `keys` env, and subfinder's temp file is handled inside the adapter. Adapter file names follow docs/03: `httpx_tool.py`, not `httpx.py`.

### Tool table (from tools.yaml)

| Tool | Stage | Tier | Adapter |
|---|---|---|---|
| crtsh | subs | core | yes |
| certspotter | subs | core | yes |
| otx | subs | core | yes |
| hackertarget | subs | core | yes |
| urlscan | subs | core | no |
| subfinder | subs | core | yes |
| assetfinder | subs | core | yes |
| amass | subs | core | no |
| findomain | subs | core | no |
| chaos | subs | core | no |
| github_subdomains | subs | core | no |
| dnspython | dns | core | yes |
| dnsx | dns | core | no |
| puredns | dns | core | no |
| massdns | dns | core | no |
| dig | dns | core | no |
| pyprobe | live | core | yes |
| httpx | live | core | yes |
| httprobe | live | core | no |
| tlsx | live | core | no |
| smap | ports | core | no |
| pyscan | ports | core | yes |
| naabu | ports | core | yes |
| nmap | ports | core | no |
| rustscan | ports | core | no |
| masscan | ports | opt_in | no |
| httpx_tech | tech | core | no |
| whatweb | tech | core | no |
| wafw00f | tech | core | no |
| cdncheck | tech | core | no |
| webanalyze | tech | core | no |
| gau | urls | core | no |
| waybackurls | urls | core | no |
| katana | urls | core | no |
| hakrawler | urls | core | no |
| gospider | urls | core | no |
| subjs | urls | core | no |
| unfurl | urls | core | no |
| urlfinder | urls | core | no |
| nuclei | vulns | core | no |
| subzy | vulns | core | no |
| dnsreaper | vulns | core | no |
| nikto | vulns | opt_in | no |
| ffuf | vulns | opt_in | no |
| gowitness | shots | opt_in | no |
| dalfox | vulns | intrusive | no |
| crlfuzz | vulns | intrusive | no |
| sqlmap | vulns | intrusive | no |

Per-stage counts: subs 11, dns 5, live 4, ports 6, tech 5, urls 8, vulns 8, shots 1. `subs` is above the 3-8 guide (11) and `shots` below it (1, Phase-3 opt-in); no tool was invented or removed.

## Addendum: regression and pitfalls rules

- Goal: make every known trap visible before coding and make every future fix carry a failing-then-passing guard. Applied before resuming the Part 5 review, as instructed.
- Docs first: added the Known pitfalls table at the top of this file, the `REGRESSION AND PITFALLS RULES` section to `docs/MASTER_PLAN.md`, the pitfall line to G1, the `Pitfalls added this part` line to S7, and the session-start line to `AGENTS.md`. `scripts/check.ps1` now prints `WARN: fix commit without a test change` when HEAD is a `fix:` subject with no `tests/` file.
- Back-fill: no behavior changed. Existing guards were tagged with `Regression: PIT-xx` docstrings: PIT-01 `test_dnspython_nxdomain_timeout_servfail_are_distinct`; PIT-02 `test_tool_rate_args_slow_passive_vs_active`; PIT-03 the three `test_upsert_*_keeps_*_when_omitted` tests; PIT-04 `test_redact_cases`; PIT-05 `test_timeout_keeps_partial_output`; PIT-06 `test_timeout_kills_child` (skipped on Windows); PIT-11 `test_workspace_rejects_unsafe_filenames`; PIT-13 `test_wildcard_labels_are_unique_valid_and_under_the_target`; PIT-14 `test_python_httpx_cli_is_rejected`; PIT-15 `test_httpx_parser_skips_lines_without_a_status`; PIT-16 `test_run_runner_error_is_a_failed_result`; PIT-18 `test_subfinder_writes_and_deletes_provider_config`; PIT-19 `test_tools_yaml_has_no_legacy_needs_key`; PIT-20 `test_lying_small_content_length_is_still_capped`; PIT-21 `test_wildcard_unknown_is_not_none`; PIT-22 `test_workspace_redacts_two_secrets_and_a_bearer_token`; PIT-24 `test_workspace_rejects_invalid_targets`.
- Failing-before-fix evidence already recorded: PIT-01/02/03/04/20 in the Part 3-AUDIT mutation proofs; PIT-14/15/16/18 in the Part 4 proofs. No new mutation was needed because those tests are the same guards, only tagged. New Part 5 mutations are recorded in the Part 5 entry.
- UNTESTED rows: PIT-06 (needs Linux), PIT-17 (needs a PyYAML fault injection), PIT-23 (review fix; no observable behavior test). PIT-07/08/09/10/12/25/26 are non-code traps with `n/a`.
- Raw WARN simulation (the current HEAD is `wip:`, so the real gate cannot emit it yet): subject `fix: simulate` with `src/reconkit/core/wildcard.py` printed `WARN-SIM: fix commit without a test change`; the same subject with `tests/test_wildcard_workspace.py` printed `WARN-SIM: no warning`.
- Raw check output after the addendum: `342 passed, 2 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`, `ALL CHECKS PASS`, gate exit 0. A separate `ruff check .` printed `All checks passed!`.
- Pitfalls added this part: PIT-01 through PIT-26.
- Not verified: the real gate's WARN line before a real `fix:` commit (only the simulated branch was run); PIT-06 on Linux; PIT-17 and PIT-23 as above.

## Part 5: wildcard detection + target workspace

- Docs read / goal: `docs/03_ARCHITECTURE.md` section 5 (workspace layout) and section 8 (wildcard), `docs/04_DATABASE.md` (`subdomains.is_wildcard`, redaction rule), `docs/05_SECURITY.md` sections 6 (redaction, 0700 workspace), `docs/09_TOOL_CONTRACTS.md` section 5 (wildcard/confidence). Implement `core/wildcard.py` and `core/workspace.py` with no new dependencies.
- Decisions and assumptions: the detector takes an injected `probe` rather than importing the DNS adapter at runtime, so `core` keeps its dependency direction; the engine passes `DnsPythonAdapter.resolve_host` bound to the run context, which keeps probes on the same resolver and limiter. `rng` is a required injected `Rng` protocol (no `random.Random()` default, which S311 rejects). One resolved probe is enough for `present`; `unknown` covers timeout/SERVFAIL/no-answer/error only when nothing resolved. A host matches when its CNAME is in the wildcard CNAME set or all of its IPs are in the wildcard IP set. Partial probe sets still count as `present`.
- Decisions for user review (things the user may want to overrule): `Workspace` rejects a target whose first label is a Windows device name (`con.example.com`) even though `validate_target()` accepts it, because Windows cannot create that directory. Workspace writes are synchronous (`fsync` + `os.replace`); the engine must keep large outputs off the event loop. The workspace root is created but not chmodded; only the target and stage directories get `0700`.
- Docs changed first: `docs/03` gained the Workspace API, the wildcard API and the unknown/partial rules; `docs/09` section 5 gained the exact matching and unknown rule; `docs/05` now says workspace files are redacted before the write.
- Deviations: Part 5 landed as three commits because the regression/pitfalls addendum required a `wip:` commit mid-part (`d9cf6c7`), then its own `docs:` commit (`49c68ae`), then this review record. The code is complete in `d9cf6c7`; no code changed in the later commits. The first mutation attempt used the full filename parameter list, reached the UNC case, and hung on the network share until the 180 s tool timeout; the files were restored and the proof was re-run with only `../escape.txt` under a 60 s timeout. No repo file was created by the hung run (`workspaces/` absent).
- Files touched: `src/reconkit/core/workspace.py`, `src/reconkit/core/wildcard.py`, `tests/test_wildcard_workspace.py`, `docs/03`, `docs/05`, `docs/09`, `docs/REVIEW_LOG.md`, `docs/PROGRESS.md`.
- Requirement -> test table:
  - wildcard yes / no / unknown(timeout) -> `test_wildcard_present_and_only_wildcard_ips_match`, `test_wildcard_none_when_every_probe_is_nxdomain`, `test_wildcard_unknown_is_not_none`
  - partial wildcard (some resolve, some NXDOMAIN) -> `test_wildcard_present_and_only_wildcard_ips_match` (2 resolved + 1 NXDOMAIN), `test_wildcard_resolved_beats_a_failed_probe`
  - CNAME wildcard -> `test_wildcard_cname_answer_matches_cname`
  - unknown is not no-wildcard -> `test_wildcard_unknown_is_not_none`, `test_wildcard_timeout_plus_nxdomain_is_unknown`
  - traversal rejected -> `test_workspace_rejects_unsafe_filenames`, `test_workspace_rejects_unknown_stages`, `test_workspace_rejects_invalid_targets`
  - domain validated -> `test_workspace_rejects_invalid_targets`, `test_workspace_create_builds_documented_layout`
  - redaction applied -> `test_workspace_redacts_two_secrets_and_a_bearer_token`
  - atomic write leaves no partial file -> `test_workspace_failed_replace_leaves_no_partial_file`, `test_workspace_same_filename_twice_replaces_atomically`
  - documented layout only -> `test_workspace_create_builds_documented_layout`, `test_workspace_rejects_unknown_stages`
  - empty / very large output -> `test_workspace_empty_output_is_written`, `test_workspace_large_output_is_written`
  - labels valid and under target -> `test_wildcard_labels_are_unique_valid_and_under_the_target`
  - injected RNG -> `test_wildcard_labels_are_unique_valid_and_under_the_target` (CyclingRng)
  - probe exception -> `test_wildcard_unexpected_probe_exception_is_unknown`
- Self-review findings (S2 lists, S3 raw output):
  - Broad except: `except Exception` in `WildcardDetector.detect` (a probe failure must be `unknown`, never abort the scan) and `except BaseException` in `Workspace.write` (cleanup of the temp file on cancellation/KeyboardInterrupt, then re-raise). Both are deliberate and recorded; no other new broad handler.
  - External input: `target` -> `validate_target()`; `stage` -> exact `STAGES` allowlist; `filename` -> regex, length, trailing-dot, reserved-name and one-segment checks plus `resolve()` containment; `text`/`secrets` -> type checks and `store.redact()`; probe results -> `outcome` comparison and IP/CNAME sets; `rng` -> the `Rng` protocol.
  - Secrets: `redact()` runs before `mkstemp`, the temp file is `0600`, the destination keeps `0600`, and no secret enters a filename or error. Tests assert both supplied secrets and a Bearer token are gone.
  - Blocking call in async: `Workspace.write` is synchronous (local `fsync` + `os.replace`); the engine must offload large raw writes. No new blocking call inside an `async def`.
  - Escaping exceptions: `path()`/`write()` raise `ValueError`/`TypeError`/`OSError` by design; `detect()` catches probe exceptions and lets `CancelledError` (a `BaseException`) propagate. The temp file is unlinked on every failure path.
  - Unfinished path: engine wiring is Part 6 (construct the detector with `partial(dns.resolve_host, ctx)` and `random.Random`, pass `wildcard_check.probes`, call `Workspace.create` with the allowed env values).
  - S3 raw: `assert` none in the two modules; `shell=True` none; `TODO|FIXME|XXX|HACK` none; `print(` none; `subprocess` only `core/runner.py`; `sqlite3` only `core/store.py`; `os.environ` none; broad except the two above; suppressions still the 3 pre-existing; no runtime core -> adapter import (`DnsResult` is `TYPE_CHECKING` only).
- Bugs found:
  1. `random.Random()` as a default tripped S311. Root cause: convenience default. Fix: require an injected `Rng`; tests use `CyclingRng`. Guard: PIT-13 `test_wildcard_labels_are_unique_valid_and_under_the_target`.
  2. `Workspace.create` chmodded `self.root`, which may be a caller-owned parent. Root cause: applied workspace mode to the shared root. Fix: chmod only the target and stage dirs. Guard: none (PIT-23 UNTESTED; review fix).
  3. A test edit produced `probe = ...    result = ...` on one line (syntax error). Root cause: a replacement lost a newline. Fix: split the lines; collection passes. Not a product bug.
  4. The first mutation run hung on a UNC path. Root cause: with the traversal checks disabled, the test tried to write to `\\server\share`. Fix: re-ran the proof with only the `../escape.txt` case and a timeout. No product change; recorded above.
- Mutation proofs: traversal checks disabled (all four guards no-op) -> `test_workspace_rejects_unsafe_filenames[../escape.txt]` failed `DID NOT RAISE ValueError`, 1 failed; redaction disabled (`cleaned = text`) -> `test_workspace_redacts_two_secrets_and_a_bearer_token` failed because `sk-live-abc123` was still present, 1 failed; UNKNOWN changed to NONE -> `test_wildcard_unknown_is_not_none[timeout|servfail|noanswer|error]` all failed `NONE is not UNKNOWN`, 4 failed. Each file was restored from a backup; the post-restore grep showed no mutation and the full gate passed.
- Raw check output (twice): `342 passed, 2 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`, `ALL CHECKS PASS`, exit 0. The new test file alone: `47 passed, 1 skipped`.
- Not verified: real wildcard DNS (no resolver/network run) and real CNAME wildcard behavior; POSIX `0700`/`0600` assertions are skipped on Windows; Windows-reserved target rejection is only simulated on this host; engine integration (Part 6) and the effect of synchronous large writes on the loop; the addendum's real `fix:`-commit WARN path.
- Pitfalls added this part: PIT-13, PIT-21, PIT-22, PIT-24.
- Next part must know: `WildcardDetector(probe, rng, probes)` requires the engine to bind the DNS adapter to the run context; `matches()` is the only `is_wildcard` decision; `Workspace.create(root, target, secrets)` is the only constructor the engine should use, and writes are redacted atomically.

## Part 6a: staged engine, selection and safety gates

- Docs read / goal: `docs/09_TOOL_CONTRACTS.md` sections 3-5 (selection rules, wildcard, host rule), `docs/01_PRD.md` pipeline description, `docs/02_CLI_UX.md` flags/speed table, `docs/03_ARCHITECTURE.md` data flow and dependency rules, `docs/04_DATABASE.md` bulk-write/redaction rules. Build the engine skeleton: stage order, tool selection, tier/mode/scope gates, env filtering, phase timeouts, mock pipeline and batched writes.
- Decisions and assumptions: one `scan_runs` row per executed stage; one `tool_runs` row per selected or skipped tool. `subs` gets `[target]`; `dns`/`live` get the target plus discovered hosts; `ports` gets only hosts with an ALIVE record, and is skipped when none exist. The target is always checked against scope for active stages even when it is the only host. An active stage whose `require_active()` fails is skipped with a recorded reason, not raised out of the pipeline; Part 8 will refuse `--active` earlier. `--tools` is validated globally (unknown and intrusive names raise `ConfigError`); `opt_in` needs `--include-noisy` or an explicit `--tools`; intrusive tools are never selected. `--mock` bypasses `check_installed()` and every adapter's non-mock path. `FindingRecord` is not persisted because the findings table is still deferred.
- Decisions for user review (things the user may want to overrule): a port scan with no stored ALIVE host produces no run instead of scanning the root target; a scope failure silently skips active tools (the CLI's refusal is the user-facing guard); `scan_runs.stage` is the stage name, not a single `run` row for the whole pipeline.
- Docs changed first: `docs/03` gained the Engine API and the env/selection/mock/transaction contract; `docs/04` gained `store.transaction()` semantics; docs/09 already specified the selection rules and needed no change.
- Deviations: `Store.transaction()` uses SQLite's implicit transaction rather than an explicit `BEGIN`; the explicit form failed inside the implicit transaction that the previous write left open (PIT-27). Engine asset writes are batched; `tool_runs` are recorded per tool as they finish so a phase timeout still leaves evidence.
- Files touched: `src/reconkit/engine.py`, `src/reconkit/core/store.py`, `tests/test_engine.py`, `tests/test_store.py`, `docs/03`, `docs/04`, `docs/REVIEW_LOG.md`, `docs/PROGRESS.md`.
- Requirement -> test table:
  - stage order -> `test_stage_order_and_tool_rows`
  - tier gating / opt_in -> `test_tier_gating_and_explicit_intrusive_refusal`
  - unknown or intrusive `--tools` refused -> `test_tier_gating_and_explicit_intrusive_refusal`
  - active without `--active` skipped -> `test_active_without_flag_skips_and_scope_drops_host`
  - out-of-scope host dropped before active contact -> `test_active_without_flag_skips_and_scope_drops_host`
  - env filtering and `--no-keys` -> `test_env_filtering_and_no_keys`
  - one tool crashing, others succeed -> `test_one_crash_does_not_stop_the_stage`
  - all tools failing -> `test_all_tools_failing_is_not_an_exception`
  - phase timeout -> `test_phase_timeout_records_a_timeout_row`
  - redacted stored error -> `test_tool_error_is_redacted_before_storage`
  - slow mode runs one at a time -> `test_slow_mode_runs_one_tool_at_a_time`
  - disallowed tool's command never built -> all engine tests use an adapter whose `build_command` raises; `rec.built == []` in `test_stage_order_and_tool_rows`
  - one `tool_runs` row per tool -> `test_stage_order_and_tool_rows`
  - transaction commits/rolls back -> `test_transaction_commits_once_and_rolls_back`
- Self-review findings (S2 lists, S3 raw output):
  - Broad except: `except Exception` in `Engine._run_one` (convert an adapter bug into a failed, redacted result), `except TimeoutError` for per-tool and phase timeouts, and `except BaseException` in `Store.transaction` for rollback-on-cancel. No other new handler.
  - External input: `ScanOptions` (speed checked against the literal set, timeout > 0, tools exist and are not intrusive), `target` via `validate_target`, hosts via `validate_host` + target suffix, scope via `load_scope`/`require_active`, adapter records via Pydantic models, env only through each spec's `keys`.
  - Secrets: `self._secrets` is used for workspace redaction, exception redaction and `record_tool_run`; `scan_runs.params_json` contains only tool names and booleans; `ctx.env` contains only the current tool's keys. No full environment is copied.
  - Blocking call in async: `check_installed()` is now run with `asyncio.to_thread`; `Workspace.create`, `load_scope` and `require_active` do short synchronous local file I/O, and `RateLimiter`/`Pacer` take the injected sleep/clock. Raw workspace output is not written by the engine yet, so the large-write risk is still open.
  - Escaping exceptions: `ConfigError` escapes for invalid selection (the CLI maps it to exit 2); `ScopeError` is caught and becomes skipped rows; adapter exceptions become failed results; `CancelledError` propagates (Part 6b cancellation work).
  - Unfinished path: consensus/confidence, host-state transitions, resume and exit codes are Part 6b; `FindingRecord` persistence is deferred with the findings table; the engine does not yet pass wildcard results into `is_wildcard` or write raw adapter output.
  - S3 raw: `assert` none in `engine.py`; `shell=True` none; `TODO|FIXME|XXX|HACK` none; `print(` none; `subprocess` only `core/runner.py`; `sqlite3` only `core/store.py`; `os.environ` none; broad except only the engine handler above plus the previously justified ones; suppressions still 3.
- Bugs found:
  1. PIT-27: `store.transaction()` raised `sqlite3.OperationalError: cannot start a transaction within a transaction` in `test_transaction_commits_once_and_rolls_back`. Root cause: explicit `BEGIN` while SQLite's implicit transaction was still open. Fix: drop the explicit `BEGIN`, keep the depth counter and commit/rollback at block exit. Guard: `test_transaction_commits_once_and_rolls_back` (failing output in the mutation record below).
  2. Test helper `class Fake: stage = stage` raised `NameError` (class scope does not close over the function parameter); fixed by assigning `Fake.stage` after the class. Test-only, no product change.
- Mutation proofs: scope gate disabled (`_active_hosts` returns hosts unchanged) -> `test_active_without_flag_skips_and_scope_drops_host` failed with `api.example.com` in the live hosts, 1 failed; env filter removed (`_tool_env` returns all env) -> `test_env_filtering_and_no_keys` failed with `{'ONLY_ME': ..., 'OTHER': 'not-for-you'}`, 1 failed; tier gates disabled -> `test_tier_gating_and_explicit_intrusive_refusal` failed with `['core', 'noisy', 'intrusive']`, 1 failed. All files restored from backups; the post-restore grep found no mutation.
- Raw check output (twice): `352 passed, 2 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`, `ALL CHECKS PASS`, exit 0 (both runs).
- Not verified: real adapters/network and installed binaries through the engine; resume and cancellation; consensus/host-state results (Part 6b); scope files with regex/CIDR entries and a real `allow_active: false`; Windows process behaviour. The mock pipeline is covered only with fake adapters, not the real fixture-backed adapters end to end.
- Pitfalls added this part: PIT-27.
- Next part must know: `Engine.run` returns `ScanSummary` with one `StageOutcome` per executed stage; `tool_runs` rows exist even for skipped/timeout tools; Part 6b must add confidence/host states/resume and must not move consensus out of `engine.py`. The store batch helper is `with store.transaction():`.

## Part 6b: confidence, host states, resume and exit codes

- Docs read / goal: `docs/01_PRD.md` Features 4 and 6, `docs/02_CLI_UX.md` exit-code table and the missing `--resume` flag, `docs/03_ARCHITECTURE.md` consensus/data-flow sections, `docs/04_DATABASE.md` `subdomains`/`host_status_history` schema and state rule, `docs/09_TOOL_CONTRACTS.md` section 5. Implement confidence, the unconditional host-state rule, stage resume, injected timestamps and a typed exit result in `engine.py` only.
- Decisions and assumptions: confidence counts **distinct** tools (`len(set(sources))`), with disagreement forced to `UNCONFIRMED`. Discovery merges by `fqdn`/`url`; live merges by host; ports merge by `(fqdn, ip, port)`. `min_sources` filters discovery and port rows. `--resume` uses the newest `scan_key` in `scan_runs.params_json`, skips stages whose rows are `completed`/`partial`, marks leftover `running` rows `interrupted`, and creates a fresh row for the unfinished stage. On resume, discovered/alive sets are reseeded from `Store.subdomains()`. The state rule is unconditional: only NXDOMAIN can produce `DEAD`; timeout/SERVFAIL/no-answer/error keep the previous state and warn. `SHUT_DOWN` is chosen only when the previous state was `ALIVE` or `DNS_ONLY`. Timestamps come from the injected `now` source, default `store.utc_now()`.
- Decisions for user review (things the user may want to overrule): resume is stage-level, not tool-level; a crashed stage is rerun, so tools that finished inside it run again (asset writes are batched at stage end). `scope_denied` maps to exit 3 even when passive tools succeeded. All tools failing maps to exit 4; a mixture maps to 5. A first-run timeout records `UNKNOWN` without a history row; an established host keeps its state and gets a warning. CNAME warnings are in `ScanSummary.warnings`, not the database, because `host_status_history` has no CNAME column. Wildcard detection remains unwired (Open risk).
- Docs changed first: `docs/02` gained `--resume`; `docs/03` gained the injected `now`, `min_sources`/`resume`, typed `ExitCode`, the full transition table, the unconditional timeout rule and the CNAME warning; `docs/04` gained the timestamp/resume rules and the `Store.scan_runs()`/`Store.subdomains()` read queries.
- Deviations: `--resume` was documented in `docs/08` but missing from the `docs/02` flag table, so it was added there first. Resume is stage-level as above. The engine's `now` default is a public `store.utc_now()` wrapper; `Store._utc_now` remains for direct store calls. `ScanSummary.exit_code` is an `IntEnum`; no `sys.exit()` exists in `engine.py`.
- Files touched: `src/reconkit/engine.py`, `src/reconkit/core/store.py`, `tests/test_engine.py`, `docs/02_CLI_UX.md`, `docs/03_ARCHITECTURE.md`, `docs/04_DATABASE.md`, `docs/REVIEW_LOG.md`, `docs/PROGRESS.md`.
- Requirement -> test table:
  - HIGH with 3 distinct tools -> `test_confidence_three_distinct_tools_high`
  - MEDIUM with 2 -> `test_confidence_two_distinct_tools_medium`
  - LOW with 1 -> `test_confidence_one_tool_low`
  - UNCONFIRMED on disagreement -> `test_confidence_disagreement_unconfirmed`, `test_engine_disagreement_is_unconfirmed`
  - same tool three times is not HIGH -> `test_same_tool_three_results_is_not_high`
  - engine persistence of HIGH/3 sources -> `test_engine_persists_three_distinct_tools_as_high`
  - timeout/SERVFAIL never DEAD -> `test_regression_dns_timeout_not_dead`
  - SHUT_DOWN after ALIVE, external CNAME -> `test_shut_down_after_alive_with_external_cname`
  - DEAD only on NXDOMAIN -> `test_dead_only_on_nxdomain`
  - UNKNOWN -> ALIVE -> SHUT_DOWN -> ALIVE recovery -> `test_state_recovers_unknown_alive_shut_down_alive`
  - unprobed stays UNKNOWN -> `test_unprobed_host_stays_unknown`
  - DNS resolved, no web response -> `test_dns_resolved_without_web_is_dns_only`
  - deterministic timestamps -> `test_injected_clock_controls_state_and_run_timestamps`
  - resume skips completed stages, reseeds hosts, no duplicate rows -> `test_resume_skips_completed_stages_and_continues`
  - exit 0 clean / 3 scope / 4 no tool / 5 partial / crash -> `test_exit_code_clean_is_success`, `test_exit_code_scope_violation`, `test_exit_code_all_tools_failed_is_no_tool`, `test_exit_code_partial_success`, `test_exit_code_tool_crash_is_partial`
  - 1/2/130 constants -> `test_exit_code_constants_match_docs`
  - `--min-sources` filtering -> `test_min_sources_hides_low_source_results`
  - no `consensus.py` -> `Get-ChildItem -Recurse -Filter 'consensus*.py' src\reconkit` returns nothing
- Self-review findings (S2 lists, S3 raw output):
  - Broad except: `except Exception` in `Engine._run_one` (adapter crash becomes a redacted failed result) and around `_persist_stage` (mark the run `failed`, then re-raise); `except asyncio.CancelledError` marks the run `interrupted` and re-raises; `Store.transaction` still rolls back on `BaseException`. No other new handlers.
  - External input: `ScanOptions` fields validated (`speed`, `phase_timeout`, `min_sources`, tool names/tier); target via `validate_target`; hosts via `validate_host` + suffix; scope via `load_scope`/`require_active`; adapter records via Pydantic; resume rows parsed defensively (`json.loads`, `Stage(...)` caught).
  - Secrets: `_secrets` is used for workspace, error and `params_json` redaction; resume stores only a random `scan_key`; no env values enter `scan_runs` or warnings.
  - Blocking call in async: `check_installed()` stays on `asyncio.to_thread`; `Workspace.create`, `load_scope` and SQLite writes remain short synchronous local I/O. Resume reads all `scan_runs`/`subdomains` once at start.
  - Escaping exceptions: `ConfigError` escapes for invalid options; `ScopeError` becomes skipped active tools + exit 3; `CancelledError` is recorded and re-raised; adapter crashes become failed results.
  - Unfinished path: wildcard detection is still not wired into the engine; CNAME warnings are not persisted; `FindingRecord` remains unpersisted. Diff queries were not touched in this part.
  - S3 raw: `assert` none in `src`; `shell=True` none; `TODO|FIXME|XXX|HACK` only case-insensitive `Hackertarget` false positives; `print(` none; `subprocess` only `core/runner.py` plus docstrings; `sqlite3` only `core/store.py`; `os.environ` none; broad except only the engine handlers above plus the previously justified `dnspython`, `store`, `wildcard` and `workspace`; suppressions remain the 3 pre-existing test-only entries.
- Bugs found: PIT-28. Resume skipped completed stages but the restarted `live` stage saw only the target because `discovered`/`alive` were not reseeded from SQLite. Fix: `_seed_from_store()` on resume. Guard: `test_resume_skips_completed_stages_and_continues`; mutation 1 below shows it failing. No other product bug was found; the lost newline in the transition-table comment was a tooling artifact fixed before the gate.
- Mutation proofs: resume seeding disabled -> `test_resume_skips_completed_stages_and_continues` failed with `{'example.com'} == {'example.com', 'www.example.com'}`; uncertain DNS forced to DEAD -> `test_regression_dns_timeout_not_dead` failed with `DEAD is not ALIVE`; distinct-tool set replaced by list -> `test_same_tool_three_results_is_not_high` failed with `HIGH is not LOW`; all-failed exit changed to SUCCESS -> `test_exit_code_all_tools_failed_is_no_tool` failed with `SUCCESS is not NO_TOOL`. All files restored from a backup; the post-restore grep found no mutation.
- Raw check output (twice): `374 passed, 2 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`, `ALL CHECKS PASS`, exit 0 (both runs).
- Not verified: real DNS NXDOMAIN/CNAME behavior through the engine; a real interrupted process (the test uses `CancelledError`); tool-level resume; wildcard integration; CNAME persistence; real exit-code mapping in the CLI (Part 8); Windows/Linux process-group interruption.
- Pitfalls added this part: PIT-28.
- Next part must know: `ScanSummary.exit_code` is the only CLI exit signal; `summary.warnings` is in-memory; `Engine(now=...)` is the timestamp injection point; `Store.scan_runs()`/`subdomains()` are the resume reads; consensus and state logic stay in `engine.py`.

## Part 6b follow-up: double-confirmation, mixed scope denial, SERVFAIL

- Docs-first commit `f4ff550` added the explicit two-consecutive-NXDOMAIN rule to `docs/03`, the mixed passive-success/active-denied exit-3 rule to `docs/02`, the reasoning to PROGRESS "Deviations", and the dangling-CNAME persistence item to PROGRESS "Fix backlog". No code changed in that commit.
- Added `test_exit_code_scope_denied_with_passive_success` (asserts exit `3`, passive result stored, active tool not run) and `test_regression_dns_servfail_not_dead` (SERVFAIL collapses into `DnsSignal.UNCERTAIN`; state is `UNKNOWN`, never `DEAD`).
- Raw targeted run: 4 selected tests passed (`scope_denied_with_passive_success`, `scope_violation`, `regression_dns_servfail`, `regression_dns_timeout`).
- Raw gate twice after the tests: `376 passed, 2 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`, `ALL CHECKS PASS`, exit 0 (both runs). PROGRESS is 149 lines.
- Pitfalls added this follow-up: none.

## Part 7: UI tables, JSON and color safety

- Docs read / goal: `docs/02_CLI_UX.md` output, colors, progress and exit codes; `docs/03_ARCHITECTURE.md` dependency rules and Engine API; `docs/09_TOOL_CONTRACTS.md` JSON section; `docs/MASTER_PLAN.md` Part 7. Implement `ui.py`: Rich tables/progress on stderr, one valid JSON document on stdout, silent/no-color modes, markup escaping, and the free-key rate-limit hint. Render precomputed output only; no store/scope/adapters imports and no confidence/state logic.
- Decisions and assumptions: `HostRow` is the plain UI input (`fqdn`, `state`, `confidence`, `sources`, `status_code`, `ports`); the CLI will populate it. `ui.render(...)` returns `int(summary.exit_code)` and writes JSON to stdout or tables to stderr. `write_json` is separate so tests can parse the document directly. Tables use `Text` plus `Console(markup=False)` so hostnames such as `[red]x[/]` stay literal. `NO_COLOR` and non-TTY streams force `color_system=None`. Empty results use the docs/02 doctor hint; zero tools get a clear skipped/excluded variant.
- Decisions for user review (things the user may want to overrule): docs/09 previously specified JSONL while the Part 7 requirement/master plan specified ONE JSON document; I chose the one-document contract and updated both docs. `ScanSummary` has no skipped-tool list, so skipped adapters are not in the Tools table yet; this needs Part 8 wiring or an engine summary change. `HostRow` lives in `ui.py` rather than `engine.py`; the CLI must map stored rows to it.
- Docs changed first: `docs/02` now states one JSON document and includes the fixed shape; `docs/09` section 6 was aligned to that shape; `docs/03` gained section 8b (`ui.render`, `HostRow`, layering).
- Deviations: the JSON contract change above; skipped tools are absent from `ScanSummary`; `HostRow` is a UI-local input type; the empty zero-tool message is a wording choice not in docs/02.
- Files touched: `src/reconkit/ui.py`, `tests/test_ui.py`, `docs/02_CLI_UX.md`, `docs/03_ARCHITECTURE.md`, `docs/09_TOOL_CONTRACTS.md`, `docs/PROGRESS.md`, `docs/REVIEW_LOG.md`.
- Requirement -> test table:
  - one valid JSON document and documented keys -> `test_json_output_is_one_valid_document_with_documented_schema`
  - confidence/state/sources per host -> `test_json_hosts_carry_confidence_state_and_sources`
  - silent suppresses all stderr, returns exit code -> `test_silent_suppresses_tables_but_returns_the_exit_code`
  - silent non-TTY does not crash/hang -> `test_silent_mode_in_a_non_tty_context_does_not_crash_or_hang`
  - silent plus JSON still usable -> `test_silent_json_still_writes_one_usable_document`
  - non-TTY has no ANSI -> `test_non_tty_output_has_no_ansi_codes`
  - `NO_COLOR` has no ANSI -> `test_no_color_env_suppresses_ansi_on_a_tty`
  - redaction survives rendering -> `test_redacted_engine_values_stay_redacted_through_rendering`
  - every state label distinct -> `test_every_state_has_a_distinct_label`
  - every confidence label distinct -> `test_every_confidence_has_a_distinct_label`
  - labels visible in tables -> `test_all_state_and_confidence_labels_render_in_tables`
  - zero hosts -> `test_zero_hosts_renders_the_documented_empty_state`
  - zero tools -> `test_stage_with_zero_tools_renders_a_clear_empty_state`
  - one and many warnings -> `test_one_and_many_warnings_are_all_rendered`
  - Rich markup injection -> `test_rich_markup_in_host_data_is_printed_literally`
  - unicode/wide hostname -> `test_unicode_and_wide_hostnames_stay_intact_in_json`
  - hint only without key -> `test_rate_limit_hint_is_shown_only_when_the_key_is_unset`
  - progress disabled by silent/JSON -> `test_progress_is_suppressed_for_silent_and_json_modes`
  - no forbidden imports -> `test_ui_does_not_import_store_scope_adapters_or_cli`
- Self-review findings (S2 lists, S3 raw output):
  - Broad except: none added; `ui.py` converts no exceptions and does not catch rendering/serialization errors.
  - External input: `HostRow` fields and `ScanSummary`/`ToolResult` are Pydantic or typed; JSON serialization uses `model_dump(mode="json")`; `HostRow` supplies no raw objects. No filesystem paths or environment values are rendered except `NO_COLOR` presence.
  - Secrets: UI trusts the engine's redaction; the test feeds already-redacted `***` values and confirms no raw secret or object repr is re-expanded. `summary.warnings` and `ToolResult.error` are rendered as `Text`, never `str(raw)` of an adapter object.
  - Blocking call in async: none; all UI functions are synchronous and only write to streams.
  - Escaping exceptions: `json.dumps`/`model_dump` would raise on an unserializable type, but engine results are typed and serializable; no fallback `default=str` (which could bypass redaction) was added.
  - Unfinished path: CLI wiring, skipped-tool presentation, real terminal rendering and export formats remain for Part 8/11.
  - S3 raw: `Select-String` shows `ui.py` imports only stdlib, Rich, `reconkit.engine.ScanSummary` and `reconkit.models` (no store/scope/adapters/cli); `console.print` is the only terminal output, no `print(` or `subprocess`/`sqlite3`.
- Bugs found: no product bug. Two test expectations were corrected: the label test used a hard-coded source count that did not match the row (`HIGH (2)` vs `HIGH (3)`), and the 120-character unicode host is wrapped by Rich at 80 columns, so only its prefix is contiguous. The renderer was already correct; no PIT row was added.
- Mutation proofs: JSON prefix `noise` -> `test_json_output_is_one_valid_document_with_documented_schema` failed with `JSONDecodeError: Expecting value`; removing `Text(...)` and enabling markup -> `test_rich_markup_in_host_data_is_printed_literally` failed because `[red]x[/]` was consumed; disabling the silent early return -> `test_silent_suppresses_tables_but_returns_the_exit_code` failed because stderr contained the tables. All files restored; targeted tests passed after each restore.
- Raw check output (twice): `395 passed, 2 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS` (both runs after the final docs edits).
- Not verified: real terminal width/color behavior, CLI population of `HostRow`, skipped-tool display, `--json` in an actual Typer invocation (Part 8), and Windows console Unicode rendering.
- Pitfalls added this part: none.
- Next part must know: call `ui.render(summary, host_rows, json_output=..., silent=..., no_color=...)` and use its return value as the CLI exit code; `HostRow` is precomputed; JSON is one document, not JSONL; `render_rate_limit_hint` takes `key_set` and suppresses the hint when true.

## Part 8: Typer CLI, flags and mock end-to-end

- Docs read / goal: `docs/02_CLI_UX.md` commands/flags/output/exit codes, `docs/03_ARCHITECTURE.md` layers and engine API, `docs/04_DATABASE.md` read queries, `docs/05_SECURITY.md` scope/secrets/speed, `docs/07_TESTING.md` CliRunner rules, `docs/09_TOOL_CONTRACTS.md`, `docs/MASTER_PLAN.md` Part 8, and the Known pitfalls table. Build `cli.py` as the Typer entrypoint: parse documented flags, build `ScanOptions`, run the engine, render through `ui`, return the engine/UI exit code, and refuse active work without `--active`.
- Decisions and assumptions: one shared scan command is registered under `subs`, `dns`, `live`, `ports`, `tech`, `urls`, `vulns`, `passive`, `lite`, and `run`; `ctx.info_name` selects the stage set. No command is `lite` (passive pipeline), now documented in docs/02. `run --active` covers all stages; `run` without `--active` is passive only. Active-only stage commands require `--active` before the engine runs. `Engine.open` is the CLI-facing factory: it opens the Store and loads `.env` values, so `cli.py` never imports `store` or reads `os.environ`/`getenv`. `Engine.host_rows` supplies typed host rows; `Engine.diff`/`recent_runs` supply the read-only command data. `--json` is one document per target; multiple `-l` targets with `--json` are rejected until a batch shape is documented. Active fast mode prints the warning and requires the exact typed phrase outside `--mock` (mock bypasses it because no traffic is possible).
- Decisions for user review (things the user may want to overrule): `--timeout-<stage>` from docs/02 is not implemented; only `--phase-timeout` is accepted. `doctor`/`install`/`update` are explicit Part 9 stubs; `db list`, `db export`, `export`, and `scope import` are explicit exit-1 stubs. `.env` is the only key source through `Engine.open`; shell-exported key variables are ignored because the CLI must not read `os.environ`. `diff` compares the latest two completed `subs` runs and the latest two `live`/`ports` runs when present; `status` lists recent runs across targets.
- Docs changed first: docs/02 gained the no-command shorthand and the `diff`/`status` JSON shapes; docs/03 gained `Engine.open`/`close`, `host_rows`/`diff`/`recent_runs`, and the new UI helpers; docs/04 gained the three read queries. No new CLI flags were invented.
- Deviations: `--timeout-<stage>` missing as above; multi-target `--json` rejected; `db`/`export`/`scope import` stubs; fast active confirmation skipped in mock; `.env`-only key loading. No dependencies, suppressions, asserts, shell paths or new modules were added.
- Files touched: `src/reconkit/cli.py`, `src/reconkit/engine.py`, `src/reconkit/ui.py`, `src/reconkit/core/store.py`, `tests/test_cli.py`, `docs/02`, `docs/03`, `docs/04`, `docs/PROGRESS.md`, `docs/REVIEW_LOG.md`.
- Requirement -> test table:
  - layering: CLI imports engine/ui/config/scope and no store/adapters -> `test_cli_imports_only_the_allowed_layers`
  - every documented scan flag present -> `test_every_documented_scan_flag_is_registered`; the missing `--timeout-<stage>` is listed above, not hidden
  - no undocumented scan options -> `test_scan_has_no_undocumented_options`
  - exit code forwarded, not recomputed -> `test_mock_scope_denial_returns_three`, `test_mock_json_is_one_valid_document_and_exit_zero`
  - mock end-to-end JSON, Rich tables and two exits -> `test_mock_json_is_one_valid_document_and_exit_zero`, `test_mock_human_output_uses_rich_tables_on_stderr`, `test_mock_scope_denial_returns_three`
  - bad speed/delay/tool return 2 with no traceback -> `test_bad_flags_exit_two_without_a_traceback`
  - silent + JSON through the real command -> `test_silent_json_through_the_real_cli_has_no_stderr`
  - resume reaches engine and skips completed stages -> `test_resume_flag_reaches_the_engine_resume_path`
  - no `os.environ`/`getenv` key reads -> `test_cli_never_reads_environment_keys`
  - flag/list/root/scope/diff/status behavior -> `test_active_commands_require_active_flag`, `test_fast_active_requires_typed_confirmation`, `test_target_list_accepts_comments_and_deduplicates`, `test_root_invocation_without_a_command_runs_the_passive_pipeline`, `test_scope_check_command_reports_allowed_and_blocked`, `test_diff_and_status_after_two_mock_runs`
  - every command has help -> `test_every_scan_command_has_help`, `test_every_non_scan_command_has_help`
- Self-review findings (S2 lists, S3 raw output):
  - Broad except: `Engine.open` catches `BaseException` only to close a partially opened Store and re-raises; `_run_scan` catches `Exception` to convert an unexpected failure into exit 1 and optional `-v` traceback. No bare except.
  - External input: `-d`/`-l` through `validate_target`; file lines skip blanks/comments and dedupe; `--speed`/`--delay` through `load_config`/`parse_delay`; `--tools`/`--exclude` through the engine's registry validation; `--min-sources`/`--phase-timeout` through engine validation; `--scope` through `load_scope`/`require_active`.
  - Secrets: `cli.py` has no `os.environ`/`getenv` and no `print`; `Engine.open` loads `.env` values, the engine filters each tool's `keys`, and UI renders only redacted engine errors/warnings. No key value is put in argv or CLI output by this layer.
  - Blocking call in async: none added; `asyncio.run` wraps the engine, and CLI work is synchronous flag/format handling.
  - Escaping exceptions: `ConfigError`/`ScopeError`/`ValueError` map to documented codes; `KeyboardInterrupt` maps to 130; unexpected exceptions to 1; `typer.Exit` escapes after the return code is chosen.
  - Unfinished path: `doctor`/`install`/`update` (Part 9), `db`/`export`/`scope import`, batch `--json`, and real-tool/real-terminal verification.
  - S3 raw: `cli.py` imports only stdlib, Typer and `reconkit.{config,core.runner,core.scope,engine,errors,models,ui}`; no store/adapters. `os.environ`/`getenv` no hits; `print(` no hits; no `assert`, `noqa` or `type: ignore` in `cli.py`.
- Bugs found: no product bug. One test-side correction: Click does not include the generated `--help` in `cmd.params`, so the no-undocumented-options test adds it to the allowed set; this is not a product change. No PIT row.
- Mutation proofs: exit forwarding removed (`exit_code = render(...)` -> bare `render(...)`) -> `test_mock_scope_denial_returns_three` failed `assert 0 == 3`; active gate disabled -> `test_active_commands_require_active_flag` failed `assert 4 == 2`; delay validation disabled (`if False`) -> `test_bad_flags_exit_two_without_a_traceback[extra1-invalid delay]` failed `assert 0 == 2`. Every file restored; the restored targeted tests passed.
- Raw check output (twice): `437 passed, 2 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS` (both runs after the final docs edits).
- Not verified: real installed tools/network, real terminal width/color, `db`/`export` output, `scope import`, multi-target JSON, shell-exported keys, and the fast-active prompt outside mock.
- Pitfalls added this part: none.
- Next part must know: `Engine.open` is the only CLI store creation path; `cli.py` must keep `raise typer.Exit(code=...)` as the final step; `HostRow` is mapped from `Engine.host_rows`; `--timeout-<stage>` and `db`/`export` remain open for Part 9/11.

## Part 9: fix backlog - dangling CNAME persistence

- Docs read / goal: `docs/PROGRESS.md` Fix backlog and Open risks first; then `docs/04_DATABASE.md` schema/migrations, `docs/03_ARCHITECTURE.md` host-state/engine rules, `docs/09_TOOL_CONTRACTS.md` records, and the Known pitfalls table. Fix only the Fix backlog item: persist dangling-CNAME evidence. No CLI, UI, commands, flags or tools were changed.
- Decisions and assumptions: schema version 2 adds `host_status_history.cnames_json TEXT NOT NULL DEFAULT '[]'` and `dangling_cname TEXT`; `Store.latest_cnames()` is the read query. DNS-only resolved hosts now get a `DNS_ONLY` status row so their CNAME survives a restart. A later NXDOMAIN with no current CNAME reuses the latest stored CNAME before `decide_host_state`. `dangling_cname` is persisted only for a `SHUT_DOWN` row with an outside-target CNAME. Wildcard wiring and stage-level resume were triaged in Open risks, not fixed, because this part was limited to the Fix backlog.
- Docs changed first: docs/04 schema, read-query rules and migration version; docs/03 host-state persistence/reuse behavior; docs/REVIEW_LOG PIT-29.
- Files touched: `src/reconkit/core/store.py`, `src/reconkit/engine.py`, `tests/test_store.py`, `tests/test_engine.py`, `docs/03`, `docs/04`, `docs/PROGRESS.md`, `docs/REVIEW_LOG.md`.
- Requirement -> test table:
  - old v1 DB opens and gets both columns -> `test_v1_database_migrates_and_defaults_cname_columns`
  - existing rows default to `[]`/NULL -> same test
  - new CNAME evidence round-trips and `latest_cnames` reads it -> `test_host_status_persists_cnames_and_latest_cnames`
  - CNAME survives close/reopen and the later NXDOMAIN warns/persists `SHUT_DOWN` -> `test_regression_dangling_cname_survives_restart`
  - migration remains idempotent and history order is unchanged -> `test_migration_is_idempotent`, `test_host_status_history_order`
- Failing-first evidence: `test_regression_dangling_cname_survives_restart` failed before the fix with `assert False` on `summary.warnings`; the stored CNAME and SHUT_DOWN row did not exist. Post-fix targeted run: `5 passed in 0.84s`.
- Migration safety: v1 database with an existing ALIVE row migrated to version 2; the row read `cnames_json='[]'` and `dangling_cname=None` (no NULL list, no crash). `SCHEMA_VERSION == 2`.
- Raw check output (twice): `440 passed, 2 skipped`; `pytest=PASS`, `ruff-check=PASS`, `ruff-format=PASS`, `mypy=PASS`.
- Not verified: real DNS NXDOMAIN/CNAME behavior; the fix reuses a CNAME recorded by an earlier resolved pass, and `dnspython`'s NXDOMAIN path does not return one in the failing pass. This is recorded in Open risks.
- Pitfalls added this part: PIT-29.
- Next part must know: do not treat `host_status_history` as only live-stage data; DNS-only resolved hosts now write status rows. Use `Store.latest_cnames()` before deciding an NXDOMAIN warning. The wildcard and stage-level-resume gaps remain open.


## Part 10 docs pre-fix (docs only, no code)

- Goal: remove the contradictions that would make Part 10 unbuildable, before any `installer/` or `doctor.py` code. Every change below is a docs change; `src/`, `tests/`, `tools.yaml` and `config.yaml` were not touched.
- Docs changed: `docs/10` §1 grammar now matches `docs/02` §2 (dropped the undocumented `--stage`/`--yes`), §1 prompt text no longer implies `install --silent/--json`; §2 states `doctor` runs on Windows while `install`/`update` print the WSL2 message and exit 1 (macOS gets a Linux-required message); §3 gained the version-pin policy; §3b lists the real prerequisites (jq, dnsutils via the `dig` entry, Python >= 3.11, GOBIN, pipx via apt); §4 limits the GitHub-only host rule to `github_release` and names the Go module proxy and PyPI; §5a records the doctor checks, `--json`, and doctor exit codes; §6 defers the fixture-version warning to Phase 3 because `tools.yaml` has no fixture metadata; §9 restates that `--dry-run` may read the GitHub API. `docs/08` Flow 1 failure line no longer calls a non-Linux host fatal for `doctor`; `docs/05` §6.1 no longer says `install` prompts under `--silent`/`--json`.
- Decisions for user review: (1) removing `--stage` and `--yes` from docs/10 narrows the installer to the docs/02 surface; add them back deliberately if wanted. (2) Windows/macOS refusal uses exit 1, taken from docs/08 Flow 1 because docs/10 named no code. (3) `--all` still means "core tier only"; whether it should skip `phase: 3` entries (tools with no adapter yet) is left open. (4) The installer exit code when every tool fails is left open (docs/10 only defines 5 for a partial failure). (5) The "wordlists" check in docs/01/02 still has no documented location.
- Platform finding (not fixed): on this Linux copy `scripts/bootstrap.sh` and `.githooks/pre-commit` have CRLF line endings in the working tree while the index stores LF, so the documented `./scripts/bootstrap.sh` exits 127 and git cannot run the hook. The hook was restored from HEAD's LF blob so the mandated gate could run; `bootstrap.sh` is left as-is for the user to decide.
- Not verified: no Part 10 behavior exists, so nothing about install/doctor was exercised beyond the three stubs returning exit 1.

## Part 10 scope decisions (docs only, no code)

- Goal: settle the three questions left open by the docs pre-fix (commit `5f3b907`) before any Part 10 code. Docs only; `src/`, `tests/`, `tools.yaml` and `config.yaml` untouched.
- Evidence for `--all`: `tools.yaml` header defines `phase (build phase: 2 = working adapter in Phase 2, 3 = later)`. The only runtime consumer is `src/reconkit/engine.py:722`, which skips such a tool with `no adapter yet (phase {spec.phase})`; `adapters/registry.py:80` says the same in an error, and `registry.py:110` defaults a missing phase to `3`. Security gating is `tier` + `mode` in the engine's selection loop, never `phase`. Of 48 tools, 41 are core and 30 of those are `phase: 3` (`urlscan, amass, findomain, chaos, github_subdomains, dnsx, puredns, massdns, dig, httprobe, tlsx, smap, nmap, rustscan, httpx_tech, whatweb, wafw00f, cdncheck, webanalyze, gau, waybackurls, katana, hakrawler, gospider, subjs, unfurl, urlfinder, nuclei, subzy, dnsreaper`); core phase 2 is exactly the 11 tools that have adapters. So `nmap: phase 3` is build tracking, not a tier bug, and a phase filter would silently exclude `nmap -sV`.
- Decision 1: `--all` remains "core tier tools only", no phase filter. `MASTER_PLAN.md` Part 4 called `masscan, rustscan, nmap -sV` opt-in, contradicting `tools.yaml` (`rustscan`/`nmap` are core, only `masscan` is opt_in); the line now names only `masscan` and adds that core-but-phase-3 tools install and run by default once their adapters land.
- Correction to the review premise: docs/01 Feature 5 acceptance criteria never mention `nmap -sV`. They say "Default scan is a top-ports connect scan (no root needed)". The `nmap -sV` phrases live in docs/09 (`service fingerprint ... raises confidence`) and MASTER_PLAN Part 4, which is the line that was wrong.
- Decision 2: exit code `6` = "Every requested tool failed to install or update" was added to docs/02 section 6 as a new row. `git show b752ec2` proves the table was frozen only for layout (it moved the scope paragraph out from between rows, no renumbering): `4` = "No usable tool for the stage" and `5` = "Partial success (some tools failed or timed out)" keep their scan meanings, so all-failed install needed its own code rather than overloading `4`.
- Decision 3: the wordlists check was removed from docs/01 Feature 2 and the docs/02 command table, and recorded under PROGRESS Open risks. Evidence: `grep -rn -i wordlist src/ tools.yaml config.yaml` returns nothing; only docs/01:61 and docs/02:20 mentioned it; the only wordlist-consuming tools (`puredns`, `massdns`, `amass`, `findomain`, `dnsx`) are phase 3 with no adapter. `doctor` will not print a fabricated "not applicable" line.
- Not verified: nothing in this commit is behavior; the four checks were re-run for the tree, and no Part 10 command was exercised beyond the existing stubs.
- Next: 10a only (doctor's real checks, `--json`, exit rules). Blocked on confirming that the registry exposes stage membership readably, so 10a adds no module outside docs/03.

## Part 10a - doctor's real checks (code)

- Goal: replace the `doctor` stub with the checks docs/01 Feature 2, docs/08 Flow 1 and docs/10 section 5a require, without installing anything and without a new module.
- Code changed: `doctor.py` (report models, `collect_report`, `default_status`, `installed_packages`, `db_writable`), `adapters/registry.py` (`ToolSpec.requires_apt`, `load_system_packages()`, shared `_document()`), `ui.py` (`doctor_document`, `render_doctor`), `cli.py` (`doctor` now takes `--fix/--json/--no-color/--config` and exits 0 with warnings, 1 on Python < 3.11 or an unreadable config).
- Decisions: (1) apt packages are read from `/var/lib/dpkg/status` rather than by running `dpkg-query`, so doctor starts no subprocess for them and on a non-Debian host prints `unknown` instead of guessing; (2) non-binary tools print `n/a (no binary required)` in version and path exactly as docs/02 says; (3) `installed=False` with a path becomes `wrong program` plus a warning, per the sentence added to docs/09 in `a7d0399`; (4) `--fix` refuses with exit 1 until `install` exists (10b+), because a silent no-op would be a lie; (5) the doctor JSON field list is documented in docs/02 section 5.
- Tests added: `tests/test_doctor.py` (12) - all-present, all-missing with n/a rendering, wrong `httpx` namesake, unparsable version, dpkg installed/missing/unknown, JSON shape and no key values, warnings keep 0, Python < 3.11 exits 1, `--fix` refuses, unreadable config exits 1, one JSON document. `tests/test_registry.py` (+4) - `requires_apt` parsed, `load_system_packages()` matches tools.yaml, both invalid-list cases raise `ConfigError`.
- Real run on this Kali box: `reconkit doctor` reported subfinder 2.17.0 and naabu 2.7.0 as installed, and `httpx` as `wrong program` because the PATH copy is not ProjectDiscovery's - the case docs/10 section 5 names. Exit 0 with the missing-tools suggestion line.
- Not verified: no real `--fix` (no installer yet); the dpkg parser was exercised against synthetic status files and the real Kali database, not against a package installed mid-run; no Windows run of doctor.
- Known cosmetic: the `n/a (no binary required)` cells wrap in an 80-column terminal. The text matches docs/02; compacting it would need a docs change first.

## Part 10b - install plans and verification primitives (code)

- Goal: turn `tools.yaml` into typed install plans and make checksum/archive handling correct before any download code exists. No network, no subprocess, no apt.
- Code changed: `installer/registry.py` (`InstallPlan`, `load_plans`, `plan_for`, `resolve_plan`, `tool_versions` pinning that rewrites a trailing `@latest`), `installer/verify.py` (`sha256_file`, `checksum_for`, `verify_checksum`, `extract_binary` for zip and tar.gz, `ARCHIVE_LIMIT` 200 MiB, `MEMBER_LIMIT` 100 MiB). Docs first: docs/10 gained section 3c (plan fields, pin rule, `none` plans, `resolve_plan`) and the size caps in section 4.
- Decisions: (1) plans are built from `tools.yaml` directly because `ToolSpec` deliberately does not carry `install`; the tool set still comes from `load_tools()` so the two loaders cannot drift on which tools exist; (2) a tool with no `install` block is a `none` plan (`httpx_tech` reuses the `httpx` binary) rather than an error; (3) extraction places the member under the destination using its own basename, refuses absolute paths, drive letters and any `..` segment, and fails when no member matches; (4) the binary is made 0755 with `Path.chmod` (ruff's S103 rejects a literal `os.chmod(0o755)`, and the documented mode is the requirement, not a mistake).
- Tests added: `tests/test_installer_registry.py` (10) - full registry coverage, subfinder's github_release to go_install chain, `requires`/`requires_apt`, `httpx_tech` as `none`, pin rewriting for pinned and unpinned packages, unknown method, missing package, missing repo, unknown tool, no-fallback chain. `tests/test_installer_verify.py` (11) - checksum match and mismatch, checksum line selection, zip extraction of only the expected binary with 0755, missing member, `..` and absolute members refused, archive and member caps, tar.gz extraction and `..` member.
- Not verified: no real release asset was downloaded or extracted; the caps are enforced against synthetic archives. `checksums_pattern`/`asset_pattern` templating is only parsed, not rendered - that belongs to 10c.

## Part 10a follow-up - identity probe destroyed tool configs (code)

- Found while smoke-testing `reconkit doctor` on Kali: `git status` showed untracked `naabu/` and `subfinder/` in the repo root, born at the run time, containing files dated 2026-10-29. `~/.config/naabu` and `~/.config/subfinder` no longer existed: `BinaryAdapter.check_installed()` calls `run_exec(..., env={})`, so HOME was unset and the ProjectDiscovery tools wrote (moved) their config directories into the CWD. This was latent for scans too, because the engine calls the same method.
- Fix: pass `env={"HOME": str(Path.home())}` to the version probe, with a docstring that says why. The configs were moved back to `~/.config` and the tree is clean again.
- Test: `test_identity_probe_passes_home` in `tests/test_binary_adapters.py` asserts the child env is exactly `{"HOME": <home>}`.
- Guard: `test_every_binary_adapter_declares_needs_home_or_is_allowlisted` walks every `kind: binary` tool that has an adapter and fails unless it sets `needs_home = True` or appears in `NO_HOME_NEEDED` with a checkable reason (today only `assetfinder`, whose `build_command` passes no config path and whose registry entry has no keys). Mutation check: flipping `SubfinderAdapter.needs_home` to `False` makes the test report `['subfinder']`; restoring it reports `[]`.
- Not verified: that every ProjectDiscovery version subcommand accepts an unset HOME was never true; this change removes the question rather than answering it per tool. Tools that need `XDG_CONFIG_HOME` instead are untested.

## Part 10c - github_release download and dry-run (code)

- Goal: fetch one GitHub release asset safely, verify it, install it with a post-install version check and a `.prev` rollback, and describe the same steps under `--dry-run`. Still no `apt`, `go_install` or `pipx` (10d) and no `install --all` wiring (10e).
- Code changed: `installer/github_release.py` (`release_for`, `download`, `install_release`, `install_plans`, `exit_code`, `host_arch`, `render_pattern`, `checked_https`); `installer/registry.py` gained `InstallPlan.version_args` parsed from `version_cmd`, because the post-install check needs per-tool arguments and `tools.yaml` is the only source for them. Docs first: docs/10 section 3c lists `version_args`.
- HTTP: `httpx.Client` injected by the caller, exactly like the adapters' `transport=` injection. Tests pass `httpx.MockTransport`; **no `respx` pattern existed in this repo**, so the established MockTransport approach was reused rather than introducing a second mocking style. Nothing in the module constructs its own client, so a test cannot reach the network by accident.
- Safety: `checked_https` rejects any URL that is not HTTPS on `api.github.com`, `github.com`, `objects.githubusercontent.com` or `release-assets.githubusercontent.com`; the cap is the 200 MiB `ARCHIVE_LIMIT`; extraction reuses `verify.extract_binary` (single member, zip-slip refused, 0755); the bin dir is chmod 0700; the old binary is copied to `<name>.prev` and restored if the version check fails; `.prev` is deleted after success.
- Exit codes: `exit_code` returns 0 when everything installed, 5 when some did, 6 (docs/02) when every requested tool failed; `install_plans` catches `InstallError` per plan so one failure cannot stop the rest.
- rustscan: option (b) chosen. The real release (tag 2.4.1 through the `bee-san/RustScan` redirect) publishes `x86_64-linux-rustscan.zip` and `aarch64-linux-rustscan.zip`, which do not fit the registry's `amd64`/`arm64` `{arch}` values, and no checksums asset was listed, while `tools.yaml` still holds `"verify-at-implementation"`. 10c therefore never resolves it; `test_rustscan_placeholder_cannot_resolve` pins that it fails with "has no asset" rather than guessing. The Open risk carries the evidence.
- Tests added: `tests/test_installer_github_release.py` (14) - resolve asset + checksums, missing asset, dry-run touches nothing and calls no runner, install places 0755 in a 0700 dir with a HOME-only version probe, checksum mismatch, checksums file without our asset, `verify_checksums` with no checksums asset, plain-HTTP refusal, non-GitHub asset host refusal, download cap, rollback restores the previous binary, per-plan isolation with 0/5/6, arch mapping, rustscan placeholder. `tests/test_installer_registry.py` gained `version_args` assertions.
- Not verified: no real GitHub API request or download was made by code; everything ran through MockTransport. The 200 MiB cap and rollback were exercised with synthetic archives. The `asset_pattern` values in `tools.yaml` beyond subfinder's are still unverified against real releases - only subfinder's shape is proven here, and rustscan's is known wrong.
- Follow-ups for 10d/10e: fallback plans are parsed but not executed (`resolve_plan` exists, `install_release` never walks it); `install --all` and the config `tool_versions` wiring remain 10e.

### Part 10c - review follow-ups (same part, before close)

- Host allowlist made explicit in docs/10 section 4: it previously said "the GitHub release asset hosts", which could drift from `ALLOWED_HOSTS`. The doc now names all four hosts and their roles (`api.github.com` lookup, `github.com` download URLs, `objects.githubusercontent.com` and `release-assets.githubusercontent.com` for redirects) and points at the constant.
- Checksums fetch was unbounded: `_fetch_text` used `client.get(...).text`, so a hostile or broken server could return an arbitrarily large body. It now streams like `download()` with `CHECKSUMS_LIMIT` (64 KiB, documented in docs/10) and rejects non-UTF-8 bodies instead of raising `UnicodeDecodeError`.
- Tests: `test_checksums_fetch_is_size_capped` (15 tests in the file, 498 in the suite). `bin_dir` still has no default - it is a required keyword argument on `install_release`/`install_plans`; the `~/.reconkit/bin` path stays 10e's job.

## Part 10d - apt, go_install and pipx backends (code)

- Goal: the three remaining install methods plus per-method dispatch, with sudo shown and confirmed, and minimal child environments.
- Docs first: docs/10 gained section 3d (exact argv and env dicts for all three backends, the sudo contract, validation rules, the two-pipx-prompts rule and the no-rollback rule), section 8 gained the "sudo needs a password" and "pipx missing" rows, docs/05 section 5 now states `sudo -n`. Code followed.
- Decision: `sudo -n`. `runner.run_exec` opens children with `stdin=subprocess.DEVNULL` and captures stdout/stderr, so an interactive sudo password prompt cannot work; without `-n`, apt would fail with "no tty present" anyway. With `-n` the failure is immediate and is reported as `skipped` with "sudo needs a password: run `sudo -v` in this terminal and retry". reconkit never handles a sudo password and never runs as root.
- Confirmation: `confirm(message: str) -> bool` is a required keyword for apt and pipx plans. `False` means no `runner` call happens at all (`test_apt_declined_starts_no_process_at_all`, `test_declined_pipx_prerequisite_installs_nothing`), and `install_plans` without a handler raises `ConfigError` instead of silently skipping. The backend modules never print or prompt, so the CLI owns the wording.
- Two prompts for pipx: a missing pipx produces "pipx is required for wafw00f: sudo apt-get install -y pipx (sudo required)" and then "wafw00f: pipx install wafw00f -> <path>" - two distinct confirmations and two distinct argv calls, pinned by `test_pipx_missing_apt_prompts_twice_and_keeps_them_distinct`. Declining the first installs nothing; declining the second stops before the pipx call.
- Env dicts are exactly the documented ones: apt `{PATH, DEBIAN_FRONTEND, LC_ALL}` (asserted with `==`, and `HOME` asserted absent), go `{HOME, GOBIN, PATH}`, pipx `{HOME, PATH, PIPX_BIN_DIR, PIPX_HOME}`. `PATH` is the only value copied from the parent, because `go`/`pipx` must be findable; no other parent variable is passed.
- Validation before argv: apt `^[a-z0-9][a-z0-9+.-]*$`, go `^[A-Za-z0-9._+/-]+(@[A-Za-z0-9._-]+)?$`, pipx the same plus `git+https://...`. Violations are `ConfigError` and no runner call (`test_apt_package_names_are_validated`, `test_go_specs_are_validated`, `test_pipx_git_spec_is_allowed_and_other_specs_are_rejected`).
- Shared version check: `verify.check_version` now backs both github_release's post-install check and the new backends, so one place decides "timed out or non-zero = failed". github_release's rollback stays where it was.
- Dispatch: `install_plans` in `installer/github_release.py` (the module docs/03 lists; no new module) now routes by method, keeps per-tool isolation, and marks declined steps `skipped=True`. `exit_code` is unchanged, so skipped counts as failed for 5/6.
- Tests added: `tests/test_installer_backends.py` (24) - apt argv/env/decline/password/timeout/validation/dry-run, go env/success/failure/missing binary/validation/dry-run, pipx env/two prompts/declines/one prompt/validation, and dispatch (mixed methods, declined apt exits 5, missing handler, dry-run, all-fail exits 6).
- Not verified: no real `sudo`, `apt-get`, `go install` or `pipx` was executed; every test injects a fake runner. The password-detection markers come from sudo's real messages ("a password is required", "no tty present", "askpass") but were not reproduced against a live sudo in this session. `pipx_available()` uses a real `shutil.which`, so tests always inject `has_pipx`.
- Carried forward: no `.prev` rollback for package-manager installs (documented, by design); `install --all`, `update`, the prompt text and `bin_dir` resolution remain 10e; `dnsreaper`'s `git+https://github.com/...` pipx source is allowed by the registry and now by the spec check, but has never been installed.

## Part 10e - install/update CLI, idempotency and exit codes (code)

- Docs first: docs/10 section 1 gained the idempotency rules, the update comparison rules and its apt/pipx limitation, the exit-code aggregation, the summary columns, the `bin_dir()` resolution, the `nuclei -ut` step (flag confirmed against the installed `nuclei --help`: `-ut, -update-templates`, engine v3.11.1 on this box) and the `tier` field in section 3c.
- CLI surface is exactly docs/02 section 2 plus the documented global flags: `install [TOOL...|--all] [--dry-run] [--config PATH] [--no-color]` and the same for `update`. No `--force`, no `--yes`, no `--stage`. Unknown tool names and a missing selection exit `2`; Windows/macOS exit `1` with the SETUP.md message (tested by patching `sys.platform`).
- Aggregation: `install_selected` returns `(outcomes, exit_code(outcomes))` for the whole selection, so 0/5/6 is computed once, not per backend. `engine.ExitCode` gained `ALL_FAILED = 6` to match docs/02 section 6.
- Idempotency: `install` skips a tool when `installed_version` finds a usable copy (managed `~/.reconkit/bin` first, then `PATH`) whose `version_cmd` exits 0, and reports `already installed`. `update` resolves the desired version where one exists (GitHub release tag, or a go pin/`@version`) and skips with `up to date` when the tag appears in the installed version output. apt/pipx re-run their package-manager install because there is no local version query here; that limitation is in docs/10 section 1.
- `tool_versions` wiring: `_install_selection` calls `load_plans(versions=config.tool_versions)`; a test writes a config copy with `tool_versions: {subfinder: 9.9.9}` and asserts the selected plan carries `9.9.9` (no network: `install_selected` is stubbed in that test).
- `doctor --fix` now calls the same `_run_install` path with `--all`; the old refusal test was replaced by `test_fix_runs_the_installer`, which asserts the installer is called and the refusal text is gone.
- Keys prompt: implemented per docs/05 section 6.1 - only on a TTY, never under `--dry-run`, copies `.env.example` to `.env` (never overwrites) with mode 0600. Deviation: it does not re-print the Keys table there; logged in PROGRESS Open risks.
- Tests added: `tests/test_install_cli.py` (14) - bin_dir default, installed-version probing, install skip, update skip on equal pin, update when older, exit 5/6 aggregation, nuclei `-ut` step, the three CLI usage/platform errors, tool_versions + core selection wiring, update flag plumbing, `doctor --fix`, and no `.env` write without a TTY. `tests/test_doctor.py`'s refusal test was rewritten.
- Not verified: no real install was performed by the tests; `--all` selection is exercised with a stubbed `install_selected`, so the end-to-end download/apt path is still covered only by 10c/10d unit tests. The `nuclei -ut` flag was confirmed from real `--help` but the refresh itself was not run.

### Part 10e - review follow-ups (same part, before close)

- Keys table implemented instead of deferred: `doctor.key_checks()` returns every documented key by name (`set=False`, values never read) and `ui.render_keys` prints tool/key/state/adds/sign-up. `_maybe_ask_keys` now prints it after writing `.env`, matching docs/05 section 6.1. The helper lives in `doctor.py` because `tests/test_cli.py::test_cli_imports_only_the_allowed_layers` forbids `cli` importing `reconkit.adapters` - the first attempt imported `load_tools` in cli and that test caught it.
- One definition of the managed bin dir: `adapters/base.py` gained `managed_bin_dir()`, which imports `installer.registry.bin_dir` lazily (adapters -> installer.registry -> adapters.registry -> adapters.base would import in a loop) and `BinaryAdapter.binary_path` uses it. `test_managed_bin_dir_has_one_source_of_truth` asserts `adapters.base.managed_bin_dir() == installer.registry.bin_dir()`.
- docs/10 section 1 now states the UX cost: because apt/pipx have no version comparison, `update --all` re-asks the sudo confirmation for every apt/pipx tool on every run.
- Exit codes unchanged: `ERROR=1`, `USAGE=2`, `SCOPE=3`, `NO_TOOL=4`, `PARTIAL=5`, `ALL_FAILED=6`, `INTERRUPTED=130` (code 6 added in 10e, no renumbering).
- Tests: 18 in `tests/test_install_cli.py`, 540 in the suite.

### Part 10e - second review pass

- The keys-table claim was only in prose: the pasted cli diff was from `0d6f762`, and the actual `render_keys` call landed in `14c43cf`. Two tests now prove the call path, not just the renderer: `test_keys_table_is_printed_by_the_prompt` captures the console `_maybe_ask_keys` builds and asserts "wrote"/"CERTSPOTTER_API"/"missing"; `test_declining_keys_prints_nothing` asserts empty output and no `.env` when the prompt is declined. docs/05 section 6.1 now states which branch prints the table (chosen keys, including when `.env` already exists) and that declining prints nothing.
- `_refresh_templates` was a new subprocess call site; it passed only `HOME`. That is a PIT-30-adjacent gap in the making: `nuclei` lives under `$HOME/go/bin` here, and `execvpe` with no `PATH` in the child env only searches `os.defpath`, so the refresh would have failed to find the binary. It now passes `{"HOME", "PATH"}` (the documented exception in docs/10 section 3d) and the nuclei test pins the exact env keys.
- Engine exit codes were re-checked: `NO_TOOL = 4`, `INTERRUPTED = 130` unchanged.
- The unverified sudo-marker risk bullet is in docs/PROGRESS.md (Open risks).
- Tests: 20 in `tests/test_install_cli.py`, 542 in the suite.
- Pitfalls added this pass: PIT-31 (custom `env=` without `PATH` cannot resolve a bare binary), with `test_regression_custom_env_without_path_cannot_resolve_binary` and the `Regression: PIT-31` docstring on the nuclei test.

## Part 10f - close-out (code + real run)

- What 10e already covered, so 10f did not duplicate it: Windows refusal for `install` (added for `update` too), the TTY key prompt and `.env` copy-without-overwrite (10e tests; 10f adds the existing-`.env` and missing-`.env.example` branches), `--no-keys` end-to-end (`tests/test_engine.py::test_env_filtering_and_no_keys`), second `install` changing nothing (`test_install_skips_a_tool_that_is_actually_usable`). The three Part 8 stubs (`install`, `update`, `doctor --fix`) are all wired.
- Real run, first attempt (2026-11-13, this Kali box): `reconkit install --all --dry-run --no-color` exited 5 with three genuine defects that the fake-runner tests could never have caught:
  1. `RustScan/RustScan` answers the releases API with HTTP 301 (the repo moved to `bee-san/RustScan`) and `release_for` did not follow redirects. Fixed with `follow_redirects=True` plus `test_release_lookup_follows_a_rename_redirect`.
  2. `naabu` and `katana` reported "no checksums asset". Live API shows `naabu-checksums.txt` and `katana-1.8.0-checksums.txt`, so the shared `{name}_{version}_checksums.txt` anchor was wrong for both. `tools.yaml` now overrides each pattern (verified names, fetched today).
  3. After the fix the same command exits 5 with exactly one failure: `rustscan` (the documented placeholder), every other tool `would install`.
- New safety check: `install_apt` now confirms the binary is on `PATH` after a successful `apt-get` (the MASTER_PLAN adversarial case "apt succeeds but the binary is still missing"), with `test_apt_that_leaves_no_binary_is_an_error`. `shutil.which` is monkeypatched in the apt tests so they do not depend on the host.
- New adversarial tests: a `PATH` copy whose `version_cmd` fails is not treated as installed; an unparsable version line is not treated as current; existing `.env` is kept and the table still prints; missing `.env.example` prints no table.
- docs/10 section 5a and section 6 synced to the code: `--fix` runs the `install --all` selection and relies on idempotency; `update` points at the apt/pipx limitation; the nuclei refresh is stated as implemented with the confirmed `-ut, -update-templates` flag.
- Not verified: the real non-dry install. It needs a sudo password on this box (`sudo -n true` returns "a sudo: a password is required"), so `install --all` would skip every apt tool; the run has to happen in a shell where `sudo -v` has been done. Also untested: Ctrl-C mid-install (logged in Open risks).

### Part 10f - mutations, Ctrl-C, diff confirmations

- Mutation proofs (break, fail, restore, pass), raw one-line results:
  - Windows refusal: `if sys.platform != "linux":` -> `if False:` -> `test_cli_install_refuses_non_linux` FAILED; restored, PASSED.
  - `.env` no-overwrite: `if env_path.exists():` -> `if False:` -> `test_existing_env_is_kept_and_the_table_still_prints` FAILED; restored, PASSED.
  - Failure isolation: `except InstallError` in `install_selected` -> `except ZeroDivisionError` -> `test_exit_code_is_aggregated_over_every_selected_tool` FAILED with the uncaught `InstallError`; restored, byte-identical, PASSED.
- `KeyboardInterrupt` is now wired for install/update, matching the scan path (`cli.py:222` already caught it and exited 130): `_run_install` catches it around `install_selected`, prints "interrupted; tools already installed are kept" and exits 130, with `test_ctrl_c_during_install_exits_130`.
- The three live-run fixes did not need a new registry field: `checksums_pattern` already existed (added in 10c); the fix populated it per tool. `git show 0b8e1f7 -- src/reconkit/installer/registry.py` is empty.

### Part 10f - second pass: mutation proofs re-run, real non-dry run, non-TTY abort

Repo state: `104d23e` plus the uncommitted registry/doctor/`tools.yaml` work; gate before this pass `558 passed`.
Every restore below was checked with `sha256sum`; the digests before and after each cycle are identical
(`src/reconkit/cli.py c1f9206ec7e83368d64e76cfc508284d6c5f791b0c2ab1963aae2007db07e928`,
`src/reconkit/installer/github_release.py 91b73b6664a38dd26684f8e2d09a86bc5b7b6ee8cc4c5366a2aebe4f7f19ffad`).

- Mutation 1, Windows refusal (`cli.py:575`): `if sys.platform != "linux":` -> `if False:`. Both
  `test_cli_install_refuses_non_linux` (`assert 'Use WSL2 Kali' in ''`) and `test_cli_update_refuses_non_linux`
  (`assert 5 == 1`) FAILED, mutant exit 1; restored, both PASSED, exit 0.
- Mutation 2, `.env` no-overwrite (`cli.py:553`): the keep branch -> `if False: pass`. The committed test has
  `.env` but no `.env.example`, so on its own it can only show the lost message, not a clobber: an inline driver
  with **both** files present printed `ENV AFTER: 'EXAMPLE=1\n'` under the mutation and `ENV AFTER: 'KEEP=1\n'`
  restored. `test_existing_env_is_kept_and_the_table_still_prints` FAILED
  (`assert 'keeping existing' in '.env.example not found; nothing copied\n'`), PASSED after restore.
  A first attempt at this mutation replaced the branch with `if False:` alone and left `elif` without a body, so
  the suite failed to import (`IndentationError`); that proves nothing and was redone with a valid body.
- Mutation 3, failure isolation on the CLI path: `install_selected` `except InstallError` -> `except ZeroDivisionError`.
  `test_exit_code_is_aggregated_over_every_selected_tool` FAILED with the uncaught
  `InstallError: broken: go install finished but .../broken was not created`; restored, PASSED. The same mutation on
  `install_plans` FAILED `test_plans_are_isolated_and_exit_codes_follow_the_table` with
  `InstallError: subfinder: release v2.6.0 has no asset 'subfinder_missing.zip'`. Two identical
  `except InstallError as exc:` blocks exist; a naive first attempt matched both sites and aborted without writing
  anything (the test still passed), so the applied mutations target the enclosing function by line index.

- Ctrl-C: already wired before this pass by `104d23e`.
  `grep -n "KeyboardInterrupt\|130" src/reconkit/cli.py src/reconkit/engine.py` -> `cli.py:222` (scan),
  `cli.py:606` (`_run_install`), `engine.py:79` (`INTERRUPTED = 130`). `test_ctrl_c_during_install_exits_130` passes;
  the stale Open-risk bullet is removed. No further change.
- Real non-dry run, first attempt: `reconkit install --all --no-color < /dev/null` printed
  `massdns: sudo apt-get install -y massdns (sudo required) [y/N]: Aborted.` and exited 1 **before installing
  anything**. That is a real defect: without a TTY, `typer.confirm` aborts the whole run, while docs/10 section 3d
  says a declined prompt skips only that tool. Fix: `_install_confirm` returns `False` when
  `sys.stdin.isatty()` is false; docs/10 section 3d updated first; new tests
  `test_sudo_prompt_without_a_tty_refuses_instead_of_aborting` and
  `test_a_piped_install_skips_the_sudo_tool_instead_of_aborting`.
- Real non-dry run after the fix: 30 tools `already installed`, `massdns` `skipped` (sudo needs a password),
  `rustscan` `failed` (`release lookup failed with HTTP 403`), exit 5. Nothing was downloaded or compiled: the
  managed bin dir was already populated by an earlier real run (files dated 15:31-16:15 on this box).
- The sudo half is still unrun: `sudo -n true` -> `sudo: a password is required`; `sudo -v < /dev/null` ->
  `sudo: a terminal is required to read the password`. No NOPASSWD rule exists for `kali`. `massdns`, `amass`,
  `dig`, `nmap`, `whatweb` and `libpcap-dev` have only ever been exercised as `skipped`.
- GitHub rate limit, captured rather than retried: `GET /rate_limit` at 21:25 UTC returned core
  `limit 60, remaining 0, used 60, reset 1794607056 (21:57:36 UTC)`. A direct
  `GET /repos/projectdiscovery/nuclei/releases/latest` returned `HTTP/2 403` with
  `{"message":"API rate limit exceeded for 152.59.43.217. ..."}` and `x-ratelimit-remaining: 0`.
  `update --all` therefore reported all 13 `github_release` tools as `failed` with HTTP 403 and continued (exit 5).
  docs/10 promised "Suggest setting `GITHUB_TOKEN`; skip remaining" and claimed an optional `GITHUB_TOKEN` raises
  the limit, but `release_for` sends no token at all; both statements are corrected, and the gap is listed as an
  Open risk for a decision before Part 11.
- `update --all` idempotency: **not achieved**. 13 `github_release` tools failed (403), 6 sudo/pipx tools were
  `skipped`, and all 14 `go_install` tools re-ran `go install` and reported `installed`. Measured that the re-run
  is not a corrupting reinstall: `sha256sum` of `assetfinder`, `subjs` and `gau` were identical before and after
  `reconkit update assetfinder` (`d5173bdac4eb2054438adaea2c4c1b7173923224516976bf6df7e40fc6def4e7`).
  docs/10 section 6 now states the `@latest` behaviour; the reporting gap is an Open risk.
- `doctor` (exit 0): 8 tools missing (`massdns`, `rustscan`, `httpx_tech`, `dnsreaper`, `crlfuzz`, `dalfox`,
  `gowitness`), `masscan` warned as "not the expected program", `libpcap-dev missing`, coverage
  `dns 4/5, ports 4/6, tech 4/5, vulns 5/8, shots 0/1`. The plan-probe fallback added in this pass is what makes
  the adapter-less tools (`assetfinder`, `findomain`, `chaos`, `gau`, ...) report `yes` instead of `missing`.
- Follow-up from mutation 2: the pre-existing `.env` test could not fail on a real clobber, so
  `test_existing_env_is_not_overwritten_when_env_example_exists` now copies the real `.env.example` beside a
  `.env` and asserts the bytes are unchanged. Proved it guards the property: clean PASS, mutated (keep branch
  removed) FAILED with the `.env.example` contents in the actual value, restored (`git hash-object` equals
  `HEAD:src/reconkit/cli.py`), PASS.
- Gate after the fix: `560 passed`; `ruff check .`, `ruff format --check .`, `mypy src/reconkit` clean.

- Review ruling after this pass: 10f **code** is accepted. The Part 10 gate stays open on one item only - the
  sudo-authenticated apt install, which needs a human terminal (agent has no sudo password on this box). The
  `@latest` go_install reporting gap is deferred to a future part (`docs/10` section 6 says so explicitly; it is
  non-destructive and needs its own docs-first design), and authenticated GitHub release lookups are deferred to
  Part 11 planning. Neither is a Part 10 blocker. Do not start Part 11 until the apt run's output is recorded.

### Part 10f - `requires_apt` was never installed (docs/10 3a was false)

- Defect: `InstallPlan.requires_apt` was parsed and read only by `doctor` (system-packages list). No installer
  backend consumed it, so `install --all` would install `naabu` without `libpcap-dev`, while docs/10 section 3a
  said "The installer installs dependencies first and reports them in `--dry-run`". Found by checking our own
  instruction before spending the scarce sudo run, not by the run itself.
- Docs first (docs/10 3a): `requires_apt` is installed before the tool with its own prompt; a declined
  prerequisite skips the tool; `--dry-run` lists the step; prerequisites are not reached for an already-installed
  tool; `requires` (puredns -> massdns) is still not auto-installed and is deferred.
- Code: `github_release._install_one` now calls `_install_required_packages` before dispatching, and merges the
  prerequisite steps ahead of the backend steps via `replace(outcome, steps=(*prelude, *outcome.steps))`. The old
  dispatch body moved unchanged to `_dispatch_backend`. `apt.apt_install_package` (the confirmed primitive) is
  reused, so the prerequisite prompt is `naabi`-style distinct: `naabu: sudo apt-get install -y libpcap-dev
  (required by naabu)`. A declined prerequisite raises `InstallSkipped` out of `_install_one`, so
  `install_selected`/`install_plans` mark the **tool** skipped and never call its backend.
- Tests added (`tests/test_installer_backends.py`): `test_requires_apt_is_installed_before_the_tool_with_its_own_prompt`,
  `test_a_declined_prerequisite_skips_the_whole_tool`, `test_dry_run_lists_the_apt_prerequisite_and_runs_nothing`,
  `test_naabu_declares_libpcap_as_its_prerequisite`.
- Mutation proofs (restore verified by `sha256sum` = `12f009fde7df9e11a694b64da90e12ca5f5dc2707bc5227318c51ed6292945c5`):
  - A: `for package in plan.requires_apt:` -> `for package in ():` -> the ordering, declined and dry-run tests all
    FAILED (`3 failed`), e.g. `assert 'puredns: go install ...' == 'puredns: sudo apt-get install -y libpcap-dev ...'`.
  - B: wrap `apt_install_package` in `except InstallSkipped: continue` -> `test_a_declined_prerequisite_skips_the_whole_tool`
    FAILED (`assert [go install ...] == []`); the tool was installed despite the refusal.
  - Note: the `MUTANT_*_EXIT=` lines printed `0` because `$?` captured `tail` in the pipeline, not pytest. The
    `3 failed` / `1 failed` summary lines are pytest's real verdict; the restored run used `if ... then ... fi`.
- Gate: `565 passed`; ruff, ruff format and mypy clean.
- Consequence for the gate run: on this box `naabu` is already installed, so `install --all` will install only
  `massdns` through apt. A live `libpcap-dev` proof needs `update naabu` (when the release comparison says "not
  current") or a machine without naabu.

- Evidence weight agreed in review for the `requires_apt` fix: the prerequisite **orchestration** (loop over
  `requires_apt`, a distinct prompt per package, install before the backend dispatch, skip the whole tool on a
  decline, the step listed under `--dry-run`) is verified by the four unit tests and the two mutation proofs above.
  The prerequisite **apt mechanism** is the same `apt.apt_install_package` call site (same `sudo -n apt-get`, same
  `InstallSkipped` mapping) that `massdns` exercises live, so a separate live `libpcap-dev` run is not required to
  close the Part 10 gate: `massdns` alone is the accepted live proof. Forcing it would need either a destructive
  `apt-get remove naabu` or waiting for a natural not-current state.

## Part 10f follow-up - sudo ticket invisible to detached children (code, PIT-32)

- Symptom, isolated by the user's A/B test in one shell with a fresh `sudo -v` ticket: the direct
  `subprocess.Popen([...])` call succeeds under `sudo -n true`, and the identical call with only
  `start_new_session=True` added fails with `sudo: a password is required` and exit 1. Nothing else changed.
- Root cause confirmed: `start_new_session=True` calls `setsid()`; sudo's `tty_tickets` caches the ticket against
  the parent's controlling terminal/session, so the detached child cannot see it.
- Docs check (step 8) before touching code: `grep -rn "session\|setsid\|start_new_session\|process group\|pgid\|subprocess"
  docs/03_ARCHITECTURE.md docs/10_TOOL_INSTALLER.md` finds only docs/03:5,34,60,108,117,161,193 and docs/10:83, none of
  which describes session membership. docs/03:193 says "Kill process group" and stays true after the fix, so no doc
  text needed changing; only this log and the PIT row were updated. No adapter, installer or test assumes detachment:
  `grep -rn "getsid\|setsid\|start_new_session\|process_group\|preexec_fn" src/reconkit/ tests/` matched only
  `src/reconkit/core/runner.py:112`, and a daemon/double-fork/orphan/survive grep matched only the runner's drain
  threads and `spawn_child.py`, which is used solely by the timeout-kill test.
- Fix (`src/reconkit/core/runner.py`): `start_new_session=is_windows`,
  `process_group=None if is_windows else 0`. Verified against the CPython 3.11 source that Windows accepts and
  ignores both arguments (`_execute_child(..., unused_start_new_session, unused_process_group)`).
- Tests added (`tests/test_runner.py`, fake child `tests/fakebin/session_child.py`):
  `test_regression_child_shares_parent_session_but_not_pgid` and
  `test_regression_kill_tree_kills_only_the_child_group`. PIT rule followed: the first failed before the fix with
  `AssertionError: child sid=8034 parent sid=8011; child pgid=8034 parent pgid=8011` / `assert 8034 == 8011`
  (getsid; pgid already passed) and passed after (`1 passed`). The kill test starts a child with `process_group=0`
  plus a sibling in the parent's group, calls `_kill_tree`, and asserts the child exits by `SIGKILL`, the sibling is
  still alive, and the parent's pgid is unchanged.
- Mutation proof: reverting only `process_group=0` to `start_new_session=True` (the old line) reproduces the PIT-32
  assertion failure above; restoring the fix passes. The pre-fix run of the same test is that proof; no separate
  mutant was needed.
- Residual risk (named): every adapter and every installer backend now runs its child in the parent's session
  instead of a fresh one. Consequences: (a) a child can now open `/dev/tty` where `setsid()` previously detached it;
  stdin is `DEVNULL` and the apt path uses `sudo -n` with `DEBIAN_FRONTEND=noninteractive`, so no known tool prompts;
  (b) terminal-generated signals are sent to the foreground process group, and children are still in their own
  process group (`process_group=0`), so Ctrl-C still does not reach them, while a session-wide teardown such as a
  terminal hangup can now reach them where it previously could not. Scans and installs are run to completion in the
  foreground under a live terminal, and `_kill_tree` still owns timeout cleanup, so this is accepted; it is recorded
  rather than silently ignored. (c) tools that daemonize themselves (none in the registry today) would still
  `setsid()` on their own and detach. `_kill_tree` is unchanged and still targets only `os.getpgid(process.pid)`.
- Check output: `tests/test_runner.py` 34 passed; full gate recorded in PROGRESS. The real sudo-authenticated
  `install --all` proof is still outstanding and is the only open Part 10 gate item.

## Part 10f follow-up - massdns version display (code)

- Symptom: the idempotent `install --all` row read
  `massdns  apt  already installed  massdns: already installed (/usr/bin/massdns)`, while every other apt tool
  showed a version (`amass (v5.1.3)`, `dig (DiG 9.20.30-1-Debian)`, `nmap (Nmap version 7.991 ...)`).
- Cause: `github_release.installed_version()` returns `str(copy)` when `plan.version_args` is empty, and
  `registry._plan()` discarded `version_cmd[0]`. `massdns --help` has no version flag and `massdns -v` reads a
  filename, so the plan had no `version_cmd` at all. The dpkg package version is the only source:
  `dpkg-query -W -f='${Version}' massdns` -> `1.1.0-0kali2`.
- Fix: docs/10 (commit `66b117c`) defines `version_cmd[0]` as the program that reports the version, defaulting to
  `binary`. `InstallPlan.version_command` is set only when the head differs from `binary` (so the managed-copy
  preference is unchanged); `installed_version` resolves it with `shutil.which` and runs it; `apt.install_apt`
  passes it to `check_version`. `tools.yaml` gives massdns `[dpkg-query, -W, '-f=${Version}', massdns]`.
- Tests: `test_massdns_version_command_is_the_package_manager` and
  `test_massdns_version_cmd_reports_dpkg_version` (fake runner; asserts the exact argv
  `['/usr/bin/dpkg-query', '-W', '-f=${Version}', 'massdns']` and the state `1.1.0-0kali2`). Full gate:
  `569 passed`, ruff/format/mypy clean.
- Live proof: after `sudo apt-get remove -y massdns`, a fresh `reconkit install --all --no-color` under a pty
  authenticated with `sudo -v` reported `massdns apt installed`; `dpkg-query` then read
  `install ok installed 1.1.0-0kali2` and `command -v massdns` -> `/usr/bin/massdns`. The next idempotent
  `install --all` (no sudo needed) showed `massdns  apt  already installed  1.1.0-0kali2`.
- Caveat: the pty driver's first attempt answered the earlier "Free only, or add keys?" prompt with `y`, so the
  massdns confirmation went unanswered and the run was killed. The orphaned installer continued: it installed
  `katana` into `~/.reconkit/bin` and attempted `nuclei`, which failed with
  `'nuclei' exceeds 104857600 bytes`. The following idempotent run reports both as `already installed`
  (nuclei via `/home/kali/go/bin/nuclei`, v3.11.1). `.env` was not modified.
- `install --all` exits 5 because `rustscan`'s placeholder asset (`verify-at-implementation`) still fails; that is
  the known, tested exclusion, not a massdns failure.

## Part 11b - docs sync (docs 01-10)

- docs/01: primary platform is a native Linux checkout (Kali/Ubuntu) with a separate Windows checkout; Windows runs
  mock/passive flows and `doctor`, not recon tools. The Phase 2 command list marks `db list`, `db export`, `export`
  and `scope import` as Phase 3 stubs, the success metric and test platform no longer say WSL2, and the open
  questions are closed.
- docs/02: `-q/--silent` (the docs said `--quiet`, which does not exist); `--json` is documented on the scan
  commands, `doctor`, `diff` and `status`, not on `install`/`update`/`scope check`/the stubs; `db list` and `db
  export`/`export` are marked Phase 3 stubs; the status JSON field list now matches `ui.status_document`; the
  progress line says `--silent`.
- docs/03: the dead `dns_python.py` name is corrected to `dnspython.py`; 429/5xx are documented as failed results
  with no retry (only a connection error retries once); `meta/` no longer claims a `reconkit.log`; the platform
  decision and workflow section describe the native Linux checkout instead of the WSL2-only workflow.
- docs/04: the DB hosting line no longer hard-codes `~/reconkit`; the nonexistent `db delete -d X` command was
  removed.
- docs/05: logging now states that this build has no file logger; data protection no longer names `db delete`.
- docs/06: `InstallSkipped` is added to the exception list; logging matches the console-only build.
- docs/07: live tests are documented as manual, with the `live` marker registered but no checked-in test; the test
  tree is replaced with the real files; the unverified ~85% coverage target was removed.
- docs/08: setup is not WSL-only; `install` does not rerun `doctor`; the status JSON example matches
  `ui.status_document`; resume is stage-level (the interrupted stage reruns); export is marked a Phase 3 stub.
- docs/09: intrusive tools are refused because there is no `--intrusive` flag; 429/5xx are failed without a
  back-off; the `InstallStatus.version` comment no longer implies the installer's `version_cmd` field.
- docs/10: the apt row shows `apt-get`; the dry-run example is the real table shape (`tool/method/result/detail`).
- Deliberately not changed here: `README.md` and `SETUP.md` are still the WSL2 beginner guide (11a is next);
  docs/10's Windows refusal text still says `Use WSL2 Kali (see SETUP.md)` because that is the code's literal
  message; stage-table tools without adapters remain Phase 3 by design; `docs/PROGRESS.md` line 101 about the
  original uv/WSL venv is an environment deviation, not current setup advice.
- Checks: docs-only change; the pre-commit hook runs the full gate (569 passed, ruff, format, mypy).

## Part 11b-2 - docs/08 flow audit and follow-ups

- `docs/01` §12: the deployment question "which optional keys a user configures first" is restored; it was removed in
  11b by folding three questions into one "no blocking questions" sentence, which was a judgment call, not a resolved
  item. Release asset names and the `nuclei` phase are genuinely closed.
- `docs/01` Feature 5: removed the nonexistent `--ports`/`--full` flags; ports come from each adapter's default set.
- `docs/02`: the result-table example now has the real `Status` column and plausible rows; the tools panel is a table
  with stage/status/items/detail; the Progress section states that no live line is wired
  (`ui.render_progress` is uncalled); the summary line no longer claims "new items"; the success state no longer
  claims workspace/DB paths are printed (they are not).
- `docs/03` failure table: Ctrl+C marks the run `interrupted` and exits 130, but a child already running is **not**
  explicitly killed in this build; the old "kill children" claim was wrong.
- `docs/08` Flow 2: dry-run columns are `tool/method/result/detail`; the installer has no per-tool progress line, only
  a final table; checksum errors use the real message shape; the empty state is not a separate line.
- `docs/08` Flow 4: no header/estimated time and no live progress line; the wildcard check only surfaces as a warning
  when detection is `unknown`; real result columns include `Status`; the footer has counts and tool statuses but no
  workspace/DB paths.
- `docs/08` Flow 5: no title/tech columns and no `[NOW ALIVE]`/`[WENT DOWN]` tags in the stage table; changes appear
  later as `STATE` rows in `diff`.
- `docs/08` Flow 6: removed `--ports`/`--full` (they do not exist); no IP/service columns are rendered.
- `docs/08` Flow 7: real labels are `NEW`, `GONE`, `STATE`, `PORT OPEN`, `PORT CLOSED`; empty message has no date;
  the no-run message is `No completed discovery run for this target.`, and the one-run message includes `(#N)`.
- `docs/08` Flow 9: Ctrl+C does not explicitly kill a running child; only new launches stop.
- `pyproject.toml`: the `live` marker description now says Kali/Ubuntu instead of WSL2.
- Evidence for the flow fixes: a real `passive -d example.com --mock` run printed the six-column table
  (`Subdomain/State/Status/Ports/Sources/Trust`) and the counts/tool-status footer, and a second run plus `diff`
  printed `No changes since run #1.` A fresh DB printed `No completed discovery run for this target.`
- Remaining by design: docs/10's Windows refusal message still matches the code's literal `Use WSL2 Kali` string;
  port IP/service data is stored but not rendered; stage-table tools without adapters remain Phase 3.

## Wildcard filter wiring in the engine (2026-11-14)

- Docs read / goal: docs/03 section 8 (wildcard filter and API bullets), docs/09:166 (`matches` rule), docs/04
  (`subdomains.is_wildcard`), docs/PROGRESS "Part 9 triage: wildcard detection is still not wired". Goal: make the
  existing `core/wildcard.py` detector run per scan and store `is_wildcard`.
- Decisions and assumptions:
  - The two docs bullets were already ahead of the code, so only one gap needed a docs change: `wildcard_check.enabled`
    was modeled and set `true` but named by no document. It now means "filter off when false"; the same sentence
    records the `--mock` rule that docs/03's engine API already implies.
  - The detector is constructed in `Engine.run` right after `_run_tools` returns the `dns` stage's `RunContext`.
    That is the one place where the stage's limiter and resolver context exist, and a run has at most one `dns`
    stage, so this is one detector per run in practice.
  - The probe uses a fresh `DnsPythonAdapter()` bound to that context: the stage's own adapter instance is created
    inside `_run_one` and is not retained, so "reuse that resolver" means the same adapter code path and the same
    stage limiter, not the same resolver object.
  - `is_wildcard` is written only in `_persist_dns`'s `RESOLVED` loop, the first point where a host is known to have
    resolved. `PRESENT` passes `matches()`; `NONE` and `UNKNOWN` pass `None` (no mark, no clearing of an older mark).
- Decisions for user review:
  - `wildcard_check.enabled` is honored as a switch. The docs previously said nothing about it; if it was meant to
    control something else (for example whether wildcard hosts are hidden), say so and the docs/code change again.
  - docs/09's "exclude them from counts by default" was **not** implemented: no doc defines which count (host table,
    JSON summary, confidence) and no code path filters it. It is now an open item in PROGRESS rather than a guess.
- Docs changed first: `docs/03_ARCHITECTURE.md` section 8 (switch + mock clause), commit `581a556`.
- Deviations: none from the agreed spec. The `enabled` switch is the one behavior added beyond the two bullets.
- Files touched: `docs/03_ARCHITECTURE.md`, `docs/PROGRESS.md` (docs commit); `src/reconkit/engine.py`,
  `tests/test_engine.py`, `docs/PROGRESS.md`, this file (code commit).
- Requirement -> test table:
  - PRESENT marks matching hosts: `test_wildcard_present_marks_matching_hosts`.
  - NONE leaves hosts at 0: `test_wildcard_none_marks_nothing`.
  - UNKNOWN warns and marks nothing: `test_wildcard_unknown_warns_and_marks_nothing`.
  - `is_wildcard` reaches the `subdomains` table: `test_wildcard_mark_reaches_the_subdomains_table`.
  - `--mock` never probes: `test_wildcard_never_probes_under_mock`.
  - Probes stay under the target: asserted inside the PRESENT test (`<label>.example.com`, three calls).
- Self-review findings (S2 lists, S3 raw output): no new dependencies, no `assert` in `src/`, no new suppressions, no
  adapter imports added to `core/`; `engine` already imported `cast`/`Any`, so the probe binding adds no new import
  surface beyond `functools.partial` and `core.wildcard`.
- Bugs found: none beyond the already-logged "built but never wired" gap this change closes.
- Mutation/red proof: with the old `engine.py` restored and the new tests kept, `4 failed, 1 passed, 36 deselected`,
  exit 1 (`assert 0 == 3` for the probe count; `{'www.example.com': 0} != {'www.example.com': 1}` for the table).
  The mock test passes in both states by design. Restored with `git stash pop`; green run `5 passed`.
- Raw check output (`.venv`, Python 3.14.8): `585 passed in 12.96s` -> `pytest=PASS`; `ruff check .` ->
  `All checks passed!` -> `ruff=PASS`; `ruff format --check .` -> `69 files already formatted` -> `format=PASS`;
  `mypy src/reconkit` -> `Success: no issues found in 37 source files` -> `mypy=PASS`.
- Real run (v4) `/tmp/rk_testfire_v4.db`, `reconkit passive -d testfire.net --db /tmp/rk_testfire_v4.db -v
  --no-color`: 2 `scan_runs` (`subs` partial 15:11:17-15:13:58Z, `dns` completed 15:13:58-15:14:56Z), 16
  `tool_runs`, 36 `subdomains`, `0` non-zero `is_wildcard`, no wildcard warning, exit 5 (`otx` 429 only).
  `PRAGMA integrity_check` = `ok`, `PRAGMA foreign_key_check` empty. v1/v2/v3 sha256 values are unchanged before and
  after (`f1832f...`, `f90227...`, `61f748...`), so the first three artifacts were not touched.
- What `detect()` returned for testfire.net: `none`. Confirmed two ways: the v4 run printed no inconclusive warning,
  and an observer run (a wrapper around `WildcardDetector.detect` with no `src/` change) recorded exactly one call,
  `{'target': 'testfire.net', 'status': 'none', 'probes': 3, 'resolved': 0, 'ips': [], 'cnames': []}`. Before
  interpreting it, three random `A` labels under `testfire.net` were resolved directly with the venv's dnspython and
  all returned `nxdomain`, so `none` is the expected status and no wildcard answer exists to match.
- Not verified (needs network/tools): nothing new. The `live`/`ports` marking path was not exercised because it is
  the `dns` stage that owns resolution; `_write_host` passes no `is_wildcard`, so an earlier mark is preserved. That
  preservation is covered by the store's `COALESCE` tests, not by a new end-to-end live run.
- Next part must know: `is_wildcard` is a mark only (docs/09's "exclude from counts" is unimplemented and undefined);
  11d-findings-b and (c) remain open; `certspotter` still returns `ok` with 0 items on every real run and needs a
  one-line hypothesis before Part 11 closes.

## Part 11 - findings backfill (docs only, 2026-11-14)

- Why this entry exists: MASTER_PLAN:222 requires every Part 11 finding to be logged under "Bugs found". Only the
  wildcard wiring had a REVIEW_LOG section; the rest lived in `docs/PROGRESS.md`, in commit subjects, or nowhere.
  This section is the accounting for the whole Part 11 window (`3a14568`..`b24f39b`). It records dispositions as the
  code and docs actually stand today. It does not re-verify any fix, and it does not claim an open item is closed.
- Scope: docs-only. No `src/`, `tests/`, `tools.yaml` or `config.yaml` change. No test is added by this entry; the
  four guarding tests below pre-date it and are named, not created, here.
- Provenance of the list: an earlier conversational tally of "14 findings" was never a repo artifact
  (`grep -rn 11c docs/*.md` returned only MASTER_PLAN:222, MASTER_PLAN:223 and PROGRESS:189). The table below is the
  first committed enumeration: 14 findings plus one cleanup row.

### Findings

| ID | Finding | Class | Disposition | Commit | Guarding test |
|---|---|---|---|---|---|
| 11d-a | `_write_host` overwrote the discovery consensus: `demo.testfire.net` stored `LOW`/1 while docs/04 section 5 requires `MEDIUM`/2 from two sources | logic | FIXED | `1b41f4e` | `tests/test_engine.py::test_dns_pass_does_not_overwrite_discovery_confidence` |
| 11d-b | the `dns` stage INSERTs subdomain rows for hosts discovery never returned, with `first_seen_run` = a dns run and no `subdomain_sources` row | logic | **OPEN** | ticket in PROGRESS | none (blocked on a product decision) |
| 11d-c | `tool_runs.duration_s` stores `0.0` for real I/O; three writers | logic | **OPEN** | ticket in PROGRESS | none |
| 11d-e | `subfinder`/`assetfinder` launched bare `argv[0]` with no `PATH` in the child env, so `doctor` said installed and the scan said not installed | logic | FIXED | `df218b5` (docs `a0d06b5`) | `test_build_command_launches_the_resolved_managed_binary`, `test_installed_binary_in_managed_dir_actually_runs` |
| D | identity markers were satisfied by ANY marker, so the `httpx` namesake passed `check_installed()` | logic | FIXED | `d265dc0` (docs `22fbd49`) | `test_projectdiscovery_identity_requires_every_marker`, `test_naabu_identity_accepts_real_version_banner`, `test_subfinder_identity_accepts_pre_264_version_only_banner` |
| W | wildcard filter built but never called; an inconclusive detection was silent | logic | FIXED | `1dd63e5` (docs `581a556`) | see "Wildcard filter wiring in the engine" above (5 tests) |
| 11d-d | "missing binary" meant two different moments across docs/03, docs/09 (two sections) and MASTER_PLAN | doc text | RESOLVED, docs only | `a0d06b5` | n/a |
| 11b-2 | docs/08 flows did not match the built CLI; the docs/01 deployment question had been dropped | doc text | RESOLVED, docs only | `d2e3c66` | n/a |
| - | first-contact contradictions across docs/01, 02, 04, 05, 07 and README | doc text | RESOLVED, docs only | `722b2d1` | n/a |
| - | AGENTS session-start checklist was duplicated and inconsistent | doc text | RESOLVED, docs only | `046e0a2` | n/a |
| 11a | README/SETUP were still the WSL2 beginner guide | doc text | RESOLVED, docs only | `cc70b15` | n/a |
| R1 | managed-directory shadowing: a broken `~/.reconkit/bin` copy shadows a working PATH binary | doc text | **OPEN RISK**, deliberate | `3e2aff9` | n/a (manual mitigation; PROGRESS "Open risks") |
| R2 | interactive Ctrl+C does not kill an already-running child | doc text | **OPEN RISK** | `86be2bb` | n/a (killpg path unverified on Linux) |
| - | `certspotter` reporting `ok`/0 on every run | not a defect | EXPLAINED | `430aa1d` | n/a |
| - | `src/reconkit/adapters/dns_python.py` dead stub | cleanup | REMOVED | `b24f39b` | n/a (docs/03:70 fixed earlier in `3a14568`) |

### Logic findings fixed in this window (symptom / root cause / fix / guard)

- **11d-a (high).** Symptom: `/tmp/rk_testfire_v2.db` stored `LOW`/1 for a host with two `subdomain_sources` rows,
  where docs/04 section 5 requires `MEDIUM`/2; the stored value followed write order across six runs. Root cause:
  `_write_host` passed `source_count=len(transition.sources)`, and `upsert_subdomain`'s `COALESCE` guards only
  `None`, so a state pass overwrote a column it had no data to justify. Fix: `_write_host` supplies no `source_count`
  and supplies `confidence` only for `UNCONFIRMED`; `_persist_dns` gained the same `if not transition.persist:
  continue` that `_persist_live` already had. Guard: the test above, red first (`('LOW', 1) == ('MEDIUM', 2)`,
  `1 failed, 35 deselected`), green after (`1 passed`); full suite 570. Verified on the v2 real run.
- **11d-e (high).** Symptom: `check_installed()` reported `subfinder v2.17.0` at
  `/home/kali/.reconkit/bin/subfinder` while a real passive run stored `failed` with `[Errno 2] No such file or
  directory: 'subfinder'`. Root cause: `build_command()` used the bare name while `Engine._tool_env` passes only key
  variables, so the child had no `PATH` to resolve it against. Fix: launch `binary_path() or binary`; the child env
  was deliberately not widened with `PATH` (hijack surface). Guard: the two tests above, red first (`4 failed, 59
  deselected`, production message reproduced verbatim), green after (574 passed). Two existing argv assertions were
  hardened from bare `argv[0]` to `Path(argv[0]).name` because they only passed on a box without the tool installed.
  Verified on the v3 real run.
- **Identity markers (medium).** Symptom: a binary whose banner carried only one of two markers was accepted, which
  cannot reject the `httpx` namesake docs/09 promises to reject. Root cause: `check_installed()` used `any()`. Fix:
  `BinaryAdapter.identity_require_all = True` drives `all()`, with one documented opt-out, `SubfinderAdapter`,
  because upstream added the `Subfinder Config Directory` line in v2.6.4 and an AND would report a working pre-2024
  install as not installed. The missing `naabu` positive identity test was added at the same time, so the
  strictness change did not ship its success path untested. Guard: the three tests above, red first (`4 failed, 2
  passed, 63 deselected`), green after (identity slice `11 passed`; full suite 580).
- **Wildcard wiring.** Already logged above in this file; this entry only assigns it an ID so the table is complete.

### Logic findings still open

- **11d-b (medium).** Not a test gap: the fix is a product decision first (drop dns-only hosts, or keep the row and
  label its provenance as dns and exclude it from discovery counts and `diff_new`), then the two call sites, then
  the rule in docs/04 section 5. Data-dependent: visible in v1/v2, absent in v3/v4 because `assetfinder` returned
  the apex.
- **11d-c (low).** Metadata only. Needs a decision on which measurement is authoritative (adapter-measured vs
  `Engine._run_one`-measured) recorded in docs/04 before any writer changes; a careless fix double-counts.

### What this entry does not establish

- The ten S3 scans (MASTER_PLAN:38) were **not** re-run for this docs-only commit. 11c still requires one final run
  of all ten plus a second full `pytest`; both remain outstanding.
- 11c-bis (fresh-venv `--mock` end-to-end run) is still not done. No REVIEW_LOG entry, commit body or PROGRESS line
  records it ever running.
- 11f (final report) remains unwritten. The RESUME block was stale until this commit corrected it.
- Pitfalls added this entry: PIT-33 (docs-only commits bypass the pre-commit PROGRESS requirement).

## Part 11c - fresh-eyes audit (docs only, 2026-11-14)

- What was read: `engine.py` (all 1238 lines), `cli.py` (all 702), `core/scope.py`, `core/runner.py`, `core/pacing.py`, `core/workspace.py`, `core/wildcard.py`, `adapters/base.py`, all twelve adapters, `doctor.py` (report and key paths), `store.redact`, `installer/github_release.py` (`install_selected`, `desired_version`), `config.yaml` and the `tools.yaml` stage modes. No `src/` or `tests/` change in this entry.
- Requirement -> outcome, one row per MASTER_PLAN:222 hunt category:
  - (a) active tool without `--active` + scope pass: no bypass. `cli.py:47`, `cli.py:168-170`, `engine.py:707-741` (selection), `engine.py:683-712` (gate + skip), exit 3 on denial.
  - (b) timeout becoming DEAD/SHUT_DOWN: none. `dnspython.py:126-127` is the only DEAD producer; `engine.py:234-255` keeps the previous state on uncertain evidence; `pyprobe.py:112-124` maps TLS failures to `UNKNOWN`.
  - (c) secrets: no proven leak. Keys only in headers (`certspotter.py:33`, `otx.py:23`), never argv (`subfinder.py:88-89`); redaction in `runner.py:184-189`, `engine.py:867-877`, `store.redact`; `doctor.py:266-273` prints names and computes `Set` from `.env`. Open question stays `cli.py:227` / `-v` (`cli.py:125-127`).
  - (d) traceback escaping: none demonstrated. `cli.py:225-229`, `github_release.py:601-611`, `:518-521`. Unverified: `BrokenPipeError`, fast-active prompt EOF.
  - (e) blocking in async: E-1 `engine.py:551-556`, E-2 `engine.py:687`, E-3 `engine.py:463`. No structural change made.
  - (f) confidence from non-distinct tools: none. `engine.py:118-131` uses `set()`; ports disagree into `UNCONFIRMED` (`engine.py:1204-1238`).
  - (g) docs/code mismatches: G-1 workspace never written (`workspace.py:104` no callers, `models.py:112` never set vs docs/03:120); G-2 `pacer.before_host()` never called (`pacing.py:73`, docs/03:125, `config.yaml` host_delay); G-3 `scope.passive_warning()` never called (`scope.py:325`); G-4 unreachable `ExitCode.ALL_FAILED`; G-6 the 11d-e blast-radius claim is false (`httpx_tool.py:48`, `naabu.py:41`).
- Consolidated findings and states: see the `## Part 11c` table in `docs/PROGRESS.md`; the head-line items are A-1 (high, fix queued), G-1 (high, ticketed), G-2 (high, contract ambiguity reported), G-3 (medium, ticketed), C-1 (known), E-1/E-2/E-3, C-2 and G-4 (low, ticketed).
- Not verified: the two (d) edges above; every finding is static analysis - no tool was executed and no target was touched in this audit.
- Checks: docs-only change; the pre-commit hook runs the full gate (585 passed, ruff, format, mypy).

## Part 11c-G-2 - inter-host pacing was documented but never called (docs + code)

- **Symptom:** `active.host_delay` is configured for every speed (`[1, 5]` slow, `[0, 2]` normal, `[0, 0]` fast) and docs/03 §7 lists `before_host()`, but nothing called it: active stages sent host after host with no inter-host pause.
- **Why it was reported instead of guessed:** the docs only listed the method in the API; they did not say which loop owns it, and the three adapter shapes disagree - a sequential loop (`pyscan`), a gather (`pyprobe`), and one process for all hosts (`httpx`/`naabu`). A per-host call inside `pyprobe`'s gather would sleep concurrently rather than space dispatches. Owner ruling: Option B.
- **Docs first:** `0ced491` - docs/03 §7 now states that `before_host()` spaces host dispatches in `pyscan` and `pyprobe`, uses `active.host_delay`, does not wait for the first host, that `pyprobe` dispatches sequentially at `parallel_limit("active") == 1`, and that `httpx`/`naabu` are exempt and pace via `-rl`/`-rate`.
- **Code:** `pyscan.run` awaits `before_host()` before the second and later valid host; `pyprobe.run` takes a sequential branch at `parallel_limit("active") <= 1` and keeps the gather above it. `httpx`, `naabu` and passive `dnspython` are untouched (the last because `before_host()` reads the active preset).
- **Guarding tests:** `test_pyscan_waits_between_hosts_before_dispatching_the_next` and `test_pyprobe_waits_between_hosts_when_dispatch_is_sequential` (docstring `Regression: 11c-G-2`). Red before the wiring: `2 failed, 35 deselected`, both `StopIteration` because no pause was recorded. Green after: `2 passed, 35 deselected`.
- **Assertion strength:** ordering, not call count - host B is not dispatched until the recorded pause after host A completes, the first host never waits, and the pause is inside slow's `[1, 5]`.
- **Not verified:** no live active run; the tests inject a recording sleep, so real wall-clock spacing is unmeasured.

## Part 11c-A-1 - active binary adapters launched a bare argv[0] (code)

- **Symptom:** `doctor` reported `httpx v1.12.0` and `naabu 2.7.0` at `~/.reconkit/bin/...`, while a `live` or `ports` stage would record `failed` with `not installed or not executable` - the same self-contradiction 11d-e removed from subfinder/assetfinder.
- **Root cause:** `httpx_tool.py:48` and `naabu.py:41` built `argv[0]` from the bare `self.binary`; `Engine._tool_env` (`engine.py:867-870`) passes only key variables and `BinaryAdapter.child_env` (`base.py:213-219`) adds only `HOME`/`USERPROFILE`, so the child has no `PATH`. `run_exec` turns the resulting `OSError` into `returncode=None` (`runner.py:105-124`) and `base.py:158-164` maps that to `failed`. `check_installed()` used `binary_path()`, hence the disagreement.
- **Fix:** launch `self.binary_path() or self.binary` in both adapters. The child env was deliberately not widened with `PATH`.
- **Guarding tests:** `test_active_binary_adapters_launch_the_resolved_managed_binary` (new, parametrized over both adapters; docstring `Regression: 11c-A-1`), red before the fix (`2 failed, 69 deselected`, `PosixPath('httpx').is_absolute()` False) and green after (`4 passed, 67 deselected`; full suite 587). `test_httpx_command_dedupes_and_lowercases_hosts` and `test_naabu_command_and_ports` were hardened from a bare `argv[0]` to `Path(argv[0]).name` for the same environment-dependence reason as 11d-e.
- **Not verified:** no real binary and no target were used; the test launches a stand-in in the managed directory.
- **Why 11d-e missed it:** that entry claimed subfinder/assetfinder were the only two `build_command` implementations. Corrected in `docs/PROGRESS.md` (11c-G-6).

## Part 11c-G-7 - the IP/CIDR scope rule is unenforced (docs only)

- **Symptom:** docs/05 rule 6 requires an IP to be inside `in_scope_cidrs` before it is probed, and to be skipped entirely when no CIDRs are defined. The code contains the predicate for that rule and never uses it.
- **Evidence:** `scope.py:296` `ip_allowed(ip, *, path)` and `ScopeGate.ip_allowed` (`scope.py:110`) both implement "no CIDRs means no IPs"; `tests/test_scope.py:142-148` exercises all three outcomes directly. `grep -rn ip_allowed src tests --include=*.py` returns only those definitions, the wrapper and the tests - **zero call sites in `src/`**. `pyscan.py:75-81` then does the exact thing the rule forbids: `addresses = await self._resolve(host)`, `ip = addresses[0] if addresses else host`, and probes `ip`.
- **Ruling recorded in the ticket:** until fixed, no IP-connecting active tool (`pyscan`, `naabu`, or any future resolve-then-connect adapter) may run. This is a hard precondition on active-stage work, not a note. `pyprobe` is exempt from the precondition because it connects by hostname and never touches a resolved IP.
- **Why it matters for a real run:** the local `scope.yaml` for the first supervised run has no `in_scope_cidrs`, and the wildcard `*.testfire.net` would otherwise authorize any name that resolves anywhere. With only `pyprobe` selected, that run touches no resolved IP, which is why it can proceed under this ticket.
- **Not done:** no code fix, no test change, no decision on where the enforcement belongs (`_active_hosts`, per-adapter, or a shared resolve helper).
- **Checks:** docs-only change; the pre-commit gate runs the full four checks (see the commit output pasted in the session report).

## Part 11c-G-7 - the IP/CIDR rule is enforced in `pyscan` (2026-11-14)

- **Docs read / goal:** docs/05 section 2 rule 6, docs/03 section 13, docs/09 section 3 (adapter contract, `RunContext`, per-host adapters), docs/06 (no `assert`, no new suppressions, adapters never import `scope`), docs/07 (no network in tests). Goal: make the documented IP rule true at the only place in this build that resolves and then connects.
- **Order of work, and why two commits:** `30c368e` first added a selection-time block for both IP-connecting adapters with a test that fails if the block is removed, so the tree could not launch an unchecked IP even if the wiring below were reverted. The wiring then removed `pyscan` from that block and changed the test to assert `pyscan` is selectable and `naabu` is not.
- **Enforcement point, decided:** the adapter, not `_active_hosts` and not a shared helper. `pyscan` owns its resolver call, and the engine cannot filter an address it never sees. To keep the adapter free of `core.scope` (hard rule), `RunContext` gained `ip_allowed: Callable[[str], bool] | None`, filled by `Engine._ip_allowed()` from `load_scope(self.scope_path).ip_allowed` once the active gate passed. `None` (no readable scope) means deny, matching the predicate's own "no CIDRs means no IPs".
- **Behaviour fixed beyond the literal ticket:** `ip = addresses[0] if addresses else host` was a second bypass - an empty resolver answer handed the *hostname* to `asyncio.open_connection`, which resolves again below the filter. Empty now counts as `blocked=1` and nothing is probed. `addresses[0]` also became "the first *allowed* address", so a mixed answer no longer skips a permitted address just because the resolver listed a forbidden one first. A resolver answer the predicate cannot parse (`ValueError`) is a block, not a pass.
- **Decision for user review - `naabu` stays blocked.** `naabu` is handed hostnames and resolves inside the child; neither the adapter nor the engine can see the address, so there is no place to apply rule 6. Passing pre-resolved IPs instead would change `PortRecord.fqdn` semantics and could not be verified against the real binary (not installed here, and G4 forbids guessing its output). The safe choice is the skip: `blocked: resolves inside the binary, so in_scope_cidrs cannot be enforced (11c-G-7)`. The ports pool is therefore `pyscan` only in this build. Overrule this if a pre-resolve design is wanted.
- **Tests:** `test_pyscan_probes_only_an_address_inside_in_scope_cidrs` (mixed answer, only the permitted address is probed), `test_pyscan_skips_a_host_whose_address_is_outside_in_scope_cidrs` (no connection, no invented `closed` row, `blocked=1`), `test_pyscan_without_cidrs_probes_no_addresses` (predicate `None`), `test_pyscan_never_falls_back_to_the_hostname`, `test_pyscan_blocks_a_malformed_resolved_address`, `test_active_ports_stage_receives_the_cidr_predicate` (engine-level: the stage gets the scope file's predicate; `203.0.113.5` allowed, `198.51.100.5` not), `test_naabu_stays_blocked_because_it_resolves_inside_the_binary`.
- **Test helper change, disclosed:** `make_ctx()` in `tests/test_python_adapters.py` gained `ip_allowed` defaulting to a permissive lambda. That stand-in represents the engine's hand-down; the real wiring is proven separately by `test_active_ports_stage_receives_the_cidr_predicate`, so the default cannot hide a missing hand-down.
- **Mutation proofs (raw):** (1) `_allowed_addresses` made to `return addresses` -> `3 failed, 1 passed, 38 deselected`, first failure `AssertionError: assert ['not-an-ip'] == ['203.0.113.5']`; restored -> `17 passed, 25 deselected`. (2) `RunContext` built without `ip_allowed` -> `AssertionError: the active ports stage must get a CIDR predicate`, `1 failed, 42 deselected`; restored -> `1 passed, 42 deselected`. `git status --short` showed only the five intended modified files afterwards.
- **Checks:** `pytest -q` -> `596 passed`; `ruff check .` -> `All checks passed!`; `ruff format --check .` -> `68 files already formatted` (after `ruff format tests/test_python_adapters.py`, which reformatted 1 file); `mypy src/reconkit` -> `Success: no issues found in 36 source files`.
- **Not verified:** no real resolver and no real target were used - `pyscan` has never run against a live host, so the filter is proven against injected resolvers only. The `blocked=` token is new in `ToolResult.error` and appears nowhere in real data yet.

## Part 11 close-out - rulings for the nine open items (2026-11-14)

- **Why this entry exists:** Part 11 could not close with findings that were merely "ticketed, no code": an owner reading the table could not tell whether an item was dropped. Every open 11c/11d item now has a ruling, and the deferred ones name a single future part instead of a vague "later".
- **Named future part:** **Part 12 - evidence, secrets and loop hygiene**. It is not in `docs/MASTER_PLAN.md`; adding a part is the owner's decision, so this entry records the name and scope rather than editing the plan.
- **Two fixes landed with this entry:** G-3 and G-4 (below). Everything else is deferred with a reason, and the two new findings from the first real active run (11d-findings-f and -g) are ticketed and deferred rather than silently absorbed.

| Item | Ruling | Why | What a fix needs |
|---|---|---|---|
| 11d-findings-b | **deferred to Part 12**, product decision made now | no traffic or scope impact, but the choice changes inventory semantics and `diff_new` | decision: keep the dns-only row, mark provenance `dns`, exclude from `diff_new` and discovery counts; then `_persist_dns` / `_previous_facts`, docs/04 section 5, migration if a column is added |
| 11d-findings-c | **deferred to Part 12** | metadata only: three writers disagree (`HttpAdapter` omits `duration_s` on two branches, `DnsPythonAdapter` never sets it, `_run_one` discards its own measurement on success), so the fix starts with which measurement is authoritative | decide adapter-measured vs engine-measured (docs/04 states it for the column), then fill all three sites, then test a 429, a parse error and a successful DNS run each store `> 0` |
| G-1 | **deferred to Part 12** | docs/03 promises raw output files; writing them needs per-adapter raw text, so it is an adapter-contract change, not a one-line call to `Workspace.write` | a `raw_path` per result, one write per adapter branch, redaction before write (PIT-22), tests per adapter |
| G-3 | **fixed now** | one caller away from the documented behaviour; no design decision needed | `Engine._note_passive_warning` calls `scope.passive_warning()` for a non-active run and splits/strips the `warning:` prefix so the UI does not print it twice |
| G-4 | **closed, not a defect** | docs/02 section 6 gives code 6 to install/update only, so a scan whose tools all failed returning 4 is correct; the member was dead weight that implied a scan outcome | removed `ExitCode.ALL_FAILED`; the enum test now pins the scan set {0,1,2,3,4,5,130}. The installer's numeric 6 is untouched |
| C-1 | **deferred to Part 12** | no reachable leak demonstrated (keys travel in headers, not URLs); a correct fix needs a secret source inside the CLI layer, which docs/03 must decide first | either redact `str(exc)` with the same env-derived secret list the engine uses, or keep secrets out of exception text at the source; decide whether `-v` may print a traceback |
| C-2 | **deferred to Part 12** | the file is 0600 and removed in `finally`; only SIGKILL can strand it, and a cleanup sweep is a new mechanism | decide between a startup sweep of the managed temp names and an unlinked-file design; keep the key out of argv |
| E-1 | **deferred to Part 12** | the SQLite transaction is synchronous and short; moving it risks write ordering for no correctness gain | `asyncio.to_thread` around the transaction body, or a writer thread; needs a test that persistence ordering survives |
| E-2 | **deferred to Part 12** | a YAML read on the loop delays the scheduler, never a result | make `_active_hosts` async and `await asyncio.to_thread(load_scope, ...)`; the gate already loads twice, so load once and pass the gate |
| E-3 | **deferred to Part 12** | mkdir/chmod happens once per run, before any network work | move `Workspace.create` into `to_thread` alongside E-1/E-2 |
| 11d-findings-f (new) | **deferred to Part 12** | `pyprobe` classifies a TLS `ConnectError` by substring and discards the text, so an UNKNOWN host cannot be explained without probing again | a diagnostic detail field carried from adapter to store (redacted), and a docs/04 column decision |
| 11d-findings-g (new) | **deferred to Part 12** | an inconclusive live pass with no previous state writes no `host_status_history` row, while docs/04 section 5 says one row per host per status pass | a docs/04 decision on whether UNKNOWN transitions persist, then `decide_host_state`'s `persist` flag and the state-change diff |

- **G-3 details.** `scope.passive_warning()` returns `warning: <host> is outside scope.yaml\nwarning: continuing with passive stages only` or `None`. The UI prefixes every entry with `warning: ` (`ui.py:462`), so the engine strips the prefix per line instead of double-prefixing. The call sits after `self._warnings = []`, guarded by `not opts.active`; an active run does not need it because the gate decides there.
- **G-4 details.** `_exit_code` was never wrong: docs/02 section 6 assigns 6 to "Every requested tool failed to install or update", and no scan path returns 6. `ALL_FAILED = 6` had zero references in `src/` and `tests/` (only historical REVIEW_LOG prose), so removing it changes no behaviour and makes the enum match the documented scan codes.
- **Red before green, raw:** with the passive-warning call removed and `ALL_FAILED = 6` restored, `pytest -q tests/test_engine.py -k "exit_code_constants or passive_run_outside"` -> `2 failed, 42 deselected`, `Extra items in the left set: 6` and `test_passive_run_outside_scope_warns - Assertion...`. Restored -> `2 passed, 42 deselected`.
- **Tests:** `test_passive_run_outside_scope_warns` (outside target warns with both lines; in-scope target warns nothing) and the extended `test_exit_code_constants_match_docs`.
- **Checks:** `pytest -q` -> `597 passed`; `ruff check .` -> `All checks passed!`; `ruff format --check .` -> `68 files already formatted`; `mypy src/reconkit` -> `Success: no issues found in 36 source files`.
- **Decisions for user review:** (1) Part 12's name and scope are proposed here, not plan-approved; (2) `naabu` remains unavailable in this build (see the G-7 entry) - overrule if a pre-resolve design is preferred; (3) 11d-findings-b's product decision is mine under A1 (keep + label provenance) and can be overruled before implementation.

## Part 11 close-out - fresh S3 scans (2026-11-14)

- **Form, disclosed:** the plan lists PowerShell `Select-String`. This checkout is Kali (`/home/kali/Desktop/reconkit`), where `Get-ChildItem`/`Select-String` are unavailable, so the scans ran in `grep` form - the same substitution PIT-08 records ("`Select-String` in PowerShell, `grep` in Git Bash"). Each command and its raw output is below, run at `18e7462` with a clean tree.

```
$ grep -rn --include=*.py -E '\bassert\b' src/
exit=1
$ grep -rn --include=*.py -E 'shell\s*=\s*True' src/
exit=1
$ grep -rn --include=*.py -E 'TODO|FIXME|XXX|HACK' src/
exit=1
```

- S3-1, S3-2, S3-3: no hits (`exit=1` is grep's "no match"). No `assert` in `src/`, no `shell=True`, no TODO markers.

```
$ grep -rn --include=*.py -E 'print\(' src/
src/reconkit/ui.py:208:    console.print(Text(message, style="yellow"))
src/reconkit/ui.py:232:    target_console.print(Text(line), soft_wrap=True)
src/reconkit/ui.py:256:        target.print(Text(hint, style="yellow"))
src/reconkit/ui.py:268:    target.print(Text(message))
src/reconkit/ui.py:275:    target.print(Text(message, style="red"))
src/reconkit/ui.py:320:        target.print(Text("No completed discovery run for this target.", style="yellow"))
src/reconkit/ui.py:323:        target.print(
src/reconkit/ui.py:335:    target.print(Text(f"No changes since run #{report.previous_run_id}."))
src/reconkit/ui.py:351:    target.print(table)
src/reconkit/ui.py:399:        target.print(Text("No runs yet.", style="yellow"))
src/reconkit/ui.py:419:    target.print(table)
src/reconkit/ui.py:447:            target.print(_host_table(rows))
src/reconkit/ui.py:449:            target.print(Text("No hosts found.", style="yellow"))
src/reconkit/ui.py:451:            target.print(_tool_table(summary))
src/reconkit/ui.py:461:        target.print(Text(summary_line))
src/reconkit/ui.py:463:        target.print(Text(f"warning: {warning}", style="yellow"))
src/reconkit/ui.py:551:    out.print(table)
src/reconkit/ui.py:552:    out.print(
src/reconkit/ui.py:561:    out.print(
src/reconkit/ui.py:573:    out.print(Text(environment), soft_wrap=True)
src/reconkit/ui.py:589:        out.print(keys)
src/reconkit/ui.py:591:        out.print(
src/reconkit/ui.py:595:        out.print(Text(f"warning: {warning}", style="yellow"))
src/reconkit/ui.py:640:    target.print(table)
src/reconkit/ui.py:660:    target.print(table)
```

- S3-4: 25 hits, all in `ui.py`, the single rendering module. No `print(` anywhere else in `src/`.

```
$ grep -rn --include=*.py 'subprocess' src/
src/reconkit/core/runner.py:1:"""The only subprocess entry point: argv lists, timeouts, process groups."""
src/reconkit/core/runner.py:8:import subprocess
src/reconkit/core/runner.py:105:        process = subprocess.Popen(
src/reconkit/core/runner.py:107:            stdin=subprocess.DEVNULL,
src/reconkit/core/runner.py:108:            stdout=subprocess.PIPE,
src/reconkit/core/runner.py:109:            stderr=subprocess.PIPE,
src/reconkit/core/runner.py:132:        raise RuntimeError("subprocess pipes were not created")
src/reconkit/core/runner.py:161:    except subprocess.TimeoutExpired:
src/reconkit/core/runner.py:191:def _kill_tree(process: subprocess.Popen[bytes]) -> None:
src/reconkit/adapters/base.py:3:Adapters return data only: no database, scope gate, UI or subprocess of their
$ grep -rn --include=*.py 'sqlite3' src/
src/reconkit/core/store.py:3:Only this module imports sqlite3. It stores and queries; the engine decides
src/reconkit/core/store.py:11:import sqlite3
src/reconkit/core/store.py:206:        self._conn = sqlite3.connect(str(self.path))
src/reconkit/core/store.py:207:        self._conn.row_factory = sqlite3.Row
```

- S3-5: only `runner.py` imports and uses `subprocess`; the `base.py` hit is prose in the module docstring stating that adapters own no subprocess. S3-6: only `store.py` mentions `sqlite3` (its own docstring plus the import and connection).

```
$ grep -rn --include=*.py 'os\.environ' src/
src/reconkit/ui.py:145                                        # NO_COLOR (docs/02 color rule)
src/reconkit/installer/go_install.py:22                       # PATH for the child env
src/reconkit/installer/pipx.py:31                             # PATH for the child env
src/reconkit/installer/github_release.py:537                  # HOME + PATH for the authenticated lookup
```

- S3-7: four hits, each justified in place: `NO_COLOR` is a documented output rule; the other three are the installer's documented "child gets PATH (and HOME)" exception in docs/10 section 3d. No adapter reads `os.environ`; keys reach adapters through `ctx.env` only.

```
$ grep -rn --include=*.py -E 'except\s*:|except Exception|except BaseException' src/
src/reconkit/core/store.py:214        # close the connection when migration fails, then re-raise
src/reconkit/core/store.py:249        # rollback on any exception, then re-raise
src/reconkit/core/workspace.py:135    # close fd / unlink the temp file on any exception, then re-raise
src/reconkit/core/wildcard.py:90      # a failed probe is "cannot tell" (None), never NONE (PIT-21)
src/reconkit/cli.py:226               # last-resort handler; the known C-1 question (unredacted str(exc))
src/reconkit/engine.py:389            # close the store when Engine construction fails, then re-raise
src/reconkit/engine.py:578            # mark the stage run "failed", then re-raise
src/reconkit/engine.py:878            # adapter exception -> ToolResult(FAILED) with redacted text (PIT-16)
src/reconkit/adapters/dnspython.py:130 # unexpected resolver error -> structured ERROR, never DEAD (PIT-01)
```

- S3-8: nine hits. Eight either re-raise immediately after cleanup or convert the failure into a structured result on purpose, with the in-code comment naming the reason. One remains the known C-1 item (`cli.py:226`), which is deferred to Part 12 by the ruling above, so this scan is "justified with one open ruling", not "clean".

```
$ grep -rn --include=*.py -E 'noqa|type:\s*ignore' src/ tests/
tests/test_scope.py:266:        return {name.lower() for name in inspect.signature(func).parameters}  # type: ignore[call-overload]
tests/test_runner.py:82:        run_exec("echo", timeout=1)  # type: ignore[arg-type]
tests/test_runner.py:86:        run_exec([sys.executable, 1], timeout=1)  # type: ignore[list-item]
```

- S3-9: no `noqa` and no `type: ignore` in `src/`; the three test-only ignores are the Part 0 baseline (signature introspection and two deliberate bad-argument cases). No new suppression was added by this part.

```
$ grep -rn -E 'import (store|scope|ui|cli)|from reconkit\.(core\.store|core\.scope|ui|cli)' src/reconkit/adapters/
exit=1
```

- S3-10: no adapter imports `store`, `scope`, `ui` or `cli`. The new `ip_allowed` field keeps that rule intact: the adapter receives a callable, it does not import the gate.
- **What the scans cannot see:** they are pattern checks, not a review. The `docs/09` "exclude from counts" gap, the C-1 reachability question and the two new live-run findings are judgement calls, not pattern hits, and they are covered by the ruling table above.

## Part 11 close-out - install exit code 6 re-check (2026-11-14)

- **Why:** G-4 removed `ExitCode.ALL_FAILED = 6` from the scan enum. The owner asked whether that broke `install --all` when every tool fails, on the premise that Part 10 put 6 into the same enum.
- **What the code actually does:** there is exactly one `class ExitCode` in `src/` (`engine.py:79`) and it is scan-only. The installer never imports it. `install` reachability comes from `installer/github_release.py:288` `def exit_code(outcomes) -> int`, which returns the literal `0`/`5`/`6` and is called at both dispatch sites (`:460`, `:611`). `grep -rn "ALL_FAILED" src/ tests/` -> no matches. `grep -rn "return 6\b" src/` -> no matches (the 6 is `return 5 if ok else 6`).
- **History:** `git log --oneline -S "ALL_FAILED" -- src/reconkit/engine.py` -> `18e7462` (removal) and `0d6f762 feat: wire install and update to the installer backends` (addition). Part 10 did add the member, but no code path ever returned it; install's 6 has always been the plain int in `github_release`.
- **Proof it still exits 6:** `pytest -v` over the five guards plus the enum test -> `6 passed in 0.38s`: `test_exit_code_is_aggregated_over_every_selected_tool` (asserts 5 then 6), `test_dispatch_every_tool_failing_exits_6` (both outcomes not ok -> `code == 6`), `test_a_piped_install_skips_the_sudo_tool_instead_of_aborting` (`result.exit_code == 6`), `test_a_declined_prerequisite_skips_the_whole_tool` (`code == 6`), `test_plans_are_isolated_and_exit_codes_follow_the_table` (`exit_code([...]) == 6`) and `test_exit_code_constants_match_docs`.
- **Doc change so the two owners are unmistakable:** docs/02 section 6 now states under the table that code 6 comes from `installer.github_release.exit_code()` and that the scan enum deliberately stops at 5 plus 130; the `ExitCode` docstring says the same. No behaviour change.
- **Verdict:** not broken. It is one enum for scans and a separate int for the installer; the 6 never lived on the scan path.
- **Checkout question (answered 2026-11-14):** all commits are in `/home/kali/Desktop/reconkit` (Kali, `uname -a` -> `Linux kali 7.2.15+kali-amd64`). The owner confirmed the history: development started on Windows (`C:\Users\anshu\Desktop\recon\reconkit`), the folder was copy-pasted to Kali to finish the parts needing real Debian tooling, and every commit since then exists only here. So Kali is canonical and the Windows folder is a stale pre-Part-10 snapshot, not a mirror. The exact snapshot commit cannot be read from Kali (no marker, two trees, one copied `.git`); the bound is at or before the last Part-9 commit `cd57fb5`, and the owner can pin it with `git log -1 --oneline` on the Windows box. Nothing was synced, copied or deleted. Consequence recorded under Open risks: the Windows-only acceptance criteria are unverified anywhere with the current code.

## Tool flags and fields verified against the real tools (2026-11-14)

- **Why:** G4 forbids guessing a flag or a JSON field. This pass checks every phase-2 tool and the phase-3 candidates named in the request (`nmap`, `rustscan`, `naabu`, `masscan`, `subfinder`, `assetfinder`, `massdns`, `httpx`, `katana`, `nuclei`) against the real binary on this Kali box where installed, and the tool's official source where not. Documentation only; no code changed in this commit.
- **Where the table lives:** `docs/09_TOOL_CONTRACTS.md` section 9. It is reproduced here as the evidence record.
- **Form:** binaries were preferred (9 of 11 external tools are installed here); the two that are not (`assetfinder`, `rustscan`) were checked against the official repo/docs. The four HTTP endpoints were checked with live requests or their official reference. Every command below ran on 2026-11-14 in `/home/kali/Desktop/reconkit`.

| Tool | Relied on | Verified by | Mismatch |
|---|---|---|---|
| crtsh | `?q=%.<domain>&output=json`, fields `name_value`, `common_name` | live 200, 28,454 bytes | none; unencoded `%` in `q` 404s, httpx encodes |
| certspotter | `/v1/issuances` + `domain`/`include_subdomains`/`expand=dns_names`, field `dns_names`, Bearer auth | official APIv1 reference + live 200 (17 entries) | none |
| otx | `/api/v1/indicators/domain/{d}/passive_dns`, `passive_dns[].hostname` | official external-API page; two live anonymous calls 429 | shape still not observed live |
| hackertarget | `?q=<domain>`, text `host,ip` | two live 200s `www.example.com,172.66.147.243` | quota string still unobserved |
| subfinder | `-d -silent -nc -duc -pc -rl -version` | installed v2.17.0 `-h`; official README | none |
| assetfinder | `--subs-only <domain>`, domain positional; `-h` identity probe | official README + `main.go` | binary not installed; probe inferred |
| httpx | `-u -json -silent -no-stdin -duc -nc -sc -title -location -td -cdn -rl`; keys `input url status_code title location tech cdn_name` | installed v1.12.0 `-h`, `-ldv`, two localhost probes | none |
| naabu | `-silent -json -no-stdin -duc -nc -scan-type c -host -p -rate`; keys `host ip port` | installed v2.7.0 `-h`, two localhost scans | `host` omitted for IP inputs (adapter falls back to `ip`) |
| nmap | `-sV`, `-T<0-5>`, `-p`, `--version` | installed 7.991 | `rate_flag: -T` needs a digit appended |
| masscan | `--max-rate`, `--version`, needs root | installed 1.3.2; `--max-rate 100 --echo` shows `rate = 100` | **`--version` exits 1**, so doctor calls a real Masscan "wrong program" |
| rustscan | `-V, --version` | not installed; Kali package page shows `rustscan -h` | not verified against a binary |
| massdns | `-r`, `-t`, `-o` (L/S/F/B, no JSON); version via `dpkg-query` | installed 1.1.0-0kali2 | none; a future adapter must parse text |
| katana | `-rl`, `-version` | installed v1.8.0 | version line is not the first line |
| nuclei | `-rl`, `-tags`, `-version` | installed v3.11.1 | same first-line defect |
| dig | `dig -v` version command | installed 9.20.30 | none |
| dnspython/pyprobe/pyscan | library/stdlib only | dnspython 2.9.2 with `NXDOMAIN`; stdlib imports | none |

Raw evidence:

```
$ for b in nmap masscan naabu subfinder assetfinder httpx katana nuclei massdns dig jq go curl; do printf "%-12s " "$b"; command -v "$b" || echo MISSING; done
nmap         /usr/bin/nmap
masscan      /usr/bin/masscan
naabu        /usr/bin/naabu
subfinder    /home/kali/go/bin/subfinder
assetfinder  MISSING
httpx        /home/kali/go/bin/httpx
katana       /home/kali/go/bin/katana
nuclei       /home/kali/go/bin/nuclei
massdns      /usr/bin/massdns
dig          /usr/bin/dig
jq           /usr/bin/jq
go           /usr/bin/go
curl         /usr/bin/curl
```

```
$ nmap --version | head -2
Nmap version 7.991 ( https://nmap.org )
Platform: x86_64-pc-linux-gnu
$ masscan --version
Masscan version 1.3.2 ( https://github.com/robertdavidgraham/masscan )
Compiled on: Jul 25 2024 16:44:22
Compiler: gcc 14.1.0
OS: Linux
CPU: unknown (64 bits)
GIT version: unknown
$ naabu -version | tail -3
		projectdiscovery.io

[INF] Current Version: 2.7.0
$ subfinder -version
[INF] Current Version: v2.17.0
[INF] Subfinder Config Directory: /home/kali/.config/subfinder
$ httpx -version | tail -2
[INF] Current Version: v1.12.0
$ katana -version
[INF] Current version: v1.8.0
$ nuclei -version | head -1
[INF] Nuclei Engine Version: v3.11.1
$ dig -v
DiG 9.20.30-1-Debian
```

Flag presence, straight from the binaries:

```
$ nmap --help | grep -nE '^\s*-sV|^\s*-T<|-p <'
31:  -p <port ranges>: Only scan specified ports
39:  -sV: Probe open ports to determine service/version info
62:  -T<0-5>: Set timing template (higher is faster)
$ naabu -h | grep -inE 'json|no-color|scan-type|-host|-p |-rate'
8:   -host string[]              hosts to scan ports for (comma-separated)
14:   -port, -p string              ports to scan (80,443, 100-200)
24:   -rate int             packets to send per second (default 1000)
35:   -j, -json                              write output in JSON lines format
45:   -scan-type, -s string            type of port scan (SYN/CONNECT) (default "c")
103:   -no-color, -nc            disable colors in CLI output
$ subfinder -h | grep -nE '^\s+-(d|silent|nc|duc|pc|rl)\b'
8:   -d, -domain string[]  domains to find subdomains for
24:   -rl, -rate-limit int      maximum number of http requests to send per second (global)
30:   -duc, -disable-update-check  disable automatic subfinder update check
41:   -pc, -provider-config string  provider config file (default "/home/kali/.config/subfinder/provider-config.yaml")
50:   -silent             show only subdomains in output
53:   -nc, -no-color      disable color in output
$ httpx -h | grep -nE '^\s+-(u|sc|title|location|td|cdn|rl|duc|no-stdin|nc)\b'
10:   -u, -target string[]     input target host(s) to probe
14:   -sc, -status-code                      display response status-code
17:   -location                              display response redirect location
24:   -title                                 display page title
27:   -td, -tech-detect                      display technology in use based on wappalyzer dataset
38:   -cdn                                   display cdn/waf in use (default true)
88:   -rl, -rate-limit int          maximum requests to send per second (default 150)
105:   -duc, -disable-update-check  disable automatic httpx update check
159:   -no-stdin                        Disable Stdin processing
174:   -nc, -no-color            disable colors in cli output
$ katana -h | grep -nE '^\s+-rl'
100:   -rl, -rate-limit int                maximum requests to send per second (default 150)
$ nuclei -h | grep -nE 'rate-limit|\-tags'
50:   -tags string[]                     templates to run based on tags (comma-separated, file)
153:   -rl, -rate-limit int                     maximum number of requests to send per second (default 150)
```

Real JSON output, produced by running the installed binaries against a local `python3 -m http.server` on 127.0.0.1:18080 (no packets left this machine):

```
$ httpx -u 127.0.0.1:18080 -json -silent -sc -title -location -td -cdn -nc -duc
{"timestamp":"2026-11-14T13:47:12.211473768-05:00","port":"18080","url":"http://127.0.0.1:18080","input":"127.0.0.1:18080","title":"reconkit probe","scheme":"http","webserver":"SimpleHTTP/0.6 Python/3.14.8","content_type":"text/html","method":"GET","host":"127.0.0.1","host_ip":"127.0.0.1","path":"/","time":"5.500479ms","a":["127.0.0.1"],"tech":["Python:3.14.8","SimpleHTTP:0.6"],"words":2,"lines":1,"status_code":200,"content_length":30,"failed":false,"knowledgebase":{"pHash":0}}

$ httpx -u 127.0.0.1:18080/subdir -json -silent -sc -title -location -td -cdn -nc -duc
{"timestamp":"2026-11-14T13:47:31.262194637-05:00","port":"18080","url":"http://127.0.0.1:18080/subdir","input":"127.0.0.1:18080/subdir","location":"/subdir/", ...,"status_code":301, ...}

$ naabu -host 127.0.0.1 -p 18080 -json -silent -nc -duc -no-stdin -scan-type c
{"ip":"127.0.0.1","timestamp":"2026-11-14T18:47:12.26100621Z","port":18080,"protocol":"tcp","tls":false}

$ naabu -host localhost -p 18080 -json -silent -nc -duc -no-stdin -scan-type c
{"host":"localhost","ip":"127.0.0.1","timestamp":"2026-11-14T18:47:32.005116457Z","port":18080,"protocol":"tcp","tls":false}
```

The httpx JSON key list was also read from the binary itself (`httpx -ldv`), which contains `input`, `url`, `status_code`, `title`, `location`, `tech`, `cdn_name`, `webserver`, `host`, `port`.

```
$ masscan --max-rate 100 -p1234 --echo | grep -inE 'rate|ports'
2:rate = 100
8:ports = 1234
$ dpkg-query -W '-f=${Version}' massdns; echo
1.1.0-0kali2
$ massdns -h
Usage: massdns [options] [domainlist]
  -r  --resolvers        Text file containing DNS resolvers.
  -t  --type             Record type to be resolved. (Default: A)
  -o  --output           Flags for output formatting.
Output flags:
  L - domain list output
  S - simple text output
  F - full text output
  B - binary output
```

```
$ curl -s -m 25 "https://crt.sh/?q=%25.example.com&output=json" -w "http=%{http_code} bytes=%{size_download}\n"
http=200 bytes=28454
$ curl -s -m 25 "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names" -w "http=%{http_code}\n"
http=200 bytes=7739   -> 17 entries, first keys include dns_names
$ curl -s -m 25 "https://api.hackertarget.com/hostsearch/?q=example.com"
http=200 bytes=31
www.example.com,172.66.147.243
$ curl -s -m 25 "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns"
http=429 bytes=80   -> {"detail": ...}; shape taken from the official API page instead
```

Two defects found, both outside the adapter contract and fixed/ticketed separately:

1. **`masscan --version` exits 1** while printing `Masscan version 1.3.2 (...)` on stdout. `installer.github_release.installed_version()` returns `None` for any nonzero exit, so `default_status()` reports `installed=False, path=/usr/bin/masscan` and doctor prints `masscan | wrong program | failed` for a genuine, working Masscan. Confirmed with `reconkit doctor` on 2026-11-14.
2. **Banner-first version text.** `installed_version()` returns `text.splitlines()[0]`; for katana and nuclei the first line is ASCII art, so doctor shows `__` and `[I…`. Adapter-backed tools are unaffected because they use `check_installed()` and a version regex. Cosmetic, but it also defeats `_same_version` for those tools.

## Bugs found by the Part B audit - masscan reported as "wrong program" (2026-11-14)

- **Symptom:** `reconkit doctor` printed `masscan | ports | opt_in | wrong program | - | /usr/bin/masscan | failed` and `warning: masscan: /usr/bin/masscan is not the expected program; doctor ignores it.` on a box where `/usr/bin/masscan` is genuine Masscan 1.3.2.
- **Cause:** `masscan --version` prints `Masscan version 1.3.2 ( https://github.com/robertdavidgraham/masscan )` on stdout and exits **1**. `installer.github_release.installed_version()` returned `None` for `returncode != 0`, so `doctor.default_status()` produced `installed=False` with a resolved path, which the doctor maps to `WRONG_PROGRAM`.
- **Fix:** a nonzero exit is now accepted only when the probe output still names the program (`plan.binary.lower() in text.lower()`); every other nonzero probe remains not-usable, so the "wrong program" guard keeps its purpose. Docs first: the mismatch is recorded in docs/09 section 9 and this entry.
- **Red before green:** `pytest -v tests/test_install_cli.py -k "masscan_version_counts or nonzero_version_probe"` -> `1 failed, 1 passed` (`assert None == 'Masscan version 1.3.2 ( https://github.com/robertdavidgraham/masscan )'`). After the fix -> `2 passed in 0.20s`.
- **Verified on the real binary, not only the fake runner:** `reconkit doctor` now prints `│ masscan │ ports │ opt_in │ yes │ Masscan │ /usr/bin… │ ok │` and no masscan warning.
- **Not fixed (ticketed to Part 12):** the same function returns `text.splitlines()[0]`, so `katana` shows `__` and `nuclei` shows `[I…` in the version column, which also defeats `_same_version()` for update reporting. Recorded in PROGRESS Open risks.

## Open-risk retry - OTX and HackerTarget (2026-11-14, one request each)

- **Why:** the Part B audit left OTX's response shape and HackerTarget's quota text unobserved. The owner asked for one polite retry each, or to leave them named. Both were retried once, with the honest UA `reconkit/0.1`, no key.
- **OTX:** still refused.
  ```
  $ curl -s -m 30 -A "reconkit/0.1" "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns" -w "http=%{http_code} bytes=%{size_download}\n"
  http=429 bytes=80
  {"detail": "Anonymous access to this endpoint is limited. Please authenticate."}
  ```
  The exact 429 body is now known, but the `passive_dns` shape is still not observed from this box. No code reads the body: the HTTP adapter maps 429 to a `failed` result with the status and no retry, which the fixture tests pin. Open risk unchanged except that the refusal text is now recorded.
- **HackerTarget:** succeeded, quota not hit, so the quota message is still unobserved.
  ```
  $ curl -s -m 30 -A "reconkit/0.1" "https://api.hackertarget.com/hostsearch/?q=example.com" -w "http=%{http_code} bytes=%{size_download}\n"
  http=200 bytes=31
  www.example.com,172.66.147.243
  ```
  The `host,ip` format is confirmed twice; the adapter's `api count exceeded` branch remains unexercised and is named in Open risks rather than guessed.
- **Not done, deliberately:** no key was used, no rate-limit window was waited out, and nothing was installed to make a probe possible. `assetfinder`/`rustscan` and the Windows acceptance criteria remain named Open risks per the owner's ruling.

## Real-tool verification session - testfire.net (2026-11-14)

- **Purpose:** exercise the code at `c9072d9` against the already-authorized target with real installed tools, no mock, no keys. Verification only: no code changed in this entry. Scope was the existing `scope.yaml` (`in_scope: testfire.net, *.testfire.net`, `allow_active: true`); nothing outside it was contacted.
- **Step 1 - install.** `reconkit install --all` (real, exit 5). Every tool came back `already installed` from earlier work except `rustscan`:

```
rustscan           github_release  failed             rustscan: release 2.4.1
                                                      has no asset
                                                      'verify-at-implementation'
rustscan: rustscan: release 2.4.1 has no asset 'verify-at-implementation'
```

  That is the documented placeholder in tools.yaml, not a new failure. **`libpcap-dev` is NOT installed and could not be installed:** `dpkg -s libpcap-dev` says "package 'libpcap-dev' is not installed", and `sudo -n true` returns `sudo: a password is required`, so the apt step cannot run non-interactively. `install --all` never reaches it because `naabu` is "already installed" and prerequisites only run when their tool installs (the documented consequence in docs/10 section 3a). This prerequisite is therefore **unverified**, independent of the CIDR gate.
- **Doctor** (exit 0) confirms the same state:
```
coverage: subs 11/11 ready, dns 5/5 ready, live 4/4 ready, ports 5/6 ready, tech
4/5 ready, urls 8/8 ready, vulns 5/8 ready, shots 0/1 ready
system packages: python3 installed, python3-venv installed, python3-pip installed, git installed, golang-go installed, libpcap-dev missing, jq installed, curl installed
python 3.14.8 | scope.yaml found | db recon.db writable
Missing tools: 6. Run: reconkit install --all
```
  Every Keys row reads `Set: no`; no key was used and none was added.
- **Step 3 - the run command, and one trap.** The requested command `reconkit -d testfire.net --active --speed slow --no-keys --json` executed **`lite`, not `run`**: docs/02 section 2 defines the bare form as `lite` (passive only), and `_stages("lite", active)` ignores `--active` entirely (`cli.py:103`). It completed after 2 min 48 s with `subs` + `dns` only and exit 5 (`crtsh` 502, `otx` 429). The full active pipeline was then run as `reconkit run -d testfire.net --active --speed slow --no-keys --json`, twice. Neither run wrote one byte to stderr despite docs/02 section 5 saying tables and progress stay on stderr (recorded below as a finding, not fixed).
- **Run 1** (19:11:26Z-19:16:56Z, exit 5, `alive 8 / dead 28 / hosts 36`, `tools_ok 8 / tools_failed 2`):

| Stage | Tool | Status | Items | Real detail |
|---|---|---|---|---|
| subs | crtsh | failed | 0 | `crtsh: server error (HTTP 502)` |
| subs | certspotter | ok | 0 | real empty answer |
| subs | otx | failed | 0 | `otx: rate limited (HTTP 429)` |
| subs | hackertarget | ok | 3 | |
| subs | subfinder | ok | 35 | 15.63 s |
| subs | assetfinder | ok | 4 | 6.49 s |
| dns | dnspython | ok | 36 | `duration_s` 0.0 (known 11d-findings-c) |
| live | pyprobe | ok | 8 | `unreachable=28`, `duration_s` 0.0 |
| live | httpx | ok | 8 | 7.04 s |
| ports | pyscan | ok | 0 | `blocked=8` - the CIDR gate refused every host because scope.yaml has no `in_scope_cidrs` |
| tech, urls, vulns | - | - | 0 | **no adapter exists for any tool in these pools** (all phase 3); each stage was created, ran zero tools and completed |

- **Run 2** (19:18:45Z-19:24:09Z, exit 5, `alive 8 / dead 28`, `tools_ok 9 / tools_failed 1`): `crtsh` recovered (ok, 1 item, 8.19 s), `otx` still 429, `subfinder` returned **8** items in 68.55 s instead of 35 in 15.63 s, `certspotter` 0, `hackertarget` 3, `assetfinder` 4; `dns` resolved 9; `live` 8 ALIVE from pyprobe + httpx; `ports` `blocked=8`; tech/urls/vulns again zero tools.
- **skipped, from `tool_runs` (run 1):** `urlscan`, `amass`, `findomain`, `chaos`, `github_subdomains`, `dnsx`, `puredns`, `massdns`, `dig`, `httprobe`, `tlsx`, `smap`, `nmap`, `rustscan`, `httpx_tech`, `whatweb`, `wafw00f`, `cdncheck`, `webanalyze`, `gau`, `waybackurls`, `katana`, `hakrawler`, `gospider`, `subjs`, `unfurl`, `urlfinder`, `nuclei`, `subzy`, `dnsreaper` all `no adapter yet (phase 3)`; `naabu` skipped as `blocked: resolves inside the binary, so in_scope_cidrs cannot be enforced (11c-G-7)`. These rows are in the database, not in the JSON summary (`tools_skipped: 0`), which is the pre-existing Part 7/8 gap named below.
- **Step 5 - database, raw.** After both runs:
```
targets              1
scan_runs            17
tool_runs            99
subdomains           36
subdomain_sources    100
host_status_history  81
ports                0
port_sources         0
urls                 0
```
  One full stored status row (`run_id` 13, ALIVE) and one `tool_runs` row:
```
            id: 73
  subdomain_id: 1
        run_id: 13
         state: ALIVE
   status_code: 200
      location:
         title: Altoro Mutual
      ips_json: ["65.61.137.117"]
     tech_json: ["Apache Tomcat", "Java"]
           waf:
    tools_json: ["httpx"]
    checked_at: 2026-11-14T19:23:39Z
   cnames_json: []
dangling_cname:

        id: 42
    run_id: 7
      tool: pyscan
    status: ok
item_count: 0
duration_s: 0.0
     error: blocked=8
```
  `ports` is empty, so **the LOW-only confidence ceiling could not be observed in practice**: no port row was written at all. What the run proves is the gate itself (`blocked=8`), not a LOW row.
- **Step 6 - `reconkit diff -d testfire.net` after run 2** (exit 0): 27 `GONE` rows, no `NEW`, no `CHANGED`. The list is exactly the run-1 discovery set minus run-2's 9 hosts, e.g. `social.testfire.net`, `tv.testfire.net`, `mvaas.testfire.net`, `www.demo.testfire.net`. Cause: `subfinder` returned 35 items in run 1 and 8 in run 2, so the latest-two-subs comparison sees an absent source as a disappearance. `diff` behaved as docs/02 defines it ("gone since the previous run"); the output is nonetheless dominated by source variance rather than a target change.
- **Findings (no code changed):**
  1. **Bare `--active` is silently a no-op** (`lite` ignores it). Docs-conformant, but the exact command in this request produced a passive-only run with exit 5 and no warning. Recommend a CLI warning or rejecting `--active` for `lite`; that is a docs-first decision.
  2. **A stage with zero adapters completes silently.** `tech`, `urls` and `vulns` ran zero tools in both runs and the JSON reports `tools_skipped: 0`; only `tool_runs` shows the 30 skipped rows. With a clean subs stage the same run would exit 0 while three of six requested stages did nothing. Related to the known Part 7/8 gap (skipped tools not in the summary) but broader: it also hides whole empty stages.
  3. **`--json` writes nothing to stderr** (0 bytes in both runs), while docs/02 section 5 says progress stays on stderr. No progress was visible during 5-minute runs.
  4. **`diff` amplifies passive-source variance**: 27 of 36 hosts reported GONE after one flaky `subfinder` run. Not a code defect against docs/02, but a real-world usability problem worth a tolerance/union decision.
  5. **Known items re-confirmed on real data, not new:** `duration_s` 0.0 for `dnspython` and `pyprobe` (11d-findings-c), `pyprobe` carrying `unreachable=28` in `error`, `otx` anonymous 429, `certspotter` legitimately empty, `scan_runs` partial status when a passive source fails.
- **Confidence actually observed, and a decision this forces.** Every ALIVE host in both runs came back `confidence: UNCONFIRMED`, e.g. `altoro.testfire.net` with discovery sources `assetfinder, hackertarget, subfinder` and `status_code: 200`. Cause: `pyprobe` returned `UNKNOWN` for all 8 hosts (and `unreachable=28` for the rest) while `httpx` returned 200 for the same 8, and `decide_host_state` treats *any* web state that is not `ALIVE` as disagreement (`engine.py:166-168`), which `confidence_for` maps to `UNCONFIRMED` before counting sources. `test_engine_disagreement_is_unconfirmed` pins that behaviour deliberately, and docs/09 section 5 says only that "at least 2 agreeing checks ... sets confidence (**LOW when only one check is available**)" without naming `UNCONFIRMED` for host state. So this is ambiguous, not an untested defect: `UNKNOWN` can mean "no evidence" (which docs/09 would score LOW) or "contradicts the ALIVE tool" (current behaviour). Decision needed; no code was changed. The related reason `pyprobe` cannot reach hosts that `httpx` gets 200 from is 11d-findings-f, still deferred.
- **What this run does NOT prove:** no tech/urls/vulns tool was executed (no adapters), no open port was ever observed (`pyscan` blocked, `naabu` blocked, `nmap`/`rustscan`/`smap` phase 3), `libpcap-dev` is absent, no keyed provider ran, and `killpg`/`sudo`/Windows paths were not exercised.

## Bug-fix session - 2026-11-14: pyprobe TLS short-circuit, `--active` on passive commands, skipped tools in the summary

- Docs read / goal: `AGENTS.md`, `docs/PROGRESS.md` RESUME, the pitfalls table above, `docs/02_CLI_UX.md` (sections 2, 5, 6), `docs/09_TOOL_CONTRACTS.md` (section 3 adapter contract, section 4 selection rules), `docs/03_ARCHITECTURE.md` section 7, and the code paths `cli._run_scan`/`_stages`, `adapters/pyprobe._probe`, `engine._select`/`StageOutcome`, `ui.summary_document`/`_tool_table`/`render`. Owner instruction: fix the two most serious findings for real (not `--mock`), investigate one before calling it a bug, log one as a named finding without changing behaviour, do not touch `scope.yaml`/`in_scope_cidrs`, do not install anything with sudo, do not push.
- **Item 1 - `--active` is now a usage error on passive-only commands.** docs/02 section 2 already defines the bare form as "shorthand for `lite` (the passive pipeline)" and says "`lite` is the workflow shortcut for exactly that passive pipeline and nothing active ... Only `run` includes active stages", so the flag had no honest meaning there; option (a) from the request (reject with exit 2 and name `run`) is the behaviour the doc already requires. docs/02 was edited first: a new paragraph in section 2 states that `--active` is exit `2` on the bare form, `lite`, `passive`, `subs` and `dns`, and names `run -d X --active`. Code: `cli._run_scan` derives the stage tuple once, and when `active` is set and every stage in it is passive it raises `ConfigError("<command> is passive-only; --active needs: reconkit run -d X --active")` before the engine opens (no `scan_runs` row, no workspace). The message is deliberately under 80 columns after the first real run wrapped it as `use 'reconkit / run -d X --active'`.
- **Item 2 - investigated, and it is a real bug, not scanner variance.** Scratch reproduction of the exact client config (`timeout=10`, `User-Agent: reconkit/0.1.0`, `follow_redirects=False`), verbatim stderr/stdout:
  ```
  GET https://www.testfire.net/
    EXC TYPE: httpx.ConnectError
    EXC STR : [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate is not valid for 'www.testfire.net'. (_ssl.c:1127)
    is ConnectError: True
    _is_tls_error  : True
  GET http://www.testfire.net/
    status      : 200
    http_version: HTTP/1.1
    location    : None
    server      : Apache-Coyote/1.1
  ```
  All eight hosts behaved identically (`https` certificate failure, `http` 200):
  ```
  altoro.testfire.net          https=ConnectError<CERTIFICATE_VERIFY_FAILED] certificate verify failed>  http=200
  demo.testfire.net            https=ConnectError<CERTIFICATE_VERIFY_FAILED] certificate verify failed>  http=200
  demo2.testfire.net           https=ConnectError<CERTIFICATE_VERIFY_FAILED] certificate verify failed>  http=200
  evil.testfire.net            https=ConnectError<CERTIFICATE_VERIFY_FAILED] certificate verify failed>  http=200
  ftp.testfire.net             https=ConnectError<CERTIFICATE_VERIFY_FAILED] certificate verify failed>  http=200
  localhost.testfire.net       https=ConnectError<CERTIFICATE_VERIFY_FAILED] certificate verify failed>  http=200
  testfire.net                 https=ConnectError<CERTIFICATE_VERIFY_FAILED] certificate verify failed>  http=200
  www.testfire.net             https=ConnectError<CERTIFICATE_VERIFY_FAILED] certificate verify failed>  http=200
  ```
  Root cause: `_probe` looped `SCHEMES = ("https", "http")` but on `httpx.ConnectError` it returned a `HostStatusRecord(state=UNKNOWN)` **inside** the loop as soon as `_is_tls_error()` matched, so the `http` attempt was never made. A certificate whose name does not match the host (or any TLS-only failure) therefore hid a working plain-HTTP service from the tool that was supposed to be the independent second opinion, while ProjectDiscovery `httpx` reported 200. Fix: remember `tls_error`, `continue` to the next scheme, and only after every scheme has failed is a TLS error turned into `UNKNOWN` (plain connect failures still produce no record, so `unreachable=` is unchanged). docs/09 section 3 was updated with that contract. Real proof after the fix, production `PyprobeAdapter.run` with a real `RunContext` (real `Pacer`/`RateLimiter`, 8 hosts, `slow`):
  ```
  status: ok error: None
    altoro.testfire.net        ALIVE    200 'Altoro Mutual'
    demo.testfire.net          ALIVE    200 'Altoro Mutual'
    demo2.testfire.net         ALIVE    200 'Altoro Mutual'
    evil.testfire.net          ALIVE    200 'Altoro Mutual'
    ftp.testfire.net           ALIVE    200 'Altoro Mutual'
    localhost.testfire.net     ALIVE    200 'Altoro Mutual'
    testfire.net               ALIVE    200 'Altoro Mutual'
    www.testfire.net           ALIVE    200 'Altoro Mutual'
  ```
  CLI proof (`reconkit live -d www.testfire.net --active --tools pyprobe --no-keys --speed slow`, then the same for the root): both `exit=0`, host table `www.testfire.net ALIVE 200` / `testfire.net ALIVE 200`, and `host_status_history` holds `('www.testfire.net','ALIVE',200,'Altoro Mutual','["pyprobe"]')` and `('testfire.net','ALIVE',200,'Altoro Mutual','["pyprobe"]')`. The earlier real run had the same tool return `UNKNOWN` for both.
- **Item 2 - what this does and does not settle.** The "100% disagreement" was not two tools disagreeing; it was one tool short-circuiting. In the two-tool live run (`--tools pyprobe,httpx`, `--json`) both now return `ALIVE 200` for `www.testfire.net`, so the input that produced `UNCONFIRMED` in the full run is gone. It does **not** settle the queued UNKNOWN-vs-disagreement ruling: `engine.decide_host_state` still treats any non-`ALIVE` web state as disagreement, and `_persist_stage`/`Store.host_rows` still read confidence and sources from the discovery tables, so a `live`-only invocation displays `LOW (0)` with `sources: []`. Both observations are in the raw JSON of this session; neither behaviour was changed. `11d-findings-f`'s other half (the TLS text is still discarded, no diagnostic column) stays deferred to Part 12: adding a column is a docs/04 decision and this session was not allowed to add one.
- **Item 3 - a stage that built nothing no longer reports a clean zero.** docs/02 section 5 now documents `stages[].skipped` (`{"tool","reason"}`) and says `summary.tools_skipped` counts selection-time skips as well as executed `skipped` results; docs/09 section 4 states the same reporting rule. Code: `engine.ToolSkip` and `StageOutcome.skipped` carry the list `_select` already produced, `ScanSummary.skipped` flattens it; `ui.summary_document` writes it per stage and adds its length to `tools_skipped`; `_tool_table` renders skipped rows (which docs/02 already promised) and the summary line adds the same count; a run whose only rows are skips now prints the Tools table instead of the empty-state line. Exit codes were deliberately **not** changed (a stage with no adapter still exits `4`, and whether it should make a mixed run partial is still an owner decision). Real, no-`--mock`, against testfire.net:
  ```
  reconkit tech  -d testfire.net --active --json -> exit 4, 5 skipped
  reconkit urls  -d testfire.net --active --json -> exit 4, 8 skipped
  reconkit vulns -d testfire.net --active --json -> exit 4, 3 skipped
  stages[0].skipped = [{"tool":"httpx_tech","reason":"no adapter yet (phase 3)"}, ...]
  summary.tools_skipped = 5 / 8 / 3
  ```
- **Item 4 - logged, not fixed: `diff` reports source flakiness as infrastructure change.** New named finding in `docs/PROGRESS.md` "Open risks" - `subfinder` returned 35 names in run 1 and 8 in run 2 five minutes apart, and `diff` printed 27 `GONE` rows for hosts nothing had re-probed. `diff` matches docs/02 ("gone since the previous run") so no code changed. Proposed fix shapes for the owner's ruling: (a) require two consecutive misses before `GONE` (a run history query, no schema change); (b) compare against a union of the last N discovery runs (a new `Store` read, no schema change); (c) leave the rule and rename the column/JSON key to "not seen this run", which is honest but breaks the documented `gone` name and the `--json` shape. (a) hides real removals for one run; (b) hides them for N runs; (c) keeps the data exact and changes only the label. Ruling required before any of them.
- Bugs found:
  1. **`--active` silently swallowed by the bare form and by every passive-only command.** Symptom: `reconkit -d testfire.net --active --speed slow --no-keys --json` exited 5 after running only subs+dns; the user could believe an active scan ran. Root cause: `_stages("lite", active)` ignores `active` by design and nothing rejected the flag. Fix: docs/02 section 2 paragraph plus the `cli._run_scan` guard. Guarding tests: `test_bare_command_rejects_active_instead_of_running_lite`, `test_passive_only_commands_reject_active[lite|passive|subs|dns]`.
  2. **`pyprobe` returned `UNKNOWN` instead of trying `http` after a TLS failure.** Symptom: 8 of 8 hosts that `httpx` got 200 on were `UNKNOWN`, forcing `UNCONFIRMED` confidence. Root cause: `_probe` returned inside the scheme loop on the first TLS `ConnectError`. Fix: `tls_error` flag plus `continue`, UNKNOWN only when every scheme failed. Guarding test: `test_pyprobe_tls_failure_still_tries_http` (the older `test_pyprobe_tls_error_is_a_result` still pins "TLS on every scheme is a result, never a crash").
  3. **A stage with zero adapters reported `tools_skipped: 0`.** Symptom: `tech`/`urls`/`vulns` returned `results: []` and a zero skip count while 30 tools had been skipped. Root cause: the summary counted only executed `ToolResult`s and `StageOutcome` dropped `_select`'s skip list. Fix: `ToolSkip`/`StageOutcome.skipped`/`Summary.skipped` plus the docs/02 JSON field and the Tools table rows. Guarding test: `test_a_stage_with_no_adapter_reports_its_skips`.
- Requirement -> test table: item 1 -> `test_bare_command_rejects_active_instead_of_running_lite` (bare form, exit 2, no DB file created) and `test_passive_only_commands_reject_active` (parametrized over `lite`, `passive`, `subs`, `dns`); item 2 -> `test_pyprobe_tls_failure_still_tries_http` (asserts both URLs were requested, `ALIVE`, `200`, title); item 3 -> `test_a_stage_with_no_adapter_reports_its_skips` (exit 4 unchanged, `stages[0].skipped`, `summary.tools_skipped == len(skipped)`); item 4 -> docs only, no test.
- **Red before the fix** (source reverted, tests kept): `7 failed in 88.79s`, exit 1. Reproduced failures: `assert 0 == 2` on the bare form and on each passive-only command (old code exited 0), `KeyError: 'skipped'` for the JSON stage, and `assert <HostState.UNKNOWN: 'UNKNOWN'> is <HostState.ALIVE: 'ALIVE'>` for pyprobe with the record `HostStatusRecord(fqdn='www.example.com', source='pyprobe', state=UNKNOWN, status_code=None, ...)`.
- **Green after the fix:** the five new test functions (eight cases with the parametrization) -> `8 passed in 0.41s`, exit 0.
- Mutation proofs (source mutated, targeted tests run, source restored by `git checkout -- src/reconkit` + `git apply` of the saved diff each time):
  - A: guard condition turned into `if False and ...` -> `5 failed in 93.55s` (`test_bare_command_rejects_active_instead_of_running_lite` plus all four `test_passive_only_commands_reject_active` cases), `MUTATION_A_CAUGHT`.
  - B: restore the early `return HostStatusRecord(state=UNKNOWN)` on a TLS error -> `1 failed` with the same UNKNOWN-vs-ALIVE assertion, `MUTATION_B_CAUGHT`.
  - C: drop `+ len(summary.skipped)` from `tools_skipped` -> `assert 0 == 5`, `MUTATION_C_CAUGHT`.
  - D: emit `"skipped": []` for the stage -> `assert []` on the stage list, `MUTATION_D_CAUGHT`.
- Raw gate output after the last edit: `pytest -q` -> `606 passed in 13.01s` (`PYTEST_PASS`); `ruff check .` -> `All checks passed!`; `ruff format --check .` -> `68 files already formatted`; `mypy src/reconkit` -> `Success: no issues found in 36 source files`. The full suite went from 599 to 606 (seven new cases; one pre-existing pyprobe test kept and documented).
- Not changed on purpose: `scope.yaml` and `in_scope_cidrs` (the owner's decision), `pyscan`/ports, `diff`, exit codes for empty stages, `--json` progress, the UNKNOWN-vs-disagreement rule, and every deferred Part 12 item. No dependency, module, file or CLI command was added; no sudo install was attempted; nothing was pushed.
- Not verified: no full `run --active` pipeline was repeated after the fix (the two real `live` runs and the real per-host adapter run cover the changed code path); the `ALIVE`-from-`http` case is proved on testfire.net only; Windows remains unverified; the tech/urls/vulns tools still have no adapter, so item 3 was proved only on stages that skip everything.
- **S1 (second pass):** `pytest -q` run a second time after the commit -> `606 passed in 12.94s`, `PYTEST_SECOND_PASS`; the commit itself ran the pre-commit hook with the same four checks (`606 passed`, `All checks passed!`, `68 files already formatted`, `Success: no issues found in 36 source files`).
- **S2 (own diff, `git diff HEAD~1 -- src` read line by line):**
  - Broad `except`: **none added**. The nine pre-existing sites are unchanged (`store.py:214,249`, `workspace.py:135`, `wildcard.py:90`, `cli.py:232` the top-level error boundary, `engine.py:406,595,901`, `dnspython.py:130`); the new code adds no `try` at all.
  - External input and where it is validated: the only new input is `--active` (a Typer bool) and `command`, which comes from `ctx.info_name` or the literal `_SCAN_COMMANDS` tuple, never from the target; the new `ConfigError` message interpolates no user text, so there is no path for shell/format/JSON injection. `pyprobe` still validates every host with `validate_host()` inside `_probe` before building a URL (unchanged).
  - Secrets reaching a log/error/argv/URL/file: **none**. Skip `reason` strings now travel into JSON and the Tools table; they are produced by `engine._select` from constants (`no adapter yet (phase N)`, `requires --active`, `not installed`, `IP_GATE_BLOCKED`) or by `require_active()`'s scope message, which carries a hostname, never an env value. No tool stdout is included, and `ToolSkip` has no secret field.
  - Blocking calls inside async code: **none added** (`ToolSkip`/`StageOutcome` are plain dataclasses; `ui` is sync and already only called from the CLI).
  - Exceptions that could escape an adapter or the engine: **none new**; `ToolSkip(spec.name, reason)` and the list comprehension cannot raise, and the CLI guard raises `ConfigError`, which `_run_scan` already maps to exit 2.
  - Unfinished paths: `StageOutcome.skipped` is empty for a **resumed** stage (the earlier run owned those rows; `tool_runs` still has them); a stage whose pool is entirely excluded/opt-in is still omitted from `summary.stages` rather than reported as empty; a zero-adapter stage still exits `4` on its own and does not force `5` in a mixed run.
- **S3 scans (bash grep form of the PowerShell block, run on the committed tree):** `\bassert\b` in `src` -> `NONE`; `shell\s*=\s*True` -> `NONE`; `TODO|FIXME|XXX|HACK` -> `NONE`; `print(` -> `src/reconkit/ui.py` only; `subprocess` -> `src/reconkit/core/runner.py`, `src/reconkit/adapters/base.py` (pre-existing: `base.py` only names `subprocess.CalledProcessError`); `sqlite3` -> `src/reconkit/core/store.py` only; `os.environ` -> `ui.py:148` (`NO_COLOR`), `installer/go_install.py:22`, `installer/pipx.py:31`, `installer/github_release.py:542` (all pre-existing, justified in docs/10 section 3d); the nine broad-`except` sites above are the pre-existing justified set; `noqa|type: ignore` in the six changed files -> `NONE`; adapters importing store/scope/ui/cli -> `NONE`. `git status --short` after the commit -> empty tree.

## Rule decision - 2026-11-14: `diff` GONE needs two consecutive misses

- Docs read / goal: `docs/02_CLI_UX.md` (section 2 state/output table, section 5 JSON), `docs/04_DATABASE.md` section 6 (diff queries) and section 5 (state rules), `docs/08_UX_FLOWS.md` Flow 7, plus `core/store.py` `diff_*`, `engine.DiffSnapshot`/`Engine.diff` and `ui.diff_document`/`render_diff`. Owner ruling on the logged finding: **option (a)** - a host must be missing for two consecutive runs before `diff` reports `GONE`; this entry implements exactly that and changes nothing else (`state_changes`, ports, `NEW`).
- **Definition, docs first:** docs/02 section 2 now states the rule in user terms ("`GONE` only after two consecutive misses ... a host missing from only the latest run is silent in the table and listed once under `Not reported as GONE yet`"), docs/04 section 6 restates it for the queries, and docs/08 Flow 7 shows the message. "Two consecutive runs" means the two latest **completed discovery runs** for the target: `scan_runs` rows for the `subs` stage with status `completed` or `partial`, newest first. Resume does not change the set (a resumed stage gets its own row like any run); no other stage takes part. Formally, with the three newest discovery runs `baseline`, `previous`, `latest`: a host is `GONE` iff it was seen in `baseline` **and** is absent from both `previous` and `latest`. Fewer than three completed discovery runs -> `gone` is empty.
- **No schema change:** presence per run already lives in `subdomain_sources.run_id`, so the rule is the old single-miss query plus one more `NOT EXISTS`. docs/04 says so explicitly. `Store.diff_gone(baseline, previous, latest)` carries the rule; the old query survives as `Store.diff_pending_gone(previous, latest)`, which powers the human "not reported as GONE yet" line and the new `pending_gone` JSON array. `DiffSnapshot` gained `baseline_run_id` and `pending_gone` (both defaulted), and `diff --json` now documents all three run ids.
- Adversarial cases and their tests (all in `tests/test_store.py` / `tests/test_engine.py`):
  - missing once then back: `test_diff_gone_is_not_confirmed_when_the_host_reappears` (not GONE, not pending once it is back).
  - missing twice in a row: `test_regression_diff_gone_needs_two_consecutive_misses` (GONE on the second miss, and only then).
  - visible in both baseline and previous, missing from the latest only: `test_diff_gone_needs_the_miss_to_be_consecutive` (not GONE; pending).
  - no sighting in the run before the pair: `test_diff_gone_needs_the_baseline_run_not_just_two_empty_ones` (not GONE - two empty runs alone are not evidence).
  - first-ever run / fewer than three runs: `test_diff_with_one_run_has_nothing_to_compare`, `test_diff_with_two_runs_reports_pending_and_no_gone`, and the real CLI path in `test_diff_and_status_after_two_mock_runs` (`baseline_run_id: null`, `gone: []`, "GONE needs three discovery runs" on stderr).
  - the session's own repro, 35 names then 8: `test_regression_diff_gone_needs_two_consecutive_misses` seeds exactly that shape and asserts the 27 are **not** GONE after one miss (they are `pending_gone`), then GONE after the second identical run.
- **Red before the fix** (source reverted, tests kept): `7 failed in 0.48s`, exit 1 - `AttributeError: 'Store' object has no attribute 'diff_pending_gone'`, `TypeError: Store.diff_gone() takes 3 positional arguments but 4 were given` (twice), `AttributeError: 'DiffSnapshot' object has no attribute 'baseline_run_id'` (twice), `KeyError: 'baseline_run_id'`. Green after the fix: the same seven plus the two extra cases -> `148 passed in 2.71s` over `test_store.py test_engine.py test_cli.py`.
- Mutation proofs (source mutated, targeted tests run, restored with `git checkout -- src/reconkit` + `git apply`):
  - M1 drop the "absent from previous" clause -> `test_diff_gone_needs_the_miss_to_be_consecutive` fails with `assert ['a.example.com'] == []`, `MUT_M1_CAUGHT`.
  - M2 drop the "seen in baseline" clause -> `test_diff_gone_needs_the_baseline_run_not_just_two_empty_ones` fails with `assert ['old.example.com'] == []`, `MUT_M2_CAUGHT`.
  - M3 engine passes `discovery[1]` as the baseline -> `test_diff_with_two_runs_reports_pending_and_no_gone` fails with `assert (1, 1, 2) == (None, 1, 2)`, `MUT_M3_CAUGHT`.
- **Real data, unchanged database:** `reconkit diff -d testfire.net` against the existing `recon.db` (the two verification-session runs, 35 then 8) now prints:
  ```
  {"type":"diff","target":"testfire.net","baseline_run_id":2,"previous_run_id":4,"latest_run_id":11,"new":[],"gone":[],"pending_gone":["altoroc.testfire.net", ... 27 names ...],"state_changes":[],"ports_opened":[],"ports_closed":[]}
  No changes since run #4.
  Not reported as GONE yet (needs two consecutive misses): altoroc.testfire.net, ...
  ```
  The 27 rows that were `GONE` in the verification session are `pending_gone`, and `gone` is empty - the exact reported defect, on the exact data that produced it.
- Mock end-to-end of the changed command: two `passive --mock` runs then `diff --json` -> `"baseline_run_id":null, "gone":[], "pending_gone":[]`, and the human run prints `No changes since run #1.` plus `GONE needs three discovery runs to compare; nothing can be confirmed gone yet.`
- **S1:** `pytest -q` -> `613 passed in 13.04s` and a second pass `613 passed in 12.98s`; `ruff check .` -> `All checks passed!`; `ruff format --check .` -> `68 files already formatted`; `mypy src/reconkit` -> `Success: no issues found in 36 source files`. Suite went 606 -> 613 (eight new cases, one obsolete single-miss test replaced).
- **S2 (own diff):** no broad `except` added (`git diff -- src/reconkit | grep '^+.*except'` -> `NONE`); the only new external input is the report of a read-only query, and SQL stays parameterized (four bound parameters in `diff_gone`, three in `diff_pending_gone`, no interpolation); no secret can reach the new fields (they are FQDNs already stored in `subdomains`); no blocking call added inside async code (`Engine.diff` was and stays synchronous, called from the CLI, not from `run`); no new exception path (`diff_pending_gone` cannot raise beyond `sqlite3`, as before); unfinished paths: `state_changes`/ports still use the previous pair only, and `NEW` still means `first_seen_run = latest`, so a host that reappears after a miss is neither `NEW` nor `GONE` (documented in docs/02).
- **S3 scans:** `\bassert\b` -> `NONE`; `shell\s*=\s*True` -> `NONE`; `TODO|FIXME|XXX|HACK` -> `NONE`; `noqa|type: ignore` in the three changed source files -> `NONE`; broad-`except` grep on the diff -> `NONE`.
- PIT-39 added. Not verified: no real third discovery run was made for this rule in step 1 (the real `diff` above proves the first-miss half on real data; the second-miss half is proved by the store/engine tests and will be exercised again in the session-2 run).

## Real-tool verification session 2 - testfire.net, post-fix (2026-11-14)

- Command: `reconkit run -d testfire.net --active --speed slow --no-keys --json` (the `run` subcommand, not the bare form), against the existing `recon.db`, one pass. Started `2026-11-14T20:10:59Z`, finished `20:19:24Z` (8m25s), **exit 5**. `stdout` 18,771 bytes (one document), **`stderr` 0 bytes** - the known `--json` progress gap is unchanged and still contradicts docs/02 section 5.
- Summary object, verbatim from the document:
  ```
  {"hosts":36,"alive":8,"dns_only":0,"shut_down":0,"dead":28,"unknown":0,
   "tools_ok":8,"tools_failed":2,"tools_skipped":31,"tools_timeout":0}
  ```
  Stages, their run ids and their executed/skipped counts: `subs` 18 (6 executed, 5 skipped), `dns` 19 (1, 4), `live` 20 (2, 2), `ports` 21 (1, 4), `tech` 22 (0, 5), `urls` 23 (0, 8), `vulns` 24 (0, 3). The 31 skipped are exactly the selection-time skips this build always had; they now appear in `stages[].skipped` and in `tools_skipped` (fix from the previous session), so the run reports what it did **not** do for the first time.
- Executed tools (`tool_runs` rows, verbatim): `crtsh ok 1 51.7`, `certspotter ok 0 0.83`, `otx failed 0 0.0 'otx: rate limited (HTTP 429)'`, `hackertarget failed 0 0.0 'hackertarget: free quota exceeded'`, `subfinder ok 35 64.02`, `assetfinder ok 3 6.19`, `dnspython ok 36 0.0`, `pyprobe ok 8 0.0 'unreachable=28'`, `httpx ok 8 7.04`, `pyscan ok 0 0.0 'blocked=8'`. Every other pool member is `skipped` with `no adapter yet (phase 3)`, except `naabu` (`blocked: resolves inside the binary, so in_scope_cidrs cannot be enforced (11c-G-7)`).
- **pyprobe now agrees with httpx on every live host.** `pyprobe`: 8 records, all `ALIVE`, `error='unreachable=28'`; `httpx`: 8 records, all `ALIVE`, `error=None`. No `UNKNOWN` record exists in this run. This is the fix from the previous session working on the real target that produced the 8-of-8 disagreement.
- **Confidence observed, before and after, and what it actually means.** Session 1 stored `confidence: UNCONFIRMED` for all 8 ALIVE hosts (its log entry quotes them). This run: `demo.testfire.net HIGH`, `www.testfire.net MEDIUM`, the other six ALIVE hosts `LOW`, and **zero `UNCONFIRMED`**. The number is not live-tool agreement: `Engine._write_host` writes `confidence` only when the transition is `UNCONFIRMED` and otherwise keeps the discovery value, so the displayed trust is `subdomains.source_count` from the `subs` stage (docs/04), and the two-tool live agreement lives in `host_status_history.tools_json` (`["pyprobe","httpx"]` on every ALIVE row). So the honest statement is "the disagreement override no longer fires; HIGH/MEDIUM/LOW are discovery-source counts", not "two live tools now set MEDIUM". `altoro.testfire.net` is `LOW` because `hackertarget` failed this run, leaving `subfinder` as its only contributing source, while the JSON `sources` array still lists all-time sources.
- **`diff` after the run** (latest pair now runs 11 and 18, baseline 4):
  ```
  {"type":"diff","target":"testfire.net","baseline_run_id":4,"previous_run_id":11,"latest_run_id":18,"new":[],"gone":[],"pending_gone":[],"state_changes":[],"ports_opened":[],"ports_closed":[]}
  No changes since run #11.
  ```
  The rule's effect on the actual defect, measured directly against the same database (`Store` methods, no hand-edited numbers):
  ```
  completed subs run ids (newest first): [18, 11, 4, 2]
  old rule  (seen in 4, absent in 11):            27 hosts
  new rule  (seen in 2, absent in 4 AND 11):       0 hosts
  new rule  (seen in 4, absent in 11 AND 18):      0 hosts
  pending after run 18 (seen in 11, absent in 18): 0 hosts
  ```
  So: on the pair that produced the false GONEs (4 -> 11) the old rule said 27, the new rule says 0 (they were `pending_gone` until run 18), and because `subfinder` came back with 35 names in run 18 the 27 were never confirmed gone. **`subfinder` is still flaky** (35, then 8, then 35 in this run - 64.02 s this time); what changed is that a single flaky run no longer produces a `GONE` report. If a second consecutive run had also missed them, the rule would have confirmed them at that point - that is the designed behaviour, not a gap.
- Database, raw. Counts before -> after: `scan_runs` 17 -> 24, `tool_runs` 99 -> 140, `subdomains` 36 -> 36, `subdomain_sources` 100 -> 139, `host_status_history` 81 -> 117, `ports` 0 -> 0, `urls` 0 -> 0. Discovery runs now: `2 partial 36`, `4 partial 36`, `11 partial 9`, `18 partial 36` hosts. `scan_runs` 18-24: `subs partial`, then `dns`, `live`, `ports`, `tech`, `urls`, `vulns` all `completed` - note that a stage which executed **zero tools** is still recorded `completed` (the empty-stage exit-code question stays open). One full history row, verbatim:
  ```
  {'id': 104, 'subdomain_id': 4, 'run_id': 20, 'state': 'ALIVE', 'status_code': 200,
   'location': None, 'title': 'Altoro Mutual', 'ips_json': '["65.61.137.117"]',
   'tech_json': '[]', 'waf': None, 'tools_json': '["pyprobe", "httpx"]',
   'checked_at': '2026-11-14T20:19:01Z', 'cnames_json': '["testfire.net"]',
   'dangling_cname': None}
  ```
- **A previously unverified fact is now verified live:** `hackertarget` returned its free-quota refusal and the adapter mapped it to a failed result with `hackertarget: free quota exceeded`. The quota-message branch that previous sessions could not exercise has now run for real. `otx` returned 429 again, so its response shape remains unobserved.
- Still wrong or surprising, stated plainly: (1) `--json` still writes nothing to stderr (docs/02 promises progress there); (2) `tech`/`urls`/`vulns` ran zero tools and are recorded and reported `completed` - their skips are now visible, but the run's exit 5 comes from `otx` and `hackertarget`, not from the three empty stages; (3) `ports` is still `blocked=8` with zero port rows (no `in_scope_cidrs`, `naabu` blocked) - unchanged by design; (4) `duration_s` is `0.0` for `dnspython` and `pyprobe` (11d-findings-c); (5) `pyprobe` reports `unreachable=28`, which counts the 28 hosts that do not answer HTTP at all, not errors; (6) `crtsh` took 51.7 s and `subfinder` 64.02 s at `--speed slow`, which is pacing, not a defect.
- Not verified, unchanged: no tech/urls/vulns tool has ever run; no open port has ever been observed; no keyed provider ran (`--no-keys`); `killpg`, the sudo-authenticated installer path and every Windows path remain untested; `libpcap-dev` is still absent.

## Part 12a: write raw tool output to the workspace (G-1)  (commit subject `feat: write every tool's raw output to the workspace`; hash filled by the next commit)

- **Docs read / goal:** `MASTER_PLAN.md` Part 12 (12a, its `DECIDED` line is the spec), docs/03 sections 4-6 and 9, docs/09 sections 2-3, docs/05 rules 5 and 8 (secrets, honest UA), docs/07, docs/02 section 5 (JSON shape), `config.yaml` and `tools.yaml`. Goal: `Workspace.write` had no caller and `ToolResult.raw_path` was never set, so every parse bug (pyprobe TLS, certspotter empties, HackerTarget quota) had to be reproduced by hand. Every adapter run now leaves its bytes on disk.
- **Decisions and assumptions (docs written first, then code):**
  - Capture is a per-result field, not per-adapter side effects: `ToolResult.raw_text` (unredacted, in memory, `Field(exclude=True)`) plus the existing `raw_path`. Both base classes fill `raw_text` in every return path; the three python adapters fill it through one shared helper instead of hand-rolling a format.
  - Binary capture is `stdout` then `--- stderr ---` then `stderr` (stdout-only when stderr is empty, stderr only when stdout is blank); HTTP capture is the response body, or the failure message when no body was read; `python` capture is a JSON document of the parsed records plus the error counters (they have no child process); `--mock` captures the fixture text.
  - The engine writes, never the adapter (adapters stay free of workspace/store imports): `_run_one` calls `Workspace.write`, which redacts with the run's secrets and caps at `MAX_OUTPUT_BYTES`, and only then sets `raw_path`.
  - Filename `<run_id>-<tool>.txt` in `RAW_OUTPUT_DIRS[stage]`: unique per stage run and tool, so two tools in a stage and the same tool in two runs cannot collide and a rerun cannot overwrite older evidence. `dns` has no workspace directory of its own (the layout is exactly six), so it uses `meta/`, like phase-3 `vulns`/`shots`.
  - `raw_text` is excluded from serialization so an unredacted payload can never reach `--json`; `raw_path` does appear there because that object is the docs/09 `ToolResult` schema (verified below).
  - The cap is enforced at the disk boundary (`Workspace.write(..., max_bytes=MAX_OUTPUT_BYTES)`) so every raw file is capped no matter which caller writes it; `MAX_OUTPUT_BYTES` is `runner`'s existing 1,000,000 default, now a named constant - no new config key.
  - An empty capture still writes an empty file (one executed tool = one file); a write that raises is contained and leaves `raw_path` at `None`.
- **Decisions for user review:** (1) a python adapter's raw file is post-parse evidence (JSON of records + counters), not wire bytes - a host that produced no record appears only in the counters; (2) an HTTP failure writes the failure message (e.g. `otx: rate limited (HTTP 429)`) because the body is deliberately not read on error; (3) `dns` raw files live in `meta/` rather than a new seventh directory; (4) a capped file carries no "truncated" marker line, because a marker would push it over the cap (the binary path still reports `output truncated` in `result.error` from the runner).
- **Docs changed first:** `docs/09_TOOL_CONTRACTS.md` (ToolResult schema gains `raw_text` with its `Field` exclude, plus a "Raw output (12a)" bullet covering all three kinds, every status, mock, redaction and `raw_path`); `docs/03_ARCHITECTURE.md` (`workspace.write` signature with `max_bytes` and the cap rule, a new bullet for the raw-file naming and `dns`->`meta` mapping, a `_run_one` bullet in the Engine API, and data-flow step 9). No `docs/02` change: the JSON tool object is defined by docs/09.
- **Deviations:** the plan says "the four python adapters"; the tree has three (`dnspython`, `pyprobe`, `pyscan`) and all three changed. docs/03 section 3 (technology stack) needed no change: the capture rule belongs to sections 5 and 6 step 9. `Workspace.write` now caps every caller, so the old `test_workspace_large_output_is_written` (2 MiB uncapped) became `test_workspace_large_output_is_written_up_to_the_cap`; the new assertion is stricter, not weaker.
- **Files touched:** `src/reconkit/models.py`, `adapters/base.py`, `adapters/dnspython.py`, `adapters/pyprobe.py`, `adapters/pyscan.py`, `core/runner.py` (constant only), `core/workspace.py`, `engine.py`; `tests/test_engine.py`, `test_binary_adapters.py`, `test_python_adapters.py`, `test_wildcard_workspace.py`; `docs/03`, `docs/09`, this entry, `docs/PROGRESS.md`. 14 files, +497/-36 before the docs edits.
- **Requirement -> test table:**
  | Requirement (12a `DECIDED` line / owner instruction) | Test |
  |---|---|
  | a mock run writes exactly one redacted file per executed tool and sets `raw_path` | `test_each_executed_tool_writes_one_raw_file_and_sets_raw_path` |
  | a successful tool run produces a raw file containing its stdout | `test_binary_run_captures_stdout_and_stderr`, `test_each_executed_tool_writes_one_raw_file_and_sets_raw_path` |
  | a failed tool run ALSO produces a raw file (main behavior change) | `test_failed_tool_still_writes_its_raw_output`, `test_binary_failed_run_captures_its_output`, `test_parse_error_keeps_the_raw_output` |
  | a timed-out tool keeps its partial output | `test_binary_timeout_captures_partial_output` |
  | output beyond `max_output_bytes` is truncated, not dropped or unbounded | `test_raw_output_file_is_capped_at_max_output_bytes`, `test_workspace_large_output_is_written_up_to_the_cap`, `test_workspace_write_honours_an_explicit_byte_cap`, `test_workspace_cap_never_writes_a_broken_multibyte_character`, `test_workspace_write_rejects_a_non_positive_cap` |
  | a secret/key pattern is redacted in the raw file too | `test_raw_output_file_is_redacted_with_the_run_secrets` (+ PIT-22's `test_workspace_redacts_two_secrets_and_a_bearer_token`) |
  | stdout and stderr are both present when both exist | `test_binary_run_captures_stdout_and_stderr`, `test_binary_run_without_stderr_keeps_stdout_only` |
  | the python adapters flow through the shared capture path | `test_python_adapters_capture_their_fixture_in_mock_mode`, `test_pyprobe_raw_text_is_json_evidence_of_each_host`, `test_dnspython_raw_text_carries_the_outcome_counters`, `test_pyscan_raw_text_carries_the_blocked_count` |
  | adversarial: NUL + ANSI bytes | `test_raw_output_keeps_nul_and_ansi_bytes_verbatim` |
  | adversarial: filename collision across two tools in one stage / two runs | `test_raw_file_names_do_not_collide_across_tools_or_runs` |
  | adversarial: a workspace write that raises keeps the tool result | `test_a_failed_workspace_write_keeps_the_tool_result` |
  | adversarial: a crash before any output still leaves a file | `test_a_crashed_tool_writes_an_empty_file_instead_of_nothing` |
  | Windows path containment unchanged | unchanged `test_workspace_rejects_unsafe_filenames`, `test_workspace_rejects_unknown_stages`; the filename is `int` + adapter name, still passed through `Workspace.path` |
- **Red before green (the failed-tool half, proved):** with the tests in place and only `MAX_OUTPUT_BYTES` added to `runner.py`, `pytest -q tests/test_engine.py tests/test_binary_adapters.py tests/test_python_adapters.py tests/test_wildcard_workspace.py -k "raw or capture or cap"` -> **`19 failed, 2 passed, 209 deselected`**, exit 1. The 19 were every 12a test (`AttributeError: 'ToolResult' object has no attribute 'raw_text'`, `TypeError: Workspace.write() got an unexpected keyword argument 'max_bytes'`); the 2 passes are pre-existing `cap`-named HTTP body tests. Before that constant existed the same command was a collection `ImportError` for `MAX_OUTPUT_BYTES`, so the constant alone is not what made the tests pass. After the implementation the same selection is **`21 passed, 209 deselected`**.
- **Self-review findings (S2):**
  - Broad excepts: none added. The one new handler is `except (OSError, ValueError, TypeError)` in `Engine._write_raw`, deliberately narrow and documented; `git diff -- src | grep '^+.*except'` shows only that line. Pre-existing broad excepts in `store.py` (214, 249), `workspace.py` (150), `wildcard.py` (90), `cli.py` (232), `engine.py` (421, 615, 922) and `dnspython.py` (142) are unchanged.
  - External input: only `ToolResult.raw_text`, produced by our own adapters from tool output. It reaches disk through `Workspace.write` (redact -> cap -> `mkstemp` + `os.replace`); the filename is `f"{run_id}-{adapter.name}.txt"` from an int and a class constant and is validated by `Workspace.path` (regex, one segment, resolve containment, device names). No user-supplied string is in a path.
  - Secrets: `raw_text` is unredacted in memory and is redacted exactly once, at the disk boundary. It is `Field(exclude=True)`, so `model_dump`/`model_dump_json`/`--json` cannot carry it (verified: the `--json` tool object has keys `duration_s, error, raw_path, records, status, tool` and `raw_text` is absent from the whole document). `error` strings are unchanged and still go through `_record`'s redaction. Redaction runs before the cap so a secret straddling the cut cannot survive as a prefix.
  - Blocking calls in async code: `Workspace.write` is synchronous and now runs inside async `_run_one` (one local write of at most 1,000,000 bytes, `fsync` + `os.replace`). This matches the existing design: `_persist_stage` already does synchronous SQLite work and the runner is pushed to a thread only because it is long. No new `asyncio.to_thread` was added; the write is bounded and local.
  - Exceptions that could escape: `Workspace.write` raises `OSError`/`ValueError`/`TypeError`, all caught in `_write_raw`; `cap_bytes` raises `ValueError` for a non-positive cap, also caught. `KeyboardInterrupt`/`CancelledError` are not caught, as before. Nothing new escapes an adapter or the engine.
  - Unfinished paths: HTTP error bodies are not captured (the failure message is); python adapters capture post-parse evidence, not raw responses; the `dns` raw file has no directory of its own.
  - Blocking scope/security check: no scope code touched; `_write_raw` only runs for a tool the engine already selected after the gates.
  - **S3 raw output** (bash/grep form, repo root): `\bassert\b` in `src/reconkit` -> `NONE`; `shell\s*=\s*True` -> `NONE`; `TODO|FIXME|XXX|HACK` -> `NONE`; `print(` -> `src/reconkit/ui.py` only; `subprocess` -> `src/reconkit/core/runner.py` plus a pre-existing docstring mention in `adapters/base.py:3` ("no database, scope gate, UI or subprocess of their own"), no import; `sqlite3` -> `src/reconkit/core/store.py` only; `os.environ` -> `ui.py:148`, `installer/go_install.py:22`, `installer/pipx.py:31`, `installer/github_release.py:542` (all pre-existing, none in adapters); broad-except scan -> the pre-existing nine, none added; `noqa|type: ignore` -> only the three pre-existing `type: ignore` lines in `test_scope.py:266`, `test_runner.py:82`, `test_runner.py:86`, none added; adapters importing store/scope/ui/cli -> `NONE`. Extra 12a scans: `raw_text` outside `adapters/`, `models.py`, `engine.py` -> `NONE`; `.write_text(|open(` in `src/` -> only the pre-existing `workspace.py:143` (`os.fdopen`), `runner.py:109`, `installer/verify.py`, `installer/github_release.py`, `subfinder.py:68` - no new raw writer; `Workspace.write` callers -> exactly one, `engine.py:956`; `raw_text` in `ui.py`/`cli.py`/`store.py` -> `NONE`.
- **Bugs found:** none new. No `fix:` follow-up is needed and no PIT row was added; PIT-22's guard now covers this path through `test_raw_output_file_is_redacted_with_the_run_secrets`.
- **Mutation proofs** (each mutation applied by hand to the working tree, related tests only, then restored from a byte-identical copy; `sha256sum -c` printed `OK` for both files after every restore, and `git diff --stat` for the two files reads `21 ++++++++++++++++++---` / `42 ++++++++++++++++++++++++++++++++++++++++++++++++-` again at the end):
  - M1 drop the redaction -> `cleaned = cap_bytes(text, max_bytes)`: `test_raw_output_file_is_redacted_with_the_run_secrets` and `test_workspace_redacts_two_secrets_and_a_bearer_token` -> **`2 failed`**, `AssertionError: assert 'sk-live-abc123' not in 'key=sk-live-abc123...'`. Restored -> `2 passed`.
  - M2 set `raw_path` before the write succeeds -> `_write_raw` computes the destination with `workspace.path(...)`, swallows the write failure and still returns the path: `test_a_failed_workspace_write_keeps_the_tool_result` -> **`1 failed`**, `AssertionError: assert '/tmp/.../subs/1-tool.txt' is None`. Restored -> `1 passed`.
  - M3 skip the write on failure -> `if result.status is ToolStatus.OK:` around the `model_copy`: `test_failed_tool_still_writes_its_raw_output` -> **`1 failed`**, `AssertionError: assert False ... is_file()` (raw_path was `None`). Restored -> `1 passed`.
  - M4 remove the cap -> `cleaned = redact(text, values)`: `test_raw_output_file_is_capped_at_max_output_bytes` and `test_workspace_large_output_is_written_up_to_the_cap` -> **`2 failed`**, `AssertionError: assert 1002048 == 1000000`. Restored -> the 21-test selection passes again.
- **Raw check output (S1, first pass, full output):**
  ```
  --- pytest -q ---
  ........................................................................ [ 11%]
  ... (9 lines of dots) ...
  634 passed in 13.35s
  --- ruff check . ---
  All checks passed!
  --- ruff format --check . ---
  68 files already formatted
  --- mypy src/reconkit ---
  Success: no issues found in 36 source files
  ```
  Second pass in the same session: `634 passed in 13.14s`, same three clean lines. Suite 613 -> 634 (21 new cases; one existing workspace test rewritten to the capped contract).
- **End-to-end `--mock` run with the changed code:** `reconkit passive -d example.com --mock --db /tmp/12a/recon.db` -> exit 0, 7 tools `ok`, 9 `skipped`. Files written, all mode `0600`: `workspaces/example.com/subs/1-crtsh.txt` (1577 B), `1-certspotter.txt` (596), `1-otx.txt` (591), `1-subfinder.txt` (64), `1-hackertarget.txt` (31), `1-assetfinder.txt` (49) and `workspaces/example.com/meta/2-dnspython.txt` (172). `1-crtsh.txt` starts with the real CT JSON (`{"issuer_ca_id": 409703, ...}`); `2-dnspython.txt` is the parsed fixture document (`{"www.example.com": {"ips": [...], "cnames": []}, ..., "gone.example.com": {"state": "DEAD"}}`). A second run, `reconkit subs -d example.com --mock --json`, showed the tool object keys `['duration_s','error','raw_path','records','status','tool']`, `raw_path: workspaces/example.com/subs/3-crtsh.txt`, and `raw_text` absent from the whole document.
- **Not verified:** no real (non-mock) tool ran with this code, so the binary branch's real stdout+stderr file and the HTTP adapter's real body file are proved by unit tests on `ExecResult`/`MockTransport` only; no Windows path; no real `--active` run; a python adapter's file cannot show a host that produced no record; the `dns`->`meta` mapping is only exercised by mock runs and unit tests.
- **Next part must know:** `Engine._run_one` now does `model_copy(update={"raw_path": ...})` before `self._record(...)`. 12c changes `duration_s` in the same function (adapter value wins, engine fills only when the adapter reported none) and must keep the `raw_path` update and the write ordering; 12g will add per-run directories, so `RAW_OUTPUT_DIRS` and the `<run_id>-<tool>.txt` name must move with that layout rather than be duplicated. The cap constant is `core/runner.MAX_OUTPUT_BYTES`.

## Part 12f: redact console error text and the `-v` traceback (C-1)  (commit subject `feat: redact console error text and the -v traceback`; hash filled by the next commit)

- **Docs read / goal:** `MASTER_PLAN.md` Part 12 (12f, its `DECIDED` line is the spec), docs/03 sections 4, 5 and 9, docs/05 rules 5/8 and sections 6 and 8, docs/04 section 10 (`redact`), docs/02 section 6 (exit codes), `cli.py`, `core/store.py`, `engine.py` (`Engine.open`), and the C-1 row in the Part 11c audit. Goal: `cli.py`'s last-resort handler formatted raw `str(exc)` and the `-v` branch printed a raw traceback; no secret source existed in the CLI, so an escaping exception could print a key. Nothing in this build had demonstrated a reachable leak (keys travel in headers), so this closes the last unguarded output path rather than a known incident.
- **The existing redaction source, named:** `core/store.py` owns the one implementation - `REDACTED`, the compiled pattern list (`_AUTH_HEADER`, `_COOKIE_HEADER`, `_BEARER`, `_URL_CREDENTIALS`, `_FLAG_VALUE`, `_SECRET_PAIR`) and `redact()`. Its secret *values* reach it per call; the engine's set is `Engine._secrets` = every non-empty value of the env dict that `Engine.open` builds from `dotenv_values()`, and that is the same set 12a routes through `Workspace.write` and `_record`. `configure_redaction()` reuses that exact `redact()` - one pattern list, one value source - it does not build a parallel list.
- **Startup order (found and handled):** `Engine.open` is called *inside* `_run_scan`, after `_targets()`, `load_config()` and the usage refusals, so at the moment `_report_error` can first fire the env is **not** loaded yet. The CLI therefore loads `.env` itself at the top of the Typer callback (`main`) and calls `configure_redaction()` there. It uses the same `dotenv_values()` call with no path argument: python-dotenv resolves `.env` from the calling file's directory, and `cli.py` and `engine.py` are both in `src/reconkit`, so both resolve the same checkout-level `/home/kali/Desktop/reconkit/.env`. Verified by reading `dotenv.main.find_dotenv` in the venv (it uses `sys._getframe()`'s file, not cwd) and by a test that feeds a fake `.env` dict. An unreadable `.env` is ignored at startup (the engine reports the real problem when it loads it), and the callback reads no `os.environ` - `test_cli_never_reads_environment_keys` still passes.
- **API shape (in `core/store.py`, no new file):** `configure_redaction(secrets)` replaces the process-wide value set (deduplicated, longest first, values under 3 chars ignored); `redact(text, secrets=None)` now treats `None` as "use that set" and an explicit iterable - **including `()`** - as "exactly these values". That keeps every existing caller byte-identical: `Core`/engine/workspace/store all pass their per-run tuple, so stored text, `tool_runs.error` and raw files still use only that run's values, while the CLI console path uses the startup set. No new env var, no new pattern, no new module.
- **Dependency rule change (needs owner awareness):** `cli.py` now imports `configure_redaction` and `redact` from `reconkit.core.store`. The existing `test_cli_imports_only_the_allowed_layers` banned *any* `reconkit.core.store` import, which the ruling makes impossible to keep. The assertion was replaced with a stricter, name-level rule: the only names imported from `reconkit.core.store` are exactly `{"configure_redaction", "redact"}`, and the source still must not contain `Store(` or `sqlite3`. docs/03 section 9 records the rule. This is an amendment, not a bypass: a `Store`/sqlite import in the CLI still fails the test.
- **Docs changed first:** docs/03 (CLI bullet, `store.py` structure comment, new "Redaction API (`core/store.py`)" section covering the one implementation, the replace-not-append contract, the startup-order fix and both console paths, plus the section 9 dependency rule); docs/05 (section 6 gains the console guarantee including chained exceptions, section 8 notes the traceback path).
- **Files touched:** `src/reconkit/core/store.py`, `src/reconkit/cli.py`; `tests/test_cli.py`, `tests/test_store.py`; `docs/03`, `docs/05`, this entry, `docs/PROGRESS.md`. 6 files, +223/-10 before the docs edits.
- **Requirement -> test table:**
  | Requirement (12f `DECIDED` / owner instructions) | Test |
  |---|---|
  | an exception message with a secret-shaped value is redacted in `_report_error` | `test_report_error_redacts_a_secret_in_the_message` |
  | the `-v` traceback output is redacted too (separate path) | `test_verbose_traceback_redacts_the_same_secret` |
  | an exception with no secret prints unchanged (no over-redaction, no mangling) | `test_report_error_leaves_a_message_without_a_secret_unchanged` |
  | a secret in a nested `__cause__`/`__context__` chain is redacted | `test_verbose_traceback_redacts_a_secret_in_a_chained_exception` |
  | `configure_redaction()` is seeded from the already-loaded env at startup | the four tests above (they all rely on it), plus `test_configure_redaction_replaces_values_and_ignores_short_ones` |
  | the shared pattern list still works with no configured values | `test_console_redaction_uses_the_shared_patterns_without_a_dotenv` |
  | the `--json` error path (adversarial) keeps stdout clean and redacts stderr | `test_json_error_path_keeps_stdout_clean_and_redacts_stderr` |
  | an unreadable `.env` cannot break the CLI | `test_an_unreadable_dotenv_does_not_break_the_cli` |
  | one pattern list, one value source; explicit per-run values unchanged | `test_configure_redaction_replaces_values_and_ignores_short_ones` |
  | CLI imports only the redaction helpers from the persistence layer | `test_cli_imports_only_the_allowed_layers` (amended, see above) |
- **Red before green (proved in two stages so the failure is the real one):** with the docs, the `store` helper and all tests in place, the CLI was wired only as far as *calling* `configure_redaction()`; `_report_error` was still unredacted. `pytest -q tests/test_cli.py -k "redact or verbose or json_error or unreadable or allowed_layers"` -> **`6 failed, 1 passed, 48 deselected`**, including `AssertionError: assert 'sk-live-abc123' not in 'unexpected ...ive-abc123\n'` with `unexpected error: RuntimeError: boom sk-live-abc123` printed in the assertion output, and `assert 'api_key=***' in 'unexpected error: RuntimeError: api_key=abcd1234efgh\n'`. The sixth failure was the amended dependency test waiting for the `redact` import. After adding `render_error(redact(message), ...)` the same selection is **`7 passed, 48 deselected`**.
- **Self-review findings (S2):**
  - Broad excepts: none added. The one new handler is `except OSError:` around `dotenv_values()` in `_configure_redaction`, narrow and documented. The broad-except scan still lists the same nine pre-existing sites (`store.py` 242/277, `workspace.py` 150, `wildcard.py` 90, `cli.py` 254, `engine.py` 421/615/922, `dnspython.py` 142); line numbers moved only because `store.py` grew.
  - External input: the values of `.env`, used solely as literal replacement strings - never a path, never argv, never SQL. None of them is printed; the module-level tuple holds them in memory only. Values shorter than 3 characters are ignored, matching the helper's long-standing rule.
  - Secrets: exactly one implementation and one pattern list (`store.py`); `configure_redaction` replaces instead of appending, so repeated startup calls cannot grow a parallel set. `redact()` is applied once, after `traceback.format_exc()`, so the chained text is inside the redacted string. `--json` still writes errors to stderr, and `redact` never writes to stdout.
  - Blocking calls in async code: none - the callback and `_report_error` are synchronous.
  - Exceptions that can escape: `dotenv_values()` OSError is caught; `configure_redaction` accepts any iterable of strings; a `None` value from python-dotenv is filtered out in the CLI before it reaches `len()`. `redact()` cannot raise for string input.
  - Unfinished paths, stated plainly: six `render_error(str(exc))` sites handle **typed, self-generated** messages rather than arbitrary exception text - `scope_check` (cli.py:442,445), `diff` (481), `status` (513), `doctor` (535) and `_run_install` (628). They are outside 12f's ruled scope (the ticket names the last-resort handler and `-v`), their messages are built by `scope`/`config`/`validate_target`, and they are listed here so a future item can widen redaction if the owner wants it.
  - **S3 raw output** (bash/grep form): `\bassert\b` -> `NONE`; `shell\s*=\s*True` -> `NONE`; `TODO|FIXME|XXX|HACK` -> `NONE`; `print(` -> `ui.py` only; `subprocess` -> `core/runner.py` + the pre-existing docstring word in `adapters/base.py:3`; `sqlite3` -> `core/store.py` only (and, as a test assertion string, `tests/test_cli.py`); `os.environ|getenv` -> `ui.py:148`, `installer/go_install.py:22`, `installer/pipx.py:31`, `installer/github_release.py:542`, all pre-existing, none in `cli.py`; broad except -> the same nine; `noqa|type: ignore` -> the same three pre-existing test lines; adapters importing store/scope/ui/cli -> `NONE`. 12f-specific: `def redact|def configure_redaction|REDACTED =|_configured_secrets` -> one of each in `core/store.py` (plus `runner.REDACTED`, a separate child-output mask that predates this part and is not a second `redact()`); `redact(` call sites -> `store.py` (params/error), `workspace.py` (raw files), `engine.py` (exception text), `cli.py` (console) - one CLI call, no duplicates; `dotenv` -> `cli.py`, `engine.py`, `doctor.py`, all calling `dotenv_values` (doctor passes its own file path).
- **Bugs found:** none in product code. Two test-suite friction points were fixed, not worked around: (1) `test_cli_never_reads_environment_keys` scans the CLI source for the literal string `os.environ`, and my first docstring contained it; the docstring was reworded ("no process environment is read directly") instead of weakening the guard; (2) ruff S105 flagged the new test constant name `SECRET`, so it was renamed `LEAK_VALUE` - the value and the assertions are unchanged. No PIT row was added: no product defect was found, and the new guards are listed in the table above.
- **Mutation proofs** (applied by hand, related tests only, restored from byte-identical copies; `sha256sum -c` printed `OK` for both files after every restore, and the final state is `src/reconkit/cli.py: OK`, `src/reconkit/core/store.py: OK`):
  - M1 `configure_redaction()` made a no-op (`return` before the assignment): `4 failed` - `AssertionError: assert 'sk-live-abc123' not in 'unexpected ...ive-abc123\n'`, with `unexpected error: RuntimeError: boom sk-live-abc123` in the output. Restored -> `4 passed`.
  - M2 remove the redaction call from `_report_error` (`render_error(message, ...)`): `4 failed`, same raw secret in the assertion output. Restored -> `4 passed`.
  - M3 forget the `-v` branch (redact before `traceback.format_exc()`): `2 failed, 2 passed` - exactly the two `-v` tests fail, the non-verbose ones pass, which is the signature this mutation should leave. Restored -> `4 passed`.
- **Raw check output (S1, first pass, full output):**
  ```
  --- pytest -q ---
  ........................................................................ [ 11%]
  ... (8 lines of dots) ...
  642 passed in 13.95s
  --- ruff check . ---
  All checks passed!
  --- ruff format --check . ---
  68 files already formatted
  --- mypy src/reconkit ---
  Success: no issues found in 36 source files
  ```
  Second pass: `642 passed in 13.90s` plus the same three clean lines. Suite 634 -> 642 (eight new cases: one store, seven CLI).
- **End-to-end runs of the changed path:** `reconkit subs -d example.com --mock --db /tmp/12f/recon.db --silent` -> exit 0 (the startup `.env` load does not disturb a normal run). The last-resort handler was then driven for real with an unwritable DB path: `--db /proc/1/x.db` printed `unexpected error: OperationalError: unable to open database file` and exited 1; with `-v` it printed the full traceback (`cli.py:204 -> engine.py:418 -> store.py:234 -> sqlite3.OperationalError`) - both go through `redact()` and neither contains a secret, so the text is unchanged, which is the no-over-redaction case on a real path.
- **Not verified:** no real exception carrying a real `.env` key has ever been observed, so this is a guard on an unproven leak path, not a reproduced incident; the fixtures never print a keyed provider error. Windows is untested. A `.env` value shorter than three characters is intentionally not masked by the value list (existing rule of `redact`), and a key that appears only in a *typed* message at the six out-of-scope sites above would not be masked by this part.
- **Next part must know:** `redact(text)` now means "the configured set" - any new caller that wants a per-run set must pass it explicitly (as `engine`/`workspace`/`store` already do). `configure_redaction` is process-global and replaces; it is called once from the Typer callback, so a test that invokes the app without patching `reconkit.cli.dotenv_values` will configure the real checkout `.env`. 12d's bounded `detail` string should reuse `redact(detail, self._secrets)` and this console path.

## Part 12c: `duration_s` has one authoritative source (11d-findings-c)  (commit subject `feat: let each tool measure its own duration`; hash filled by the next commit)

- **Docs read / goal:** `MASTER_PLAN.md` 12c and its `DECIDED (owner, 2026-11-14)` line, `docs/04` sections 3 and 5, `docs/09` section 3, `docs/03` section 5. Goal: the adapter measures its own work and reports `duration_s` on every outcome; `_run_one` fills a measured value only when the adapter reports none, and never overwrites one. The observed gap was `dnspython ok 36 0.0`, `pyprobe ok 8 0.0`, `otx failed 0.0` beside a real 429 in verification session 2.
- **Which adapters were already compliant, stated before touching code (as asked):** the binary flow in `BaseToolAdapter.run` already reported a duration - `run_exec` measures the child with `time.monotonic()` around spawn/wait (`ExecResult.duration_s`, `core/runner.py:106,129,180`). That is the tool's real work time, not harness overhead, so **it counts as adapter-reported** and the binary adapters needed no new measurement; only their two branches that omitted it changed. `HttpAdapter.run` also measured its own work on the ok branch (`perf_counter` since 11d), so HTTP adapters only needed the two failure branches. `DnsPythonAdapter`, `PyprobeAdapter` and `PyscanAdapter` never measured anything (every branch left the `0.0` default) and needed the measurement added in their existing run paths.
- **The ruling made concrete, and the ambiguity resolved:** `ToolResult.duration_s` stays a plain `float` defaulting to `0.0` (no model or DB change), and `0.0` is defined as "the adapter did not measure". `Engine._run_one` stores the adapter's value whenever it is `> 0` and only substitutes its own `perf_counter` delta when the value is `<= 0`; a negative value (only reachable with an injected/frozen clock) is treated the same way, so a stored value is never negative and an adapter value is never overwritten. That is **one fallback site** (`engine.py:926-930`). Timeout and crash rows now fall through the same site instead of measuring inline, so a timed-out tool records the harness's wall clock for the whole `wait_for` call.
- **Docs changed first:** `docs/04` section 3 column comment (`duration_s REAL -- wall seconds the tool itself worked`) plus three rules in section 5: who reports it and what counts as adapter-reported (binary `run_exec` wall clock included, by name); the positive-value-wins / `<= 0` fallback contract with the one fallback site; and what mock mode means (fixture read + parse, small, positive, never a constant). `docs/09` section 3 gained the contract comment on the field (`0.0 = not measured, engine fills`). No other doc change was needed; the DB schema is untouched.
- **Files touched:** `src/reconkit/adapters/base.py` (binary ParseError/ToolFailed/FetchFailed and RuntimeError branches now carry `duration or perf_counter-started`; `HttpAdapter` ParseError and FetchFailed branches carry the measurement), `src/reconkit/adapters/dnspython.py`, `src/reconkit/adapters/pyprobe.py`, `src/reconkit/adapters/pyscan.py` (`started` at the top of `run`, reported on mock-ok, mock-parse-error and real-ok), `src/reconkit/engine.py` (single fallback); `tests/test_adapters.py`, `tests/test_python_adapters.py`, `tests/test_engine.py`; `docs/04`, `docs/09`, this entry, `docs/PROGRESS.md`.
- **Requirement -> test table:**
  | Requirement (12c `DECIDED` / owner instructions) | Test |
  |---|---|
  | a successful adapter run reports a positive duration from its own measurement | `test_a_successful_run_reports_the_adapters_own_duration`, `test_every_python_adapter_times_its_own_work` |
  | `_run_one` does not overwrite an adapter-provided value | `test_adapter_reported_duration_is_stored_and_never_overwritten` (12.5 stored exactly) |
  | a failed run (429) reports a positive duration, not 0.0 (the session-2 gap) | `test_a_429_failure_still_reports_its_own_duration` |
  | a parse-error path reports a positive duration | `test_a_parse_error_still_reports_its_own_duration` |
  | a mock run has a documented, sensible duration | `test_a_mock_run_duration_is_small_and_measured`, `test_every_python_adapter_times_its_own_work` (docs/04: fixture read + parse, `0 < d < 5`) |
  | an adapter that cannot measure is filled by the harness's own wall clock | `test_missing_adapter_duration_gets_the_harness_wall_clock` (adapter sleeps 50 ms, reports 0.0, stored `> 0.04` and `==` the result value) |
  | a frozen clock stores no negative value | `test_a_non_positive_adapter_duration_is_never_stored` (-1.0 replaced) |
  | a timeout keeps a measured duration (12a/11d behaviour preserved) | `test_phase_timeout_records_a_timeout_row` (existing; now fed by the fallback site) |
- **Red before green (raw):** the new tests were written first against the fixed code, then the five source files were restored to HEAD (`git checkout -- src/reconkit/adapters/*.py src/reconkit/engine.py`, tests kept), producing a genuine failure of exactly the new behaviour:
  ```
  E       AssertionError: assert 0.0 > 0
  E        +  where 0.0 = ToolResult(tool='crtsh', status=<ToolStatus.FAILED: 'failed'>, records=[], duration_s=0.0, error='crtsh: rate limited (HTTP 429)', raw_path=None, raw_text='crtsh: rate limited (HTTP 429)').duration_s
  ...
  E       AssertionError: assert 0.0 > 0
  E        +  where 0.0 = ToolResult(tool='crtsh', status=<ToolStatus.FAILED: 'failed'>, records=[], duration_s=0.0, error='crtsh: invalid JSON', ...).duration_s
  ...
  FAILED tests/test_adapters.py::test_a_429_failure_still_reports_its_own_duration
  FAILED tests/test_adapters.py::test_a_parse_error_still_reports_its_own_duration
  FAILED tests/test_python_adapters.py::test_every_python_adapter_times_its_own_work
  FAILED tests/test_engine.py::test_missing_adapter_duration_gets_the_harness_wall_clock  (assert 0.0 > 0.04)
  FAILED tests/test_engine.py::test_a_non_positive_adapter_duration_is_never_stored  (assert -1.0 > 0)
  5 failed, 3 passed, 144 deselected in 0.31s
  ```
  The three that passed at HEAD are the ones that guard existing behaviour (HTTP ok duration, the engine's pass-through of a positive value, the HTTP mock duration). The fixed files were then restored from `/tmp/12c` and verified: `adapters/base.py: OK`, `adapters/dnspython.py: OK`, `adapters/pyprobe.py: OK`, `adapters/pyscan.py: OK`, `engine.py: OK` (`sha256sum -c`), and the three test files ran `152 passed in 0.98s`.
- **Mutation proof (M1, the required one):** `if result.duration_s <= 0:` changed to `if True:` (overwrite unconditionally) -> `test_adapter_reported_duration_is_stored_and_never_overwritten` failed with the raw value:
  ```
  >       assert raw_result(summary, "timed").duration_s == 12.5
  E       AssertionError: assert 0.00025354699755553156 == 12.5
  1 failed, 57 deselected in 0.15s
  ```
  Restored `engine.py` from `/tmp/12c` -> `engine.py: OK`; `pytest -q tests/test_engine.py -k "duration"` -> `3 passed, 55 deselected in 0.21s`.
- **Self-review findings (S2):**
  - Broad excepts: none added; the engine's pre-existing `except Exception` now builds a result without a duration and relies on the fallback, which is the intended path for a crashed adapter. The broad-except scan lists the same six `src/` sites as at the 12f baseline (plus the pre-existing `ui.py`/doctor handlers outside this scan's `src/reconkit` filter), none new.
  - External input: none. The only new values are clock readings; no user string, path or argv is involved.
  - Secrets: unchanged; durations are floats and never redacted.
  - Blocking calls in async code: none - `time.perf_counter()` is non-blocking.
  - Exceptions that can escape: none new; the adapters' `time` calls cannot raise.
  - Double counting: impossible by construction - the adapter value is used when positive and the fallback is skipped; proved by M1.
  - Unfinished paths, stated plainly: UI and `--json` do not print `duration_s` (it is a DB/`status` surface); a timeout row's duration includes `wait_for` overhead, which is the harness clock by definition; the six `render_error` sites from 12f remain untouched.
- **S3 raw output (bash/grep form, 13 scans):** `duration_s=` assignments -> 22 in `src/reconkit`, of which 3 are the pass-through/record in `engine.py` (`result.duration_s`, `_record` param), 2 are `run_exec`'s child clock in `core/runner.py`, and the rest are adapter measurements; exactly one conditional fallback (`engine.py:926`). Hardcoded `duration_s = 0` -> only the two model defaults (`models.py:111`, `core/runner.py:38`). Clocks -> `monotonic` in `core/runner.py` and `core/pacing.py`, `perf_counter` in `engine.py` and the four adapter modules. `assert` in `src/` -> NONE. `shell=True|os.system` -> NONE. `TODO|FIXME|XXX|HACK` -> NONE. `print(` outside `ui.py` -> NONE. `import subprocess` -> `core/runner.py` only. `import sqlite3` -> `core/store.py` only. `os.environ|os.getenv` -> the same four pre-existing sites (`ui.py:148`, `go_install.py:22`, `pipx.py:31`, `github_release.py:542`). `except Exception` -> six pre-existing `src/` sites, none added. `noqa|type: ignore` -> the same three pre-existing test lines. Adapters importing `store/scope/ui/cli` -> NONE. `adapters/*.py` `async def run` -> the four run paths changed, no new adapter.
- **Adversarial cases:** an adapter that raises after measuring -> the engine builds a fresh `ToolResult` and the fallback fills a positive value (no stale adapter number); a frozen adapter clock -> `0.0`, engine fills its own positive reading, never negative; an adapter reporting a huge value -> stored untouched (M1's inverse); a skipped tool -> `duration_s` stays `NULL` (no row change, `_record` not called for skips).
- **Raw check output (S1, first pass):**
  ```
  --- pytest -q ---
  ........................................................................ [ 11%]
  ... (8 lines of dots) ...
  650 passed in 13.68s
  --- ruff check . ---
  All checks passed!
  --- ruff format --check . ---
  68 files already formatted
  --- mypy src/reconkit ---
  Success: no issues found in 36 source files
  ```
  Second pass and the pre-commit output are in the same shape; suite 642 -> 650 (eight new cases: four HTTP, one python-adapter trio, three engine).
- **End-to-end run of the changed path:** `reconkit run -d example.com --mock --no-keys --db /tmp/12c.db --speed slow` -> exit 0, and the stored `tool_runs` rows are all positive: `crtsh 0.00025068799732252955`, `certspotter 0.0008128530025715008`, `otx 0.00047691899817436934`, `hackertarget 0.0005171979937586002`, `subfinder 0.000467628997284919`, `assetfinder 0.0003922159958165136`, `dnspython 0.00029269300284795463`; the ten skipped tools store `NULL`. No `0.0` row remains in a real CLI run.
- **Deviations / owner awareness:** `docs/09` was touched for the field contract although the ruling named only `docs/04` (AGENTS section 8 requires the adapter-contract doc to match); the test fake-adapter helper gained two keyword arguments (`duration_s`, `delay`), both defaulted, so existing tests are unchanged; the "0.0 means not measured" meaning is the ambiguity the instructions asked to resolve, and it is now stated in docs/04 rather than left implicit.
- **Not verified:** no real 429 was re-triggered this session (the session-2 evidence is what motivated the fix; the branch is covered by MockTransport); no real non-mock tool ran, so a real binary `run_exec` duration was not re-observed (the 12a/baseline runs did record it); `perf_counter` resolution and a sub-millisecond real HTTP call are untested on this hardware; Windows is untested. `scope.yaml` untouched, nothing pushed, no sudo.
- **Next part must know (12k):** `_run_one`'s fallback is the only place that invents a duration; an empty stage still writes no `tool_runs` row, so 12k's exit-5 work must not assume a duration exists. The mock-run durations are sub-millisecond, so any UI sorting by duration would look flat under `--mock`.

## Part 12k: a stage that executed no tools is a partial run (11d-findings-g)  (commit subject `feat: warn and exit partial when a stage runs no tools`; hash filled by the next commit)

- **Docs read / goal:** `MASTER_PLAN.md` 12k and its `DECIDED (owner, 2026-11-14)` line plus the adversarial list, `docs/02` sections 5 and 6, `docs/03` section 5 (engine bullets), `docs/08` flow 4, `docs/09` (stage/skip contract). Ruling: a requested stage with zero executed tools exits 5 with a warning that names the stage - not a silent 0, not 4, not warning-with-0.
- **The single exit-code decision site, found before coding:** `Engine._exit_code()` (`engine.py:650`), called once from `_run_scan` (`engine.py:644`), receives `summary`, `selected_total` and `failed_total`. Today it returns, in order: 3 when `scope_denied`; 4 when nothing was selected but a new stage exists (0 when everything was resumed); 4 when `failed_total == selected_total`; 5 when `failed_total`; else 0. 12k adds `self._empty_stages(summary)` to the 5 condition only - a new input alongside `failed_total`, never a replacement. No other module decides a scan exit code (`cli.py` only maps `summary.exit_code`; `installer.github_release.exit_code()` is install/update, code 6, untouched).
- **"Zero executed tools", defined precisely:** a `StageOutcome` that is not `resumed` and has an empty `results` list. The engine only appends a stage outcome after it built the stage (created a `scan_runs` row and recorded at least one `ToolSkip`), so an outcome with no results is exactly "every tool in the pool was selected out before running" (`no adapter yet (phase N)`, `requires --active`, `not installed`, docs/05 rule 6 block). It is **not** "tools ran and all failed" - that case has results with `FAILED`/`TIMEOUT` status and keeps its own 4/5 paths. Two things deliberately do not create an outcome at all, so they are not empty stages: a stage filtered out by `--tools`/`--exclude` (`if not selected and not skipped: continue`) and `ports` when there are no hosts (`if stage is Stage.PORTS and not hosts: continue`). Neither warns nor changes the code, which is what the master plan's `--tools` adversarial note requires.
- **Warning mechanism reused, not reinvented:** `ScanSummary.warnings` is a `list[str]` filled from `Engine._warnings` at the end of `_run_scan`; the human renderer prints each entry as `warning: ...` (`ui.py:502`) and `summary_document()` copies the list into `--json` `warnings` (`ui.py:101`). `_note_empty_stage()` (`engine.py:768`) appends one entry per stage, deduplicated against the existing list, and it is called once right after the stage outcome is appended (`engine.py:641`). No UI code changed: both surfaces already existed, verified by a real run below.
- **Composition/precedence, decided and documented (docs/02 section 6), not implicit:** 3 scope denied > 4 (no new stage selected anything, or every selected tool failed) > 5 (some selected tool failed/timed out, or some requested new stage executed no tools) > 0. Consequences written down and tested: several empty stages produce one warning each and still 5; an empty stage plus a partial failure is 5 with both warnings; an empty stage plus **every** selected tool failing is 4 (the stronger "no usable tool" statement), warning still present; **every** requested stage empty is 4, because no tool ran anywhere - not 5; a fully resumed run stays 0.
- **Docs changed first:** `docs/02` section 6 - the code-5 table row now says "or a requested stage executed no tools", plus two new paragraphs (the rule, the warning text, one warning per stage) and an explicit four-step precedence list, the all-empty case, and the `--tools`/no-hosts exclusions. `docs/03` section 5 - the `ScanSummary.exit_code` bullet now names `_exit_code()` as the single decision site and the empty-stage input/warning. `docs/08` flow 4 - the Partial line mentions the empty-stage cause.
- **Files touched:** `src/reconkit/engine.py`; `tests/test_engine.py`, `tests/test_ui.py`; `docs/02`, `docs/03`, `docs/08`, this entry, `docs/PROGRESS.md`.
- **Requirement -> test table:**
  | Requirement (12k `DECIDED` / owner instructions) | Test |
  |---|---|
  | a stage with zero executed tools causes exit 5 **and** a warning naming that stage | `test_an_empty_stage_warns_by_name_and_makes_the_run_partial` (asserts `"tech" in` the note and the skipped tool/reason) |
  | a stage with executed tools that all failed keeps its previous code (regression) | `test_exit_code_all_tools_failed_is_no_tool` (existing, still 4), `test_all_tools_failed_still_outranks_an_empty_stage` |
  | a run where every requested stage is empty follows the documented decision | `test_every_requested_stage_empty_is_no_tool_not_partial` (4, two warnings) |
  | one empty stage + a real tool failure is still 5 and both warnings survive | `test_empty_stages_and_a_partial_failure_together_are_still_partial` (two empty stages + a failed tool -> 5, both names) |
  | a clean run with no empty stages and no failures still exits 0 | `test_two_stages_that_ran_tools_still_exit_zero`, `test_exit_code_clean_is_success` (existing) |
  | the warning text names the stage | the core test and `test_every_requested_stage_empty_is_no_tool_not_partial` (set of names) |
  | both output surfaces carry the warning and the code | `test_an_empty_stage_warning_reaches_the_table_and_the_json` |
  | a `--tools`-filtered stage is not an empty stage | `test_a_stage_filtered_out_by_tools_is_not_an_empty_stage` (0, no warning, no outcome) |
  | a resumed run does not double-count completed stages | `test_a_resumed_run_does_not_warn_about_completed_stages` |
  | scope (3) outranks the empty-stage partial | `test_scope_denial_keeps_code_3_even_with_an_empty_stage` |
- **Red before green (raw):** tests written first, `engine.py` restored to HEAD (`git checkout -- src/reconkit/engine.py`), core test:
  ```
  >       assert summary.exit_code is ExitCode.PARTIAL
  E       AssertionError: assert <ExitCode.SUCCESS: 0> is <ExitCode.PARTIAL: 5>
  E        +  where <ExitCode.SUCCESS: 0> = ScanSummary(target='example.com', ... warnings=[], exit_code=<ExitCode.SUCCESS: 0>, resumed=False, scope_denied=False).exit_code
  1 failed in 0.14s
  ```
  The whole 12k group at HEAD: `5 failed, 3 passed, 58 deselected` (the 3 passing are the guards for old behaviour: all-failed 4, `--tools` filter 0, clean run 0; the resumed case passes trivially because HEAD never warns). Restored from `/tmp/12c/engine_12k.py`, `sha256sum -c` -> `engine_12k.py: OK`, re-run -> `8 passed`.
- **Mutation proofs (both required directions, each restored and checksum-verified):**
  - M1 drop the empty-stage check from the decision (`if failed_total or self._empty_stages(summary):` -> `if failed_total:`): core test fails `assert <ExitCode.SUCCESS: 0> is <ExitCode.PARTIAL: 5>` while the warning is still present - proves the exit input is load-bearing, not the warning alone.
  - M2 remove the warning append (`if not results: self._note_empty_stage(...)` deleted): core test fails `assert 0 == 1` on the warning count with exit still 5 - proves the warning is load-bearing separately.
  - Restores: `engine_12k.py: OK` and `src/reconkit/engine.py` sha256 `91c7639b5964adbd642e7a23e3329222db61d7ebcbabe55dc3b90a190ba79a71` both times; 8 targeted tests pass after each restore.
- **Self-review findings (S2):**
  - Broad excepts: none added. The `_empty_stages()` comprehension and the warning helper cannot raise on the engine's own dataclasses.
  - External input: none; stage names and skip reasons are engine-generated strings, and stage values come from the `Stage` enum, never from user text.
  - Secrets: the warning carries stage names and skip reasons only; skip reasons are the fixed selection strings, no key material.
  - Blocking calls in async code: none.
  - Exceptions that can escape: none new; `_exit_code` still returns a plain enum.
  - Unfinished paths, stated plainly: `ports` with no hosts and `--tools`-filtered stages intentionally produce neither a warning nor a code change; the `scan_runs.status` for an empty stage still reads `completed` (12a/12k do not touch run status; the warning and exit code carry the signal); a scope-denied active stage can now also produce an empty-stage warning while the exit stays 3.
- **S3 raw output (13 scans):** one decision site (`engine.py:644` assignment; returns only inside `_exit_code` at 660-668); one warnings list (`Engine._warnings`, appends at 774/791/1179/1224/1295 + one local list in the dangling-CNAME helper at 209); UI reads `summary.warnings` at `ui.py:101` and `ui.py:502`; `assert` in `src/` -> NONE; `shell=True|os.system` -> NONE; `TODO|FIXME|XXX|HACK` -> NONE; `print(` outside `ui.py` -> NONE; `import subprocess` -> `core/runner.py` only; `import sqlite3` -> `core/store.py` only; `os.environ|os.getenv` -> the same four pre-existing sites; `except Exception` -> the same six pre-existing `src/` sites; `noqa|type: ignore` -> the same three pre-existing test lines; adapters importing store/scope/ui/cli -> NONE; numeric `return` in `engine.py` -> NONE (typed enum only).
- **Adversarial cases:** every requested stage empty -> 4 with one warning per stage (tested); `--tools` filtering -> not an empty stage (tested); scope-denied run with an empty stage -> 3, warning present (tested); all selected tools failed plus an empty stage -> 4 (tested); fully resumed run -> 0 with no warning (tested); a stage that ran one tool and found nothing is **not** empty (it has a `ToolResult`, so no warning) - covered by `test_two_stages_that_ran_tools_still_exit_zero` and the existing empty-result tests.
- **Raw check output (S1):** first pass found one error in my own new test helper - `ruff` F821 `Undefined name 'ScanSummary'` (`tests/test_engine.py:1073`), because pytest passes on postponed annotations but ruff does not resolve them; fixed by adding `ScanSummary` to the existing `reconkit.engine` import. Re-run:
  ```
  --- pytest -q ---
  ........................................................................ [ 10%]
  ... (9 lines of dots) ...
  659 passed in 13.67s
  --- ruff check . ---
  All checks passed!
  --- ruff format --check . ---
  68 files already formatted
  --- mypy src/reconkit ---
  Success: no issues found in 36 source files
  ```
  Suite 650 -> 659 (nine new: eight engine, one UI). Second pass and the pre-commit run match (see the chat report for the raw second-pass block).
- **End-to-end runs of the changed path:** `reconkit run -d example.com --mock --no-keys --db /tmp/12k.db` (passive-only command, both requested stages have adapters) -> exit 0, only the pre-existing scope warning, no empty-stage warning. `reconkit run -d testfire.net --mock --active --no-keys --db /tmp/12k2.db --speed slow --json` -> **exit 5**, `warnings` exactly `tech stage executed no tools: 5 tool(s) skipped (no adapter yet (phase 3))`, `urls ... 8 tool(s) ...`, `vulns ... 3 tool(s) ...`; the same command without `--json` printed the three `warning:` lines and exited 5. This is the ruling reproduced on the real CLI, both surfaces, no UI code change.
- **Deviations / owner awareness:** the all-empty decision is **4, not 5**, documented in docs/02 section 6 and tested; `docs/03` and `docs/08` were touched in addition to the named docs/02 (both describe exit codes/warnings); the warning text format is new (`"<stage> stage executed no tools: N tool(s) skipped (<reasons>)"`) and is named in docs/02 so the wording is documented rather than incidental.
- **Not verified:** no real (non-mock) run this session; Windows untested; no UI snapshot of a run where the only output is the empty-stage warning.
- **Next part must know (12b):** `_empty_stages()` keys off `StageOutcome.results`, so any 12b work that starts writing synthetic `dns` discovery results will change empty-stage detection for the `dns` stage as a side effect; keep `scan_runs.status` semantics untouched unless its own ruling says otherwise.
