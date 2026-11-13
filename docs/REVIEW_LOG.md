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
| PIT-29 | A dangling-CNAME warning disappeared after restart | `host_status_history` had no CNAME columns and DNS-only resolved hosts were not persisted | Store `cnames_json` plus `dangling_cname`; reuse `Store.latest_cnames()` on a later NXDOMAIN | `test_regression_dangling_cname_survives_restart`, `test_dns_resolved_then_two_nxdomain_is_shut_down_then_dead`; migration tests in `test_store.py` |

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
- Gate after the fix: `560 passed`; `ruff check .`, `ruff format --check .`, `mypy src/reconkit` clean.
