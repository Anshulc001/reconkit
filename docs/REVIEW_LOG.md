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
- Part 8 (`feat: add the Typer CLI, flags and mock wiring`): hash filled by the Part 9 commit
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
