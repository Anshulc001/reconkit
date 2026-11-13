# Review log

Per-part evidence log for this repository. Each entry follows the template in
`docs/MASTER_PLAN.md`. Hashes are filled by the next commit, because a commit
cannot contain its own hash.

## Commit map

- Step 1 (`docs: add master plan, review log, check script, resume block`): `09a5bce`
- Part 3-AUDIT (`fix: close the phase-2 review gaps in store, keys and adapters`): `75eb261`
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
