# MASTER PLAN (verbatim)

Saved from the user's plan on 2026-11-13. Do not edit the rules; update
`docs/PROGRESS.md` RESUME and `docs/REVIEW_LOG.md` as the plan requires.

=====================================================
AUTONOMY RULES
=====================================================
A1. Do not stop to ask the user. When docs are silent, conflicting or ambiguous, decide by this order: (1) what docs say; (2) the safer/more restrictive option; (3) the smallest change. Fix the docs first to record the decision, and log it in REVIEW_LOG under "Decisions for user review" so the user can overrule it later.
A2. HARD STOP (set RESUME status to BLOCKED with the exact reason, commit, and end your turn) only if: a check still fails after 3 fix-loop iterations; a safety rule would have to be broken (scope gate, shell=True, secret in argv/log, push); a new dependency is the only way forward; real credentials or a real target would be needed; or a part's gate cannot be met honestly. Never fake a pass to avoid stopping.
A3. Context/limit safety: commit after every part. If you sense you are running low on context or time mid-part, commit what you have as `wip: <part> <what remains>`, make sure RESUME states precisely what is done and what remains, and end your turn. A new session will continue from RESUME.

=====================================================
GLOBAL PROTOCOL
=====================================================
G1. Start of every part: re-read AGENTS.md, the RESUME block, the last 3 REVIEW_LOG entries, the part's section of docs/MASTER_PLAN.md, and the docs it names. Read the Known pitfalls table at the top of docs/REVIEW_LOG.md before writing code, and check any new code against it. Set RESUME status "Part N: IN PROGRESS" before coding.
G2. Docs change first, then code. Every deviation goes into the report, PROGRESS "Deviations", and REVIEW_LOG.
G3. Not allowed unless a part explicitly says so: new dependencies; new modules/files/CLI commands not in docs/03 and docs/02 (apart from the 3 files authorized above); `assert` in src/; new lint or type suppressions (only scoped per-file ruff ignores with a reason in pyproject); shell=True; adapters importing store/scope/ui/cli; passing the whole environment to a child process; a scope-bypass flag (never add anything like --i-have-permission); consensus logic outside engine.py; a push.
G4. External tool flags and JSON fields come from the real `--help` or a real sample. If the tool is not installed, fetch the official README/docs (network works), implement from that, name any non-real fixture `*.synthetic.*`, and list it under Open risks. Never guess a flag.
G5. Test quality: assert concrete values and specific error status+message, never just "no exception"; no real network, no real subprocess, no real sleep over 0.1 s (inject resolver/transport/runner/clock/sleep/rng); use tmp_path only; tests independent of order; no test writes into the repo tree.
G6. One commit per part (`feat:`/`fix:`/`docs:`). REVIEW_LOG and PROGRESS updates go in the SAME commit as the code. A commit cannot contain its own hash: fill the previous part's hash in the next commit; never write HEAD in the task table.
G7. PROGRESS.md stays short (task table with real hashes, Deviations, Open risks, Notes for later tasks, RESUME block; under 150 lines). Detail goes to REVIEW_LOG.

=====================================================
REGRESSION AND PITFALLS RULES
=====================================================
R1. Every bug fix adds a guarding test named `test_regression_<short_slug>` or containing a docstring that starts `Regression: <PIT-ID>`. Show it FAILING before the fix (record the raw output in REVIEW_LOG), then passing after the fix.
R2. Add the pitfall row to the table at the top of docs/REVIEW_LOG.md in the SAME commit as the fix. A fix without a test is not allowed. If a bug truly cannot be tested (for example it needs real Linux), say why, add it to "Not verified", and mark the row UNTESTED.
R3. Non-code problems (environment, tooling, platform, flaky tests, external API behavior) also get a row; the Guarding test column may be `n/a` with the reason, so the next session does not rediscover it.
R4. Session start (G1) reads the Known pitfalls table. The pre-commit hook warns when the most recent commit subject starts `fix:` and the commit changes no file under `tests/`. The S7 report includes `Pitfalls added this part: <IDs or none>`.
R5. Back-fill: every bug already fixed in d03a231, e40091d, 80ddd93, the Part 3-AUDIT or later must have a `test_regression_*`/`Regression:` guard. If missing, add it (mutation first) in the addendum or the next `fix:` commit and fill its row.

=====================================================
SELF-REVIEW LOOP (mandatory after EVERY part, before moving on)
=====================================================
S1. CHECKS: run the four checks (`pytest -q`, `ruff check .`, `ruff format --check .`, `mypy src/reconkit`) and paste/record the raw output; run pytest a SECOND time to catch flaky and order-dependent tests (also `pytest -p no:randomly` is not needed; just run twice).
S2. READ YOUR OWN DIFF: run `git diff HEAD~1 --stat` and read `git diff HEAD~1 -- src` line by line. In REVIEW_LOG list: every broad except and why; every external input and where it is validated; every place a secret could reach a log, error, argv, URL or file; every blocking call inside async code; every exception that could escape an adapter or the engine; every unfinished path. If a list is empty, say how you checked.
S3. SCANS (bash grep; record raw output in REVIEW_LOG):
  grep -rn --include=*.py -E '\bassert\b' src                                   # expect none
  grep -rn --include=*.py -E 'shell\s*=\s*True' src                             # expect none
  grep -rn --include=*.py -E 'TODO|FIXME|XXX|HACK' src                            # expect none
  grep -rn --include=*.py -F 'print(' src                                         # expect only ui.py
  grep -rn --include=*.py -F 'subprocess' src                                     # expect only runner.py
  grep -rn --include=*.py -F 'sqlite3' src                                        # expect only store.py
  grep -rn --include=*.py -F 'os.environ' src                                     # justify each; adapters none
  grep -rn --include=*.py -E 'except\s*:|except Exception|except BaseException' src # justify each
  grep -rn --include=*.py -E 'noqa|type:\s*ignore' src tests                      # compare with the baseline; no new ones
  grep -rn --include=*.py -E 'import (store|scope|ui|cli)|from reconkit\.(core\.store|core\.scope|ui|cli)' src/reconkit/adapters   # expect none
  Any unexpected hit is a bug (S6).
S4. REQUIREMENT -> TEST TABLE in REVIEW_LOG: every requirement bullet of the part with the exact test name proving it. A bullet without a test gets a test now.
S5. ADVERSARIAL + MUTATION: (a) every case in the part's ADVERSARIAL list plus at least 3 you invent gets a test, or a written reason it cannot happen. (b) For each of the part's MUTATION targets: deliberately break the code, run only the related tests, record the FAILING output, restore with `git checkout -- <file>`, and record `git status --short` showing a clean tree. A test that does not fail on the broken code is worthless: rewrite it.
S6. FIX LOOP for every bug: write a test that reproduces it and confirm it FAILS; fix; confirm it passes; re-run S1-S3; record in REVIEW_LOG "Bugs found" (symptom, root cause, fix, guarding test). Bugs found before the part commit go into that commit; later ones into a `fix:` commit. Max 3 iterations, then A2.
S7. RECORD: append the REVIEW_LOG entry, update the PROGRESS table and RESUME block, then print a short REPORT in chat (part, hash, checks result, bugs found/fixed, decisions for user review, not verified, and "Pitfalls added this part: <IDs or none>").
GATE: move to the next part ONLY if: the four checks pass twice; scans clean or justified; every requirement has a test; mutation proofs recorded; no open bug. Otherwise fix (S6) or A2.

REVIEW_LOG ENTRY TEMPLATE (one per part):
  ## Part N: <title>  (commit subject; hash filled by next commit)
  - Docs read / goal:
  - Decisions and assumptions:
  - Decisions for user review (things the user may want to overrule):
  - Docs changed first:
  - Deviations:
  - Files touched:
  - Requirement -> test table:
  - Self-review findings (S2 lists, S3 raw output):
  - Bugs found: symptom / root cause / fix / guarding test
  - Mutation proofs: behavior / failing test / restored clean (yes/no)
  - Raw check output (last lines of the four checks, pytest run twice):
  - Not verified (needs real network, Linux, installed tools):
  - Next part must know:

RESUME BLOCK (top of docs/PROGRESS.md, max 25 lines, rewrite after every part):
  RESUME HERE
  - Status: Part N done | Part N IN PROGRESS | BLOCKED (reason) | ALL DONE
  - Last code commit: (run `git log --oneline -1`; never trust this line alone)
  - Baseline: tests passed/skipped at last green
  - Next action: the exact first step for the next session
  - Already decided, do not reopen: no --i-have-permission or any scope-bypass flag; consensus lives in engine.py (no core/consensus.py); adapters never import store/scope/ui/cli; subjack replaced by subzy + nuclei takeover templates; installer targets Debian-family Linux only; free mode is default, keys only from .env; no push unless the user says so
  - Do NOT: the G3 list
  - Known open bugs: (list or none)
  - Read first: AGENTS.md, this block, last 3 REVIEW_LOG entries, current part in docs/MASTER_PLAN.md

=====================================================
PART 0: baseline (commit `docs:`)
=====================================================
0a. Record raw in REVIEW_LOG: `git status --short`, `git log --oneline -8`, `git ls-remote reconkit main`, `find tests/fixtures -type f | sort`, and `git check-ignore -v .env` (if .env is not ignored, add it to .gitignore). Confirm `.tmpfetch` is gone (delete if present and untracked).
0b. Baseline: run the four checks and all S3 scans; record counts (tests passed/skipped, existing noqa/type-ignore count).
0c. Add a retroactive REVIEW_LOG entry for f1 (89ba34f): known unverified: OTX fixture is synthetic, key env names unverified, domain filtering happens in run(), hook is weak.
0d. Run the loop (S1, S3, S7 only).

=====================================================
PART 1: fixes (commit `fix:`)
=====================================================
1a. store.py: upsert_port resets `confidence` (default "LOW") and upsert_url resets `source_count` (default 0) on conflict. Fix with the same pattern as upsert_subdomain: params `| None = None`, INSERT uses COALESCE(:x, schema default), conflict update uses COALESCE(:x, table.x). Audit EVERY upsert_*/add_* method for any other defaulted column a conflict overwrites; record the methods/columns checked.
1b. HTTP body cap: docs/09 one line first. HttpAdapter streams the body up to MAX_BODY_BYTES (10 MiB). Over the cap returns a failed ToolResult "response too large"; no exception escapes; the connection is closed.
1c. hackertarget: an HTTP 200 body containing "API count exceeded" (case-insensitive) returns a failed result "free quota exceeded". Other non-row text stays "unexpected response".
1d. PROGRESS: f1 row hash 89ba34f. Add to "Notes for task g": (a) a discovered host with no probe result keeps schema default UNKNOWN, and only live/DNS stages append host_status_history rows; (b) the engine builds one RateLimiter per stage; (c) the engine passes each tool ONLY the env names listed in that tool's `keys` in tools.yaml; (d) when a tool fails "rate limited" and has unset keys, the UI hints at the free key; (e) the registry reloads tools.yaml per call, so the engine loads specs once; (f) store needs a transaction()/batch helper when the engine writes many rows.
Tests: second upsert with None keeps the value; explicit value overwrites; fresh insert gets defaults; oversize body fails; hackertarget quota vs unexpected text.
ADVERSARIAL: explicit 0 / empty string must overwrite (None means keep, 0 does not); body exactly at cap passes and cap+1 fails; chunked body without Content-Length still capped; Content-Length that lies; quota text in different case; upserts on a row that does not exist yet.
MUTATION targets: COALESCE on conflict, the body cap check, quota detection.

=====================================================
PART 2: API-key policy (commit `docs:`/`feat:`)
=====================================================
Docs first, in the existing security doc (say which); cross-reference docs/02, docs/09, docs/10; no new doc files.
1. Free mode is the default; every core tool works with zero keys.
2. Keys come only from `.env`: never CLI flags, never logged, never in URLs; redact() covers them. Enhanced mode turns on per tool when its key is set.
3. Only keys free to obtain are supported. A tool whose only key is paid gets no key support.
4. `doctor` always shows a Keys table (tool, set/missing, what it adds, sign-up URL). `--no-keys` forces free mode (add to docs/02 flag list; implemented in Part 9). `install` on an interactive TTY asks once "free only, or add keys?"; choosing keys copies .env.example to .env (never overwrites) and prints the path and table. Non-TTY, --silent and --json never prompt and default to free. (Implemented in Part 10.)
5. tools.yaml: optional `keys:` list per tool, entries {env, url, adds}; no entry means no keys. ToolSpec gains `keys`; validation: env matches ^[A-Z][A-Z0-9_]*$, url is https, adds is non-empty text; a malformed entry raises ConfigError.
Fill `keys:` for certspotter, otx, subfinder (provider sources with a free tier), assetfinder (exact env var names) from OFFICIAL docs fetched now, not memory. Record each source URL and fetch date in a PROGRESS "Key sources" line. If you cannot verify a key is free or its env name, omit it and list it under Open risks. Update .env.example (values empty; if missing, report instead of creating). No new adapter behavior beyond reading env names the code already reads.
Tests: registry parses keys; each malformed variant raises ConfigError; every `keys` env name appears in .env.example; .env.example has no non-empty values.
ADVERSARIAL: lowercase env; http:// url; missing `adds`; `keys` not a list; duplicate env within one tool; same env shared by two tools (allowed, confirm); `keys: []`.
MUTATION targets: https check, env regex, .env.example coverage test.

=====================================================
PART 3: pure-Python adapters dnspython, pyprobe, pyscan (commit `feat:`)
=====================================================
Task table: f2 = dnspython, pyprobe, pyscan; f3 = every other phase-2 tool in tools.yaml. Compare tools.yaml with docs/03 and record any mismatch.
Before code: quote the docs/09 lines on how a per-host adapter receives input hosts/ports (RunContext has only `target`). If silent, make the smallest docs/09 change first (for example a typed `inputs` field on RunContext), list it under Deviations. Name the record models used; if a field is missing, docs first.
- All three subclass BaseToolAdapter (kind python). Scope gating stays in the engine; adapters only touch hosts/ports they are given.
- Never block the event loop. Inject resolver, connection opener, sleep. Await ctx.limiter.wait() before each query/connection.
- dnspython: dns.asyncresolver with explicit lifetime/timeout. NXDOMAIN, no-answer, SERVFAIL/NoNameservers and timeout are DISTINCT outcomes. A timeout or SERVFAIL must NEVER be reported as NXDOMAIN (false DEAD). Record types per docs/09.
- pyprobe: httpx.AsyncClient, honest User-Agent, follow_redirects=False (record status and Location), capped body read, title from at most the first 256 KiB, TLS errors returned as a result.
- pyscan: TCP connect only, no payloads; optional banner read short and capped; concurrency bounded by pacer.parallel_limit(mode); port order from pacer.order(..., "port") (state per docs whether adapter or engine calls it).
- Mock mode reads fixtures; non-real fixtures are named *.synthetic.* and listed under Open risks.
Tests: normal, empty, NXDOMAIN vs no-answer vs SERVFAIL vs timeout (four distinct asserts), redirect not followed, oversized body, TLS error, connection refused vs timeout, limiter awaited, mock mode, AST import check.
ADVERSARIAL: uppercase/IDN host; empty inputs; CNAME loop or long chain; resolver raising an unexpected exception type (must become a failed result); Location to an out-of-scope host (recorded, not followed); title with bad encoding/entities/missing/huge; duplicate and out-of-range ports (0, 65536, negative); banner with binary bytes; max concurrent connections never exceeds parallel_limit; cancellation closes connections.
MUTATION targets: timeout->NXDOMAIN mapping, follow_redirects flag, concurrency bound.

=====================================================
PART 4: binary adapters f3 (commit `feat:`)
=====================================================
Implement an adapter for every remaining phase-2 tool in tools.yaml using BaseToolAdapter + run_exec. For each tool:
- check_installed verifies IDENTITY, not just presence on PATH. ProjectDiscovery `httpx` can collide with the Python httpx CLI; check `-version` output; document how.
- build_command returns a list (no shell). Rate flags come from tool_rate_args via the registry. Every host/target passes validate_host first, and a value starting with "-" must never reach argv as a possible flag (reject it or use the tool's documented separator; test it).
- Never put a key in argv. If a tool needs a key (subfinder), write a temporary provider-config file from the allowed env names with restrictive permissions, delete it in a finally block (also on timeout and exception), never log its content.
- parse_output tested against real or documented sample output; malformed output returns a failed result, never an exception. Non-zero exit, timeout and a binary that cannot be spawned at run time are distinct `failed`/`timeout` results with different messages; a binary that is absent at selection time is `skipped` and never runs (docs/03 section 13, docs/09 selection rules).
- Opt-in tools (masscan) obey tiers from tools.yaml: hard-capped rates; build_command refuses rates above the cap; the run gate itself lives in the engine.
- `rustscan` and `nmap` are `tier: core` but `phase: 3`: they install and run by default once their adapters land. `phase` is build tracking only (the engine reports "no adapter yet (phase N)"), never a security gate.
Tests use a fake run_exec: argv construction, rate-flag injection per speed preset, parse normal/empty/malformed, not-installed, wrong-binary identity, timeout, non-zero exit with partial output, AST import check, no secret value in argv/result/error, temp key file deleted after success AND failure.
ADVERSARIAL: host "-oN /tmp/x" or "--script=..." values; ANSI codes in output; duplicate lines; stderr noise mixed with stdout; huge output (runner truncation flag honored); exit 0 with empty output vs non-zero with partial output; identical hosts twice; uppercase hosts.
MUTATION targets: key-not-in-argv, identity check, rate-cap refusal.
End with a table in REVIEW_LOG: every tool in tools.yaml, stage, tier, adapter yes/no. Every stage should have 3-8 tools; if one falls short (possibly impossible before Phase 3), log it; do not invent tools.

=====================================================
PART 5: core/wildcard.py + core/workspace.py (commit `feat:`)
=====================================================
Docs first: quote docs/03 and docs/04 for both modules.
- wildcard: detect wildcard DNS per root domain by resolving N random labels via the injected resolver (reuse the dnspython adapter logic, not a second resolver stack; rng injected). Return the wildcard IP set; hosts resolving only to wildcard IPs get is_wildcard. A resolver timeout must not be read silently as "no wildcard": return an explicit unknown state for the engine to warn about.
- workspace: create `workspaces/<domain>/` per docs; safe path joining (reject traversal; domain validated with validate_target); atomic writes (temp file then replace); ALL raw tool output goes through store.redact() before touching disk. Layout names from docs only.
Tests: wildcard yes/no/unknown(timeout), partial wildcard, traversal rejected, redaction applied to saved output, atomic write leaves no partial file on failure.
ADVERSARIAL: labels where some resolve and some NXDOMAIN; CNAME wildcard; `..`, absolute paths, `C:\`, UNC paths, trailing dot/space; two secrets in one output; empty output; very large output; same filename written twice.
MUTATION targets: traversal check, redact call, unknown-vs-no-wildcard.

=====================================================
PART 6a: engine skeleton, gating, mock pipeline (commit `feat:`)
=====================================================
Docs first: quote the stage pipeline, confidence rules, host-state rules and exit codes from docs/01-04, 06, 09. If conflicting or silent, apply A1 and log it.
- Stage order: subs -> dns -> live -> ports -> tech -> urls -> js/vulns per docs. Each stage: pacer.reset(), a fresh RateLimiter, tool selection from tools.yaml via --tools/--exclude/tier/--include-noisy, sequential in slow mode and bounded parallel otherwise per pacer.parallel_limit, random pause between tools per the pacer, --phase-timeout per stage, a tool_runs row per tool with redacted error. Load specs once.
- Safety gate: active tools run ONLY with --active AND scope check_target passing (in_scope match, no out_of_scope match). Passive by default. Discovered hosts pass validate_host and scope BEFORE any active contact. Out-of-scope hosts are recorded and skipped, never probed. A disallowed tool must not even have its command built.
- Env: each tool gets only the env names in its `keys`; with --no-keys none.
- store.transaction()/batch helper with tests (docs/04 first), used for bulk writes.
- `--mock`: the whole pipeline runs from fixtures with no network and no subprocess.
Tests with fakes: stage order, tier gating, scope gating (active without --active; out-of-scope host skipped; in-scope CNAME pointing out of scope), env filtering, one tool crashing while others succeed, all tools failing, unknown/intrusive tool in --tools refused, phase timeout, redaction of stored errors.
MUTATION targets: scope gate, env filtering, tier gate.

=====================================================
PART 6b: consensus, host states, resume, exit codes (commit `feat:`)
=====================================================
- Consensus: HIGH >=3 DISTINCT tools, MEDIUM =2, LOW =1, UNCONFIRMED when scanners disagree, per docs. Honor --min-sources. Computed in engine.py.
- Host states: ALIVE, DNS_ONLY, SHUT_DOWN (previously ALIVE/DNS_ONLY, now failing; flag dangling CNAME), DEAD (NXDOMAIN only), UNKNOWN (not yet probed). DNS timeout/SERVFAIL never produce DEAD; they keep the previous state and record a warning. host_status_history rows only from live/DNS stages. Wildcard hosts per Part 5 (unknown wildcard state -> warning).
- Resume: a scan_run resumes completed stages without duplicate rows; same-kind diff rule respected.
- Store used only on the event-loop thread.
- Exit codes exactly as docs/02.
- Cancellation (Ctrl-C / CancelledError): scan_run finishes as interrupted, no half-written rows, no leftover temp key files.
Tests: confidence thresholds; same tool twice counts once; UNCONFIRMED; each host-state transition (first run, ALIVE->timeout keeps ALIVE, ALIVE->failing SHUT_DOWN, DEAD->ALIVE, unprobed stays UNKNOWN); timeout-not-DEAD; resume without duplicates; cancellation; exit codes.
MUTATION targets: timeout-not-DEAD, distinct-tools confidence, exit-code mapping.
GATE EXTRA: record in REVIEW_LOG the raw output of an end-to-end engine mock run (a test or temporary script that you delete; no new CLI command yet): stages executed, per-host confidence and state, db row counts. If it cannot run, A2.

=====================================================
PART 7: ui.py (commit `feat:`)
=====================================================
Per docs/02: Rich tables/progress to STDERR; data to STDOUT only in --json mode as ONE valid JSON document; --silent/-q suppresses everything except errors and requested data; no color when not a TTY or NO_COLOR is set. Banner/legend text from docs/02 only. UI functions take plain data and never import store, scope or adapters. Include the rate-limited-without-key hint (Part 1 notes).
Tests with a captured console: stdout parses as JSON in --json mode; stderr holds the tables; silent mode; no-TTY output has no ANSI; NO_COLOR honored; no secret value appears; hint shown only when the key is unset.
ADVERSARIAL: unicode and very wide hostnames; empty result sets; Rich markup injection (hostname "[red]x[/]" prints literally); a rendering exception must not lose data in --json mode.
MUTATION targets: JSON purity, markup escaping, silent mode.

=====================================================
PART 8: cli.py (commit `feat:`)
=====================================================
Only commands and flags in docs/02: `-d`, `-l`, `--json`, `--silent/-q`, `--min-sources`, `--tools`, `--exclude`, `--include-noisy`, `--phase-timeout`, `--mock`, `--speed slow|normal|fast` (default slow), `--delay MIN-MAX`, `--active`, `--no-keys`, plus every command listed there (doctor, install, update, diff, etc.). Map ConfigError, ScopeError and ValueError from validate_target/check_target to the documented exit code (usage errors exit 2, never a traceback). Read queries needed by diff/status go into store with tests (docs/04 first). install/update/doctor remain stubs that call Part 9 functions until Part 9 exists, unless docs/02 says otherwise.
Tests with Typer CliRunner: --help for every command; bad domain exit code; bad --delay (reversed, negative, non-numeric); invalid --speed; --active without a scope match refused; --mock end to end writing recon.db and workspace into tmp_path; --json output valid; -l file input (blank lines, comments, duplicates, bad entries); diff after two mock runs; no traceback text in any error output.
ADVERSARIAL: domain with scheme or path; uppercase; trailing dot; -d and -l together; empty -l file; missing -l file; --tools with unknown name; --exclude of everything; running from a different cwd.
MUTATION targets: exit-code mapping, --active gating, --delay validation.
GATE EXTRA: record raw `reconkit -d example.com --mock --json` (first 40 lines) and `reconkit diff` after two runs in REVIEW_LOG.

=====================================================
PART 9: (reserved) fix backlog (commit `fix:`)
=====================================================
Re-read REVIEW_LOG "Bugs found", "Decisions for user review" and "Not verified" for Parts 1-8. Fix any bug still open or any decision that is unsafe. If none, record "nothing to fix" with the evidence you used and skip the commit.

=====================================================
PART 10: installer/ + doctor.py (commit `feat:`)
=====================================================
Status: CLOSED (2026-11-14). Decisive items: `5df7e98` (children stay in the parent's session so a cached `sudo -v` ticket is visible) and `9c4319b` (apt tools with no version flag report dpkg's version); live fresh `massdns` install recorded in REVIEW_LOG.
Docs/10 first. DECISION (log under Deviations): the installer targets Debian-family Linux (Kali/Ubuntu) and refuses to run on any other platform with a clear message and a documented nonzero exit code; it never tries a foreign package manager. Write this into docs/10.
- Prerequisites: libpcap-dev, jq, dnsutils, Go and Go bin in PATH, pipx/pip for Python tools. Verify package names for Kali AND Ubuntu from official package pages before writing them; cite URLs and dates in PROGRESS. Use `python3` >= 3.11, never a pinned apt python.
- Every install command is an argv list via the runner (shell=False). Never pipe curl into a shell. sudo only when not root and only for apt, announced before running. Go tools via `go install <module>@<version policy from docs>`; pin or justify.
- `install --all`, `update --all`, per-tool install; idempotent; one failing tool does not stop the rest; final summary table; exit code per docs.
- Keys flow from Part 2 (interactive TTY question, .env.example copy without overwrite, Keys table). Non-TTY/--silent/--json never prompt. Wire `--no-keys` end to end.
- doctor: tool table (installed, version, identity verified, tier), prerequisites, Keys table, scope.yaml presence, Python version, DB writable, config/wordlist presence per docs; `--json` supported. Replace the Part 8 stubs.
Tests use an injected runner and platform probe; NOTHING really installs: already-installed skipped; failure isolated; non-TTY no prompt; .env never overwritten; doctor JSON valid; every argv is a list of strings with no shell metacharacters; sudo only for apt; root gets no sudo.
ADVERSARIAL: apt succeeds but the binary is still missing; unparsable version string; wrong binary on PATH; .env exists but empty; .env.example missing; second `install` changes nothing; Ctrl-C mid-install.
MUTATION targets: no-overwrite of .env, failure isolation.

=====================================================
PART 11: docs sync, README, final audit (commit `docs:`)
=====================================================
11a. README.md and SETUP.md for the single Linux checkout (Kali/Ubuntu, native): beginner steps for `--mock`/passive use and for the full tool set. Fix hard-coded paths.
11b. Docs 01-10 must match the code. List in REVIEW_LOG every change and every remaining disagreement.
11c. FRESH-EYES AUDIT: re-read the whole src tree as if reviewing someone else's pull request. Specifically hunt for: any code path where an active tool can run without --active + scope pass; any place a DNS/HTTP timeout can become DEAD/SHUT_DOWN; any secret reaching argv/log/db/workspace/UI; any exception that escapes to a traceback in the CLI; any blocking call in async code; confidence computed from non-distinct tools; any docs/code mismatch. Write a test for each finding, fix, and log under "Bugs found". Also run every S3 scan one final time.
11c-bis. Run the end-to-end mock run from a fresh venv (`python -m venv` in a temp dir, documented install command, `reconkit --help`, `reconkit doctor`, `reconkit -d example.com --mock --json`) and record raw output.
11d. PROGRESS: task table complete with real hashes, Deviations, Open risks (carry forward: scope.yaml cannot exclude CIDRs unless fixed; per-call commits slow unless the batch helper solved it; weak pre-commit hook; kill-tree path unverified on Linux; synthetic fixtures; unverified tool JSON fields; key sources unverified items).
11e. Set RESUME status to "ALL DONE" with the exact commands the user must run on Kali/Ubuntu to verify what could not be verified here (real network, installed tools, killpg path).
11f. Print a FINAL REPORT in chat: what is verified (with pointers to REVIEW_LOG sections), what is NOT verified, all "Decisions for user review", and the git state (`git status --short`, `git log --oneline -25`, `git ls-remote reconkit main`). Then STOP. Do not push.

=====================================================
PART 12: evidence, secrets and loop hygiene (commit `fix:`/`docs:` per item)
=====================================================
Status: **PLANNED 2026-11-14, RULINGS RECORDED, NO ITEM STARTED.** The owner
approved this section and ruled on its seven decision items on 2026-11-14 (each
item now carries a `DECIDED` line); implementation starts with 12a and is not
part of this commit. The owner may still reorder, drop or re-scope any item.

Goal: close the evidence and hygiene backlog that Part 11 deferred, and record
the owner's rulings on the product questions around the ports-stage capability
(12i) and the exit-code semantics of an empty stage (12k). Every item already
has a written ticket in `docs/PROGRESS.md` ("Open risks", "11c consolidated findings",
"11d-findings-*"); this part is the order in which they get fixed, plus the
decisions that must be taken before any of that code is written.

Docs read first (before any item): `docs/04_DATABASE.md` (sections 3-6 - any
column, migration and diff rule), `docs/03_ARCHITECTURE.md` (sections 5, 7, 13 -
layers, pacing, event loop), `docs/05_SECURITY.md` (rules 6 and 8, section 6.1 -
secrets, IP gate, key handling), `docs/06_CODE_STYLE.md` (section 6 - exception
vocabulary), `docs/09_TOOL_CONTRACTS.md` (sections 3-5 - adapter contract,
selection rules, confidence), `docs/02_CLI_UX.md` (sections 5-6 - JSON shape and
exit codes), `docs/10_TOOL_INSTALLER.md` (section 5a - doctor/version display),
`tools.yaml`, `config.yaml`, and the REVIEW_LOG sections "Part 11c - fresh-eyes
audit", "Part 11 close-out - rulings", "Bug-fix session", "Rule decision - diff
GONE needs two consecutive misses" and "Real-tool verification session 2".

Order: **12a first** (owner ruling 2026-11-14: raw-output-on-disk makes every
later item easier to debug and verify), then the remaining items in the order
the implementer chooses, respecting the dependency notes below (items that touch
the same files). One item per commit; each item runs the full self-review loop
(S1-S7) before the next starts, and the owner is told after each item. A
renumbering is not allowed: reference these IDs in REVIEW_LOG.

DECISIONS (owner or docs-first) vs ASSUMPTIONS (this plan):
- 12i (ports capability) is **decided**: option (c), an accepted permanent
  ceiling. Do not pursue (a) or (b).
- 12a, 12c, 12d, 12f, 12g and 12k are **decided** by the owner on 2026-11-14;
  their `DECIDED` lines are the specification for the code.
- Assumed: no new dependencies (G3), no scope-bypass path, adapters stay free of
  store/scope/ui/cli imports, and a schema change means docs/04 plus a migration
  and a `schema_version` bump in the same commit.
- Assumed: "the owner approves" means the text of this section is accepted as
  written or amended in chat; a later session must not treat this section as
  self-approval.

12a. G-1 - raw tool output is never written (high, code + docs, cross-cutting)
  What: `Workspace.write` (`core/workspace.py`) has no callers and
  `ToolResult.raw_path` is never set, while docs/03 section 5 step 9 and section
  3 promise a raw output file per tool. Every parse bug so far (pyprobe TLS,
  certspotter empties, HackerTarget quota) had to be reproduced with a scratch
  script because the run kept no bytes.
  DECIDED (owner, 2026-11-14): **wire it.** Capture stdout+stderr for every
  adapter run, including failed tools, write to the existing raw-output files,
  capped by the existing `max_output_bytes` limit. No new flags, no new config.
  Size: cross-cutting - `models.ToolResult`, `adapters/base.py` (both base
  classes), the four python adapters, `engine._run_one`, `core/workspace.py`,
  docs/03, and `ui` only if `raw_path` becomes visible.
  Tests: a mock run writes exactly one redacted file per executed tool and sets
  `raw_path`; a failing/timed-out tool still writes its partial output; a secret
  in tool output never reaches the file (extend the PIT-22 test to a real
  adapter result); path containment unchanged.
  Adversarial: tool output containing a token, an ANSI escape, NUL bytes, a
  filename that collides across two tools in one stage, a workspace write that
  raises (the run must still record the tool result).
  Mutation targets: drop the redaction call; set `raw_path` before the write
  succeeds; skip the write on failure.

12b. 11d-findings-b - the DNS stage invents discovery rows (medium, code + docs, medium)
  What: `_persist_dns` and `_previous_facts` INSERT `subdomains` rows for hosts
  discovery never returned, so `first_seen_run` points at a `dns` run, there is
  no `subdomain_sources` row, and `diff_new`/`--new-only` can report a host as
  new that was never discovered. Reproduced offline (`alias.example.com`,
  `DNS_ONLY`, `sources: []`).
  Ruling already recorded (Part 11 close-out): keep the row, mark its provenance
  `dns`, and exclude it from `diff_new` and discovery counts.
  Size: medium - one migration (`subdomains.provenance` or equivalent, docs/04
  first), the two engine call sites, `diff_new`, `host_rows`/JSON `sources`, and
  the docs/04 section 5 rule.
  Tests: a resolved host discovery never returned is stored with `dns`
  provenance and is NOT `NEW`; a discovered host keeps `subs` provenance; a host
  first seen in `dns` then discovered in `subs` upgrades its provenance and is
  `NEW` at that later run; existing apex fixture unchanged in state.
  Adversarial: host resolved by DNS and discovered by no tool across many runs;
  provenance upgrade ordering; resume across the migration boundary.
  Mutation targets: drop the provenance filter in `diff_new`; write `subs` for
  the DNS-only path.

12c. 11d-findings-c - `duration_s` is 0.0 for real work (low, code + docs, small)
  What: three writers disagree - `HttpAdapter.run` omits it on the parse-error
  and fetch-failure branches, `DnsPythonAdapter.run` never sets it, and
  `Engine._run_one` discards its own measurement on the success path. Observed
  again in session 2: `dnspython ok 36 0.0`, `pyprobe ok 8 0.0`, `otx failed 0.0`
  next to a real 429.
  DECIDED (owner, 2026-11-14): the adapter measures its own work and reports
  `duration_s` when it can; `_run_one` only fills in a measured value when the
  adapter did not provide one. Adapter-reported time takes priority over
  harness-measured time.
  Size: small - `adapters/base.py`, `adapters/dnspython.py`,
  `engine._run_one`, docs/04.
  Tests: a 429 stores `> 0`; a parse error stores `> 0`; a successful
  `dnspython` stores `> 0`; a timeout keeps the duration `_run_one` already
  measures; no double counting when both would fill it (assert the adapter
  value wins, or the documented one).
  Adversarial: clock that returns the same instant (must still store `0.0`
  rather than a negative); adapter raising after measuring.
  Mutation targets: discard the adapter measurement; overwrite a non-zero
  adapter value with `_run_one`'s.

12d. 11d-findings-f (remaining half) - an UNKNOWN host carries no reason (low-medium, code + docs, cross-cutting)
  What: the short-circuit bug is fixed (PIT-37); what remains is that a host
  recorded `UNKNOWN` because no scheme answered still stores no cause, so
  "expired certificate / untrusted CA / handshake rejected / incomplete CA
  store" cannot be told apart without probing again. The TLS text is classified
  by substring and discarded.
  DECIDED (owner, 2026-11-14): store a bounded, redacted detail string on
  `host_status_history` (not a new field on `tool_runs`). Visible via `--json`
  and direct DB query. Not required to show in the default human-readable table.
  Size: cross-cutting - `models.HostStatusRecord`, `pyprobe`, `engine`
  (`_persist`/`_write_host`), `store` (migration), docs/04, optionally `ui`.
  Tests: a TLS-only failure stores the reason; a plain connect failure stores
  none; a long reason is truncated; a reason containing a configured secret is
  redacted before it reaches the DB; schema migration is additive on an existing
  v2 database.
  Adversarial: exception text with a newline or a URL containing a query secret;
  reason on a host that later becomes ALIVE (must not resurrect).
  Mutation targets: drop the truncation; store the unredacted text.

12e. 11d-findings-g - an inconclusive live pass writes no history row (medium, code + docs, small)
  What: `decide_host_state` sets `persist = previous is not None` for
  inconclusive evidence and `_persist` skips the write, so a first run that did
  contact a host leaves no `host_status_history` row, which is indistinguishable
  from a run that never touched it. docs/04 section 5 promises one row per host
  per status pass with a `dns`-stage exemption only.
  DECIDED (owner, 2026-11-15): persist the row with state `UNKNOWN` when a probe
  was attempted - a live-stage tool returned a record for that host - and keep
  the existing "no evidence" skip when nothing was attempted. Implemented and
  committed (`3a20679`).
  Size: small - `engine.decide_host_state`/`_persist`, docs/04.
  Tests: an inconclusive first pass writes one UNKNOWN row; the second
  consecutive NXDOMAIN rule still holds; a host with no probe attempt writes
  nothing; existing PIT-29 CNAME tests stay green.
  Adversarial: timeout then success; timeout on a host whose previous state was
  ALIVE (must keep ALIVE and still write the attempted pass).
  Mutation targets: persist on every pass including "no attempt"; skip the row
  on inconclusive evidence.

12f. C-1 - unredacted exception text on the last-resort path (medium, decision + code, small)
  What: `cli.py`'s last-resort handler formats raw `str(exc)`, and `-v` prints a
  traceback; `cli.py` imports no `redact` and has no secret source, so an
  escaping exception could print a key if one ever appeared in an exception
  message. No reachable leak has been demonstrated (keys travel in headers, not
  URLs).
  DECIDED (owner, 2026-11-14): add `configure_redaction()`, sourced from the
  already-loaded env (same source as existing redaction config), applied in both
  the `_report_error` path and the `-v` traceback path. No new env vars invented.
  Size: small code, but it is an architecture decision; touches `cli.py`,
  `core/store.redact` (or a new helper in an existing module - no new file),
  docs/03 and docs/05.
  Tests: an exception whose message contains a configured key is printed
  redacted, with and without `-v`; a message with no secret is unchanged; the
  traceback path redacts too.
  Adversarial: key substring inside a longer token; exception raised before the
  env is loaded; `--json` error path.
  Mutation targets: remove the redaction call from `_report_error`; forget the
  `-v` branch.

12g. C-2 - a SIGKILL can strand the subfinder provider file (low, decision + code, small)
  What: the adapter writes `provider-config.yaml` with `mkstemp` in the system
  temp dir (0600) and deletes it in `finally`; a `SIGKILL` in between leaves a
  key file. `finally` is the mitigation today.
  DECIDED (owner, 2026-11-14): per-run directory created with mode 0700, plus
  startup cleanup of stale directories from prior killed runs. Do not use
  memfd/O_TMPFILE. Do not accept-the-risk.
  Size: small (one adapter + docs/09 + a cleanup step), no schema change.
  Tests: a run leaves no provider file; a stale file from a previous run is
  removed on the next start; the file is
  never in argv except as a path.
  Adversarial: two concurrent runs (must not cleanse each other's live file);
  crash between mkdir and write.
  Mutation targets: skip the cleanup; widen the directory mode.

12h. E-1/E-2/E-3 - blocking calls on the event loop (low, code, medium, ordering risk)
  What: the SQLite transaction and `_persist_stage` run on the event loop
  (`engine.py`), `load_scope()` reads and parses YAML inside async
  `_active_hosts`, and `Workspace.create` mkdirs/chmods inside `async def run`.
  None causes a wrong result; together they can stall other stages' I/O.
  DECIDED (owner, 2026-11-15): move the `scope.yaml` read and the workspace
  mkdir/chmod behind `asyncio.to_thread`; leave the SQLite persistence block on
  the event loop with the reason written down in docs/03 (single-writer SQLite
  ordering, `check_same_thread` safety). Implemented and committed (`77fd36d`).
  Size: medium - `engine.run`/`_active_hosts`/`_persist_stage`, plus tests that
  assert ordering did not change.
  Tests: a scope file read that sleeps does not block a concurrent heartbeat
  task (injected slow read); persistence ordering across two stages is
  unchanged; resume still seeds before the first stage.
  Adversarial: cancellation during a `to_thread` call; a scope error raised
  inside the thread; two targets in one CLI invocation.
  Mutation targets: move the transaction back onto the loop (ordering test must
  catch it) - or, if the transaction stays, remove the documented reason.

12i. Ports capability: `naabu` is permanently blocked and confidence cannot pass LOW (medium capability gap, DECIDED - accepted ceiling, docs only)
  What: `naabu` is skipped at selection time because it resolves hostnames
  inside its own process, so docs/05 rule 6 cannot filter the address it
  connects to; every other ports adapter except `pyscan` is phase 3 with no
  adapter. With one selectable tool, ports confidence can only ever be LOW, and
  the open/closed disagreement rule needs two scanners.
  DECIDED (owner, 2026-11-14): Option (c) - leave ports stage permanently
  LOW-only / pyscan-only for this build. Do not pursue (a) pre-resolve redesign
  or (b) a second IP-connecting adapter. This is accepted as a permanent
  ceiling, not a temporary gap.
  Size: (a) large and cross-cutting; (b) one adapter; (c) docs only.
  Tests: (a) an IP outside `in_scope_cidrs` is never connected to by any port
  adapter and the hostname is never re-resolved inside the child (must be
  observable, not asserted from docs); (b) two port adapters produce MEDIUM on
  agreement and UNCONFIRMED on open/closed disagreement.
  Adversarial: (a) a host whose A record is inside and AAAA outside; (b) one
  adapter reports open and the other closed; both after a failed tool.
  Mutation targets: only after the owner picks an option.

12j. katana/nuclei version-line parsing (low, code + docs/10, small)
  What: `installed_version()` returns `text.splitlines()[0]`, so `katana` shows
  `__` and `nuclei` shows `[I...` in the doctor table, which also defeats
  `_same_version()` and makes `update` unable to call them up to date. The
  masscan half of the same audit is already fixed (PIT-35).
  DECIDED (owner, 2026-11-15): a per-tool `version_regex` field in `tools.yaml`
  (docs/10 section 3c); used when the tool defines one, with the existing
  `splitlines()[0]` behaviour kept as the fallback when the field is absent or
  finds no match. Implemented and committed (`b035a04`).
  Size: small - `installer/registry.py`, `installer/github_release.py`, docs/10,
  `tools.yaml` rows for the banner-first tools.
  Tests: katana and nuclei parse a real captured banner; masscan's nonzero-exit
  case still passes (PIT-35); a banner with no match falls back to the first
  line, not to `wrong program`; `_same_version` reports current for a matching
  parsed version.
  Adversarial: banner with ANSI colour; version line on line 3; two versions in
  the text.
  Mutation targets: fall back to `splitlines()[0]`; accept any substring match.

12k. Exit code for a stage that executed nothing (low-medium, DECISION + code, small)
  What: a stage whose pool has no adapter (or whose adapters were all skipped)
  executes zero tools, is recorded `completed`, and contributes nothing to the
  run's exit code. Session 2: `tech`/`urls`/`vulns` ran zero tools, `scan_runs`
  says `completed`, and exit 5 came from `otx` + `hackertarget`; a clean passive
  stage in the same shape would exit 0.
  DECIDED (owner, 2026-11-14): exit 5, with a warning that names the empty stage
  explicitly. Not silent 0, not the existing exit 4, not warning-only with exit
  0.
  Size: small - `engine._exit_code`, `ScanSummary.warnings`, docs/02 section 6.
  Tests: `run --active` with only passive adapters installed and a clean passive
  stage exits per the ruling and names the empty stages; a stage with a failed
  tool keeps its current code; a resumed run does not double-count.
  Adversarial: every stage empty; a stage empty because of `--tools` filtering
  (must not be treated the same as "no adapter exists"); scope-denied run.
  Mutation targets: after the ruling, remove the warning; make every skip count.

PART 12 ADVERSARIAL LIST (beyond each item's own): a schema migration applied to
a database written by 2026-11-14 code (v2, real `recon.db` copy) must be
additive and must pass `PRAGMA integrity_check`/`foreign_key_check`; a resumed
run across a migration; `--json` shape changes must stay documented and tested
in the same commit; every item must leave the scope gate, the IP gate and the
pacing rules exactly as they are (no item may touch `scope.yaml`, and 12i is the
only item allowed to change how an address is filtered, after its ruling).

PART 12 MUTATION TARGETS: one per item, listed above. In addition, the exit-code
change (12k) and the redaction change (12f) must each be proved by mutating the
new code and watching the new test fail, then restoring.

PART 12 GATE: (1) the owner has approved or amended this section and ruled on
12i, 12a, 12c, 12d, 12f, 12g and 12k before their code starts; (2) every item
is either closed with its own commit, or explicitly re-deferred by the owner in
writing (PROGRESS "Open risks" updated in the same commit); (3) `pytest` twice,
`ruff check`, `ruff format --check` and `mypy` clean after every item; (4) each
item's docs change landed in the same commit as its code, with docs-first where
the item says so; (5) no new dependency, no new module outside docs/03, no new
CLI flag or command outside docs/02; (6) PIT rows added for every bug found;
(7) PROGRESS RESUME, Deviations and Open risks updated; (8) nothing pushed.

=====================================================
PART 13: interactive scan mode (commit `feat:`)
=====================================================
Status: **IMPLEMENTED 2026-11-16** from the owner's task text in this session;
this section is consecrated in the same commit as the code, docs first
(docs/02 section 2b, docs/03 sections 5 and 8b). One item, one commit.

Goal: a first-time user can run a scan without knowing a flag, and every scan
shows what it is doing while it runs. The flag-based surface must not change at
all: no new flag, no new prompt on a flagged run, no new output on stdout.

13. Interactive scan mode (medium, code + docs, cross-cutting)
  What: `reconkit passive` with no `-d`/`-l` exits 2 with "provide a target";
  a slow scan prints nothing until each stage finishes, and `--json` prints
  nothing at all for the whole run (the documented open risk).
  DECIDED (owner, 2026-11-16): five questions - target or domain file, scope file
  yes/no + path, passive/active/full, a numbered report-field menu (multi-select
  or `all`), and a separate aggressive-scanning yes/no - and one folder per domain
  per run holding a `.txt` and a `.json` of the selected fields. Progress goes to
  stderr for every scan, `--json` included, and only `--silent` suppresses it.
  Hard constraints: the interactive path may only trigger when neither `-d` nor
  `-l` is present and stdin is a TTY; `-d`/`-l` behaviour, output and files are
  unchanged; no scope behaviour may change and no bypass may be added; `vulns`
  stays out of the mode (recon-only build).
  Size: cross-cutting - `cli.py` (questions and wiring), `engine.py` (progress
  callback, richer `HostSnapshot`), `core/store.py` (extra read columns),
  `ui.py` (`render_progress` wiring, `report_directory`, `write_field_report`),
  `config.py` + `config.yaml` (`results_dir`), docs/02, docs/03.
  Tests: a flagged run never prompts (every existing CLI test stays untouched);
  a TTY-less run without a target keeps exit 2; the interactive path with a fake
  TTY produces the documented folders for one domain and for a file of domains;
  alive-only fields are `not applicable` for non-`ALIVE` hosts; two runs of the
  same domain never share a folder; `--json` stdout stays one document while
  progress appears on stderr; `--silent` stays silent.
  Adversarial: an empty domain file; a path that is a directory; `0` or an empty
  field answer; a field number out of range; a scope path that does not exist;
  aggressive `yes` with `passive` chosen; a target whose report folder already
  exists; Ctrl-D at a prompt.
  Mutation targets: drop the `sys.stdin.isatty()` guard; let two runs share a
  folder name; populate an alive-only field for a `DEAD` host; make `--json`
  write progress to stdout.

PART 13 GATE: the four checks clean twice; no existing test changed unless the
TEST POLICY in the task text documents the reason; every new behaviour has a
regression test; PROGRESS "Deviations" records the new `results_dir` key and the
new `docs/tool_manuals/` tree from Phase 1; nothing pushed.

=====================================================
DATED DEVIATIONS (owner-requested, 2026-11-17)
=====================================================
These are explicit owner requests made after the plan above was saved. They
take precedence over the rules they touch; each is recorded here with its date
and reason, and mirrored in docs/PROGRESS.md "Deviations".

D1. 2026-11-17 - No scope file means unrestricted active scanning.
    Reason: "user-requested: no scope file should mean unrestricted scanning of
    operator-specified targets, not auto-derived restricted scope."
    A run with no scope file at the resolved path (default `./scope.yaml`,
    `--scope` overrides) runs active/full stages unrestricted against the
    target(s) given with `-d`/`-l` and every host discovered under them: no
    auto-derived scope object, no implicit restriction, no refusal. A scope
    file that **is** present is enforced exactly as before and is only ever
    read. This changes plan rule 2 of docs/05 for the no-file case only; there
    is still no flag that weakens a real scope file.

D2. 2026-11-17 - naabu is scope-mode dependent; entry 11c-G-7 is SUPERSEDED
    (not deleted).
    Reason: "user-requested: naabu unrestricted in active/full with no scope
    file; scope-file-present uses resolve-and-verify-IP path."
    No scope file: naabu runs unrestricted like any other active tool - no
    pre-resolution gate, no IP-only restriction, no special-case skip. Scope
    file present: reconkit resolves each already-in-scope target itself, checks
    every address against `in_scope_cidrs`, and passes naabu only the verified
    IP address(es) via `-host` - never a bare domain; a target whose resolution
    fails or resolves out of scope is skipped, with no hostname fallback, and
    naabu is skipped entirely if no target verifies. Passive mode: naabu does
    not run. 11c-G-7's permanent block (12i) is superseded by this decision; its
    historical entries in docs/REVIEW_LOG stay as written.

D3. 2026-11-17 - All speed/throttle control is removed.
    Reason: "user-requested removal, no throttling desired."
    `--speed slow|normal|fast` and `--delay MIN-MAX` are gone from the CLI and
    from interactive mode, the `fast` typed confirmation is gone, `config.yaml`
    no longer carries a `speeds` block or `default_speed`, `core/pacing.py`
    (pacer, rate limiter, shuffle, rate flags) is deleted, `RunContext` has no
    `pacer`/`limiter`/`speed`, `tools.yaml`/the registry have no `rate_flag`,
    and every stage starts its tools together under `asyncio.gather` with no
    sleep, semaphore or shuffling. Schema 5 drops `scan_runs.speed`. A
    `scope.yaml` `max_speed` key is still accepted (so real files keep loading)
    and is ignored, because there is no speed left to cap. Timeouts and
    per-tool caps are not throttling and remain. This supersedes plan rule 3 of
    docs/05 for the pacing part only; the scope gate is untouched.

D4. 2026-11-17 - The installer is removed; reconkit does not install tools.
    Reason: "user-requested removal of install/update commands."
    `src/reconkit/installer/` is deleted (registry plans, apt/pipx/go_install
    backends, GitHub release download, checksum/archive verification), and with
    it `reconkit install`, `reconkit update`, `doctor --fix`, the `.env` key
    prompt, `InstallError`/`InstallSkipped`, and the install UI. `tools.yaml`
    `install:` blocks become inert `source:` strings (per-tool instructions in
    docs/10_TOOL_SOURCES.md); `ToolSpec` gains `binary`, `version_cmd`,
    `version_regex` and `source`, and the read-only lookup/probe that `doctor`
    needs moves to `core/toolcheck.py` (`bin_dir()` lives in `config.py`).
    `doctor` is unchanged in what it checks: adapter identity first, then the
    managed copy / `PATH` lookup and the `version_cmd` probe. Exit code 6 is
    retired. `config.yaml` `tool_versions` and the `install:` block are
    accepted and ignored (`doctor` warns once about a non-empty
    `tool_versions`); no pin has a consumer. This supersedes Part 10's installer
    scope and the install half of docs/10; the tool registry, the scope gate and
    the scan path are untouched.

D5. 2026-11-17 - `httpx_tech` must not accept the Python `httpx` CLI.
    Reason: "V-UNEXPECTED item 1: httpx_tech reported Python httpx as installed;
    fixed with a version_cmd + version_regex and a regex-miss-means-not-installed
    rule" (owner ruling, option B, targeted fix). The D4 fallback treated a tool
    with no `version_cmd` as installed on presence alone, so with only
    `/usr/bin/httpx` (the Python CLI) visible, `doctor` said
    `yes | /usr/bin/httpx | identity ok` while the `httpx` adapter row said
    `wrong program` for the same file. `tools.yaml` `httpx_tech` gains
    `version_cmd: [httpx, -version]` and a ProjectDiscovery banner pattern, and
    `core.toolcheck.installed_version()` now returns `None` when a *declared*
    `version_regex` does not match, instead of falling back to the first line.
    A pattern is therefore a requirement, not a formatting hint; the first-line
    fallback survives only for tools that declare no pattern. No new `ToolSpec`
    field (identity markers stay an adapter-class concept), no change to
    `BinaryAdapter.check_installed()`, and no probes are added to the other 12
    presence-only tools - they stay a documented limitation (docs/10 section 3).
    Supersedes the "absent or nothing matches" wording of decision 12j.

D6. 2026-11-17 - `doctor` reports installed/not-installed, path and identity,
    never a version.
    Reason: "user-requested: doctor shows installed/not-installed only, not
    versions; version_cmd/version_regex kept for identity checks" (owner
    ruling). The Version column answered a question the user does not have -
    what matters is whether a scan can use the tool - and it was the only place
    a probe's raw text reached the screen. `ToolCheck` and the `doctor --json`
    tool object lose the `version` key, and the table loses the column; the D5
    identity check is untouched, because `core.toolcheck.installed_version()`
    still runs `version_cmd`, still applies `version_regex`, and still returns
    `None` on a miss (so Python's `httpx` stays `wrong program` under
    `httpx_tech`). Nothing is deleted from `tools.yaml`: `version_cmd` and
    `version_regex` remain the identity machinery. The `Missing tools: N`
    footer is reworded to describe what a scan does with the gap
    (`Scans will use the tools that are installed and skip the rest.`),
    replacing the install-advice wording left after D4. This supersedes the
    display half of 12j and D5 only; the probe itself is unchanged.

D7. 2026-11-17 - Standing pre-approvals established.
    Reason: "user-requested: reduce batch friction by pre-approving settled
    decisions." Pre-approved without asking: sudo for installs/system steps;
    doc mirrors code; regression tests; `tools.yaml` version fields from real
    output; install-residue removal; `tool_versions` stays removed; interactive
    `scope.yaml` writes with an explicit `y`; `--no-scope`; `--full` narrowing
    `--active`; consistency audits; adapter implementations wave 1+ (own S1-S7,
    real `--help` pasted, own fixture). Still requires a ruling: AGENTS scope-rule
    changes beyond `--no-scope`; exploitation-tools-auto-fire; new CLI flags not
    in a batch prompt; `scope.yaml` edits outside interactive `[a]`; new
    dependencies; unfreezing F1/F2; widening active scanning; confidence and
    host-state changes. Full list: AGENTS.md section 0d. Reviewed by owner
    2026-11-17. Mirrored in docs/PROGRESS.md Deviations.

D8. 2026-11-17 - Scan modes are one table: stages + tool modes + tiers.
    Reason: "user-requested: unify scan-mode definitions across CLI help, the
    interactive prompt, all docs and README." The owner's table is the source
    of truth: `passive` = subs+dns / passive tools / core (+opt_in with
    `--include-noisy`); `active` = subs+dns+live / passive+active / core
    (+opt_in); `full` = all seven stages / passive+active / core+opt_in+
    intrusive. Implemented as `MODE_STAGES` + `MODE_TOOLS` in `engine.py`;
    `_select()` reads them, and the CLI help strings and interactive legend are
    generated from them. Two disclosed behaviour changes: (a) CLI `--active`
    narrows from all stages to subs+dns+live (matching the interactive prompt);
    (b) `--full` is new and implies `--active` and `--include-noisy`, so the
    opt_in tier is no longer skipped under it. Safety pre-ruling: a new
    `tools.yaml` field `exploitation: true` marks sqlmap, dalfox and crlfuzz;
    the engine skips any such tool in every mode unless it is named with
    `--tools`, preserving AGENTS "recon only - no exploitation". No intrusive
    tool has an adapter in this build, so full mode still reports `no adapter
    yet (phase 3)` for them. Also in this batch: scope pre-flight warning,
    `--no-scope` + `scan_runs.scope_mode` (schema 6), `--only-alive` /
    `--only-states` / `--status-codes` filters, `--ports` / `--header` /
    `--user-agent` / `--redact-headers` injectables, the extended interactive
    Q&A, and the out-of-scope `[a]/[b]/[c]/[d]` prompt.

D9. 2026-11-17 - Zero-tool stages caused by absence are gaps, not failures.
    Reason: "user-requested: --full exits 0 with a warning block when stages
    lack adapters." A requested stage that executed no tools exits 0 when every
    one of its skips was `no adapter yet (phase N)` or `not installed`: the scan
    used every tool that was available. The honesty moves into a stderr block
    (and `--json` `completion`); exit 5 stays reserved for real partials (a
    failed/timed-out tool, or a stage emptied by tier/tool-mode/exploitation/
    scope rules). "Nothing usable at all" still exits 4. Supersedes the
    12k rule in docs/02 section 6 that made every zero-tool stage exit 5.

D10. 2026-11-17 - Mode table expansion: passive includes passive urls, active
    includes urls and tech. Reason: "owner ruling: passive urls in passive mode,
    active urls + tech in active mode." `MODE_STAGES` is `passive` =
    `(SUBS, DNS, URLS)`, `active` = `(SUBS, DNS, LIVE, TECH, URLS)`, `full` =
    `STAGE_ORDER`; `MODE_TOOLS` is unchanged (`opt_in` stays a flag). Tuples are
    in `STAGE_ORDER`, so a run's order always equals the documented order
    (urls after live, tech before urls). Consequence the expansion exposed: the
    urls stage is fed the alive hosts, and a passive run has none, so a
    `mode: passive` urls tool now receives `[target, *discovered]` instead; an
    active one still gets the alive hosts, and in passive mode it is skipped at
    selection with `tool mode not included in passive mode`. The interactive
    legend is generated from the table, and docs/02 section 1 is the source.

D11. 2026-11-17 - Tech-stage persistence and stdin input (forced by adapter wave 2).
    The `tech` stage had no persistence branch, so webanalyze/cdncheck records
    would have been dropped; and `run_exec` had no stdin channel, so httprobe and
    waybackurls (which read hosts on stdin) could not be driven without a shell,
    which AGENTS rule 1 forbids. Ruling: `_persist_tech` merges `tech`/`waf` into
    the host's newest `host_status_history` row (`Store.update_host_extras`) and
    never appends a state row or touches `state`; `run_exec(..., stdin_text=...)`
    feeds the child from a thread and `None` keeps the documented EOF. Both are
    documented in docs/03, docs/04 and docs/09; the alternative (a new tech
    table or a second persistence path) was rejected as a schema change the
    columns do not need.

D12. 2026-11-17 - Deterministic WAF merge via tool priority (owner ruling,
    supersedes the wave-4 open item). Wave 4 found that the single
    `host_status_history.waf` column was filled by whichever WAF-capable tool
    finished first inside a pass (`asyncio.gather` completion order) and by the
    latest pass across runs, so two tools on the same host could flip the stored
    name between runs. Owner ruling: priority-based deterministic merge. Each
    `tools.yaml` entry may carry `waf_priority` (int, default 0); the merge keeps
    the highest-priority detection, so `wafw00f` (100) beats `cdncheck` (80),
    `whatweb` (50) and `httpx_tech` (20) no matter who finishes first, and no
    rerun can change the result. Equal priorities keep the first writer (inside
    a pass: first record; across passes: the stored value), and the first
    detection always fills an empty column. That needs somewhere to remember the
    priority of the stored name, so the ruling carries a schema change -
    `host_status_history.waf_priority INTEGER NOT NULL DEFAULT 0`, schema 6 -> 7 -
    and `Store.update_host_extras` compares priorities instead of overwriting.

D13. 2026-11-17 - Inline default wordlist for ffuf (owner ruling). Wave 5 left
    ffuf unadapted because no wordlist existed anywhere in the repo or under
    `~/.reconkit`, and an adapter without one cannot fuzz anything. Owner
    ruling: ship `src/reconkit/data/wordlists/common.txt` - about 110 common
    paths, committed, packaged as package data, no runtime download - and add
    `--ffuf-wordlist PATH` on the scan commands so an operator can replace it.
    `ffuf` is `opt_in`, and its findings are `severity="info"`: a discovered path
    is not a confirmed vulnerability. dnsreaper stays unadapted: it is not on
    PyPI, has no `setup.py`/`pyproject.toml`, and is a script run by hand, so it
    needs an adapter kind that does not exist.

D14. 2026-11-17 - Ports wave: four mechanics the brief and the tools disagreed
    on. (1) **masscan root is a selection-time skip, not a runtime status.** The
    brief asked the adapter to check `os.geteuid()` and return `SKIPPED`; done,
    but a run-time `SKIPPED` made `_exit_code` count the tool as failed, so every
    `--full` run by a normal user exited 5. The skip moved to `_select`, driven
    by the `needs_root: true` that `tools.yaml` already carried and that
    `ToolSpec` now parses; the adapter keeps the same guard for a direct call.
    (2) **rustscan needs no nmap.** Verified with `PATH` emptied: `-g` prints
    `IP -> [ports]` and its help says `No Nmap`; 2.3.0 has no `--` passthrough,
    so service detection stays nmap's job and no "requires nmap" skip exists.
    (3) **masscan writes the list format (`-oL`), not JSON.** `-oJ` needs a root
    scan to observe and `sudo -n` asks for a password on this box, so the
    adapter uses the format whose example ships in
    `/usr/share/doc/masscan/README.md.gz` instead of an unverified schema.
    (4) **`_persist_ports` now stores `service`/`version` and applies the
    documented `-sV` confidence bump.** The real ports run exposed that the
    fingerprint was parsed and then thrown away, so docs/09 section 5's "raises
    confidence by one level" had never fired. Two tools that disagree (`http`
    vs `http?`) store neither value. Also: `smap` cannot be told which ports to
    scan, so `--ports` filters its passive records; `_VERSION` accepts a
    two-part version (`Nmap version 7.991`); `adapters/nmap.py` carries a
    per-file `S314` ignore because it parses only the `-oX` file nmap itself
    wrote.

D15. 2026-11-17 - dnsreaper is not adapted (owner ruling). `pip install
dnsreaper` has no distribution (`No matching distribution found`), the GitHub
project has no `setup.py`/`pyproject.toml` and ships `main.py` +
`requirements.txt`, so driving it needs a checkout plus a script-launching
adapter kind the contract (http/python/binary) does not have. `subzy` already
covers subdomain takeover. The tool stays in `tools.yaml` for the record and is
reported as `no adapter yet`; revisit only if script-launch adapters are added.

D18. 2026-11-17 - A key the tool cannot run without is a selection skip. `chaos`
exits 1 with `[FTL] PDCP_API_KEY not specified` and `github-subdomains` has no
keyless path; `tools.yaml` `keys` describes an optional upgrade, so the new
class attribute `requires_env` marks a hard requirement. The engine skips such a
tool at selection with `requires <NAME>` (recorded, not a gap, run stays
complete), the same mechanism as masscan's `needs_root` - not a runtime
`ToolStatus.SKIPPED`, which counts as a failed tool and exits 5.

D16. 2026-11-17 - Bundled resolver list for massdns/puredns (owner approved).
massdns and puredns both need a resolver file and the build downloads nothing
at runtime (rule 4), so `src/reconkit/data/resolvers.txt` ships 16 public
resolvers as package data, and the new `--resolvers PATH` flag replaces it. A
missing file is a failed tool result, never a silent fallback to the system
resolver. `puredns` also gets `-b <absolute massdns>` because a child process
sees only the env keys the engine passes.

D17. 2026-11-17 - Screenshots are per-run files, not DB records (owner
approved). gowitness writes `results/<target>/<UTC stamp>/screenshots/*.png`
plus a `screenshots.jsonl` manifest (`{"url", "path", "timestamp"}` per line).
No `ScreenshotRecord`, no table, no schema bump: a screenshot is a per-run
artifact of an opt-in active stage, and `reconkit status`/`diff` do not show it.
The adapter learns the results root from the engine through a new
`RunContext.results_dir` field (plumbing, not a record model), so `--config` and
the reports stay in agreement. gowitness itself defaults to `jpeg`, so the
adapter passes `--screenshot-format png`. (The stage was wired into `full` by
D19.)

D19. 2026-11-17 - The `shots` stage is wired into full mode (owner requested:
"wire the shots stage so gowitness becomes runnable"). `Stage.SHOTS` was
orphaned - it existed in `models.py` and `RAW_OUTPUT_DIRS` but in neither
`STAGE_ORDER` nor a `MODE_STAGES` row, so no mode and no `--tools` selection
could reach the completed gowitness adapter. It now sits in `STAGE_ORDER`
between `urls` and `vulns` (a screenshot needs the alive hosts the live stage
produced, and a slow browser must not delay the findings stage), and therefore
in `MODE_STAGES["full"]`; `passive` and `active` do not list it and there is no
`shots` stage command. No other stage, tier, flag or table changed.

Disclosed conflict: the batch expected `gowitness` to be "skipped (opt_in tier
requires --include-noisy)" in a `--full` run. That cannot happen in this build,
for two independent reasons, both pre-existing and documented: `--full` sets
`include_noisy = True` in the CLI (docs/02 section 2: "implies --active and
--include-noisy"), and `--tools <name>` bypasses the tier gate by design
(docs/02 section 3). No stage-specific gate was invented to manufacture the
skip; the actual behaviour is pinned by
`test_full_runs_gowitness_without_the_noisy_flag_because_full_implies_it`. If
the owner wants screenshots to stay behind an explicit flag in full mode, that
is a separate ruling and a new rule in `MODE_TOOLS`.

D20. 2026-11-18 - Reports on both paths, a live status line, and the amass
read-back (owner batch after a real `run -d testfire.net --active --no-scope`).

(1) **The report is written by every scan.** docs/02 section 5 said only the
interactive mode wrote `report.txt`/`report.json`; the owner reported the effect
plainly - a `-d` run printed tables and left no artifact. The writer is no longer
gated on the interactive plan: the questions now only *choose columns*, and a
flagged run passes every `REPORT_FIELDS` key. No new flag, no new prompt, no new
stdout; the `report: <txt> and <json>` line still goes to stderr and `--silent`
still suppresses it. `test_a_flagged_run_writes_no_report_folder` became
`test_a_flagged_run_writes_its_own_report_folder` (the old name asserted the
behaviour that was removed; it is a contract change, not a weakened assertion).

(2) **A transient activity channel for the live status line.** `Engine` gained
`activity=callable`, a second callback carrying
`<stage>: <done>/<total> tool(s) done, <n>s elapsed - running: <tools>` on every
tool start/finish, rendered by `ui.activity_spinner` as one in-place Rich status
line on stderr. It exists because the durable progress lines only appear when a
tool *finishes*: `gau` ran 600 s with no sign of life. Constraints kept: stderr
only, drawn only when stderr is a terminal, transient, `--silent` removes it,
and `done` advances only for a tool that actually finished (a phase-timeout
cancellation must still get its `timeout` row - caught by
`test_phase_timeout_records_a_timeout_row` during this batch).

(3) **amass: `post_command` and the v5 read-back.** A real run reported `amass ok
1 item(s)` every time. v5.1.3 `enum` is a thin client for its own engine
(`POST /api/v1/sessions`) and prints only `Session Scope` / `FQDN:` / the target
to stdout, so the parser was harvesting the target from the header. Findings are
read back with `amass subs -d DOMAIN -names` (verified: the same 8 hosts the
table showed) through a new documented adapter hook `post_command(ctx)`, run by
the base flow after a successful primary run, only when `read_output` returned
`None`; its stdout is parsed and a failed read-back is a FAILED tool. `-o` does
not exist in v5 and `-dir` writes only config templates, so neither is a
findings channel (docs/09 wave-7 note corrected).

**Two premises in the request did not hold, so they were reported rather than
re-implemented.** Stage tools were already concurrent (`asyncio.gather` in
`_run_tools`, D3): the `urls` stage spent 664 s wall clock on 1581 s of summed
tool time. Duplicates already do not cross a stage boundary (`discovered` is a
`set`, `_stage_hosts` runs `_clean_hosts` with a `seen` set, `_persist_urls`
keys a `dict`, and the schema has `UNIQUE(target_id, fqdn)` /
`UNIQUE(target_id, url)`); measured on the real DB: 1655 url rows = 1655
distinct, 41 hosts = 41 distinct, zero duplicate groups. The report therefore
cannot repeat a host or a URL.

D21. 2026-11-18 - `scripts/install-tools.sh`: the owner reinstates installation,
    outside the CLI.
    Reason: "one script file which should install all tools whether its apt
    install or go install with sudo cmd so user first run script file with sudo
    and install every tool in kali ... and in end the script will verify with
    doctor" (owner request, superseding the *scope* half of D4 - not its safety
    rules). The CLI surface does not come back: there is still no
    `reconkit install`, no `reconkit update`, no `doctor --fix`, and
    `src/reconkit/installer/` stays deleted. What returns is a single shell
    script a human runs deliberately.

    Constraints that keep it compatible with everything already ruled:
    (1) **`tools.yaml` stays the only tool list.** The script does not carry its
    own catalogue; it reads every `kind: binary` entry and follows its `source:`
    string - `apt: <pkg>`, `go install <module>@latest`, `pipx install <pkg>` -
    and reports the rest (release-only: `findomain`, `rustscan`, `dnsreaper`) as
    manual, with the upstream URL from the same entry. The `(or: go install
    ...)` hints added today to the nine release-only ProjectDiscovery entries
    were each verified with `go install -n` against the module proxy before
    being written (REVIEW_LOG, "scripts/install-tools.sh" entry), so no module
    path is from memory and
    nothing is downloaded by the script itself: `go install` fetches from the
    official proxy, exactly as the registry describes.
    (2) **No unverified downloads.** The script never curls a GitHub release, so
    the D4 removal of archive/checksum handling is not being quietly reversed.
    (3) **Sudo only where needed.** It must run as the invoking user (it refuses
    under `root`, and says why: `GOBIN` would land in `/root`); `sudo` is applied
    per `apt-get` command only.
    (4) **Verification is `doctor`.** The script does not grow its own checker:
    it ends with `reconkit doctor --json` and fails when a tool it was supposed
    to install reports `installed != yes` or `identity != ok`, which is the
    adapter's own probe (D5/D6), so a binary that exists but is the wrong
    program counts as a failure.
    (5) **Linux only** - bash script, Kali/Debian, by owner decision (2026-11-18).

D22. 2026-11-18 - www/non-www deduplication (owner request: "www.anywebsite.com
    and anywebsite.com are the same - fix that yourself").
    Reason: a real `sakec.ac.in` scan listed `sakec.ac.in` (301) and
    `www.sakec.ac.in` (200) as two ALIVE hosts, and the same again for
    `admission`, `iprc`, `research`, `portal`, so 39 "ALIVE" hosts looked like
    39 websites. New metadata, not a new state rule: schema 9 adds
    `host_status_history.duplicate_of` and `.www_note`;
    `Engine._dedupe_www_variants()` runs after `live` and before `tech`/`urls`
    and writes them on the newest status row of each host; the results table
    gains a Notes column and the summary line a unique count; `--json` gains
    `hosts[].duplicate_of`/`.www_note` and a top-level `www_dedup` block.

    **Frozen rules untouched:** no change to host-state definitions
    (ALIVE/DNS_ONLY/SHUT_DOWN/DEAD/UNKNOWN), to the confidence formula, to
    `decide_host_state`, to any count query, or to `diff`. The pass only reads
    stored rows and writes two nullable columns.

    Rules (docs/09 section 5): a 3xx name is the duplicate of the 2xx name; two
    2xx names are never marked (both serve content) and get the
    `has www sibling at ...` note; two alive names with the same non-2xx status
    that share an IP mark `www.X` as a duplicate of `X`; two names on different
    servers get the `www variant on a different server` note; a dead/DNS-only
    variant is never a duplicate of an alive name (that means "this name does
    not resolve"); a single variant is untouched.

    Disclosed: the brief said "schema 7 -> 8", but Part 1 of the same batch had
    already taken 8 (the `tool_runs` CHECK rebuild for the `gap` status), so the
    dedup columns are **schema 9**. The brief also asked for the sibling note on
    the existing `detail` column; that column is documented as the UNKNOWN
    reason and is exposed as `hosts[].detail`, so a second column (`www_note`)
    keeps the two meanings apart.

D23. 2026-11-18 - URL liveness probe (`url_probe` stage, owner-requested after
    the sakec.ac.in scan).

    Problem: the urls stage records what the archives and the crawl returned
    (11,785 URLs on that target) but nothing says which of them still answers,
    so every URL is equally good evidence and `/admin` from 2019 looks the same
    as a page that answered today.

    Design: a new `Stage.URL_PROBE` in `STAGE_ORDER` after `URLS` and before
    `SHOTS`, in `MODE_STAGES["active"]` and (through `STAGE_ORDER`) in `full`;
    never in `passive`, because it sends HTTP. It has **no adapter and no
    `tools.yaml` entry**: `Engine._run_url_probe()` owns the pass, uses httpx
    with the honest `reconkit/<version>` UA, and writes `urls.status_code`
    (schema 10) itself. A URL that cannot be reached is stored as `-1`, so a
    later run does not retry a dead URL and `NULL` keeps its single meaning:
    "not probed yet". A server that answers with a certificate that does not
    verify (hostname mismatch, untrusted chain) is stored as `-2`, not `-1`:
    verification is never disabled, and "answered, bad certificate" must not
    pass for "dead" - found on the first real testfire.net run, where every
    URL carries a `www.testfire.net` certificate.

    Bounds (`config.yaml` `url_probe:`): `max_urls` 5000 per run (a bigger list
    is cut and the run says so), `batch_size` 200, `threads` 50, `timeout_s` 10
    per request. `--skip-url-probe` turns the stage off (a named flag, per the
    batch prompt). `--mock` never sends traffic: it leaves `status_code` NULL
    and says so on stderr rather than inventing answers.

    Scope: it is an active stage, so it goes through `_active_hosts()` like
    every other one - with a scope file present, only URLs whose host the gate
    allows are probed, and a denial is exit 3 with the usual block. `--no-scope`
    behaves exactly as if no scope file existed (docs/05 section 3).

    Frozen rules untouched: no change to host-state definitions, to the
    confidence formula, to `decide_host_state`, or to `diff`. The probe writes
    one integer on the `urls` row and nothing else.

D25. 2026-11-18 - www dedup requires a known, equal status (verification gap 2).

    Problem: `_dedupe_www_variants` compared the two `status_code` values with
    `==`, so `NULL == NULL` counted as "same status" and a pair of ALIVE names
    with no HTTP status on either side but a shared IP was marked
    `duplicate_of` from DNS evidence alone. The documented rule (D22,
    docs/09 section 5) is "same **non-2xx** status"; `NULL` means "no status
    observed", which is not a status. Found in verification: a mock run marked
    `www.testfire.net` as a duplicate of `testfire.net` while both rows carried
    `status_code = NULL`.

    Fix: the shared-IP branch requires both codes to be present and equal. A
    pair with no status on either side is now left alone (no `duplicate_of`, no
    note), because nothing about the two answers is known. The 3xx/2xx and
    both-2xx branches already required real codes and are unchanged, as is the
    "different known IPs" note. No schema change, no state or confidence change.

D24. 2026-11-18 - Faster `url_probe`, and `--reprobe-urls` (owner-requested batch).

    Goal: the probe's worst case was `max_urls x timeout_s / threads` (5000 x 10
    / 50 = 1000 s), and the owner asked to replace the Python httpx transport with
    the PD `httpx` binary (`-l file -threads 100`) to cut that down.

    Measured and rejected: PD httpx v1.12.0 has **no `-insecure` flag**
    (`flag provided but not defined: -insecure`) and **skips TLS verification by
    default** - `https://testfire.net/`, whose certificate is issued for
    `www.testfire.net`, comes back `200`. It also emits **no JSON line at all**
    for a URL that fails, so "answered with a bad certificate" and "never
    answered" are the same absence, and its default User-Agent is a random
    browser string (docs/05 rule 8 forbids that). On the same 158 stored URLs:
    **PD httpx 9.19 s** and 58 certificate-invalid URLs reported as `200`;
    **Python httpx 4.59 s** with `-2` for all 58. The premise that the binary is
    faster did not hold on this box, and swapping transports would have silently
    erased the `-2` semantics added in D23.

    Kept: the Python transport. Changed: **one `AsyncClient` per pass** instead of
    one per 200-URL batch (each batch paid its own pool/TLS setup), and `threads`
    **50 -> 100**. Same 158 URLs: **3.44 s** with an unchanged answer
    distribution (`-2 58, -1 1, 200 66, 302 2, 400 1, 404 30`). The pass is still
    bounded by `max_urls` and per-request `timeout_s`; D26 adds the stage
    deadline.

    `--reprobe-urls` (new flag, owner-requested): probes **every** stored URL
    again, not only the `NULL` ones, so a URL that has since gone dead is found.
    `Store.probe_candidates(..., reprobe=True)` backs it, the answer overwrites
    `urls.status_code` in place, `scan_runs.params_json` records
    `"reprobe": true`, and the usual `max_urls` cut and warning still apply. With
    `--skip-url-probe` the flag has no stage to act on, so the run prints a
    warning and continues.

=====================================================
LATER BUG FIXES (any session)
=====================================================
Reproduce with a failing test first, fix, run the SELF-REVIEW LOOP on the fix, log it in REVIEW_LOG "Bugs found", update RESUME. Never change behavior without a test.
