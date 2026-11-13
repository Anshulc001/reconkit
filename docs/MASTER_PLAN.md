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
R4. Session start (G1) reads the Known pitfalls table. `scripts/check.ps1` warns when the most recent commit subject starts `fix:` and the commit changes no file under `tests/`. The S7 report includes `Pitfalls added this part: <IDs or none>`.
R5. Back-fill: every bug already fixed in d03a231, e40091d, 80ddd93, the Part 3-AUDIT or later must have a `test_regression_*`/`Regression:` guard. If missing, add it (mutation first) in the addendum or the next `fix:` commit and fill its row.

=====================================================
SELF-REVIEW LOOP (mandatory after EVERY part, before moving on)
=====================================================
S1. CHECKS: run scripts/check.ps1 and paste/record the raw output; run pytest a SECOND time to catch flaky and order-dependent tests (also `pytest -p no:randomly` is not needed; just run twice).
S2. READ YOUR OWN DIFF: run `git diff HEAD~1 --stat` and read `git diff HEAD~1 -- src` line by line. In REVIEW_LOG list: every broad except and why; every external input and where it is validated; every place a secret could reach a log, error, argv, URL or file; every blocking call inside async code; every exception that could escape an adapter or the engine; every unfinished path. If a list is empty, say how you checked.
S3. SCANS (PowerShell; record raw output in REVIEW_LOG):
  Get-ChildItem src -Recurse -Filter *.py | Select-String -Pattern "\bassert\b"              # expect none
  Get-ChildItem src -Recurse -Filter *.py | Select-String -Pattern "shell\s*=\s*True"         # expect none
  Get-ChildItem src -Recurse -Filter *.py | Select-String -Pattern "TODO|FIXME|XXX|HACK"      # expect none
  Get-ChildItem src -Recurse -Filter *.py | Select-String -Pattern "print\("                  # expect only ui.py
  Get-ChildItem src -Recurse -Filter *.py | Select-String -Pattern "subprocess"               # expect only runner.py
  Get-ChildItem src -Recurse -Filter *.py | Select-String -Pattern "sqlite3"                  # expect only store.py
  Get-ChildItem src -Recurse -Filter *.py | Select-String -Pattern "os\.environ"              # justify each; adapters none
  Get-ChildItem src -Recurse -Filter *.py | Select-String -Pattern "except\s*:|except Exception|except BaseException"   # justify each
  Get-ChildItem src,tests -Recurse -Filter *.py | Select-String -Pattern "noqa|type:\s*ignore" # compare with Part 0 baseline; no new ones
  Get-ChildItem src\reconkit\adapters -Filter *.py | Select-String -Pattern "import (store|scope|ui|cli)|from reconkit\.(core\.store|core\.scope|ui|cli)"   # expect none
  Any unexpected hit is a bug (S6).
S4. REQUIREMENT -> TEST TABLE in REVIEW_LOG: every requirement bullet of the part with the exact test name proving it. A bullet without a test gets a test now.
S5. ADVERSARIAL + MUTATION: (a) every case in the part's ADVERSARIAL list plus at least 3 you invent gets a test, or a written reason it cannot happen. (b) For each of the part's MUTATION targets: deliberately break the code, run only the related tests, record the FAILING output, restore with `git checkout -- <file>`, and record `git status --short` showing a clean tree. A test that does not fail on the broken code is worthless: rewrite it.
S6. FIX LOOP for every bug: write a test that reproduces it and confirm it FAILS; fix; confirm it passes; re-run S1-S3; record in REVIEW_LOG "Bugs found" (symptom, root cause, fix, guarding test). Bugs found before the part commit go into that commit; later ones into a `fix:` commit. Max 3 iterations, then A2.
S7. RECORD: append the REVIEW_LOG entry, update the PROGRESS table and RESUME block, then print a short REPORT in chat (part, hash, checks result, bugs found/fixed, decisions for user review, not verified, and "Pitfalls added this part: <IDs or none>").
GATE: move to the next part ONLY if: scripts/check.ps1 passes twice; scans clean or justified; every requirement has a test; mutation proofs recorded; no open bug. Otherwise fix (S6) or A2.

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
  - Raw check output (last lines of scripts/check.ps1, twice for pytest):
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
0a. Record raw in REVIEW_LOG: `git status --short`, `git log --oneline -8`, `git ls-remote reconkit main`, `Get-ChildItem tests\fixtures -Recurse | Select-Object FullName, Length`, and `git check-ignore -v .env` (if .env is not ignored, add it to .gitignore). Confirm `.tmpfetch` is gone (delete if present and untracked).
0b. Baseline: run scripts/check.ps1 and all S3 scans; record counts (tests passed/skipped, existing noqa/type-ignore count).
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
- Never put a key in argv. If a tool needs a key (subfinder), write a temporary provider-config file from the allowed env names with restrictive permissions, delete it in a finally block (also on timeout and exception), never log its content. Open risk: chmod is weak on Windows.
- parse_output tested against real or documented sample output; malformed output returns a failed result, never an exception. Non-zero exit, timeout and missing binary are distinct failed results with different messages.
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
ADVERSARIAL: labels where some resolve and some NXDOMAIN; CNAME wildcard; `..`, absolute paths, `C:\`, UNC paths, reserved Windows names (CON, NUL), trailing dot/space; two secrets in one output; empty output; very large output; same filename written twice.
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
Docs/10 first. DECISION (log under Deviations): the installer targets Debian-family Linux (Kali/Ubuntu). On native Windows, `doctor` runs and reports found/missing, `--mock` and the pure-Python adapters work, and `install`/`update` refuse with a clear message and a documented nonzero exit code; they never try apt. Write this into docs/10.
- Prerequisites: libpcap-dev, jq, dnsutils, Go and Go bin in PATH, pipx/pip for Python tools. Verify package names for Kali AND Ubuntu from official package pages before writing them; cite URLs and dates in PROGRESS. Use `python3` >= 3.11, never a pinned apt python.
- Every install command is an argv list via the runner (shell=False). Never pipe curl into a shell. sudo only when not root and only for apt, announced before running. Go tools via `go install <module>@<version policy from docs>`; pin or justify.
- `install --all`, `update --all`, per-tool install; idempotent; one failing tool does not stop the rest; final summary table; exit code per docs.
- Keys flow from Part 2 (interactive TTY question, .env.example copy without overwrite, Keys table). Non-TTY/--silent/--json never prompt. Wire `--no-keys` end to end.
- doctor: tool table (installed, version, identity verified, tier), prerequisites, Keys table, scope.yaml presence, Python version, DB writable, config/wordlist presence per docs; `--json` supported. Replace the Part 8 stubs.
Tests use an injected runner and platform probe; NOTHING really installs: already-installed skipped; failure isolated; Windows refusal; non-TTY no prompt; .env never overwritten; doctor JSON valid; every argv is a list of strings with no shell metacharacters; sudo only for apt; root gets no sudo.
ADVERSARIAL: apt succeeds but the binary is still missing; unparsable version string; wrong binary on PATH; .env exists but empty; .env.example missing; second `install` changes nothing; Ctrl-C mid-install.
MUTATION targets: Windows refusal, no-overwrite of .env, failure isolation.

=====================================================
PART 11: docs sync, README, final audit (commit `docs:`)
=====================================================
11a. README.md and SETUP.md for the single Windows-native checkout: remove WSL-only and old Kali-only steps; keep clear beginner steps for Windows mock/passive use and for the full tool install on Kali/Ubuntu. Fix hard-coded paths.
11b. Docs 01-10 must match the code. List in REVIEW_LOG every change and every remaining disagreement.
11c. FRESH-EYES AUDIT: re-read the whole src tree as if reviewing someone else's pull request. Specifically hunt for: any code path where an active tool can run without --active + scope pass; any place a DNS/HTTP timeout can become DEAD/SHUT_DOWN; any secret reaching argv/log/db/workspace/UI; any exception that escapes to a traceback in the CLI; any blocking call in async code; confidence computed from non-distinct tools; any docs/code mismatch. Write a test for each finding, fix, and log under "Bugs found". Also run every S3 scan one final time.
11c-bis. Run the end-to-end mock run from a fresh venv (`python -m venv` in a temp dir, documented install command, `reconkit --help`, `reconkit doctor`, `reconkit -d example.com --mock --json`) and record raw output.
11d. PROGRESS: task table complete with real hashes, Deviations, Open risks (carry forward: scope.yaml cannot exclude CIDRs unless fixed; per-call commits slow unless the batch helper solved it; weak pre-commit hook; kill-tree path unverified on Linux; synthetic fixtures; unverified tool JSON fields; key sources unverified items).
11e. Set RESUME status to "ALL DONE" with the exact commands the user must run on Kali/Ubuntu to verify what could not be verified here (real network, installed tools, killpg path).
11f. Print a FINAL REPORT in chat: what is verified (with pointers to REVIEW_LOG sections), what is NOT verified, all "Decisions for user review", and the git state (`git status --short`, `git log --oneline -25`, `git ls-remote reconkit main`). Then STOP. Do not push.

=====================================================
LATER BUG FIXES (any session)
=====================================================
Reproduce with a failing test first, fix, run the SELF-REVIEW LOOP on the fix, log it in REVIEW_LOG "Bugs found", update RESUME. Never change behavior without a test.
