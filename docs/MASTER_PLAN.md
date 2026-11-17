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
Status: CLOSED (2026-11-14). Decisive items: `5df7e98` (children stay in the parent's session so a cached `sudo -v` ticket is visible) and `9c4319b` (apt tools with no version flag report dpkg's version); live fresh `massdns` install recorded in REVIEW_LOG.
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
  adapter result); Windows path containment unchanged.
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
  removed on the next start; Windows path behaves as documented; the file is
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

=====================================================
LATER BUG FIXES (any session)
=====================================================
Reproduce with a failing test first, fix, run the SELF-REVIEW LOOP on the fix, log it in REVIEW_LOG "Bugs found", update RESUME. Never change behavior without a test.
