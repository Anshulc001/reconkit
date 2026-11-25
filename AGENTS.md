# AGENTS.md - Instructions for AI coding agents

Read this file first, every session. It points to the documents in `docs/`.

## 0. Session start (do this first, every session)

1. Read `docs/PITFALLS.md` first: it is the live rule set (~90 lines) and every new change is checked against it. Then read the RESUME block at the top of docs/PROGRESS.md, the last 3 entries of docs/REVIEW_LOG.md, and the part you are on in docs/MASTER_PLAN.md. Then pick the docs for your area from the table in section 2 and read **only those**. Do not read `docs/01`-`docs/10` wholesale and do not guess a file name: if the area is not in that table, say so and ask before writing code. The routing, by task:
   - CLI flag, command, output, exit code -> `docs/02` + `COMMANDS.md`
   - adapter, parser, stage pool, confidence -> `docs/09`
   - engine flow, layer, concurrency -> `docs/03`
   - table, column, query, migration -> `docs/04`
   - scope gate, subprocess, secrets, logging -> `docs/05`
   - tests, fixtures, `--mock` -> `docs/07`
   - tool source, install, doctor -> `docs/10` + `tools.yaml`
   - user journey or expected terminal output -> `docs/08`
   - style, errors, typing -> `docs/06`
2. Run `git status --short` and `git log --oneline -10`.
3. Activate the venv and run the gate, one command at a time:

   ```bash
   source .venv/bin/activate
   pytest -q
   ruff check .
   ruff format --check .
   mypy src/reconkit
   ```

   Report the baseline and record it in REVIEW_LOG. If anything fails, fix that first. There is no wrapper script for these four commands in either direction; run them directly.
4. If the tree is dirty, identify which part the changes belong to and finish or complete that part; never discard work.
5. Continue from the RESUME "Next action" following docs/MASTER_PLAN.md, doing only that task (or the one I give you), one task per turn, then stop. Never push. Never redo finished parts. When all parts are done, print the final report and stop.

## 0b. Task loop

plan (5-10 lines, assumptions) -> trace every affected file (section 4.2) -> implement -> tests (normal, empty, malformed, failure) -> run checks -> update **every** doc the change touches -> update `docs/PROGRESS.md` RESUME + entry -> add a `docs/REVIEW_LOG.md` entry -> commit -> report -> stop.

Every error found in a review, CI run or real scan gets a regression test in the
same batch: reproduce it, then fix it. No error is closed by prose alone.

This loop is unconditional. It applies to a one-line fix, a docs edit, or a
request that mentions neither tests nor documentation; the request never has to
ask for the gate, the regression test or the doc updates.

## 0c. Rules learned from reviews

- Never add AI attribution trailers to a commit (`Co-Authored-By:`,
  `Generated with ...`). This repository records no attribution trailers, by
  anyone or any tool.
- Never say a check passed unless you ran it and pasted the output.
- Test results with `if cmd; then echo PASS; else echo FAIL; fi`, never `echo $?`.
- Work only in the repo root of this checkout. Never edit other copies. Never push unless asked.
- Root domains use `validate_target()`; discovered hosts use `validate_host()`.
- Tool flags and JSON field names come from the real tool's `--help` or real sample output, never from memory.
- Child processes get only the env keys passed in; pass `HOME` explicitly for tools that read config from it.
- No `assert` in `src/`. No new lint suppressions except scoped per-file ignores with a reason in `pyproject.toml`.
- No new dependencies without asking me.
- Every deviation from the docs goes in the report AND in `docs/PROGRESS.md` "Deviations". Docs change first, then code.
- **Update all affected docs after every change, in the same commit.** That means the doc for the area you touched (`docs/01`-`docs/10`), plus `docs/PROGRESS.md` (RESUME status and a dated `D<n>` entry) and a `docs/REVIEW_LOG.md` evidence entry with the real commands and their output. A later session must be able to resume from the docs alone; do not leave that knowledge only in the chat.
- **Every error gets a test case.** A failing check, CI failure, or bug found in a real run is reproduced by a regression test in the same batch, then fixed. CI failures count: fix the test or the code, never the assertion's honesty. Its row goes in `docs/PITFALLS.md` in the same commit and cites a guard test that exists; `tests/test_invariants.py` fails otherwise.
- **Run the gate the way CI does.** GitHub Actions sets `FORCE_TERMINAL`, so run both `pytest -q` and `FORCE_TERMINAL=1 pytest -q` before pushing. Rich styling has broken raw substring assertions that passed locally (2026-11-21).
- Adapters never import `store`, `scope`, `ui`, `cli`.
- Do not create modules, files or CLI commands that are not in `docs/03` and `docs/02`. If one seems needed, change the docs first and tell me.

## 0d. Standing pre-approvals (established 2026-11-17, D7)

These are pre-approved by the owner. Do not stop to ask before proceeding on
any of them; disclose in the batch report and do not re-litigate.

Pre-approved without asking:

1. Sudo for installs and system operations; record what for. No per-command confirmation.
2. Doc updates that mirror code changes, in the same batch.
3. Regression tests for new behavior.
4. `tools.yaml` `version_cmd` / `version_regex` edits derived from real `--help` / `--version` output (paste the raw output, commit the edit).
5. Removing "install:" / "reconkit install" / "reconkit update" residue anywhere in the repo (D4).
6. `config.yaml` `tool_versions` stays removed; do not re-add.
7. Scope-file writes never happen from the CLI (the interactive `[a]` path was removed in D104). The operator edits `scope.yaml`; the CLI only reads it.
8. The `--no-scope` flag, per the scope-bypass amendment in rule 2.
9. `--full` narrowing CLI `--active` to subs+dns+live (dated deviation).
10. Consistency audits across help text, docs and code; fix stale text in the same batch and disclose in the F-map.
11. Adapter implementations (wave 1 onwards) following the existing adapter pattern - no approval needed per adapter, but each adapter gets its own S1-S7, its real `--help` pasted, and a test fixture.

Still requires an owner ruling:

1. Any change to the scope-bypass rule beyond the `--no-scope` amendment.
2. Any change that makes exploitation-category tools fire automatically in any mode (the current rule is the pre-ruling in rule 6: `exploitation: true` tools only run via explicit `--tools`).
3. Any new CLI flag or command not explicitly named in the current batch prompt.
4. Any modification to `scope.yaml` outside the interactive `[a]` path.
5. Any new dependency, module or file outside the batch's stated scope.
6. Unfreezing F1 (dropped-host DNS verdicts) or F2 (`scope.yaml` authorization text).
7. Any change that widens active scanning beyond "typed target plus what is discovered in association with it" (D1).
8. Any change to confidence computation, host-state definitions, or the ALIVE/DNS_ONLY/SHUT_DOWN/DEAD/UNKNOWN criteria.

If a decision is on neither list, stop and ask - one short question, not a paragraph.

## 0e. Contribution invariants (machine-checked)

`tests/test_invariants.py` and the `PIT-68`..`PIT-70` regressions in
`tests/test_engine.py` are the executable form of this section. Run them before
every commit, and add a case whenever you add a rule. Any change by anyone -
owner, friend or agent - must keep these true:

1. **Registry first.** A tool runs only if it has a `tools.yaml` row and an
   adapter in `adapters/__init__.py`. A new tool ships in one batch: registry
   row, adapter, fixture, parser tests (normal, empty, malformed, failure), and
   the docs/09 stage table if the pool changed. No adapter without a row; no row
   without an adapter unless it is an intrusive phase-3 tool (no adapter yet).
2. **The adapter is not trusted.** `parse_output` may return any string. The
   engine canonicalizes every host (`validate_host`: lower-case, no trailing
   dot, no `*.`) and every URL (`normalize_url`: scheme/host case, default port,
   empty path, fragment) before a unique key sees it, and drops any host outside
   the target. Never add a persistence path that writes `record.fqdn` or
   `record.url` raw.
3. **One fact, one row.** The natural keys are `targets(domain)`,
   `subdomains(target_id, fqdn)`, `ports(subdomain_id, ip, port, protocol)` and
   `urls(target_id, url)`. All writes go through the `Store.upsert_*` helpers;
   no raw `INSERT` in the engine or CLI. A schema change needs a migration, a
   migration test and an update to docs/04 in the same commit. `tcp/53` and
   `udp/53` are different rows; never default a protocol away.
4. **Stage handoff is explicit.** `_stage_hosts()` is the one definition of what
   each stage receives. A new stage must state its input (docs/03) and must not
   silently narrow another stage's pool. A stage that runs zero tools must be
   visible as a skip with a reason or a completion gap - never as a successful
   empty stage.
5. **Mock is a contract.** Every adapter needs at least one fixture that
   `parse_output` accepts; `--mock` must never touch the network or spawn a
   process. Mock fixtures are synthetic evidence, and a mock run must not create
   rows a real report shows (D109). A fixture whose hosts are not the mock
   target proves only the parser, not the pipeline. A target with no matching
   fixture is a **skip** (`no fixture for <target>`), never a failed tool: `--mock`
   must exit 0 on any target.
6. **Verify both states.** A database change is verified on an existing
   database **and** on a fresh one (target deleted from the DB, results folder
   removed). "Works on my warm venv/warm DB" is not verification.
7. **Before you commit:** `pytest -q`, `FORCE_TERMINAL=1 pytest -q`,
   `ruff check .`, `ruff format --check .`, `mypy src/reconkit`, plus
   `pytest -q tests/test_invariants.py`. Paste the real output in REVIEW_LOG.
   No new dependency, flag, module or file outside the batch scope without the
   owner's ruling (section 0d).
8. **Never break a documented rule to make a test pass.** Fix the cause; if the
   documented rule is wrong, change the docs first and record the deviation.

## 1. Project context

- **Project:** reconkit
- **Purpose:** A command-line reconnaissance orchestrator for **authorized** security testing. It runs several recon tools per stage, merges and deduplicates their output, scores confidence by how many tools agree, and tracks changes between scans in SQLite.
- **Users:** Penetration testers and bug bounty hunters working inside a written scope.
- **Stack:** Python 3.11+, Typer (CLI), Rich (terminal UI), Pydantic v2 (schemas), asyncio, httpx (HTTP), dnspython, PyYAML, SQLite (stdlib `sqlite3`), pytest, ruff, mypy.
- **Environment:** Linux (Kali or Ubuntu, native) is the only supported platform. Use one canonical checkout: this repository root only. Run checks from this checkout only. Python 3.11+ is required; use the active `.venv` and verify with `python --version`.

## 2. Source of truth

Before any significant change, read the relevant documents:

| Document | Read it when you touch... |
|---|---|
| `docs/01_PRD.md` | features, scope, acceptance criteria |
| `docs/02_CLI_UX.md` | commands, flags, output, colors, exit codes |
| `docs/03_ARCHITECTURE.md` | layers, folders, engine, concurrency, data flow |
| `docs/04_DATABASE.md` | any table, column, query, migration |
| `docs/05_SECURITY.md` | scope gate, subprocess, secrets, tool sources, logging |
| `docs/06_CODE_STYLE.md` | any code you write |
| `docs/07_TESTING.md` | tests, fixtures, `--mock` |
| `docs/08_UX_FLOWS.md` | user journeys and expected terminal output |
| `docs/09_TOOL_CONTRACTS.md` | adapters, schemas, stage registry, confidence rules |
| `docs/10_TOOL_SOURCES.md` | tool reference, sources, doctor |
| `docs/MASTER_PLAN.md` | the part order, autonomy rules and self-review loop |
| `docs/PITFALLS.md` | the live rule set: every known trap, the rule that prevents it, the test that guards it (read at session start) |
| `docs/REVIEW_LOG.md` | evidence for every part: decisions, tests, mutations, check output |
| `tools.yaml` | the registry of every tool (the only list of allowed tools) |
| `config.yaml` | timeouts, thresholds |

Do not contradict these documents. If code and docs disagree, stop and report the conflict.

## 3. Hard rules (never break these)

1. **Subprocess:** run external programs only through `reconkit.core.runner.run_exec(argv: list[str], ...)`. Never `shell=True`, `os.system`, string-built commands, or user input inside a shell string.
2. **Scope gate:** every active stage must call `scope.require_active(target, hosts)` before sending any traffic. Never add a flag, env var, or code path that skips it. No `--i-have-permission` style bypass.

   **Scope bypass amendment (2026-11-17, owner-requested).** No scope-bypass flag has ever existed for the purpose of scanning targets outside a real scope file's declared list. `--no-scope` (added 2026-11-17, owner-requested) is not a bypass - it is an explicit opt-out of the scope file itself. Since D82 (2026-11-19), a missing scope file is no longer equivalent: active runs are refused unless `--no-scope` is passed. Using `--no-scope` produces a loud warning and is recorded in `scan_runs.scope_mode = 'unrestricted_flag'`. It must NEVER be used to scan targets the operator is not authorized for. Reviewers must refuse any new flag whose effect is "ignore an in-scope/out-of-scope list while still reading that list" - that would be a real bypass.
3. **No pacing:** speed control was removed on 2026-11-17 (docs/MASTER_PLAN.md D3). There is no pacer, rate limiter, delay or speed flag; tools start together and run at their own pace. Do not reintroduce artificial throttling.
4. **Registry only:** tools, install sources and download URLs come from `tools.yaml`. Never add `curl | bash`, unverified downloads, or sources not in the registry.
5. **Secrets:** API keys come from `.env` / environment only. Never print, log, store in SQLite, or put them in command lines that get logged.
6. **No exploitation in core:** the `core` and `opt_in` tiers are discovery and inventory only. Tools that send attack payloads belong to the `intrusive` tier (Phase 3). There is no `--intrusive` flag in this build; intrusive tools are not selectable.
7. **Do not invent** CLI flags, tool flags, DB columns, endpoints or business rules. Change the docs first, then the code. If a tool's flags are unknown, check its `--help` output or ask. Do not guess.
8. **Honest User-Agent:** `reconkit/<version>` for our own HTTP requests. No User-Agent rotation or evasion features.
9. **Tests never touch the network or require installed tools.** Use fixtures in `tests/fixtures/`.
10. **Paths:** use `pathlib.Path`. No hard-coded `/` or `\` separators.
11. **The workflow is not optional and not request-dependent.** Whether or not
    the user asks for it, every change must (a) keep the existing pipeline and
    commands working, (b) implement the behavior properly instead of a narrow
    patch that only satisfies the example, (c) add a regression test for every
    new behavior or fixed defect, and (d) update every affected doc
    (`AGENTS.md`, `COMMANDS.md`, `README.md`, `SETUP.md`, `docs/01`-`docs/10`,
    `docs/PROGRESS.md`, `docs/REVIEW_LOG.md`) in the same commit. "Just do X"
    never waives the gate, the tests, the docs, or section 0e's invariants.
12. **Consistency is part of correctness.** `__version__`, `pyproject.toml`, the
    release tag, the banner and README examples, CLI help, flag names, defaults
    and docs must all say the same thing. Change one, grep for the others and
    update them in the same commit; find a mismatch, treat it as a defect and
    fix it then. A tag that disagrees with the package version is a broken
    release, not a cosmetic detail.

## 4. Planning (non-trivial tasks)

1. Read the relevant docs and code.
2. **Find every affected file before editing one.** Grep `src/`, `tests/`,
   `tools.yaml`, `config.yaml`, `scripts/` and every `*.md` (`AGENTS.md`,
   `COMMANDS.md`, `README.md`, `SETUP.md`, `docs/01`-`docs/10`) for the flag,
   command, column, field, constant or term you are about to change. Read each
   hit: the code that consumes the old shape, the tests that assert it, the docs
   that describe it, the registry/config entries and any generated fixture. A
   file you have not inspected is a file you may break; do not edit it until the
   list is complete.
3. List affected files, DB changes, CLI changes, tests needed.
4. Write a short plan (5-10 lines) and state assumptions.
5. Then implement.

## 5. Implementation

- Make focused changes. Reuse existing utilities (`runner`, `store`, `ui`).
- One logical change per commit-sized task. No unrelated refactors.
- Prefer small functions, typed signatures, Pydantic models at every boundary.

## 6. Validation (run before saying "done")

```bash
source .venv/bin/activate
pytest -q
FORCE_TERMINAL=1 pytest -q   # the way GitHub Actions runs it
ruff check .
ruff format --check .
mypy src/reconkit
```

Also run the changed command with `--mock` and report what you ran. Do not claim a check passed unless you ran it.

After changing `pyproject.toml`, a `scripts/*.sh` file or any setup step, also
run `./scripts/setup.sh --check` from the checkout: it must re-sync the venv
(the install stamp, D108) and finish with `reconkit doctor`. Verify setup work
from a clean environment (a fresh venv, or the Kali container check), never
only from the already-warm developer venv.

### 6b. Kali container check (Docker)

Verified on this box on 2026-11-25 (D121). Use it for clean-environment work: a
fresh venv proves a dependency is installed, this proves it on the platform the
project targets.

The daemon is not running by default and the login user is not in the `docker`
group, so `sudo` is needed for `service docker start` and for every `docker` call.
`sudo` wants the box password; pass it on stdin with `sudo -S`. Ask the operator
for the password - never write it into a file, a commit or a logged command
(rule 5, and this repository is public).

```bash
git clone -q . /tmp/rk-kali      # committed state, with .git for the index test
printf '<password>\n' | sudo -S service docker start
printf '<password>\n' | sudo -S docker pull kalilinux/kali-rolling
cat > /tmp/rk-kali/kali_check.sh <<'EOS'
set -e
apt-get update -qq             # the base image ships NO python3
apt-get install -y -qq python3 python3-venv python3-pip python3-yaml git
useradd -m -u 1000 tester      # the suite must not run as root (see below)
chown -R tester /repo
su tester -c "cd /repo && python3 -m venv .venv && .venv/bin/pip install -q -e '.[dev]' && .venv/bin/pytest -q"
su tester -c "cd /repo && .venv/bin/reconkit active -d example.com --mock --no-scope"
EOS
printf '<password>\n' | sudo -S docker run --rm -v /tmp/rk-kali:/repo -w /repo \
  kalilinux/kali-rolling bash /repo/kali_check.sh
```

- **Run as a non-root user.** `scripts/setup.sh` refuses root by design, so the
  seven `tests/test_package.py` setup cases fail under the container's default
  root user. That is the script working, not a regression (D121).
- **Clone, do not `git archive`.** `test_documented_scripts_are_executable` only
  checks the git index when `.git` exists.
- Expected result: `1269 passed, 3 skipped`, ruff/format/mypy clean, mock exit 0.

## 7. Recipe: adding a tool

1. Add an entry to `tools.yaml` (stage, tier, mode, install method, version command).
2. Create `src/reconkit/adapters/<tool>.py` implementing `BaseToolAdapter` (see `docs/09_TOOL_CONTRACTS.md`).
3. Save a real sample output in `tests/fixtures/<tool>/` (sanitized).
4. Add parser tests in `tests/test_adapter_<tool>.py`.
5. Register the adapter in `adapters/__init__.py`.
6. Update `docs/09_TOOL_CONTRACTS.md` stage table if the stage pool changed.

## 8. Documentation updates

Update the matching doc in the same change when you alter: commands/flags, DB
schema, adapter contract, security rules, tool-source/doctor behavior, or config
keys. Then update the rest of the docs that mention the changed behavior - grep
for the flag, command, section number or term and fix every live reference.
Historical evidence in `docs/PROGRESS.md` and `docs/REVIEW_LOG.md` is the
exception: it records what happened and is not rewritten.

Every batch also updates:

1. `docs/PROGRESS.md` RESUME (status + next action) and a dated `D<n>` entry.
2. `docs/REVIEW_LOG.md` with the commands actually run, real output, tests added
   and the gate result.
3. Any doc whose section number, example, table or claim the change invalidated.

### 8b. New tools, dependencies, scripts and setup steps

Adding a moving part is a full-stack change, not just a code change. In the
same batch:

1. `pyproject.toml` declares a new runtime dependency and `scripts/setup.sh`
   installs it. `./scripts/setup.sh` must reach a working state on an
   **existing** checkout, not only a fresh clone: the install stamp makes it
   re-bootstrap when `pyproject.toml` changed (D108), and a re-run with a
   matching venv is a no-op.
2. Every place that lists it is updated: `SETUP.md`, `docs/03`, `docs/07`,
   `docs/09`, `docs/10`, `README.md`, `COMMANDS.md` as applicable. Grep for the
   dependency, script, flag or tool name and fix every live mention.
3. It has a test: an adapter fixture/parser test, or a setup-script regression
   test for the wrapper's behaviour. Shell changes get shell tests; prose alone
   closes nothing.
4. It is verified from a clean environment (fresh venv or the Kali container
   check) and the real output is pasted into `docs/REVIEW_LOG.md`. A dependency
   that only exists in your warm venv is not installed.
5. A script may use only utilities present in a minimal Kali/Debian image
   (`coreutils`, `grep`, `sed`, `git`, `python3`); `awk`, `curl` and `unzip` are
   not guaranteed. Check with the container run before relying on one.

## 9. Conflict handling

If requirements conflict or are ambiguous: do not guess. State the conflict and ask.

## 10. Completion criteria

A task is done only when: requirements are met, all checks in section 6 pass, no unrelated files changed, hard rules in section 3 are respected, and docs are updated where needed.
