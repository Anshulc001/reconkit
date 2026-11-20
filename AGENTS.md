# AGENTS.md - Instructions for AI coding agents

Read this file first, every session. It points to the documents in `docs/`.

## 0. Session start (do this first, every session)

1. Read the RESUME block at the top of docs/PROGRESS.md, the last 3 entries of docs/REVIEW_LOG.md, and the part you are on in docs/MASTER_PLAN.md. Read the Known pitfalls table at the top of docs/REVIEW_LOG.md before writing code, and check any new code against it. Then read the `docs/*.md` files for the area you will touch.
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

plan (5-10 lines, assumptions) -> implement -> tests (normal, empty, malformed, failure) -> run checks -> update touched docs -> update `docs/PROGRESS.md` -> commit -> report -> stop.

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
7. Scope-file writes in interactive mode only, with an explicit `y` (the `[a]` option). Never in non-interactive mode.
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

## 4. Planning (non-trivial tasks)

1. Read the relevant docs and code.
2. List affected files, DB changes, CLI changes, tests needed.
3. Write a short plan (5-10 lines) and state assumptions.
4. Then implement.

## 5. Implementation

- Make focused changes. Reuse existing utilities (`runner`, `store`, `ui`).
- One logical change per commit-sized task. No unrelated refactors.
- Prefer small functions, typed signatures, Pydantic models at every boundary.

## 6. Validation (run before saying "done")

```bash
source .venv/bin/activate
pytest -q
ruff check .
ruff format --check .
mypy src/reconkit
```

Also run the changed command with `--mock` and report what you ran. Do not claim a check passed unless you ran it.

## 7. Recipe: adding a tool

1. Add an entry to `tools.yaml` (stage, tier, mode, install method, version command).
2. Create `src/reconkit/adapters/<tool>.py` implementing `BaseToolAdapter` (see `docs/09_TOOL_CONTRACTS.md`).
3. Save a real sample output in `tests/fixtures/<tool>/` (sanitized).
4. Add parser tests in `tests/test_adapter_<tool>.py`.
5. Register the adapter in `adapters/__init__.py`.
6. Update `docs/09_TOOL_CONTRACTS.md` stage table if the stage pool changed.

## 8. Documentation updates

Update the matching doc in the same change when you alter: commands/flags, DB schema, adapter contract, security rules, tool-source/doctor behavior, or config keys.

## 9. Conflict handling

If requirements conflict or are ambiguous: do not guess. State the conflict and ask.

## 10. Completion criteria

A task is done only when: requirements are met, all checks in section 6 pass, no unrelated files changed, hard rules in section 3 are respected, and docs are updated where needed.
