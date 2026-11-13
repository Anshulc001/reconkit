# AGENTS.md - Instructions for AI coding agents

Read this file first, every session. It points to the documents in `docs/`.

## 1. Project context

- **Project:** reconkit
- **Purpose:** A command-line reconnaissance orchestrator for **authorized** security testing. It runs several recon tools per stage, merges and deduplicates their output, scores confidence by how many tools agree, and tracks changes between scans in SQLite.
- **Users:** Penetration testers and bug bounty hunters working inside a written scope.
- **Stack:** Python 3.11+, Typer (CLI), Rich (terminal UI), Pydantic v2 (schemas), asyncio, httpx (HTTP), dnspython, PyYAML, SQLite (stdlib `sqlite3`), pytest, ruff, mypy.
- **Environment:** VS Code on Windows connected with the WSL extension to **WSL2 Kali Linux**. The repo lives at `~/reconkit` inside Kali. **Never** at `/mnt/c/...` (slow, SQLite locking problems, CRLF line endings).

## 2. Source of truth

Before any significant change, read the relevant documents:

| Document | Read it when you touch... |
|---|---|
| `docs/01_PRD.md` | features, scope, acceptance criteria |
| `docs/02_CLI_UX.md` | commands, flags, output, colors, exit codes, `--speed` |
| `docs/03_ARCHITECTURE.md` | layers, folders, engine, pacing, data flow |
| `docs/04_DATABASE.md` | any table, column, query, migration |
| `docs/05_SECURITY.md` | scope gate, subprocess, secrets, installer, logging |
| `docs/06_CODE_STYLE.md` | any code you write |
| `docs/07_TESTING.md` | tests, fixtures, `--mock` |
| `docs/08_UX_FLOWS.md` | user journeys and expected terminal output |
| `docs/09_TOOL_CONTRACTS.md` | adapters, schemas, stage registry, confidence rules |
| `docs/10_TOOL_INSTALLER.md` | install, update, doctor |
| `tools.yaml` | the registry of every tool (the only list of allowed tools) |
| `config.yaml` | speeds, timeouts, thresholds |

Do not contradict these documents. If code and docs disagree, stop and report the conflict.

## 3. Hard rules (never break these)

1. **Subprocess:** run external programs only through `reconkit.core.runner.run_exec(argv: list[str], ...)`. Never `shell=True`, `os.system`, string-built commands, or user input inside a shell string.
2. **Scope gate:** every active stage must call `scope.require_active(target, hosts)` before sending any traffic. Never add a flag, env var, or code path that skips it. No `--i-have-permission` style bypass.
3. **Pacing:** all network activity goes through the `Pacer` (`core/pacing.py`). Do not call `asyncio.gather` over network tools or hosts without it. Default speed is `slow`.
4. **Registry only:** tools, install sources and download URLs come from `tools.yaml`. Never add `curl | bash`, unverified downloads, or sources not in the registry.
5. **Secrets:** API keys come from `.env` / environment only. Never print, log, store in SQLite, or put them in command lines that get logged.
6. **No exploitation in core:** the `core` and `opt_in` tiers are discovery and inventory only. Tools that send attack payloads belong to the `intrusive` tier (Phase 3, gated by `--intrusive` + scope entry + typed confirmation).
7. **Do not invent** CLI flags, tool flags, DB columns, endpoints or business rules. Change the docs first, then the code. If a tool's flags are unknown, check its `--help` output or ask. Do not guess.
8. **Honest User-Agent:** `reconkit/<version>` for our own HTTP requests. No User-Agent rotation or evasion features.
9. **Tests never touch the network or require installed tools.** Use fixtures in `tests/fixtures/`.
10. **Paths:** use `pathlib.Path`. No hard-coded `/` or `\` separators, no `/mnt/c` assumptions.

## 4. Planning (non-trivial tasks)

1. Read the relevant docs and code.
2. List affected files, DB changes, CLI changes, tests needed.
3. Write a short plan (5-10 lines) and state assumptions.
4. Then implement.

## 5. Implementation

- Make focused changes. Reuse existing utilities (`runner`, `pacing`, `store`, `ui`).
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

Update the matching doc in the same change when you alter: commands/flags, DB schema, adapter contract, security rules, installer behavior, or config keys.

## 9. Conflict handling

If requirements conflict or are ambiguous: do not guess. State the conflict and ask.

## 10. Completion criteria

A task is done only when: requirements are met, all checks in section 6 pass, no unrelated files changed, hard rules in section 3 are respected, and docs are updated where needed.
