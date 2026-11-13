# PROGRESS

Read this after `AGENTS.md`, before touching code. Update it in every commit.

## Environment

- Windows, one canonical checkout: `C:\Users\anshu\Desktop\recon\reconkit` (Git Bash paths: `/c/Users/anshu/Desktop/recon/reconkit`). Do not create a second copy.
- venv `.venv` (Python 3.11 via `uv`); activate with `. .venv/Scripts/activate` in Git Bash. System `python` is 3.10, so always use the venv or `uv`.
- Checks (run all four, report PASS/FAIL with `if cmd; then ...`):

```bash
pytest -q
ruff check .
ruff format --check .
mypy src/reconkit
```

- Pre-commit hook (`.githooks/pre-commit`) runs those checks and requires `docs/PROGRESS.md` when `src/` or `tests/` change. `git config core.hooksPath .githooks` is set by `scripts/bootstrap.sh`. The hook and bootstrap support both `.venv/bin` (POSIX) and `.venv/Scripts` (Windows).
- Push from this checkout: `git push reconkit main` (remote is named `reconkit`, not `origin`).

## Task status

| Task | Status | Commit | Scope |
|---|---|---|---|
| a | done | `f4d81e2` | Package skeleton, pyproject, config.yaml, docs |
| b | done | `0e39f18`, `9423eaa` | `errors`, `models`, `config`, `core/runner` + tests |
| c | done | `45b0ba8` | `core/scope` gate + tests |
| d | next | - | `core/pacing.py`: delays, per-tool rate limits, host ordering, speed presets |
| e | pending | - | `core/store.py`: SQLite schema/queries per `docs/04_DATABASE.md` |
| f | pending | - | `core/consensus.py`: merge records, confidence tiers, disagreements |
| g | pending | - | `core/workspace.py` + `ui/`: raw output files, Rich tables |
| h | pending | - | `cli/` + engine: Typer commands, stage registry, `--mock`, exit codes |
| i | pending | - | Passive adapters (crtsh, certspotter, otx, hackertarget, subfinder, assetfinder, dnspython) |
| j | pending | - | Live/ports adapters (pyprobe, httpx, pyscan, naabu) + `doctor`/installer |

Letters d-j are mapped from `docs/01_PRD.md` section 8 and `docs/03_ARCHITECTURE.md`; adjust if the original task list differs.

## Module map

- `errors.py`: `ScopeError` (3), `ConfigError` (2), `ParseError` (1), `ToolNotInstalled` (4), `ToolFailed`/`ToolTimeout`/`InstallError` (5). Each has `exit_code`.
- `models.py`: enums (`Stage`, `Tier`, `Mode`, `HostState`, `Confidence`, `ToolStatus`), records (`SubdomainRecord`, `HostStatusRecord`, `PortRecord`, `UrlRecord`, `FindingRecord`), `Record`, `ToolResult`, `InstallStatus`, `RunContext`.
- `config.py`: `load_config(path, speed=, delay=)`, `resolve_speed`, `parse_delay`, `SpeedPreset`; `_StrictModel` forbids unknown keys; `Webhook` model.
- `core/runner.py`: `run_exec(argv, timeout=, env=, max_output_bytes=, cwd=)` (only `subprocess` user), `validate_target` (root, strict RFC-1123), `validate_host` (discovered: allows `_`, strips `*.`), `ExecResult`; timeout kills the process group, output capped, env values redacted.
- `core/scope.py`: `load_scope`, `require_active` -> `ActiveCheck(scope, match, hosts, dropped)`, `check_target`, `ip_allowed`, `passive_warning`, `ScopeGate`; `out_of_scope` always wins.

## Deviations and assumptions

- `core/pacing.py` holds a temporary `Pacer` stub so `RunContext` type-checks; task d replaces it.
- `types-PyYAML` added as a dev dependency for strict mypy.
- Enums use `StrEnum` (ruff UP042) instead of the docs' `(str, Enum)`; same values.
- `--delay` applies to both passive and active `tool_delay` (not `host_delay`).
- Bootstrap prefers `uv`; venv is Python 3.11 because WSL `python3` is 3.14.
- Ruff excludes `docs/`; per-file ignores: `tests/**` S101, `tests/fakebin/**` S603, `src/reconkit/core/runner.py` S603 (argv is passed as a list).
- `host_status_history.waf` added for the CDN/WAF marker; port scans require a stored `live` result and skip hosts with `waf` set.
- Exit codes: Scope 3, ToolNotInstalled 4, ToolFailed/Timeout/Install 5, Parse 1, Config 2.
- `scope.yaml` defaults: missing `expires` = never expires; missing `max_speed` = `slow`.
- `check_target` reports `out_of_scope` before expiry (out always wins) and raises `ValueError` on an invalid target.
- `AGENTS.md` environment corrected from Kali to Ubuntu to match the actual machine.
- Consolidated to a single Windows checkout on the Desktop; the WSL clone is no longer used. Pushes come from the Desktop checkout (`git push reconkit main`).
- `_kill_tree` guards on `sys.platform != "win32"` so mypy passes on Windows; the process-group kill itself only runs on POSIX.
- Commits are authored by `Anshul <anshulc4444@gmail.com>` with no AI co-author trailer.

## Open risks

- `scope.yaml` cannot exclude IP ranges (no out-of-scope CIDRs).
- CLI must catch `ValueError` from `check_target`/`validate_target` and exit 2.
- Real `httpx` JSON field names are not verified yet; confirm with `--help`/sample output before writing the adapter.
- Scope behavior is only unit-tested; engine tests must prove an out-of-scope host is never probed.
- Redaction only masks env values; `tool_runs.error` still needs a general `redact()` for tokens and credential-bearing URLs.

## Next task

**Task d: `core/pacing.py`.** Replace the `Pacer` stub with the real pacer: random delays from the speed preset, per-tool rate limits, host ordering/shuffling, and a fake-clock-friendly API. Read `docs/03_ARCHITECTURE.md` and `docs/09_TOOL_CONTRACTS.md` first.
