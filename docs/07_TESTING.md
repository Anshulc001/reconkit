# Testing

## 1. Testing Goals

Critical functionality to protect:
- **Scope gate** (active stages refuse out-of-scope, missing, expired or disallowed scope).
- **Parsers** for every adapter (real sample outputs).
- **Consensus and confidence** (merge, source counts, UNCONFIRMED on disagreement).
- **Host state transitions** (ALIVE / DNS_ONLY / SHUT_DOWN / DEAD) and diff.
- **Installer logic** (registry parsing, checksum verification, dry-run) without network.
- **Subprocess safety** (argument lists only, input validation).

## 2. Test Types

### Unit tests
Pure logic with fixtures: parsers, scope matching, confidence rules, wildcard detection, store queries on an in-memory/temp SQLite DB.

### Integration tests (no network)
CLI invoked through Typer's `CliRunner` with `--mock`, a temp workspace and temp DB. Fake binaries (small scripts in `tests/fakebin/`) test the runner, timeouts and failure handling.

### Live smoke tests (Kali/Ubuntu only, manual)
The `live` marker is registered in `pyproject.toml`, but no live test is checked in yet. A real authorized-target run is performed manually on Kali/Ubuntu, never in the default run or CI.

## 3. Tools

| Purpose | Tool |
|---|---|
| Runner | pytest, pytest-asyncio |
| CLI tests | `typer.testing.CliRunner` |
| HTTP mocking | `respx` (httpx) or `pytest-httpx` |
| Time and randomness | injected fake sleep and seeded `random.Random` |
| Lint / format / types | ruff, mypy |

## 4. Test File Structure

```
tests/
  conftest.py            # temp dirs, temp DB, fake scope files, fake clock
  fixtures/              # sanitized real tool output, one directory per tool
  fakebin/               # tiny fake executables for runner/version-probe tests
  test_adapters.py       # HTTP adapters: parsing, caps, keys, mock mode
  test_binary_adapters.py
  test_python_adapters.py
  test_engine.py         # stage order, tiers, scope, consensus, host state, resume
  test_scope.py  test_runner.py  test_config.py
  test_store.py  test_wildcard_workspace.py  test_ui.py  test_cli.py
  test_branding.py       # banner, credits and live version (D107)
  test_logging.py        # levels, UTC timestamps, redaction, unique log paths (D107)
  test_pdf_report.py     # PDF sections, privacy mode, 600-host pagination (D107)
  test_registry.py  test_package.py
  test_doctor.py
  test_tools_registry.py  # tools.yaml -> ToolSpec, version probes, source: strings
  test_no_shell_true.py  # scans src for shell=True / os.system
```

## 5. Critical Flows to Verify

**Flow: passive scan with `--mock`**
1. Run `reconkit passive -d example.com --mock`
2. Fixtures load for every Phase 2 passive adapter
3. Results merge; HIGH/MEDIUM/LOW appear as expected
Expected: table printed, DB rows created, exit code 0.

**Flow: active scan without scope**
1. Run `reconkit live -d example.com --active` with no `scope.yaml`
Expected: no tool runs, exit code 3, clear message.

**Flow: out-of-scope host removed**
1. Scope allows `*.example.com`, excludes `admin.example.com`
2. Stored subdomains include `admin.example.com`
Expected: `admin.example.com` never probed; summary counts it as out of scope.

**Flow: diff after second run**
1. Run twice with fixtures A then B (B adds one host, removes one, one goes down)
Expected: `NEW`, `GONE` and `STATE` (`old -> new`) shown correctly; port changes use `PORT OPEN` / `PORT CLOSED`.

**Flow: tool failure**
1. One adapter fixture raises timeout
Expected: other results kept, run status `partial`, exit code 5.

## 6. Coverage

- No coverage threshold is enforced. The suite prioritizes the scope gate, subprocess safety, consensus, store diff and tool detection (the registry probe and `doctor`).
- `test_tools_registry.py` replaced the five installer test files on 2026-11-17: it keeps the 22 registry/probe tests (adapted from `InstallPlan` to `ToolSpec`) and re-expresses the 12 deleted plan/method tests as `source:` validation. `tests/test_config.py` gained the one-source-of-truth test for `bin_dir()`.

## 7. Commands

```bash
Test:        pytest -q
Live tests:  pytest -m live -q        # Kali/Ubuntu only, authorized target; none checked in yet
Lint:        ruff check .
Format:      ruff format --check .
Type check:  mypy src/reconkit
```

## 8. Rules

- Unit and default integration tests must not use the network or installed tools.
- Every new adapter ships with a real (sanitized) fixture and parser tests, including an empty-output and a malformed-output case.
- Seed randomness (`random.Random(1234)`) in tests that involve jitter.
- Help assertions read `help_text(result)`, which strips ANSI styling, and invoke with `env=HELP_ENV` (`COLUMNS=120`). On GitHub Actions Typer sets `FORCE_TERMINAL`, so Rich styles the help even into a captured pipe and splits a name like `--only-alive` across escape runs; a raw substring check misses it even though the render is fine. `terminal_width=` is ignored by Typer's Rich help console — do not rely on it. Also assert help from a scope-free `tmp_path`, never from the repository's local `scope.yaml` (D88, D91, D92).
- A CLI test that runs `--active` or `--full` either passes `--no-scope` (when it is testing mode/flag wiring) or `monkeypatch.chdir(tmp_path)` so the scope written by `make_config` is found; never rely on the repository's local `scope.yaml` (D89).
- Adapter tests inject `finder`/`which` for companion binaries (`puredns` -> `massdns`) and set `ctx.workspace` to `tmp_path`; no test may require a system-installed tool or write under the repository's `workspaces/` (D90).

## 9. Definition of Done

- [ ] `pytest -q` passes
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `mypy src/reconkit` passes
- [ ] Changed commands verified with `--mock`
- [ ] Critical flow tests above pass
- [ ] No blocking errors; no unrun checks claimed as passed
