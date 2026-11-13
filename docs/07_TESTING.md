# Testing

## 1. Testing Goals

Critical functionality to protect:
- **Scope gate** (active stages refuse out-of-scope, missing, expired or disallowed scope).
- **Pacing** (delays, shuffling, parallel limits, rate flags per speed).
- **Parsers** for every adapter (real sample outputs).
- **Consensus and confidence** (merge, source counts, UNCONFIRMED on disagreement).
- **Host state transitions** (ALIVE / DNS_ONLY / SHUT_DOWN / DEAD) and diff.
- **Installer logic** (registry parsing, checksum verification, dry-run) without network.
- **Subprocess safety** (argument lists only, input validation).

## 2. Test Types

### Unit tests
Pure logic with fixtures: parsers, scope matching, pacing with a fake clock, confidence rules, wildcard detection, store queries on an in-memory/temp SQLite DB.

### Integration tests (no network)
CLI invoked through Typer's `CliRunner` with `--mock`, a temp workspace and temp DB. Fake binaries (small scripts in `tests/fakebin/`) test the runner, timeouts and failure handling.

### Live smoke tests (WSL2 Kali only, manual or marked)
`pytest -m live` runs real tools against a domain you own or a lab target. Excluded from the default run. Never part of CI.

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
  fixtures/
    subfinder/  assetfinder/  crtsh/  certspotter/  otx/  hackertarget/
    httpx/  naabu/  dns/
  fakebin/               # tiny fake executables for runner tests
  test_scope.py
  test_pacing.py
  test_runner.py
  test_store_diff.py
  test_consensus.py
  test_wildcard.py
  test_adapter_<tool>.py
  test_cli_passive.py  test_cli_live.py  test_cli_ports.py
  test_installer.py
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
Expected: `[NEW]`, `[GONE]`, `[WENT DOWN]` shown correctly.

**Flow: tool failure**
1. One adapter fixture raises timeout
Expected: other results kept, run status `partial`, exit code 5.

**Flow: slow speed timing**
1. Run with fake clock and seeded RNG at `slow`
Expected: delays between tools in [5,30], parallel limit 1, hosts shuffled.

## 6. Coverage

- Target: ~85% on `core/`, `engine.py`, `adapters/`; CLI layer smoke-tested.
- Prioritize: scope gate, subprocess safety, pacing, consensus, store diff, installer verification.

## 7. Commands

```bash
Test:        pytest -q
Live tests:  pytest -m live -q        # WSL2 Kali only, authorized target
Lint:        ruff check .
Format:      ruff format --check .
Type check:  mypy src/reconkit
```

## 8. Rules

- Unit and default integration tests must not use the network or installed tools.
- Every new adapter ships with a real (sanitized) fixture and parser tests, including an empty-output and a malformed-output case.
- Seed randomness (`random.Random(1234)`) in tests that involve jitter.

## 9. Definition of Done

- [ ] `pytest -q` passes
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `mypy src/reconkit` passes
- [ ] Changed commands verified with `--mock`
- [ ] Critical flow tests above pass
- [ ] No blocking errors; no unrun checks claimed as passed
