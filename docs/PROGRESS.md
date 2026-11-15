# PROGRESS

Read this after `AGENTS.md`, before touching code. Update it in every commit that changes `src/` or `tests/`, and in every commit that closes named work. Detail lives in `docs/REVIEW_LOG.md`; the trimmed history (task table, module map, per-part deviations, the full risk list and all Part 11 material) is in its **PROGRESS archive (moved 2026-11-15 by the PROGRESS.md trim)** section at the end of that file.

## RESUME HERE

- Status: **PART 12 COMPLETE EXCEPT 12e/12h/12j, WHICH ARE UNDECIDED; THE PROGRESS.md TRIM IS DONE (2026-11-15).** 12a, 12b, 12c, 12d, 12f, 12g, 12i and 12k are implemented, tested and committed, one item per commit, each with a full S1-S7 self-review. Part 11 is closed and the 11f report was delivered.
- Nothing is queued. **Do not start 12e, 12h or 12j without an owner ruling**; their `Decision needed` text in `MASTER_PLAN.md` is still the only statement about them.
- Baseline on this checkout (`/home/kali/Desktop/reconkit`, Python 3.14.8, schema version 4): `687 passed`, `ruff check .` clean, `ruff format --check .` 68 files, `mypy src/reconkit` clean.
- The 12a raw file is now guarded against provider-key leakage by `tests/test_engine.py::test_subfinder_raw_file_never_contains_the_provider_key` (2026-11-15): the real `SubfinderAdapter` under the real registry, a fake child that echoes its `-pc` config - the key is absent from the file on disk, `***` takes its place. No code change was needed (redaction was already in `Workspace.write`); the test plus two mutation proofs are in REVIEW_LOG "Adversarial check: a key echoed by subfinder never reaches the raw file".
- Nothing is pushed: local `main` is ahead of `reconkit/main`, which is still `5fd1d9a`. Push only if the owner asks (`git push reconkit main`).
- Already decided, do not reopen: no scope-bypass flag; consensus lives in `engine.py`; adapters never import `store`/`scope`/`ui`/`cli`; `subjack` replaced by `subzy` + nuclei takeover templates; installer targets Debian-family Linux only; free mode is default, keys only from `.env`; the ports ceiling is permanent (12i).
- Do NOT: new dependencies; new modules/files/CLI commands not in docs/02-03; `assert` in `src/`; new lint/type suppressions; `shell=True`; the whole environment to a child; adapters importing store/scope/ui/cli; consensus outside `engine.py`; pushing.
- Read first: `AGENTS.md`, this block, the last 3 per-part entries in `REVIEW_LOG` (they are above the archive section), and the current part in `docs/MASTER_PLAN.md`.

## Environment

- **Canonical, actively developed checkout: Kali, `/home/kali/Desktop/reconkit`** (native Linux). Every commit after the Windows-to-Kali copy exists only here. `C:\Users\anshu\Desktop\recon\reconkit` is a **stale pre-copy snapshot**, not a mirror: do not treat it as current and do not edit it. Only the owner decides how it is replaced (a real `git clone`, never another copy-paste).
- The exact Windows commit is not determinable from Kali; from the owner's statement it is at or before `cd57fb5`. Read it on the Windows box if it matters.
- Venv: `.venv` (`python3 -m venv`, Python 3.14.8), activate with `source .venv/bin/activate`. The Windows snapshot's own `.venv/Scripts` belongs to that snapshot and is not used here.
- Gate (run all four, report PASS/FAIL with `if cmd; then ... else ... fi`, never `echo $?`; no pipe before the `if`, or use `set -o pipefail`):

  ```bash
  pytest -q
  ruff check .
  ruff format --check .
  mypy src/reconkit
  ```

- Pre-commit hook (`.githooks/pre-commit`) runs those checks and requires `docs/PROGRESS.md` when `src/` or `tests/` change; `git config core.hooksPath .githooks` comes from `scripts/bootstrap.sh`. `scripts/check.ps1` is an optional Windows wrapper, not a required step.
- `.gitattributes` forces LF for `*.py`, `*.md`, `*.yaml`, `*.toml`, `*.sh`, `.githooks/*`; some docs are CRLF on disk and git warns on checkout - that is pre-existing, not an edit.
- Commits are authored by `Anshul <anshulc4444@gmail.com>`; no attribution trailers are added, by anyone or any tool.

## Task status

| Part | Commits | State |
|---|---|---|
| a | `f4d81e2` | done - skeleton, pyproject, `config.yaml`, docs |
| b | `0e39f18`, `9423eaa` | done - `errors`, `models`, `config`, `core/runner` |
| c | `45b0ba8` | done - `core/scope` gate |
| d | `0a3010b` | done - `core/pacing.py` |
| e | `1ba2fd8` | done - `core/store.py`, `redact()`, diff queries |
| f | `89ba34f`, `80ddd93`, `ee06075` | done - all phase-2 adapters |
| g | `36cd3a4` (+ Part 7) | done - wildcard, workspace, engine, confidence, resume, exit codes |
| h | Part 8 commit | done - `ui.py` + `cli.py` |
| i | `9c4319b`, `5df7e98`, `66b117c` | done - `doctor.py` + `installer/` |
| j / 11 | `cc70b15` ... close-out | done - audit, fixes, report delivered |
| 12 | one commit per item | 12a, 12b, 12c, 12d, 12f, 12g, 12i, 12k done; 12e/12h/12j undecided |

There is no `core/consensus.py`: consensus lives in `engine.py`. Order and module names follow docs/01 section 8 and docs/03 section 5. Per-part hashes and full evidence are in `REVIEW_LOG`; the old table is in its archive.

## Deviations and assumptions

Standing ones only; the per-part history (Part 5 - Part 10f, the bug-fix session, the `diff` two-miss rule) is in the `REVIEW_LOG` archive.

- `types-PyYAML` is a dev dependency for strict mypy. Enums use `StrEnum` (ruff UP042) instead of the docs' `(str, Enum)`; same values.
- `--delay` applies to both passive and active `tool_delay` (not `host_delay`).
- Ruff excludes `docs/`; per-file ignores live in `pyproject.toml` with reasons (`tests/**` S101, `tests/fakebin/**` S603, `tests/test_runner.py` S603, `tests/test_binary_adapters.py` S603, `src/reconkit/core/runner.py` S603) plus scoped S311 for the pacer's jitter RNG and the seeded test RNG.
- Exit codes: Scope 3, ToolNotInstalled 4, ToolFailed/Timeout/Install 5, Parse 1, Config 2, usage 2, "every requested tool failed to install" 6. A requested stage that executed no tools exits 5 with a warning (12k); if every requested stage is empty the run exits 4.
- `scope.yaml` defaults: missing `expires` = never expires; missing `max_speed` = `slow`. `check_target` reports `out_of_scope` before expiry, and raises `ValueError` on an invalid target.
- `.env` is the only key source (`Engine.open`); the CLI has no `os.environ`/`getenv`, so shell-exported key variables are ignored.
- 12a: `dns` raw files go to `meta/` because the workspace keeps exactly six directories; `Workspace.write` caps every caller at `runner.MAX_OUTPUT_BYTES`.
- 12b: `subdomains.provenance` defaults to `dns` and the `subs` upgrade is sticky; NEW is first-discovery-sighting, not `first_seen_run`. `status --json` does not expose `provenance`.
- 12c: `duration_s` is adapter-reported; `0.0` means "not measured"; `_run_one` fills its own clock only then.
- 12d: the task text asked for a plain connect failure to store "a different, distinguishable reason", but `MASTER_PLAN.md` 12d and docs/09 say it stores none (no record at all); the documents won. The row rule covers the kept-previous-state case, and a first-run inconclusive `live` pass still writes no row (that is 12e), so the reason lands only for hosts that already have a history row.
- 12f: `cli.py` imports only `configure_redaction` and `redact` from `core.store` (docs/03 section 9); six typed `render_error(str(exc))` sites stay outside its ruled scope.
- 12g: `STALE_AFTER_S = 900` and 12d's `DETAIL_MAX_CHARS = 200` are module constants, not config keys, because the rulings allowed no new config.
- 12k: `scan_runs.status` for an empty stage still reads `completed`; only the warning and the exit code changed.

## Open risks

- **12e (inconclusive live pass writes no history row), 12h and 12j are undecided** and explicitly out of scope until the owner rules. 12e is what would make a first-run `UNKNOWN` reason storable (12d stores it only when a row exists).
- `--json` writes no progress at all (0 bytes of stderr on an 8m25s real run) while docs/02 section 5 says tables and progress stay on stderr: either the doc or the CLI needs to change, docs first.
- Six typed `render_error(str(exc))` sites in `cli.py` (scope check, `diff`, `status`, `doctor`, `install`) still bypass `redact()`; every message is built from our own values today, so no leak is known. Needs its own ruling.
- `libpcap-dev` is absent and `sudo` needs a password here, so the apt prerequisite step has never run live; `naabu` is already installed, which also means `install --all` does not attempt it.
- The sudo-authenticated half of the installer has never run end to end: `massdns`, `amass`, `dig`, `nmap`, `whatweb` and `libpcap-dev` have only ever been exercised as `skipped`.
- **Windows acceptance criteria are unverified anywhere with the current code**: no Windows run since the copy, `uname -a` is Linux, and the Windows `Popen` arguments (PIT-32) were only read in CPython source.
- GitHub release lookups are unauthenticated (60 requests/hour per IP); a 403 fails every `github_release` tool. An authenticated lookup is a Part 11 planning decision, not built.
- `update` re-runs `go install` for every `@latest` go_install tool and reports `installed` rather than `up to date` (byte-identical result; needs a version-probe mechanism).
- `installed_version()` returns the first line of the version text, so `katana` shows `__` and `nuclei` shows `[I…`, which also defeats `_same_version()` for them; `sqlmap` has no `version_cmd` and shows a bare path.
- `BinaryAdapter.binary_path()` prefers any existing file in `~/.reconkit/bin` over `PATH`, so a broken managed copy shadows a working binary (deliberate, documented in docs/10 section 5; mitigation is manual).
- Interactive Ctrl+C does not kill an already-running child (children lead their own process group, PIT-32); `killpg` remains UNTESTED on a real signal.
- `SUDO_DENIAL_MARKERS` includes `no tty present` and `askpass`, neither reproduced live; `_fetch_text`'s 64 KiB default and the non-UTF-8 checksums rejection have no dedicated tests; `requires` (puredns -> massdns) is parsed but not auto-installed.
- `doctor` does not check wordlists (no phase-2 adapter uses one); `dnsutils` is not checked because it appears only in the `dig` install block.
- `scope.yaml` cannot express out-of-scope CIDRs; `in_scope_cidrs` is the only IP gate.
- Unverifiable tool facts, named: OTX's response shape was never observed live (anonymous 429, synthetic fixture); `assetfinder`'s identity probe is inferred from Go `flag` source; `rustscan`'s `-V` and asset pattern come from Kali's package page, not a binary run.
- `subfinder` provider keys cover only certspotter, chaos, github and virustotal; no real `subfinder` run has accepted the generated provider file yet.
- 11c-bis-1: `--help` renders switches as value-taking (`--json <bool>`); `typer>=0.12` has no upper bound and no test pins the rendering. 11c-bis-2: `reconkit --json doctor` accepts a global `--json` and silently ignores it.
- `naabu` is skipped permanently and ports confidence cannot exceed LOW (12i, accepted ceiling - not a defect to fix).
- Wildcard matches are a mark only: docs/09's "exclude from counts" names no count and no code filters it.
- `tech`, `urls` and `vulns` have no adapter for any tool in their pools, so no real tool in those stages has ever run; they exit 5 with the 12k warning.

## Notes for later tasks

- Where things live (the detailed per-function map is in the `REVIEW_LOG` archive): `errors.py` exceptions + exit codes; `models.py` enums and records; `config.py` strict loader; `core/runner.py` the only `subprocess` user (`run_exec`, `validate_target`, `validate_host`); `core/scope.py` the gate; `core/store.py` the only `sqlite3` user (schema/migrations, writes, diff reads, `redact`); `core/pacing.py` the `Pacer`/`RateLimiter`; `core/workspace.py` raw files; `core/wildcard.py`; `adapters/` one module per tool plus `base.py`/`registry.py`; `engine.py` the pipeline, state rule and consensus; `ui.py` rendering; `cli.py` Typer wiring; `doctor.py`; `installer/`.
- `tool_runs` row-frequency: one per executed or skipped tool. `host_status_history`: one row per host per status pass (Part 9 change; docs/04 section 5).
- Fixtures are synthetic unless noted, written to the documented shapes, in `tests/fixtures/<tool>/`: `dnspython`, `pyprobe`, `pyscan` (JSON), `subfinder`, `assetfinder` (text), `httpx`, `naabu` (JSONL), plus real trimmed `crtsh`/`certspotter`/`hackertarget` responses and the synthetic `otx` one. No adapter test touches the network or a real binary.
- Key sources and sign-up URLs live in docs/05 section 6.1, docs/09 and the archived PROGRESS section (subfinder provider config: `docs.projectdiscovery.io/opensource/subfinder/install`, fetched 2026-11-13). Never guess a key name, flag or field; verify it and cite the URL and date (PIT-25).

## Owner verification commands

Run in `/home/kali/Desktop/reconkit` with `.venv` active. These are the checks no session here could perform; nothing in this file claims they passed.

```bash
cd /home/kali/Desktop/reconkit && source .venv/bin/activate
python --version                          # expect 3.11+
reconkit doctor                           # compare with `dpkg -l` / your .env; masscan identity is fixed (PIT-35)
reconkit install --all --no-color         # needs sudo for apt; installs the registry tools
reconkit doctor --json | python -m json.tool   # every tool ready; Keys rows reflect your .env

# Real active run. Fill in_scope_cidrs in scope.yaml first, or pyscan will
# (correctly) block every host:
reconkit run -d <authorized-host> --active --speed slow --tools pyprobe,pyscan --db /tmp/verify.db -v
#   expect: pyprobe rows from real HTTP/TLS; pyscan rows only for addresses inside
#   in_scope_cidrs; with no CIDRs, a pyscan row reading blocked=<n> and no ports.
#   naabu must appear as skipped: "blocked: resolves inside the binary, so
#   in_scope_cidrs cannot be enforced (11c-G-7)".

# killpg / Ctrl+C path (PIT-32, still UNTESTED on a real signal):
reconkit run -d <authorized-host> --active --speed slow --tools httpx --db /tmp/verify.db -v &
# then Ctrl+C, and check `ps -ef | grep httpx` for an orphan process group
```
