# PROGRESS

Read this after `AGENTS.md`, before touching code. Update it in every commit that changes `src/` or `tests/`, and in every commit that closes named work. Detail lives in `docs/REVIEW_LOG.md`; the trimmed history (task table, module map, per-part deviations, the full risk list and all Part 11 material) is in its **PROGRESS archive (moved 2026-11-15 by the PROGRESS.md trim)** section at the end of that file.

## RESUME HERE

- Status: **Project code work complete at `9dfbeec`; the capstone exited 5 for one measured reason.** `reconkit run -d testfire.net --active --phase-timeout 300` (temp config, `url_probe.max_urls: 20`) finished `36 hosts: 8 ALIVE, 26 DEAD, 2 UNKNOWN | tools: 29 ok, 1 gap, 0 failed, 2 skipped, 1 timeout` and exit **5**: `gau` was still running when the `urls` stage hit its 300 s deadline, and a timeout is a hard failure by ruling. Every other non-ok row was a gap (`otx: rate limited (HTTP 429)`) or a selection skip (`chaos`, `github_subdomains`: no API key). Remaining work is owner decisions, not code: see "Open risks" and the three questions below.
- Previous status: **BATCH 2026-11-18 COMPLETE (Parts D-H) + acceptance follow-up.** Suite 908. The follow-up added the three D30 tests and the missing D29 stage-budget test, the missing `COMMANDS.md` probe-only note, and fixed a real bug the missing tests hid: the mock DB default did not create `~/.reconkit`, so a fresh machine failed with `unable to open database file`. Evidence in REVIEW_LOG "follow-up".
- Previous status: **BATCH 2026-11-18 COMPLETE (Parts D-H).** D28 rulings recorded, D29 double-ceiling cleanup, D30 mock isolation, D31 withdrawn (premise disproved), D32 redaction routing. Suite 898 -> 903. Next action: none; report.
- Previous status: **BATCH 2026-11-18 (Part F) DONE: D30 mock isolation.** Suite 899. Next action: Part G (mock ALIVE).
- Previous status: **BATCH 2026-11-18 (Part E) DONE: D29 double-ceiling cleanup.** `urls.urlfinder_max_s` default 0; saturation logged. Suite 898 -> 899. Next action: Part F (mock isolation).
- Previous status: **BATCH 2026-11-18 (Part D) DONE: four rulings recorded (D28), push-state line made durable.** Docs only. D28 added to MASTER_PLAN and PROGRESS; four Open-risks items closed by D28; probe-only-exits-4 note added to docs/02. D.3 found no current-tense contradiction beyond the deferred urlfinder.py docstring (Part E). Next action: Part E (D27 double-ceiling cleanup).
- Previous status: **BATCH 2026-11-18 (Part C) DONE: stale claims reconciled, four rulings written down.** Only one of the four stale claims was still live: the push state. `reconkit/main` is `a49e4b5` and local `main` is ahead of it (10 commits at `aadd7b5`), so the 2026-11-18 "both refs are level" sentence was wrong and is now the verified fact - **the batch prompt's premise that HEAD is pushed did not hold, and no push was attempted**. The other three were already closed by the previous batch's Part 1 and are covered by dated notes in place: the `tech`/`urls`/`vulns` "no adapter" risk (`## Open risks

Real, current items only. Everything else this file used to list is either closed (see the dated notes in
`docs/REVIEW_LOG.md`) or is one of the three owner questions below.

- **The `urls` stage deadline decides whether a real scan exits 0.** Capstone 2026-11-19 (`--phase-timeout 300`,
  testfire.net): 29 tools `ok`, 1 gap (`otx` 429), 2 selection skips, and `gau` still running when the stage hit 300 s
  -> `timeout` -> exit **5**. `gau` normally answers in ~31 s (D20), so this is archive.org latency, not a code defect;
  whether the `urls` stage should get its own, larger budget (or whether a per-tool timeout on an archive query should
  read as a gap) is a ruling, not a fix.
- **A transient identity-probe failure silently drops a tool from every scan (D42).** `amass` read `wrong program` once
  at the start of the 2026-11-19 batch and `yes / ok` in ten consecutive probes afterwards. The consequence is quiet: a
  tool that fails its 10 s probe is `skipped (not installed)` and the work simply does not happen. A retry or a longer
  `IDENTITY_TIMEOUT` would be a behaviour change and needs a ruling.
- **`shots` cannot run on this box.** `/usr/bin/chromium` exists but `gowitness` execs `google-chrome`; `doctor` reports
  `chromium missing` and the stage is a gap (D35). Environment, not code - installing a Chrome-family binary is the fix.
- **`libpcap-dev` is absent**, so `masscan`'s build path is unverified here; the adapter is proven only with the
  installed binary and a real run still needs root (historical note kept because it is still true).
- **The interactive pty re-exercise is still outstanding** (B7, deferred by R9): the automated suite covers the
  non-interactive branches of the `[a]` scope-write prompt, and no scripted pty session has driven it end to end.

## Three questions for the owner (2026-11-19)

Questions, not work items. Each one blocks something that cannot be decided from the code or the docs.

| # | Question | What it needs |
|---|---|---|
| 1 | **Out-of-scope CIDRs (B5).** What should `scope.yaml` be able to express so an authorized *range* is legal - an `in_scope_cidrs` list beside the domain list, a per-target block, or something else? | A schema shape for the file, and whether the gate should treat a CIDR grant as "address allowed" or only as "resolvable target". Both are scope-gate changes and owner-only. |
| 2 | **masscan/smap on a real large range (B6).** Is a real-network test against a large range authorized, and against which block? | An explicit written authorization naming the range, because nothing in `scope.yaml` can express one today (see 1). testfire.net cannot answer this question honestly. |
| 3 | **Interactive pty re-exercise (B7).** Is a scripted pty session (pexpect/`script`) with a canned `y` answer enough evidence for the `[a]` scope-write prompt, or does that flow need a human at a real terminal once more? | Yes/no on the evidence standard; the automation itself is small. |

## Notes for later tasks

- Where things live (the detailed per-function map is in the `REVIEW_LOG` archive): `errors.py` exceptions + exit codes; `models.py` enums and records; `config.py` strict loader; `core/runner.py` the only `subprocess` user (`run_exec`, `validate_target`, `validate_host`); `core/scope.py` the gate; `core/store.py` the only `sqlite3` user (schema/migrations, writes, diff reads, `redact`); `core/pacing.py` the `Pacer`/`RateLimiter` (removed 2026-11-17, MASTER_PLAN D3 - no such module now); `core/workspace.py` raw files; `core/wildcard.py`; `adapters/` one module per tool plus `base.py`/`registry.py`; `engine.py` the pipeline, state rule and consensus; `ui.py` rendering; `cli.py` Typer wiring; `doctor.py`; `core/toolcheck.py` the installed-copy/version probe (the installer was deleted 2026-11-17, MASTER_PLAN D4 - no such package now).
- `tool_runs` row-frequency: one per executed or skipped tool. `host_status_history`: one row per host per status pass (Part 9 change; docs/04 section 5).
- Fixtures are synthetic unless noted, written to the documented shapes, in `tests/fixtures/<tool>/`: `dnspython`, `pyprobe`, `pyscan` (JSON), `subfinder`, `assetfinder` (text), `httpx`, `naabu` (JSONL), plus real trimmed `crtsh`/`certspotter`/`hackertarget` responses and the synthetic `otx` one. No adapter test touches the network or a real binary.
- Key sources and sign-up URLs live in docs/05 section 6.1, docs/09 and the archived PROGRESS section (subfinder provider config: `docs.projectdiscovery.io/opensource/subfinder/install`, fetched 2026-11-13). Never guess a key name, flag or field; verify it and cite the URL and date (PIT-25).

## Owner verification commands

Run in `/home/kali/Desktop/reconkit` with `.venv` active. These are the checks no session here could perform; nothing in this file claims they passed.

```bash
cd /home/kali/Desktop/reconkit && source .venv/bin/activate
python --version                          # expect 3.11+
reconkit doctor                           # compare with `dpkg -l` / your .env; masscan identity is fixed (PIT-35)
# obtain any missing tool yourself (reconkit installs nothing since 2026-11-17):
#   docs/10_TOOL_SOURCES.md section 2 is the reference - provenance per tool, not instructions
reconkit doctor --json | python -m json.tool   # every tool ready; Keys rows reflect your .env

# Real active run. Fill in_scope_cidrs in scope.yaml first, or pyscan will
# (correctly) block every host:
reconkit run -d <authorized-host> --active --tools pyprobe,pyscan --db /tmp/verify.db -v
#   expect: pyprobe rows from real HTTP/TLS; pyscan rows only for addresses inside
#   in_scope_cidrs; with no CIDRs, a pyscan row reading blocked=<n> and no ports.
#   naabu (2026-11-17, MASTER_PLAN D2): with no scope file it runs like any other
#   active tool on the discovered hostnames; with a scope file present it runs
#   only on the IPs reconkit resolved and verified against in_scope_cidrs, so a
#   target that resolves outside them is skipped and, when nothing verifies, its
#   row reads "blocked: no in-scope IP for any target".

# killpg / Ctrl+C path (PIT-32, still UNTESTED on a real signal):
reconkit run -d <authorized-host> --active --tools httpx --db /tmp/verify.db -v &
# then Ctrl+C, and check `ps -ef | grep httpx` for an orphan process group
```
