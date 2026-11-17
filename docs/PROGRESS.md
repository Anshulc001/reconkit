# PROGRESS

Read this after `AGENTS.md`, before touching code. Update it in every commit that changes `src/` or `tests/`, and in every commit that closes named work. Detail lives in `docs/REVIEW_LOG.md`; the trimmed history (task table, module map, per-part deviations, the full risk list and all Part 11 material) is in its **PROGRESS archive (moved 2026-11-15 by the PROGRESS.md trim)** section at the end of that file.

## RESUME HERE

- Status: **PART 12 AND PART 13 ARE COMPLETE (2026-11-16).** Part 12 closed on 2026-11-15 (12a-12k). Part 13 - the interactive scan mode, stderr progress and per-domain saved reports - is implemented, tested, self-reviewed (S1-S7) and committed, with docs written first. Phase 1 of the same session (the `docs/tool_manuals/` library) is closed in `8dc2829`.
- What Part 13 changed, in one line: a scan command with **no** `-d`/`-l` **and** a real terminal asks five questions and then runs the ordinary scan inputs; a domain file becomes the ordinary `-l` path (one full scan and one `results/<domain>/<UTC stamp>/` folder per domain, `report.txt` + `report.json`); progress now goes to stderr for every mode except `--silent`, including `--json`. Every flag-based invocation is unchanged, including no prompts and no report folders (tests `test_a_flagged_run_never_asks_a_question`, `test_a_listed_run_never_asks_a_question`, `test_a_flagged_run_writes_no_report_folder`).
- All four owner tasks (2026-11-17) are implemented, tested and committed: D1 `c99eaee`, D2 `6642ee4`, D3 `6a2db4d`, the interactive-mode fix `10b3a48`, Task 4 docs with this entry. Nothing else is queued; Part 13's uncertainties stay under "Open risks".
- The verification follow-up (2026-11-17) closes the eight findings from the accepted 4-task batch (`F1`-`F8`, report section V-UNEXPECTED) in one commit: `--active` help text, the owner verification commands, five historical pacing markers, the core package docstring, two dead `pyproject` ignores, the AGENTS `config.yaml` row, two tool manuals and the D3 test counts. Documentation and help text only - no behaviour, flag, schema or test change.
- **Owner-requested behavior changes (2026-11-17):** D1 (no scope file = unrestricted active scanning) is committed (`c99eaee`), D2 (naabu is scope-mode dependent) is committed (`6642ee4`), D3 (all speed/throttle control removed) is committed with this entry, and Task 4 (the end-to-end interactive-flow section in docs/02) is the next action.
- Baseline on this checkout (`/home/kali/Desktop/reconkit`, Python 3.14.8, schema version 5): `714 passed`, `ruff check .` clean, `ruff format --check .` 67 files, `mypy src/reconkit` clean (35 source files).
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
| d | `0a3010b` | done - `core/pacing.py` (removed 2026-11-17, MASTER_PLAN D3; the commit stays in history) |
| e | `1ba2fd8` | done - `core/store.py`, `redact()`, diff queries |
| f | `89ba34f`, `80ddd93`, `ee06075` | done - all phase-2 adapters |
| g | `36cd3a4` (+ Part 7) | done - wildcard, workspace, engine, confidence, resume, exit codes |
| h | Part 8 commit | done - `ui.py` + `cli.py` |
| i | `9c4319b`, `5df7e98`, `66b117c` | done - `doctor.py` + `installer/` |
| j / 11 | `cc70b15` ... close-out | done - audit, fixes, report delivered |
| 12 | one commit per item | 12a, 12b, 12c, 12d, 12e, 12f, 12g, 12h, 12i, 12j, 12k done - Part 12 complete |
| 13 | one commit | interactive scan mode, stderr progress, per-domain saved reports - done 2026-11-16 |

There is no `core/consensus.py`: consensus lives in `engine.py`. Order and module names follow docs/01 section 8 and docs/03 section 5. Per-part hashes and full evidence are in `REVIEW_LOG`; the old table is in its archive.

## Deviations and assumptions

Standing ones only; the per-part history (Part 5 - Part 10f, the bug-fix session, the `diff` two-miss rule) is in the `REVIEW_LOG` archive.

- `types-PyYAML` is a dev dependency for strict mypy. Enums use `StrEnum` (ruff UP042) instead of the docs' `(str, Enum)`; same values.
- `--delay` applied to both passive and active `tool_delay` (not `host_delay`); the flag and the pacer were removed on 2026-11-17 (MASTER_PLAN D3), so this line is history.
- Ruff excludes `docs/`; per-file ignores live in `pyproject.toml` with reasons (`tests/**` S101, `tests/fakebin/**` S603, `tests/test_runner.py` S603, `tests/test_binary_adapters.py` S603, `src/reconkit/core/runner.py` S603). The two scoped S311 ignores (the pacer's jitter RNG and the seeded test RNG) were removed with the module on 2026-11-17 (MASTER_PLAN D3).
- Exit codes: Scope 3, ToolNotInstalled 4, ToolFailed/Timeout/Install 5, Parse 1, Config 2, usage 2, "every requested tool failed to install" 6. A requested stage that executed no tools exits 5 with a warning (12k); if every requested stage is empty the run exits 4.
- `scope.yaml` defaults: missing `expires` = never expires; missing `max_speed` = `slow`. `check_target` reports `out_of_scope` before expiry, and raises `ValueError` on an invalid target.
- `.env` is the only key source (`Engine.open`); the CLI has no `os.environ`/`getenv`, so shell-exported key variables are ignored.
- 12a: `dns` raw files go to `meta/` because the workspace keeps exactly six directories; `Workspace.write` caps every caller at `runner.MAX_OUTPUT_BYTES`.
- 12b: `subdomains.provenance` defaults to `dns` and the `subs` upgrade is sticky; NEW is first-discovery-sighting, not `first_seen_run`. `status --json` does not expose `provenance`.
- 12c: `duration_s` is adapter-reported; `0.0` means "not measured"; `_run_one` fills its own clock only then.
- 12d: the task text asked for a plain connect failure to store "a different, distinguishable reason", but `MASTER_PLAN.md` 12d and docs/09 say it stores none (no record at all); the documents won. The row rule covers the kept-previous-state case. 12e has since closed the other half: a first-run inconclusive `live` pass that got a record now writes its own `UNKNOWN` row, so the reason lands there too.
- 12f: `cli.py` imports only `configure_redaction` and `redact` from `core.store` (docs/03 section 9); six typed `render_error(str(exc))` sites stay outside its ruled scope.
- 12g: `STALE_AFTER_S = 900` and 12d's `DETAIL_MAX_CHARS = 200` are module constants, not config keys, because the rulings allowed no new config.
- 12k: `scan_runs.status` for an empty stage still reads `completed`; only the warning and the exit code changed.
- 12h: the SQLite persistence block stays on the event loop by ruling; docs/03 section 11 states the reason (single writer, `check_same_thread` on the main-thread connection) and the bound (one transaction per stage). Both `scope.yaml` reads - the active gate and the `ip_allowed` predicate - moved to `to_thread`, not just the gate.
- 12j: `version_regex` is a `tools.yaml` field next to `version_cmd` (not a config key); it is compiled and rejected at registry load, the first capture group is the version, and the old first-line behaviour is the fallback.
- **2026-11-16 (Phase 1, docs only):** a new documentation tree
  `docs/tool_manuals/` (8 files: `README.md` plus one per stage) was created
  outside `docs/02`/`docs/03`. This is the documentation-only exception the
  owner granted for the tool-manual library. `docs/09` section 9 gained a
  pointer to it; no `src/` file changed in that phase.
- **2026-11-16 (Phase 1):** the whole `vulns` stage (nuclei, subzy, dnsreaper,
  nikto, ffuf, dalfox, crlfuzz, sqlmap) is deferred as "recon-only scope for now,
  revisit later": no manual, no install, no test. Reading the task's "vulnerability
  scanning tools" as the stage `tools.yaml` itself calls "Takeover and exposure/
  misconfiguration checks" is an interpretation the owner may narrow.
- **2026-11-16 (Phase 1):** `reconkit install gowitness` was run (go_install, no
  sudo) so the tool could be documented; `rustscan` was attempted and failed on
  the registry placeholder asset name, which is flagged in the manuals README
  instead of being patched. No sudo command was run in either phase.
- **2026-11-16 (Part 13 / Phase 2), new config key:** `results_dir: results` in
  `config.yaml` and `AppConfig.results_dir` (with a default, so a config file
  written before Part 13 still loads). Store directory for the saved reports;
  `results/` is in `.gitignore`.
- **2026-11-16 (Part 13), no new module:** the report writer (`REPORT_FIELDS`,
  `report_fields`, `field_value`, `format_field_value`, `report_directory`,
  `report_document`, `report_text`, `write_field_report`) lives in the existing
  `ui.py`, and the five prompts plus `_MODE_STAGES`/`_InteractivePlan` live in the
  existing `cli.py`, instead of adding `report.py`/`interactive.py` that docs/02-03
  do not name. Both are documented in docs/02 section 2b/5 and docs/03.
- **2026-11-16 (Part 13), behaviour change:** `--json` now writes progress to
  stderr (docs/02 `### Progress` changed before the code). Only `--silent`
  suppresses it. stdout stays exactly one JSON document.
- **2026-11-16 (Part 13), three existing tests changed** (none removed), each
  because of that one documented change: `test_mock_json_is_one_valid_document_and_exit_zero`
  and `test_mock_scope_denial_returns_three` in `tests/test_cli.py` now assert
  `"subs: running" in result.stderr` instead of `result.stderr == ""`;
  `tests/test_ui.py::test_progress_is_suppressed_for_silent_and_json_modes` was
  renamed `test_progress_is_suppressed_only_in_silent_mode` and asserts the new
  message shape (`"subs: running 3 tool(s)"`, `"(4s)"`). All other assertions in
  those tests are unchanged.
- **2026-11-16 (Part 13), stored fields with defaults:** `HostSnapshot` gained
  `source_count`/`ips`/`title`/`location`/`tech` (defaulted) and
  `Store.host_rows()` now LEFT JOINs the latest `host_status_history` row once
  instead of running two correlated subqueries. The host table and the `--json`
  host shape are unchanged; the new values are only used by the report.
- **2026-11-17 (owner-requested deviation D1), no scope file means
  unrestricted active scanning.** With no scope file at the resolved path
  (default `./scope.yaml`, `--scope` overrides), `--active` active/full runs scan
  the operator's `-d`/`-l` targets and everything discovered under them with no
  auto-derived scope object, no implicit restriction and no exit 3. A scope file
  that IS present keeps the unchanged gate and is only ever read. Docs 02/03/05
  and `MASTER_PLAN.md` "Dated deviations" record it. Changed test:
  `test_mock_scope_denial_returns_three` became
  `test_mock_run_without_a_scope_file_is_unrestricted` (it asserted the removed
  exit 3), and `test_mock_scope_file_denial_returns_three` keeps the exit-3
  coverage against a real file. New: `test_no_scope_file_runs_active_stages_unrestricted`,
  `test_a_present_scope_file_is_enforced_exactly_as_before`,
  `test_no_scope_file_never_loads_or_derives_a_scope_object`.
- **2026-11-17 (owner-requested Task 4), the interactive flow is documented end
  to end.** docs/02 section 2b gained "The flow end to end (2026-11-17)": launch,
  the five questions with their exact prompt text, the plan echo, the per-target
  run and report folder, the no-scope-file vs scope-file-present branch (naabu's
  resolve-and-verify path), and the statement that no speed option exists. Docs
  only; no code or test changed.
- **2026-11-17 (D1 follow-up), interactive mode never assumes a scan mode.**
  The `Scan mode: passive, active or full` question had typer's `default="passive"`
  and turned a bad word into exit 2; the owner's wording is "must not proceed
  until a valid choice is made, no silent default, no assuming passive". It now
  prints `invalid scan mode '...'` and asks again until one of the three words is
  typed, and end of input at that question cancels with exit 2 before any engine
  run. docs/02 section 2b point 3 states it. Changed test: the
  `("example.com\nn\nsideways\nall\nn\n", "invalid scan mode")` case was removed
  from the `test_a_bad_answer_is_a_usage_error` parametrization and replaced by
  `test_the_mode_is_asked_until_a_valid_answer_is_typed` (three prompt renders,
  the run starts on the third answer) and `test_no_mode_answer_means_no_scan`
  (EOF at the mode question, engine never called); the other three parametrized
  cases are unchanged.
- **2026-11-17 (owner-requested deviation D2), naabu is scope-mode dependent.**
  No scope file: naabu is an ordinary active tool (no pre-resolution gate, no
  IP-only restriction, no skip). Scope file present: the engine resolves each
  in-scope target itself (`adapters.pyscan.default_resolve`, injectable), checks
  every address against `in_scope_cidrs` via the same `ip_allowed` predicate
  `pyscan` uses, and passes naabu only verified IPs through `-host` - never a
  bare domain. Resolution failure / out-of-scope target is omitted; if nothing
  verifies, naabu is a recorded `blocked:` skip. Passive: never runs. 11c-G-7's
  permanent block is superseded (MASTER_PLAN D2). Real `naabu -h` confirms
  `-host string[]  hosts to scan ports for (comma-separated)`; a real
  `127.0.0.1` scan confirms IP input. Changed tests: `test_naabu_stays_blocked_because_it_resolves_inside_the_binary`
  -> `test_naabu_is_selectable_in_active_mode` (asserted the removed block);
  `test_aggressive_yes_adds_the_ports_stages` (assertion text follows the
  reworded notice); `test_aggressive_no_leaves_the_plan_alone` (now supplies a
  present scope file instead of relying on the checkout's git-ignored one);
  `test_no_scope_file_never_lets_an_active_tool_run` ->
  `test_a_present_scope_file_blocks_an_out_of_scope_interactive_target` (same
  reason). New: the six `test_*_naabu*`/`test_scope_file_*` cases in
  `tests/test_engine.py`, `test_naabu_accepts_verified_ip_inputs`.
- **2026-11-17 (owner-requested deviation D3), all speed/throttle control is
  removed.** `--speed`, `--delay`, the `fast` typed confirmation, the `speeds`
  block and `default_speed` in `config.yaml`, `core/pacing.py` (pacer, rate
  limiter, shuffle, rate-flag table) and `tools.yaml`/registry `rate_flag` are
  gone; `RunContext` carries no `pacer`/`limiter`/`speed`; every stage starts
  its tools together under `asyncio.gather` with no sleep or semaphore; schema
  5 drops `scan_runs.speed`. A `scope.yaml` `max_speed` is still accepted so a
  real scope file loads, and is ignored (there is no speed left to cap). Docs
  02/03/05/06/07/08/09, README, SETUP and AGENTS rule 3 were updated; MASTER_PLAN
  D3 records the decision. Tests removed (measured on the collected node ids: 32 test functions deleted
  and 4 renamed, so 44 parametrized node ids disappeared and 12 appeared - suite
  745 -> 713 passed; 17 of the deleted ones were the whole of
  `tests/test_pacing.py`, which tested the deleted module, so its file went with
  it; the interactive-mode fix below then removed one parametrized case and
  added two tests, 713 -> 714): `test_slow_delays_and_parallel_limits`,
  `test_normal_values`, `test_fast_never_sleeps`, `test_first_tool_and_reset`,
  `test_shuffle_is_deterministic_and_a_permutation`, `test_fast_preserves_order`,
  `test_next_pause_range`, `test_tool_rate_args_slow_passive_vs_active`,
  `test_tool_rate_args_normal`, `test_tool_rate_args_fast`,
  `test_tool_rate_args_nmap_and_masscan_use_active_values`,
  `test_tool_rate_args_unknown`, `test_delay_override_applies`,
  `test_rate_limiter_spacing`, `test_rate_limiter_rejects_bad_rate`,
  `test_before_host_zero_skips_sleep`, `test_mode_literal_accepts_strings`
  (all test_pacing.py; the behaviour and the module no longer exist), plus
  `test_rate_limiter_is_used_before_the_request` (test_adapters.py; asserted the
  limiter call inside the HTTP adapter), `test_dnspython_awaits_limiter_per_query`,
  `test_pyprobe_awaits_limiter`,
  `test_pyprobe_waits_between_hosts_when_dispatch_is_sequential`,
  `test_pyscan_awaits_limiter_per_query_and_connection`,
  `test_pyscan_respects_the_pacer_parallel_limit`,
  `test_pyscan_uses_pacer_order_for_ports`,
  `test_pyscan_waits_between_hosts_before_dispatching_the_next`
  (test_python_adapters.py; each asserted a pacer/limiter call that no longer
  exists in the adapter), `test_delay_override_applies_to_active_and_passive`,
  `test_delay_range_in_file_is_rejected`, `test_invalid_delay_override`,
  `test_invalid_speed_name`, `test_speed_override` (test_config.py; the settings
  themselves were deleted), `test_max_speed_cap` and `test_unknown_speed`
  (test_scope.py; `require_active` no longer takes or checks a speed). Tests
  changed and renamed: `test_slow_mode_runs_one_tool_at_a_time` ->
  `test_tools_start_together_without_a_pace_limit` (asserted the slow parallel
  limit of 1; now asserts both tools are inside `run()` at the same time),
  `test_fast_active_requires_typed_confirmation` ->
  `test_speed_and_delay_flags_are_gone` (asserted the removed prompt; now
  asserts both flags exit 2), `test_subfinder_command_and_rate_flag` ->
  `test_subfinder_command_has_no_rate_flag` (same parsed args minus `-rl`),
  `test_rate_flags_come_from_tools_yaml` -> `test_no_rate_flag_survives_in_tools_yaml`
  (asserts the field and the YAML key are absent), and the `-rl`/`-rate`/`-T`
  expectations in `test_binary_adapters.py` were dropped from the command
  assertions. New: `test_a_speeds_block_is_rejected`,
  `test_config_has_no_speed_fields`, `test_speed_and_delay_arguments_no_longer_exist`
  (test_config.py), `test_pyscan_probes_its_ports_without_an_artificial_limit`
  (test_python_adapters.py), `test_v4_database_migrates_by_removing_the_speed_column`,
  `test_create_scan_run_writes_no_speed_column` (test_store.py),
  `test_max_speed_is_accepted_and_ignored` (test_scope.py), and the three v1/v2/v3
  migration fixtures gained the `scan_runs` table because schema 5 alters it.
- **2026-11-16 (Part 13), a multi-domain file does not use a tool's own list
  flag:** the interactive file path reuses `-l` (one full scan per domain), even
  though `subfinder -dL`, `dnsx -l`, `httpx -l`, `tlsx -l`, `naabu -list`,
  `nmap -iL` etc. exist, because one report folder per domain requires results
  that are attributable to one domain. Recorded so a later part does not flip it
  by accident.
- **2026-11-17 (verification follow-up F1), the `--active` help text states the
  real rule.** The two `--active` options in `cli.py` (the shared scan command
  and the root callback) said `Allow active stages inside scope.`, which stopped
  being true with D1. They now share one module constant `_ACTIVE_HELP`:
  `Allow active stages. A scope.yaml, when present, is enforced; with no scope
  file, active scanning is unrestricted.` docs/02 section 3 quotes the same
  words, and section 2's sentence now says only that, instead of claiming the
  scope question says it too. No test asserted the old string (`grep -rn "inside
  scope" tests/` -> no match), so no test changed.
- **2026-11-17 (verification follow-up F2), the owner verification commands
  match the current CLI.** Both `reconkit run` examples in "Owner verification
  commands" lost `--speed slow` (the flag exits 2 now), and the naabu
  expectation is the D2 rule - hostnames with no scope file, verified IPs with a
  scope file, `blocked: no in-scope IP for any target` when nothing verifies -
  instead of the superseded 11c-G-7 skip.
- **2026-11-17 (verification follow-up F3), five pacing-era lines are marked
  historical, not deleted.** In this file: the task-table row d (`core/pacing.py`),
  the standing `--delay` line, the S311-ignore clause, the Part 13 open risk that
  cites `--speed fast`, and the "Where things live" map entry for
  `core/pacing.py`. Each now carries `removed 2026-11-17, MASTER_PLAN D3` so the
  audit trail stays readable.
- **2026-11-17 (verification follow-up F4), the core package docstring no
  longer lists `pacing`.** `src/reconkit/core/__init__.py` now reads `Core
  services: runner, scope, store, workspace, wildcard.`
- **2026-11-17 (verification follow-up F5), the two dead `pyproject.toml`
  per-file ignores are gone.** `src/reconkit/core/pacing.py` and
  `tests/test_pacing.py` no longer exist, so their scoped S311 entries were
  removed; no ignore was added or widened.
- **2026-11-17 (verification follow-up F6), the AGENTS source-of-truth row.**
  `config.yaml` is now listed as `timeouts, thresholds`; the `speeds` block it
  named was deleted with D3.
- **2026-11-17 (verification follow-up F7), three tool-manual references
  describe current behaviour.** The two F7 named were `docs/tool_manuals/urls.md`
  (now: `-rl` was the registry's `rate_flag` until 2026-11-17 and reconkit no
  longer passes it) and `docs/tool_manuals/ports.md`'s naabu paragraph (now: the
  D2 scope-mode-dependent rule and its `blocked:` reason, replacing "never runs
  this tool / 11c-G-7 permanently"). The manual sweep found a third of the same
  class that F7 did not name, `docs/tool_manuals/ports.md:418` in the nmap notes,
  which still described `rate_flag: -T` as current; the owner approved adding it
  to the same commit, so it now says the field was removed on 2026-11-17 and no
  adapter passes `-T` any more. `docs/tool_manuals/urls.md:484` is hakrawler's
  own `--delay` flag help, not a reconkit claim, and was left alone.
- **2026-11-17 (install backlog T1), `rustscan` installs from its real release.**
  The placeholder `asset_pattern: "verify-at-implementation"` is gone. The
  registry now names `repo: bee-san/RustScan`, `asset_pattern:
  "rustscan-{version}-x86_64-linux.zip"` and `verify_checksums: false`, and the
  version pin `2.3.0` lives in `config.yaml` `tool_versions` because
  `load_plans(versions=...)` is the only place the registry reads a pin from (a
  `version:` key inside `install:` is ignored - chosen the working way, not the
  literal one). Why 2.3.0: 2.4.1 publishes `x86_64-linux-rustscan.tar.gz.zip`, a
  nested archive the single-layer extractor cannot read, its `x86_64`/`aarch64`
  names do not match `{arch}` (`amd64`/`arm64`), and no recent release publishes
  checksums. Clean version in doctor needs a `version_regex`, because the first
  line is `rustscan 2.3.0` and the table cell truncates it: regex
  `^rustscan (\d+\.\d+\.\d+)$` -> `2.3.0`. Changed tests: (1)
  `tests/test_installer_github_release.py::test_rustscan_placeholder_cannot_resolve`
  -> `test_rustscan_pinned_plan_resolves_its_real_asset`; old: asserted
  `asset_pattern == "verify-at-implementation"` and that resolution fails; new:
  asserts the real repo, pattern, `verify_checksums is False`, the pinned
  `releases/tags/2.3.0` request and the resolved asset name; reason: the
  placeholder no longer exists. (2)
  `tests/test_config.py::test_unknown_top_level_key_is_rejected`: old built its
  fixture with `.replace("tool_versions: {}", ...)`; new appends the unknown key
  to the real file; reason: the literal `{}` is gone (rustscan pin), so the old
  test silently stopped injecting anything and passed nothing through the
  schema check - the append form tests the same thing without coupling to one
  line's spelling.
- **2026-11-17 (install backlog T2), seven tools report a real version.**
  `chaos`, `dnsx`, `httpx`, `tlsx`, `naabu`, `cdncheck` share
  `version_regex: 'Current [Vv]ersion: (v?\d+\.\d+\.\d+)'`; `wafw00f` uses
  `'WAFW00F you have is[^\n]*?(v?\d+\.\d+\.\d+)'` because its value is
  ANSI-wrapped. **Pre-check result:** no doctor or `installed_version()` change
  was needed - it reads `stdout or stderr`, and the real probes showed the PD
  six write the banner to stderr (stdout empty) while `wafw00f` writes to
  stdout, so the capture was already receiving the text; only extraction from
  the first line was wrong. Values now shown: `0.5.2`, `1.3.1`, `v1.12.0`,
  `v1.4.0`, `2.7.0`, `v1.4.0`, `v2.4.2`. No existing test asserted the old
  first-line behaviour for these tools; new test
  `tests/test_installer_registry.py::test_the_seven_version_patterns_extract_their_real_banner`
  (7 parametrized cases) pins each real banner -> expected version, and a
  mutation (dropping the ANSI tolerance from the wafw00f pattern) makes it fail.
- **2026-11-17 (install backlog T3), four tools report a version and five are
  documented as path rows.** `smap` (`-h`, stdout, `Smap 1.0.0-beta`),
  `gospider` (`--version`, stdout, `Version: v1.1.6`), `subjs` (`-version`,
  stdout, `subjs version: 1.0.1`) and `urlfinder` (`-version`, **stderr**,
  `[INF] Current Version: v0.0.3`) now carry `version_cmd` + `version_regex`.
  Their patterns are unanchored on purpose: smap and gospider print a multi-line
  body after the version, so the first draft's `^...$` patterns silently failed
  and doctor fell back to the first line (`Smap`, `Version:`) - caught before
  the commit and re-verified. `github_subdomains`, `webanalyze`, `waybackurls`,
  `unfurl` and `httprobe` genuinely have no version output (`-version` ->
  `flag provided but not defined: -version`), so they carry no probe and
  doctor's Version column shows the resolved path **by design** (docs/10).
  `httprobe`'s old `version_cmd: [httprobe, -h]` was removed - it put
  `Usage of ***/httprobe:` in the Version column, which is worse than the
  documented path. New tests:
  `test_the_four_probed_tools_extract_their_real_output` (4 cases) and
  `test_tools_without_a_version_flag_have_no_probe` (5 cases); no existing test
  changed.
- **2026-11-17 (install backlog T4), `assetfinder -h` exits 0, not 2.**
  docs/09's assetfinder row claimed "exits 2" from reading Go `flag` source and
  said the binary was not installed. Measured here:
  `assetfinder -h` writes `Usage of assetfinder:` + `-subs-only` to **stderr**,
  stdout is 0 bytes, exit **0** (the subs manual already said exit 0, so the two
  docs disagreed and the manual was right). The row now states the measured
  behaviour and that the identity probe has been exercised on the real binary
  (`reconkit doctor --json` -> `'identity': 'ok'`). Docs-only change: the
  adapter and its test already expected exit 0
  (`tests/test_binary_adapters.py::test_assetfinder_usage_identity`,
  `returncode=0`), so no code or test changed.
- **2026-11-17 (install backlog T5), the amass note matches v5.1.3.**
  `amass -version` -> `v5.1.3`; `amass -h` -> `Usage: amass
  [assoc|engine|enum|subs|track|viz] [options]`; `amass enum -h` lists
  `-passive` with `Deprecated since passive is the default setting`. The
  registry note said "Always run in passive mode (-passive)", which is stale for
  v5: passive needs no flag. `tools.yaml`, docs/09's per-stage notes and the
  subs manual now say passive is the default, `-passive` is deprecated (still
  parsed), and an adapter must be checked against `amass enum -h` first. No
  test added or changed: the change is a note string and prose, and a test
  pinning that prose would lock wording rather than behaviour (the registry
  still loads, which the gate exercises).
- **2026-11-17 (verification follow-up F8), the D3 test-count wording uses the
  measured figures.** The D3 entry above now says 32 test functions deleted and
  4 renamed (44 collected node ids removed, 12 added, 745 -> 713), then one
  parametrized case removed and two tests added by the interactive-mode fix
  (713 -> 714). The disclosed name list is unchanged.

## Open risks

- **12e is closed (PIT-47, 2026-11-15)**: a first `live` pass that got a record writes `UNKNOWN`/LOW with the reason, and a pass with no record still writes nothing. A later consumer that read "no row" as "not probed" must read the state instead.
- **CLOSED 2026-11-16 by Part 13:** `--json` used to write no progress at all while docs/02 said tables and progress stay on stderr. All scan modes now emit stage/tool progress on stderr; only `--silent` suppresses it, and stdout remains one JSON document.
- **Part 13, open for the owner:** the pty run (`results/testfire.net/...`, an in-scope domain at `--speed fast`, a flag removed on 2026-11-17 by MASTER_PLAN D3 - the historical run is unchanged) is the only real-network exercise of the interactive flow, and Windows is still untested, so the interactive prompts and the report folders have no Windows evidence.
- **Pre-existing, not caused by Part 13 and not fixed:** `reconkit run --active --mock` stores every host as `UNKNOWN` (the mock live adapter returns records the engine reads as inconclusive). Verified on the flag path before Part 13 existed; the interactive `active`/`full` modes inherit it. Needs its own ruling.
- **Part 13, accepted:** the saved report contains only values already stored in the run's DB (no recomputation), so a stored `title` that happened to contain a provider key would appear in `report.txt`/`report.json` exactly as it already appears in the SQLite file. Files are written 0600 inside `results_dir`.
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
- Unverifiable tool facts, named: OTX's response shape was never observed live (anonymous 429, synthetic fixture); `assetfinder`'s identity probe is inferred from Go `flag` source; `rustscan`'s asset naming and `--version` are now verified against the real 2.3.0/2.4.1 releases and a real binary (2026-11-17, T1 below), so its entry is no longer in this list.
- `subfinder` provider keys cover only certspotter, chaos, github and virustotal; no real `subfinder` run has accepted the generated provider file yet.
- 11c-bis-1: `--help` renders switches as value-taking (`--json <bool>`); `typer>=0.12` has no upper bound and no test pins the rendering. 11c-bis-2: `reconkit --json doctor` accepts a global `--json` and silently ignores it.
- **Superseded 2026-11-17 (D2):** `naabu` is no longer permanently skipped. It runs unrestricted with no scope file, and on engine-verified IPs when a scope file is present; ports confidence can now exceed LOW when both `pyscan` and `naabu` report a port. The 12i "pyscan-only / LOW ceiling" risk is historical.
- Wildcard matches are a mark only: docs/09's "exclude from counts" names no count and no code filters it.
- `tech`, `urls` and `vulns` have no adapter for any tool in their pools, so no real tool in those stages has ever been driven by `reconkit`; they exit 5 with the 12k warning. (2026-11-16: every phase-3 binary in `tech`/`urls`/`shots` was run by hand for the manuals - the tools work, only the adapters are missing.)
- 2026-11-16, for the owner: `docs/tool_manuals/README.md` lists six registry
  discrepancies flagged by the manual verification. **2026-11-17: all six are
  closed** by the install/doc backlog batch - `rustscan`'s placeholder asset
  (T1), the seven ASCII-art version columns (T2), the path-instead-of-version
  rows (T3), `assetfinder -h` exiting 0 (T4), `amass` v5.1.3 versus the v4 note
  (T5) and `webanalyze -update` (T6).
- **Open item, 2026-11-17 (T1 follow-up):** `reconkit`'s extractor unwraps one
  archive layer only, so `rustscan` 2.4.1 (`x86_64-linux-rustscan.tar.gz.zip`)
  cannot be installed and the registry pins 2.3.0 instead. Nested-archive
  extraction is a future installer capability, not built in this batch; the
  pin is amd64-only because 2.4.1's `x86_64`/`aarch64` asset names do not match
  the `{arch}` values `amd64`/`arm64`.

## Notes for later tasks

- Where things live (the detailed per-function map is in the `REVIEW_LOG` archive): `errors.py` exceptions + exit codes; `models.py` enums and records; `config.py` strict loader; `core/runner.py` the only `subprocess` user (`run_exec`, `validate_target`, `validate_host`); `core/scope.py` the gate; `core/store.py` the only `sqlite3` user (schema/migrations, writes, diff reads, `redact`); `core/pacing.py` the `Pacer`/`RateLimiter` (removed 2026-11-17, MASTER_PLAN D3 - no such module now); `core/workspace.py` raw files; `core/wildcard.py`; `adapters/` one module per tool plus `base.py`/`registry.py`; `engine.py` the pipeline, state rule and consensus; `ui.py` rendering; `cli.py` Typer wiring; `doctor.py`; `installer/`.
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
