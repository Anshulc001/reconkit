# CLI UX (replaces DESIGN_SYSTEM.md)

## 1. Design Direction

- **Style:** Technical, calm, readable. Tables for results, one-line status for progress.
- **Principles:**
  - Safe and polite by default (passive unless `--active` is asked for). Tools run at their own natural pace: there is no speed preset, delay or artificial throttling.
  - Every result shows where it came from and how much to trust it.
  - Never hide failures: a skipped or failed tool is always reported.
  - Works without color (`--no-color`, or when output is not a terminal).
  - Machine-friendly: `--json` on the scan commands, `doctor`, `diff` and `status`.

## 2. Command Grammar

`reconkit <command> [target] [flags]`. Target is `-d DOMAIN` or `-l FILE` (one domain per line). With no command, `reconkit -d X` is shorthand for `lite` (the passive pipeline). A scan command with **neither** `-d` nor `-l` on a terminal asks five questions instead of failing (section 2b); with a target flag present nothing changes and nothing is asked.

### Setup and health
| Command | Purpose | Phase |
|---|---|---|
| `doctor` | Tools, versions, system packages, API key names + Keys table, per-stage coverage | 2 |
| `scope check -d DOMAIN` | Show whether a target is allowed by `scope.yaml` | 2 |
| `scope import` | Build `scope.yaml` from a bug bounty program | 3 |

### Stages (single stage per command)
| Command | Mode | Needs `--active` | Phase |
|---|---|---|---|
| `passive` | subs + dns (+ passive ports/CDN info) | no | 2 |
| `subs` / `dns` | single passive stage | no | 2 |
| `live` | ALIVE / DNS_ONLY / SHUT_DOWN / DEAD | yes | 2 |
| `ports` | open ports, services (`pyscan` only; LOW is the ceiling - accepted permanently, docs/09 section 5) | yes | 2 |
| `tech` | tech, WAF, CDN | yes | 3 |
| `urls` | URLs, params, JS | yes (crawling) | 3 |
| `vulns` | takeover and exposure checks | yes | 3 |

### Workflows
| Command | Pipeline |
|---|---|
| `lite -d X` | passive only (quick) |
| `run -d X --active` | passive, live, ports, then enabled checks; resumable |

`passive` is the stage command: it runs the subs and dns stages (plus passive port/CDN info) for one target. `lite` is the workflow shortcut for exactly that passive pipeline and nothing active; adapters, flags and exit codes are the same. Only `run` includes active stages.

`--active` is a usage error (exit `2`) on every passive-only command - the bare form, `lite`, `passive`, `subs` and `dns` - because none of them runs an active stage and accepting the flag would promise work the command cannot do. The message names `run` as the active workflow. Use `run -d X --active`, or an active stage command (`live`, `ports`, `tech`, `urls`, `vulns`), for active stages.

**What `--active` needs depends on whether a scope file exists.** With `--scope PATH` (default `./scope.yaml`):

- **No scope file at that path** - active and full scanning run **unrestricted** against the target(s) given with `-d`/`-l` and every host discovered under them. Nothing is derived from the target, no implicit scope is built, and the run is not refused (docs/05 rule 2). "No scope file" means "scan freely, I know what I typed"; exit code 3 is not produced for a missing file.
- **A scope file is present** - it is enforced exactly as before (`authorization`, `expires`, `allow_active`, `in_scope`, `out_of_scope`); a violation exits 3 and the file is only ever read, never rewritten or deleted.

The `--active` `--help` text says this in one sentence: `Allow active stages. A scope.yaml, when present, is enforced; with no scope file, active scanning is unrestricted.` The interactive mode asks the scope question before the mode question, so the same branch applies there (section 2b).

**Ports run `pyscan` and `naabu`; every other ports tool is phase 3 with no adapter.** `naabu` is scope-mode dependent (owner decision 2026-11-17, superseding the 12i permanent block): with **no scope file** it runs unrestricted like any other active tool, receiving the discovered hostnames; with a **scope file present** the engine resolves each in-scope target itself, verifies every address against `in_scope_cidrs`, and passes `naabu` only those verified IPs - never a bare domain - skipping any target whose resolution fails or resolves out of scope (docs/05 rule 6, docs/09 section 4). Because two port adapters can now run, a port both report can reach `MEDIUM` confidence; a single-scanner result stays `LOW` and the open/closed disagreement rule only fires when both report. When `naabu` is absent or its targets cannot be verified, `pyscan` alone is the fallback and the ceiling is `LOW` again.

### State and output
| Command | Purpose |
|---|---|
| `diff -d X` | New / changed / gone items since the previous run; `GONE` needs two consecutive misses |
| `status [--json]` | Progress of running or finished scans |
| `db list\|export -d X [--new-only]` | **Phase 3 stub** in this build: exits 1 with a clear message; no data is read |
| `export -d X --format json\|md\|html` | **Phase 3 stub** in this build: exits 1 with a clear message; no report is written |

**`diff` semantics.** `diff` compares the two latest completed discovery runs for the target: `scan_runs` rows for the `subs` stage whose status is `completed` or `partial`, newest first. Resume does not change which runs these are (a resumed stage produces its own row like any other run); no other stage takes part in the comparison. A host is **`GONE` only after two consecutive misses**: it must have been seen in the run *before* the previous one and be missing from both the previous run and the latest run. One miss is not a change and is never reported as `GONE`, because a single flaky passive source (a CT log timing out, a subfinder run returning fewer names) is indistinguishable from a real removal in one run. Consequences a user will see: a host that is missing from only the latest run is silent in the table and is listed once under `Not reported as GONE yet (needs two consecutive misses)`; a host that comes back after one miss is neither `NEW` (its first sighting is not reset) nor `GONE`; a real removal appears as `GONE` on the run after the second consecutive miss; and with fewer than three completed discovery runs nothing can be confirmed gone, so `gone` is empty and `diff` says so. A host is **`NEW`** when the latest completed discovery run is its first sighting by any discovery tool: a host that the `dns` stage resolved before any discovery tool returned it is stored with `provenance` `dns`, appears in `status` with no sources, and is never reported NEW - the first discovery run that returns it is the run that reports it new.

## 2b. Interactive scan mode (no target flags)

A scan command given **neither `-d` nor `-l`** asks five questions instead of
failing with "provide a target". This applies to `subs`, `dns`, `live`, `ports`,
`tech`, `urls`, `vulns`, `passive`, `lite` and `run`. Two hard conditions:

- **Any target flag at all means no questions.** If `-d` or `-l` is present, the
  command behaves exactly as section 2 describes - no prompt is shown and no
  input is read. Every scripted invocation, and the whole automated test suite,
  is in this branch.
- **Interactive input requires a terminal on stdin.** With stdin redirected from a
  pipe or `/dev/null` (CI, cron, `ssh host reconkit passive`), the command keeps
  today's behaviour: `provide a target with -d/--domain or -l/--list` and exit `2`.
  Nothing ever blocks waiting for input that cannot arrive.

The five questions:

1. **Target.** A single domain, or a path to a file of domains (one per line). A
   value naming an existing file is read with the same loader as `-l`: blank
   lines and `#` comments skipped, duplicates removed, every line validated with
   `validate_target()`. Anything else is treated as one domain. Both paths end in
   the same `_targets()` handling `-d`/`-l` use, so there is no second target path.
2. **Scope file.** `yes` asks for a path and uses it exactly as `--scope` does.
   `no` leaves the scope location at its default (`./scope.yaml` if present,
   otherwise no scope file). A scope file that **is present** is enforced exactly
   as today: active stages need `allow_active`, a live `authorization`, an
   unexpired `expires`, and the target in `in_scope`/not in `out_of_scope` (exit
   `3` otherwise). With **no scope file**, active and full scanning proceed
   unrestricted against the target(s) you named and everything discovered under
   them (docs/05 rule 2) - answering `no` is not a bypass of a real file, it is
   the documented meaning of having none.
3. **Scan mode.** No default: the question is asked and re-asked until one of the
   three words is typed (an empty line or any other word prints
   `invalid scan mode '...'` and asks again). The scan never starts on an
   assumed mode. `passive` = `subs` + `dns`; `active` = `subs` + `dns` + `live`
   (passive plus alive/status-code); `full` = `subs` + `dns` + `live` + `ports` +
   `tech` + `urls`. `active` and `full` set `--active`, so the scope gate applies
   unchanged. `vulns` is never requested by this mode (recon-only build). Because
   `tech` and `urls` have no adapter in this build, a `full` choice requests two
   stages that will report their skips, warn, and make the run partial (`5`,
   section 6) - the same rule as a flag-based `run --active`, stated before the
   run starts.
4. **Report fields.** A numbered menu built from fields `reconkit` actually
   stores (host state, confidence, discovery sources, source count, IPs, status
   code, title, redirect location, open ports, technology, and the `UNKNOWN`
   reason). The answer is a comma-separated list like `1,3,5` or `all`. Fields
   that only make sense for a host that answered on the web (status code, title,
   redirect location, technology, open ports) are written as `not applicable` for
   every host whose state is not `ALIVE`, and the reason field only for `UNKNOWN`
   hosts; no value is ever guessed for a host the run did not observe.
5. **Aggressive scanning.** A separate yes/no asked whatever the answer to 3 was.
   `yes` adds the active `live` and `ports` stages (and sets `--active`), and it
   states plainly what that means in this build: TCP connect scanning by
   `pyscan` and (`naabu` when installed) - with no scope file `naabu` runs on the
   hostnames, with a scope file it runs only on IPs the engine resolved and
   verified against `in_scope_cidrs`; **service/version detection is not wired**
   (`nmap -sV` has no adapter). `no` changes nothing.

After the last answer the CLI echoes the resolved plan (targets, stages, active
or not, field numbers) and runs the ordinary engine once per target. Results also
land on disk, one folder per domain per run (section 5).

### The flow end to end (2026-11-17)

This is the whole runtime flow in one place. The prompt text below is the exact
text the CLI prints (typer renders a yes/no question as `[Y/n]` or `[y/N]`).

1. **Launch.** `reconkit subs` (or `dns`, `live`, `ports`, `tech`, `urls`,
   `vulns`, `passive`, `lite`, `run`) with no `-d` and no `-l`, on a terminal.
2. **Target.** `Domain, or path to a file of domains (one per line)` - a domain,
   or a path to a file that is read exactly like `-l`.
3. **Scope file.** `Do you have a scope file? [Y/n]`; on `y`,
   `Scope file path` (an existing path is required, used exactly like `--scope`).
   On `n` the scope location stays at its default: `./scope.yaml` if it exists.
4. **Scan mode.** `Scan mode: passive, active or full` - no default, re-asked
   until valid. `passive`, `active` and `full` mean what point 3 above says.
5. **Report fields.** The numbered menu of stored fields, then
   `Fields [all]` (`1,3,5`, `all`, ...).
6. **Aggressive scanning.** `Also run aggressive scanning (port scan + version
   detection)? [y/N]` - asked whatever the mode was; `y` adds `live` + `ports`
   and sets `--active`.
7. **Plan echo.** `plan: <target>; stages <stages>; active yes|no; fields <n>`.
8. **Run.** The ordinary engine runs once per target, results are stored, and a
   report folder per domain is written (section 5).
9. **Scope branch at run time.** With **no scope file** the active/full stages
   run unrestricted against the target(s) the operator named and everything
   discovered under them (docs/05 rule 2). With a scope file **present**, the
   unchanged gate applies (exit `3` on a missing `allow_active`, expired scope
   or out-of-scope target) and `naabu` runs only on IPs reconkit resolved and
   verified against `in_scope_cidrs`, skipping a target whose resolution fails
   or resolves out of scope (docs/05 rule 6).
10. **No speed option.** There is no `--speed`, `--delay`, preset or throttle
    question anywhere in this flow, and none in `--help` (docs/03 section 7).

The interactive path adds **no flags**: `--help` for a scan command is unchanged,
and there is no `--interactive` switch. Omitting the target is the whole trigger.

## 3. Flags

| Flag | Meaning |
|---|---|
| `-d, --domain` / `-l, --list` | Target or file of targets. Omitting both on a scan command starts the interactive mode (section 2b); that is the only trigger and it adds no flag |
| `--active` | Allow active stages. A `scope.yaml`, when present, is enforced; with no scope file, active scanning is unrestricted. Full rule: section 2 |
| `--tools a,b` / `--exclude x,y` | Pick or skip adapters |
| `--include-noisy` | Allow `opt_in` tier tools |
| `--min-sources N` | Hide results confirmed by fewer than N tools |
| `--phase-timeout SEC` | Stage time limit. `--timeout-<stage>` is deferred; `--phase-timeout` is the only stage-timeout control in this build. |
| `--mock` | Use fixtures instead of real tools/network |
| `--resume` | Continue the latest unfinished run for the target; completed stages are not repeated |
| `--no-keys` | Force free mode on the scan commands: ignore API keys from `.env` (policy in docs/05 §6.1) |
| `--json` | One JSON document on stdout, no colors or progress |
| `--no-color`, `-v/--verbose`, `-q/--silent` | Output control |
| `--config PATH`, `--scope PATH`, `--db PATH` | Override file locations |

`install`, `update` and `doctor --fix` no longer exist (removed 2026-11-17, docs/MASTER_PLAN.md D4). Installing tools is your package manager, `go install` or a release download; the per-tool sources are in docs/10_TOOL_SOURCES.md.

`config.yaml` `tool_versions` is **accepted and ignored** for the same reason: there is no download left to pin. Keeping the key means an older config still loads; `doctor` prints one warning when the block is non-empty. The `install:` block (`dir`, `verify_checksums`) is accepted and ignored too.

There is no `--speed` and no `--delay`: both were removed on 2026-11-17 at the owner's request (docs/MASTER_PLAN.md D3). Tools start together and run at their own natural pace; nothing in reconkit throttles, delays or reshuffles them.

Not provided (by design): any flag that skips the scope gate.

## 4. Speed Modes (removed 2026-11-17)

The `slow`/`normal`/`fast` presets, `--speed`, `--delay`, the pacer (delays, host/port shuffling, parallel limits, request rate limiting), the `-rl`/`-rate` flags passed to tools and the typed `I AM AUTHORIZED` confirmation for `fast` were all removed at the owner's request (docs/MASTER_PLAN.md D3, reason: "user-requested removal, no throttling desired"). Every tool starts together and runs at its own natural pace. This heading keeps its number so the existing "section 5", "section 6" references elsewhere stay valid. A `scope.yaml` that still carries `max_speed` loads unchanged; the field is accepted and ignored, because there is no speed left to cap.

## 5. Output

### Result table (example `passive` / `diff`)

```
Subdomain          State      Status  Ports    Sources                    Trust
api.example.com    ALIVE      200     80,443   crtsh, subfinder, otx      HIGH (3)
vpn.example.com    DNS_ONLY   -       443      assetfinder, naabu         MEDIUM (2)
old.example.com    SHUT_DOWN  -       -        crtsh                      LOW (1)
new.example.com    UNKNOWN    -       -        certspotter, hackertarget  MEDIUM (2)
```

- A final summary line: counts per state and tool statuses. New items are shown by `diff`, not in the stage summary.
- A "Tools" table lists each adapter with stage, status (`ok`, `skipped`, `failed`, `timeout`), item count and a short detail.

### Doctor output

`doctor` prints one row per tool: `tool`, `stage`, `tier`, `installed`, `version`, `path`, `identity`. A `kind: http` or `kind: python` tool needs no binary, so `version` and `path` print `n/a (no binary required)` and `installed` is always `yes`; only `kind: binary` tools can be missing. A binary that exists but fails its identity check prints `wrong program` in `installed` (with its `path`) and counts as not ready. Below the table: per-stage coverage (`subs 6/11 ready`), system packages, the Keys table (names and sign-up URLs, never values), and `Missing tools: N. Install them yourself (apt, go install, or release download) — per-tool sources in docs/10_TOOL_SOURCES.md. Re-run doctor to confirm.` when anything is missing. A non-empty `config.yaml` `tool_versions` adds one `warning:` line saying the pin is accepted and ignored. `--json` writes one document with `type`, `python`, `python_ok`, `config`, `scope`, `db`, `tools`, `stages`, `system_packages`, `keys`, `missing`, `warnings` and `exit_code`, and keeps warnings at exit `0` (docs/10 section 3).

### JSON (`--json`)

One JSON document is written to stdout; tables and progress stay on stderr. The fixed shape is:

```json
{"type":"summary","target":"example.com","exit_code":0,"resumed":false,"scope_denied":false,"warnings":[],"hosts":[{"fqdn":"api.example.com","state":"ALIVE","confidence":"HIGH","sources":["crtsh","subfinder","otx"],"status_code":200,"ports":[80,443],"detail":null}],"stages":[{"stage":"subs","run_id":1,"resumed":false,"dropped_hosts":[],"results":[],"skipped":[]}],"summary":{"hosts":1,"alive":1,"dns_only":0,"shut_down":0,"dead":0,"unknown":0,"tools_ok":1,"tools_failed":0,"tools_skipped":0,"tools_timeout":0}}
```

The `hosts` objects always carry `state`, `confidence` and `sources`; the top-level `summary` object carries the counts. `ToolResult` objects under `stages[].results` use the schemas in docs/09.

`hosts[].detail` is the bounded, redacted reason recorded with that host's latest status row (docs/04 section 5): `null` unless the latest pass could not decide a better state, in which case it is a one-line string of at most 200 characters with the run's known secrets redacted. It is the machine-readable half of a diagnostic the human table does not show - a script can tell a TLS failure apart from another cause without probing the host again.

`stages[].skipped` lists every tool the engine selected out before it ran, as `{"tool":"<name>","reason":"<why>"}` objects - `no adapter yet (phase N)`, `requires --active`, `not installed`, or the naabu scope-mode skip from docs/05 rule 6 (resolution failed or resolved outside `in_scope_cidrs`). A stage that has no adapter for any tool in its pool therefore shows its skips instead of an empty `results` array, so `results: []` means "ran, found nothing" only when `skipped` is empty too. `summary.tools_skipped` counts these rows along with any executed tool whose status is `skipped`; it is the total, not a per-tool count of executed results.

`diff --json` writes one document with `type: diff`, the run ids it compared (`baseline_run_id`, `previous_run_id`, `latest_run_id`; `baseline_run_id` is `null` until a third completed discovery run exists), and arrays `new`, `gone`, `pending_gone`, `state_changes`, `ports_opened` and `ports_closed`. `pending_gone` holds the hosts that are missing from the latest run only: the same list the human output prints under "not reported as GONE yet", so a script can apply its own tolerance without re-querying. `gone` follows the two-consecutive-miss rule above. `status --json` writes one document with `type: status` and a `runs` array; each run carries `id`, `target`, `stage`, `status`, `started_at` and `finished_at` (the `speed` field was removed with speed control on 2026-11-17). `scope check` and the `db` and `export` stubs do not accept `--json` in this build.

### Colors (Rich theme)

| Meaning | Color |
|---|---|
| ALIVE / ok / HIGH | `#22c55e` |
| DNS_ONLY / MEDIUM / warning | `#eab308` |
| SHUT_DOWN | `#f97316` |
| DEAD / error | `#ef4444` |
| NEW / info | `#06b6d4` |
| LOW / UNCONFIRMED / muted | `#9ca3af` |

State words are always printed (never color alone). Symbols are ASCII-safe.

### Progress
Every scan writes one progress line per stage and one per finished tool to
**stderr**, so the user can see which stage and tool is running during a long
scan. The format is
`<stage>: <tool> <done>/<total> tools <elapsed>s` plus a `running`/`ok`/`failed`
marker, and a closing line per stage with its item count.

- **`--json` keeps its stdout contract.** Progress goes to stderr only; the one
  JSON document on stdout is byte-identical to before. This closes the gap
  recorded in PROGRESS "Open risks" where `--json` wrote nothing at all while a
  slow run was in flight.
- **`--silent` suppresses it**, together with tables and warnings text (the exit
  code still carries the outcome).
- The lines are plain text, so they are readable with `--no-color` and when stderr
  is a file.

### Saved reports (interactive mode)
One folder per domain per run, never reused:

```
<results_dir>/<domain>/<YYYYmmddTHHMMSSZ>/
  report.txt    selected fields, one row per host, aligned columns
  report.json   the same rows as objects, plus target, run time and field keys
```

- `results_dir` is the `config.yaml` key of that name (default `results`), used
  by `--config` like every other key.
- A second run for the same domain gets its own folder; an existing folder is
  never written into. When two runs start within the same second the later one
  gets a `-2`, `-3`, ... suffix, so no run can overwrite another.
- Both files are always written, whatever field selection was made. A field the
  run could not observe prints `not applicable` (section 2b point 4) rather than
  a guessed value.
- Only the interactive mode writes these; a `-d`/`-l` invocation keeps today's
  behaviour exactly and writes nothing new.

### Empty, error and success states
- **Empty:** `No results from 3 tools (crtsh, subfinder, otx). Check 'reconkit doctor'.`
- **Error:** one line cause + one line fix, never a raw traceback (traceback with `-v`).
- **Success:** summary line. This build does not print the workspace or DB path; they come from `config.yaml` (`workspace_dir`, `db_path`).

## 6. Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Unexpected error |
| 2 | Usage error (bad flags) |
| 3 | Scope violation when a scope file is present (target not allowed, unauthorized, or expired). A **missing** scope file is not a violation: it means unrestricted active scanning of the operator's targets (section 2) |
| 4 | No usable tool for the stage |
| 5 | Partial success (some tools failed or timed out, or a requested stage executed no tools) |
| 6 | Retired 2026-11-17: was "every requested tool failed to install or update" |
| 130 | Interrupted by user (state saved, resumable) |

Code `6` is retired (2026-11-17, docs/MASTER_PLAN.md D4): it belonged to `install`/`update` only, and both commands are gone. No command can emit it, and the scan path's enum (`engine.ExitCode`) never could - a scan in which every tool failed is code 4. Do not reuse 6.

**A requested stage that executed zero tools is a partial run (code 5).** Zero executed tools means every tool in that stage's pool was selected out before running - `no adapter yet (phase N)`, `requires --active`, `not installed`, or the docs/05 rule 6 block - so the stage created a `scan_runs` row and `tool_runs` skip rows but no result. Two things follow, both from one engine decision:

- The engine appends one warning per such stage, `"<stage> stage executed no tools: N tool(s) skipped (<reasons>)"`. It is the existing warning channel: the human output prints it as `warning: ...`, `--json` lists it in `warnings`, and `-q`/`--silent` suppress only the text, not the exit code.
- The run exits 5. Several empty stages add one warning each and still exit 5; no warning overwrites another.

This is an additional cause of 5, not a replacement: stages that did run tools keep their existing result (0 when every selected tool succeeded, 5 when some failed or timed out).

**Precedence, highest first** (one decision site, `Engine._exit_code`):

1. `3` - scope denied (passive results already collected are kept).
2. `4` - the run has at least one new stage and selected no tool at all (a run resumed entirely from completed stages still exits 0), **or** every selected tool in the run failed. This wins over the empty-stage rule: a run where nothing usable ran or every tool failed is 4 even if another stage was empty.
3. `5` - at least one requested stage executed zero tools, **or** at least one selected tool failed/timed out.
4. `0` - otherwise. A resumed run whose requested stages were all already completed keeps 0.

When **every** requested stage is empty, the run follows rule 2 and exits `4`, not 5: no tool ran anywhere, which is the documented meaning of "no usable tool". A stage dropped by `--tools`/`--exclude` is *not* an empty stage - the engine never creates a stage outcome for it, so it neither warns nor changes the exit code; the same applies to `ports` when there are no hosts to scan (the stage is skipped before it builds a pool).

If passive stages have already completed and an active stage is denied by scope, the run still exits `3`; the passive results already collected are kept and reported.

## 7. Accessibility
- Readable with `--no-color`; no information carried only by color.
- Stable column order and plain-text output when piped.
- `--json` output uses fixed field names (see docs/09_TOOL_CONTRACTS.md).
