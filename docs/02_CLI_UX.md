# CLI UX (replaces DESIGN_SYSTEM.md)

## 1. Design Direction

- **Style:** Technical, calm, readable. Tables for results, one-line status for progress.
- **Principles:**
  - Safe and polite by default (passive, `--speed slow`).
  - Every result shows where it came from and how much to trust it.
  - Never hide failures: a skipped or failed tool is always reported.
  - Works without color (`--no-color`, or when output is not a terminal).
  - Machine-friendly: `--json` on the scan commands, `doctor`, `diff` and `status`.

## 2. Command Grammar

`reconkit <command> [target] [flags]`. Target is `-d DOMAIN` or `-l FILE` (one domain per line). With no command, `reconkit -d X` is shorthand for `lite` (the passive pipeline).

### Setup and health
| Command | Purpose | Phase |
|---|---|---|
| `doctor [--fix]` | Tools, versions, system packages, API key names + Keys table, per-stage coverage | 2 |
| `install [TOOL...\|--all] [--dry-run]` | Install missing tools into `~/.reconkit/bin`; interactive TTY asks once about API keys (docs/05 §6.1) | 2 |
| `update [TOOL...\|--all] [--dry-run]` | Update tools (and nuclei templates) | 2 |
| `scope check -d DOMAIN` | Show whether a target is allowed by `scope.yaml` | 2 |
| `scope import` | Build `scope.yaml` from a bug bounty program | 3 |

### Stages (single stage per command)
| Command | Mode | Needs `--active` + scope | Phase |
|---|---|---|---|
| `passive` | subs + dns (+ passive ports/CDN info) | no | 2 |
| `subs` / `dns` | single passive stage | no | 2 |
| `live` | ALIVE / DNS_ONLY / SHUT_DOWN / DEAD | yes | 2 |
| `ports` | open ports, services | yes | 2 |
| `tech` | tech, WAF, CDN | yes | 3 |
| `urls` | URLs, params, JS | yes (crawling) | 3 |
| `vulns` | takeover and exposure checks | yes | 3 |

### Workflows
| Command | Pipeline |
|---|---|
| `lite -d X` | passive only (quick) |
| `run -d X --active` | passive, live, ports, then enabled checks; resumable |

`passive` is the stage command: it runs the subs and dns stages (plus passive port/CDN info) for one target. `lite` is the workflow shortcut for exactly that passive pipeline and nothing active; adapters, flags, pacing and exit codes are the same. Only `run` includes active stages.

`--active` is a usage error (exit `2`) on every passive-only command - the bare form, `lite`, `passive`, `subs` and `dns` - because none of them runs an active stage and accepting the flag would promise work the command cannot do. The message names `run` as the active workflow. Use `run -d X --active`, or an active stage command (`live`, `ports`, `tech`, `urls`, `vulns`), for active stages.

### State and output
| Command | Purpose |
|---|---|
| `diff -d X` | New / changed / gone items since the previous run; `GONE` needs two consecutive misses |
| `status [--json]` | Progress of running or finished scans |
| `db list\|export -d X [--new-only]` | **Phase 3 stub** in this build: exits 1 with a clear message; no data is read |
| `export -d X --format json\|md\|html` | **Phase 3 stub** in this build: exits 1 with a clear message; no report is written |

**`diff` semantics.** `diff` compares the two latest completed discovery runs for the target: `scan_runs` rows for the `subs` stage whose status is `completed` or `partial`, newest first. Resume does not change which runs these are (a resumed stage produces its own row like any other run); no other stage takes part in the comparison. A host is **`GONE` only after two consecutive misses**: it must have been seen in the run *before* the previous one and be missing from both the previous run and the latest run. One miss is not a change and is never reported as `GONE`, because a single flaky passive source (a CT log timing out, a subfinder run returning fewer names) is indistinguishable from a real removal in one run. Consequences a user will see: a host that is missing from only the latest run is silent in the table and is listed once under `Not reported as GONE yet (needs two consecutive misses)`; a host that comes back after one miss is neither `NEW` (its first sighting is not reset) nor `GONE`; a real removal appears as `GONE` on the run after the second consecutive miss; and with fewer than three completed discovery runs nothing can be confirmed gone, so `gone` is empty and `diff` says so.

## 3. Flags

| Flag | Meaning |
|---|---|
| `-d, --domain` / `-l, --list` | Target or file of targets |
| `--active` | Allow active stages (also requires matching `scope.yaml`) |
| `--speed slow\|normal\|fast` | Pacing preset. **Default: `slow`** |
| `--delay MIN-MAX` | Random pause in seconds between tools (example `--delay 5-20`) |
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

`install` and `update` are the exception: their only options are `--all`, `--dry-run`, `--config` and `--no-color` (verified from `--help`). None of the target, pacing, key or JSON flags above apply to them.

Not provided (by design): any flag that skips the scope gate.

## 4. Speed Modes

| | `slow` (default) | `normal` | `fast` |
|---|---|---|---|
| Passive tools at once | 1 | up to 3 | all |
| Pause between tools | random 5-30 s passive, 10-60 s active | random 1-5 s passive, 2-10 s active | none |
| Active tools at once | 1 | up to 2 | all |
| Pause between hosts | random 1-5 s | random 0-2 s | none |
| Active request rate | 10/s | 50/s | 300/s |
| Order | hosts and ports shuffled | shuffled | sequential |
| nmap timing | `-T2` | `-T3` | `-T4` |

These numbers mirror `config.yaml`, which is the source of truth: slow `passive.tool_delay` is 5-30 s, slow `active.tool_delay` is 10-60 s and `active.host_delay` is 1-5 s. `--speed fast` on an active stage prints a warning and requires typing `I AM AUTHORIZED`. `scope.yaml` `max_speed` caps the speed. Slow scans can still be detected: the goal is polite and low-noise, not invisible.

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

`doctor` prints one row per tool: `tool`, `stage`, `tier`, `installed`, `version`, `path`, `identity`. A `kind: http` or `kind: python` tool needs no binary, so `version` and `path` print `n/a (no binary required)` and `installed` is always `yes`; only `kind: binary` tools can be missing. A binary that exists but fails its identity check prints `wrong program` in `installed` (with its `path`) and counts as not ready. Below the table: per-stage coverage (`subs 6/11 ready`), system packages, the Keys table (names and sign-up URLs, never values), and `Missing tools: N. Run: reconkit install --all` when anything is missing. `--json` writes one document with `type`, `python`, `python_ok`, `config`, `scope`, `db`, `tools`, `stages`, `system_packages`, `keys`, `missing`, `warnings` and `exit_code`, and keeps warnings at exit `0` (docs/10 section 5a).

### JSON (`--json`)

One JSON document is written to stdout; tables and progress stay on stderr. The fixed shape is:

```json
{"type":"summary","target":"example.com","exit_code":0,"resumed":false,"scope_denied":false,"warnings":[],"hosts":[{"fqdn":"api.example.com","state":"ALIVE","confidence":"HIGH","sources":["crtsh","subfinder","otx"],"status_code":200,"ports":[80,443]}],"stages":[{"stage":"subs","run_id":1,"resumed":false,"dropped_hosts":[],"results":[],"skipped":[]}],"summary":{"hosts":1,"alive":1,"dns_only":0,"shut_down":0,"dead":0,"unknown":0,"tools_ok":1,"tools_failed":0,"tools_skipped":0,"tools_timeout":0}}
```

The `hosts` objects always carry `state`, `confidence` and `sources`; the top-level `summary` object carries the counts. `ToolResult` objects under `stages[].results` use the schemas in docs/09.

`stages[].skipped` lists every tool the engine selected out before it ran, as `{"tool":"<name>","reason":"<why>"}` objects - `no adapter yet (phase N)`, `requires --active`, `not installed`, or the docs/05 rule 6 block. A stage that has no adapter for any tool in its pool therefore shows its skips instead of an empty `results` array, so `results: []` means "ran, found nothing" only when `skipped` is empty too. `summary.tools_skipped` counts these rows along with any executed tool whose status is `skipped`; it is the total, not a per-tool count of executed results.

`diff --json` writes one document with `type: diff`, the run ids it compared (`baseline_run_id`, `previous_run_id`, `latest_run_id`; `baseline_run_id` is `null` until a third completed discovery run exists), and arrays `new`, `gone`, `pending_gone`, `state_changes`, `ports_opened` and `ports_closed`. `pending_gone` holds the hosts that are missing from the latest run only: the same list the human output prints under "not reported as GONE yet", so a script can apply its own tolerance without re-querying. `gone` follows the two-consecutive-miss rule above. `status --json` writes one document with `type: status` and a `runs` array; each run carries `id`, `target`, `stage`, `speed`, `status`, `started_at` and `finished_at`. `install`/`update`/`scope check`/the `db` and `export` stubs do not accept `--json` in this build.

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
This build has no live progress line; each stage prints its tables when it finishes, and the summary reports counts and tool statuses. `--json`/`--silent` suppress the human output. (`ui.render_progress` exists but is not wired.)

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
| 3 | Scope violation (target not allowed, scope missing or expired) |
| 4 | No usable tool for the stage |
| 5 | Partial success (some tools failed or timed out, or a requested stage executed no tools) |
| 6 | Every requested tool failed to install or update |
| 130 | Interrupted by user (state saved, resumable) |

Code `6` belongs to `install`/`update` only: it is returned by `installer.github_release.exit_code()` (0 when every tool installed, 5 for a partial install, 6 when nothing did). The scan path's enum (`engine.ExitCode`) deliberately stops at 5 plus 130 and cannot emit 6; a scan in which every tool failed is code 4. Do not add a scan-level 6.

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
