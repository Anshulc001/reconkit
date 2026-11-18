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

`reconkit <command> [target] [flags]`. Target is `-d DOMAIN` or `-l FILE` (one domain per line). With no command, `reconkit -d X` is shorthand for `lite` (the passive pipeline). A scan command with **neither** `-d` nor `-l` on a terminal asks questions instead of failing (section 2b); with a target flag present nothing changes and nothing is asked.

### Scan modes (source of truth)

A scan mode is three things at once: **which stages run**, **which tool modes
are included** (the `mode:` field in `tools.yaml`), and **which tool tiers are
included** (`tier:` in `tools.yaml`). This table is the single definition. The
engine implements it in `MODE_STAGES` and `MODE_TOOLS` in `reconkit/engine.py`,
and the CLI help strings and the interactive question are generated from those
same two dicts.

| Mode | Stages | Tool modes included | Tool tiers included | CLI | Interactive |
|---|---|---|---|---|---|
| `passive` | `subs`, `dns`, `urls` | passive only | `core`, `opt_in`* | (default) | `passive` |
| `active` | `subs`, `dns`, `live`, `tech`, `urls` | passive + active | `core`, `opt_in`* | `--active` | `active` |
| `full` | all: `subs`, `dns`, `live`, `ports`, `tech`, `urls`, `shots`, `vulns` | passive + active | `core`, `opt_in`, `intrusive` | `--full` | `full` |

\*`opt_in` requires `--include-noisy`, unless the mode is `full` (which implies
it). `--full` also implies `--active`.

Stages still run in the fixed `STAGE_ORDER` (`subs`, `dns`, `live`, `ports`,
`tech`, `urls`, `shots`, `vulns`); a mode only decides which of them are in
scope. So in `passive` the order is `subs`, `dns`, `urls`, and in `active` it is
`subs`, `dns`, `live`, `tech`, `urls` - `urls` always runs after `live` when
`live` runs. `shots` exists in `full` only (D19) and sits between `urls` and
`vulns`, so a browser never delays the findings stage.

**What a urls tool receives depends on its `mode:`** (2026-11-17, D10):

- a **passive** urls tool (`gau`, `waybackurls`) is an archive query by domain,
  so it receives the discovered domain list (`<target>` plus every discovered
  host under it) in every mode. That is what makes `urls` runnable without the
  `live` stage.
- an **active** urls tool (`katana`, and later `hakrawler`, `gospider`, `subjs`)
  crawls what answered, so it receives the alive hosts, as before. In `passive`
  mode it is skipped at selection with `tool mode not included in passive mode`
  before any input question arises.

The `tech` stage takes the alive hosts and runs only in `active` and `full`.

Two rules cut across the table:

- **`--tools <name>` overrides tier gating.** A named tool runs whatever its
tier, but the tool-mode column still applies: an active-mode tool named in
passive mode is skipped with `tool mode not included in passive mode`.
- **Exploitation-class tools never fire automatically.** A tool whose
  `tools.yaml` entry says `exploitation: true` is skipped in every mode, `full`
  included, with `exploitation tool requires explicit --tools`; only naming it
  with `--tools` runs it. Today that is `sqlmap`, `dalfox` and `crlfuzz`
  (AGENTS "recon only", docs/09).

**Every other doc that mentions scan modes points here. If you find a
contradiction elsewhere, this table wins - file it as a doc bug.**

What "full = all" means today, honestly: every stage is requested and every
`core` and `opt_in` tool is eligible. The `intrusive` tier is enabled, but its
three tools are `exploitation: true` and therefore still skip unless named;
and the `vulns` pool still carries one tool with no adapter (`dnsreaper`, D15).
`subs`, `dns`, `live`, `ports`, `tech` and `urls` are fully adapted since
adapter waves 6-8 (2026-11-17); `shots` has an adapter (`gowitness`) and is in
the `full` mode table only (D19). An adapter-less tool reports
`no adapter yet (phase 3)`, and a stage left with only those is a completion gap
(exit `0`), not a partial run. The per-tool mode/tier table is in docs/09
section 4.

### Setup and health
| Command | Purpose | Phase |
|---|---|---|
| `doctor` | Tools, versions, system packages, API key names + Keys table, per-stage coverage | 2 |
| `scope check -d DOMAIN` | Show whether a target is allowed by `scope.yaml` | 2 |
| `scope import` | Build `scope.yaml` from a bug bounty program | 3 |

### Stages (single stage per command)
| Command | Mode | Needs `--active` | Phase |
|---|---|---|---|
| `passive` | subs + dns + urls, passive tools only (the passive mode) | no | 2 |
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
| `run -d X` | passive mode: subs + dns + urls |
| `run -d X --active` | active mode: subs + dns + live + tech + urls; resumable |
| `run -d X --full` | full mode: all eight stages (the seven discovery stages plus `shots`), `opt_in` enabled; implies `--active` and `--include-noisy` |

`passive` is the stage command: it runs the subs, dns and urls stages for one target, with passive tools only. `lite` is the workflow shortcut for exactly that passive pipeline and nothing active; adapters, flags and exit codes are the same. Only `run` includes active stages (and `run` is where `--full` applies).

`--active` is a usage error (exit `2`) on every passive-only command - the bare form, `lite`, `passive`, `subs` and `dns` - because none of them runs an active stage and accepting the flag would promise work the command cannot do. The message names `run` as the active workflow. Use `run -d X --active`, or an active stage command (`live`, `ports`, `tech`, `urls`, `vulns`), for active stages.

**What `--active` needs depends on whether a scope file exists.** With `--scope PATH` (default `./scope.yaml`):

- **No scope file at that path** - active and full scanning run **unrestricted** against the target(s) given with `-d`/`-l` and every host discovered under them. Nothing is derived from the target, no implicit scope is built, and the run is not refused (docs/05 rule 2). "No scope file" means "scan freely, I know what I typed"; exit code 3 is not produced for a missing file.
- **A scope file is present** - it is enforced exactly as before (`authorization`, `expires`, `allow_active`, `in_scope`, `out_of_scope`); a violation exits 3 and the file is only ever read, never rewritten or deleted.

The `--active` `--help` text says this in one sentence: `A scope.yaml, when present, is enforced; with no scope file, active scanning is unrestricted.` The interactive mode asks the scope question before the mode question, so the same branch applies there (section 2b).

**Ports run `pyscan`, `naabu`, `nmap`, `rustscan`, `smap` and `masscan` (wave 6).** `naabu` is scope-mode dependent (owner decision 2026-11-17, superseding the 12i permanent block): with **no scope file** it runs unrestricted like any other active tool, receiving the discovered hostnames; with a **scope file present** the engine resolves each in-scope target itself, verifies every address against `in_scope_cidrs`, and passes `naabu` only those verified IPs - never a bare domain - skipping any target whose resolution fails or resolves out of scope (docs/05 rule 6, docs/09 section 4). Because two port adapters can now run, a port both report can reach `MEDIUM` confidence; a single-scanner result stays `LOW` and the open/closed disagreement rule only fires when both report. When `naabu` is absent or its targets cannot be verified, `pyscan` alone is the fallback and the ceiling is `LOW` again. `nmap` adds a `-sV` service/version fingerprint, `rustscan` a fast greppable sweep, and `smap` passive Shodan data filtered to `--ports`. `masscan` is `opt_in` **and needs root**: as a normal user it is `skipped (requires root / sudo)` and the stage continues; `sudo reconkit run ...` or `setcap cap_net_raw+ep` on the binary is the operator's call, never something the adapter does (docs/09 section 4a6).

### State and output
| Command | Purpose |
|---|---|
| `diff -d X` | New / changed / gone items since the previous run; `GONE` needs two consecutive misses |
| `status [--json]` | Progress of running or finished scans |
| `db list\|export -d X [--new-only]` | **Phase 3 stub** in this build: exits 1 with a clear message; no data is read |
| `export -d X --format json\|md\|html` | **Phase 3 stub** in this build: exits 1 with a clear message; no report is written |

**`diff` semantics.** `diff` compares the two latest completed discovery runs for the target: `scan_runs` rows for the `subs` stage whose status is `completed` or `partial`, newest first. Resume does not change which runs these are (a resumed stage produces its own row like any other run); no other stage takes part in the comparison. A host is **`GONE` only after two consecutive misses**: it must have been seen in the run *before* the previous one and be missing from both the previous run and the latest run. One miss is not a change and is never reported as `GONE`, because a single flaky passive source (a CT log timing out, a subfinder run returning fewer names) is indistinguishable from a real removal in one run. Consequences a user will see: a host that is missing from only the latest run is silent in the table and is listed once under `Not reported as GONE yet (needs two consecutive misses)`; a host that comes back after one miss is neither `NEW` (its first sighting is not reset) nor `GONE`; a real removal appears as `GONE` on the run after the second consecutive miss; and with fewer than three completed discovery runs nothing can be confirmed gone, so `gone` is empty and `diff` says so. A host is **`NEW`** when the latest completed discovery run is its first sighting by any discovery tool: a host that the `dns` stage resolved before any discovery tool returned it is stored with `provenance` `dns`, appears in `status` with no sources, and is never reported NEW - the first discovery run that returns it is the run that reports it new.

## 2b. Interactive scan mode (no target flags)

A scan command given **neither `-d` nor `-l`** asks a short question series
instead of failing with "provide a target". This applies to `subs`, `dns`, `live`, `ports`,
`tech`, `urls`, `vulns`, `passive`, `lite` and `run`. Two hard conditions:

- **Any target flag at all means no questions.** If `-d` or `-l` is present, the
  command behaves exactly as section 2 describes - no prompt is shown and no
  input is read. Every scripted invocation, and the whole automated test suite,
  is in this branch.
- **Interactive input requires a terminal on stdin.** With stdin redirected from a
  pipe or `/dev/null` (CI, cron, `ssh host reconkit passive`), the command keeps
  today's behaviour: `provide a target with -d/--domain or -l/--list` and exit `2`.
  Nothing ever blocks waiting for input that cannot arrive.

The questions:

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
   assumed mode. The legend is generated from `MODE_STAGES`/`MODE_TOOLS` and
   says, for each choice, the stages and the tool modes/tiers - the same words
   as the "Scan modes (source of truth)" table:

   ```
   Scan mode:
     passive  - subs, dns, urls stages; passive tools only
     active   - subs, dns, live, tech, urls stages; passive+active tools
     full     - all stages (subs, dns, live, ports, tech, urls, shots, vulns);
                passive+active+intrusive
   Choice [passive/active/full]:
   ```

   `active` and `full` set `--active`, so the scope gate applies unchanged.
   `full` additionally sets `--full` and `--include-noisy`. Exploitation-class
   tools still require `--tools`. Because the `tech` and `vulns` stages have no
   adapter in this build, an `active` or `full` choice requests stages that
   report their skips and warn, then finish as **completion gaps** (exit `0`,
   section 6) - the same rule as a flag-based `run --active`/`--full`, stated
   before the run starts.
4. **Report fields.** A numbered menu built from fields `reconkit` actually
   stores (host state, confidence, discovery sources, source count, IPs, status
   code, title, redirect location, open ports, technology, and the `UNKNOWN`
   reason). The answer is a comma-separated list like `1,3,5` or `all`. Fields
   that only make sense for a host that answered on the web (status code, title,
   redirect location, technology, open ports) are written as `not applicable` for
   every host whose state is not `ALIVE`, and the reason field only for `UNKNOWN`
   hosts; no value is ever guessed for a host the run did not observe.
5. **Aggressive scanning.** A separate yes/no asked when the answer to 3 was
   `passive` or `active` (a `full` run already includes every stage).
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
4. **Scan mode.** The legend above, then `Choice [passive/active/full]` - no
   default, re-asked until valid. `passive`, `active` and `full` mean what the
   table says.
5. **Report fields.** The numbered menu of stored fields, then
   `Fields [all]` (`1,3,5`, `all`, ...).
6. **Scan parameters (active/full only).** In this order:
   `Ignore scope file and run unrestricted? [y/N]` (a `y` prints the loud
   `--no-scope` warning and asks `This disables scope enforcement. Continue?`),
   `Ports to scan (comma or ranges, blank = default)`,
   `Only show ALIVE, all, or custom states? [alive/all/custom]` (with
   `States (comma list)` for `custom`),
   `Only keep HTTP status codes? (comma, blank = all)`,
   `Extra HTTP headers? [y/N]` (then `Header`, repeated until blank), and
   `Custom User-Agent? [y/N]`.
7. **Aggressive scanning (passive/active only).**
   `Also run aggressive scanning (port scan + version detection)? [y/N]`; `y`
   adds `live` + `ports` and sets `--active`. A `full` run skips this question.
8. **Plan echo.** Two lines, for example:
   `plan: example.com; mode full; scope enforced (scope file); stages subs, dns,
   live, ports, tech, urls, shots, vulns; tools passive+active+intrusive; fields 12` and,
   when anything was injected,
   `inject: ports 80,443; status_codes 200,301; states ALIVE; headers 2;
   user_agent custom`.
9. **Out-of-scope prompt (scope file present, `--no-scope` not chosen).** When
   the present scope file blocks the target, the run offers
   `[a] add <target> to scope.yaml` (asks `This will modify scope.yaml. Proceed?`,
   and only a `y` appends the entry), `[b] ignore scope and run unrestricted
   (--no-scope)`, `[c] scan an in-scope target instead`, `[d] abort` (exit `2`,
   nothing written). Only `[a]` ever writes scope.yaml, and only after the
   explicit `y`.
10. **Run.** The ordinary engine runs once per target, results are stored, and a
    report folder per domain is written (section 5).
11. **Scope branch at run time.** With **no scope file**, or with `--no-scope`,
    the active/full stages run unrestricted against the target(s) the operator
    named and everything discovered under them (docs/05 rule 2 and section 3).
    With a scope file **present** and `--no-scope` absent, the unchanged gate
    applies (exit `3` on a missing `allow_active`, expired scope or out-of-scope
    target) and `naabu` runs only on IPs reconkit resolved and verified against
    `in_scope_cidrs`, skipping a target whose resolution fails or resolves out
    of scope (docs/05 rule 6).
12. **No speed option.** There is no `--speed`, `--delay`, preset or throttle
    question anywhere in this flow, and none in `--help` (docs/03 section 7).

The interactive path adds **no flags**: `--help` for a scan command is unchanged,
and there is no `--interactive` switch. Omitting the target is the whole trigger.

## 3. Flags

| Flag | Meaning |
|---|---|
| `-d, --domain` / `-l, --list` | Target or file of targets. Omitting both on a scan command starts the interactive mode (section 2b); that is the only trigger and it adds no flag |
| `--active` | Run active stages: `subs`, `dns`, `live`. Passive stages still run. Uses passive and active tools; no intrusive/aggressive tools. A `scope.yaml`, when present, is enforced; with no scope file, active scanning is unrestricted. Full rule: section 2 |
| `--full` | Run a full scan: all stages (`subs`, `dns`, `live`, `ports`, `tech`, `urls`, `shots`, `vulns`), using passive, active and intrusive-tier tools (exploitation-class tools still need `--tools`). Implies `--active` and `--include-noisy`, so `opt_in` tools run, `shots`/`gowitness` included. `shots` is full-only: no other mode and no stage command requests it |
| `--no-scope` | Ignore any scope file and behave as if none existed: active stages run unrestricted, a loud warning is printed, the run records `scope_mode = unrestricted_flag`, and scope.yaml is never modified. If `--scope PATH` is also given, `--no-scope` wins and a warning says `--scope PATH` was ignored. On a passive run it only warns and continues. Section 3.1 |
| `--tools a,b` / `--exclude x,y` | Pick or skip adapters. A named tool bypasses tier gating but not the mode gate |
| `--include-noisy` | Allow `opt_in` tier tools |
| `--only-alive` | Print only hosts whose state is `ALIVE`. If none match, print `no ALIVE hosts (N scanned)` |
| `--only-states S` | Print only hosts whose state is one of `ALIVE,DNS_ONLY,SHUT_DOWN,DEAD,UNKNOWN` |
| `--ports LIST` | Override the default port list for the ports adapters: `pyscan` and `naabu` replace their own defaults, `nmap` swaps `--top-ports 1000` for `-p`, `rustscan` swaps `--top` for `-p`, `masscan` gets `-p<LIST>`, and `smap` filters its passive results to the list (it cannot choose what it scans). Format `80,443,8000-8100` |
| `--status-codes LIST` | Only keep hosts that responded with one of these HTTP status codes (`200,301,302`) |
| `--header "Name: Value"` | Add an HTTP header for `httpx` and `pyprobe`; repeatable. A tool without `-H` logs `--header not applied to <tool> (no -H support)` and does not fail |
| `--user-agent STR` | Override the default User-Agent for `httpx` and `pyprobe` |
| `--ffuf-wordlist PATH` | Wordlist for `ffuf` content discovery, replacing the packaged `common.txt` (about 110 paths, D13). The file must exist and be readable; a missing file is a failed `ffuf` result, never a silent fallback |
| `--resolvers PATH` | Resolver list for `massdns` and `puredns`, replacing the packaged `src/reconkit/data/resolvers.txt` (16 public resolvers, D16). The file must exist and be readable; a missing file is a failed `massdns`/`puredns` result, never a silent fallback to the system resolver |
| `--redact-headers` / `--show-headers` | Hide (default) or reveal header values in JSON and UI output |
| `--min-sources N` | Hide results confirmed by fewer than N tools |
| `--phase-timeout SEC` | Stage time limit. `--timeout-<stage>` is deferred; `--phase-timeout` is the only stage-timeout control in this build. |
| `--mock` | Use fixtures instead of real tools/network |
| `--resume` | Continue the latest unfinished run for the target; completed stages are not repeated |
| `--no-keys` | Force free mode on the scan commands: ignore API keys from `.env` (policy in docs/05 §6.1) |
| `--json` | One JSON document on stdout, no colors or progress |
| `--no-color`, `-v/--verbose`, `-q/--silent` | Output control |
| `--config PATH`, `--scope PATH`, `--db PATH` | Override file locations |

`install`, `update` and `doctor --fix` no longer exist (removed 2026-11-17, docs/MASTER_PLAN.md D4). Obtaining a missing tool is entirely up to you and is never a reconkit command; docs/10_TOOL_SOURCES.md is a reference to where each project lives, not a how-to.

`config.yaml` has no `tool_versions` key: it was accepted and ignored after the installer went, and the key itself was removed on 2026-11-17, so a config that still carries one is rejected as an unknown key like any other typo. The `install:` block (`dir`, `verify_checksums`) is accepted and ignored.

There is no `--speed` and no `--delay`: both were removed on 2026-11-17 at the owner's request (docs/MASTER_PLAN.md D3). Tools start together and run at their own natural pace; nothing in reconkit throttles, delays or reshuffles them.

Not provided (by design): any flag that skips the scope gate while still reading the scope file. `--no-scope` is **not** that: it removes the scope file from the run entirely, exactly as if it did not exist, and it always warns loudly. Section 3.1.

### 3.1 Scope mode and `--no-scope`

Every scan writes `scan_runs.scope_mode`, one of:

| Value | Meaning |
|---|---|
| `enforced` | A scope file was found at the resolved path and its gate was applied |
| `no_file` | No scope file existed at the resolved path |
| `unrestricted_flag` | `--no-scope` was given; any scope file was ignored |

With `--no-scope` and an active or full run, this block goes to stderr before
anything runs and never blocks it:

```
⚠ --no-scope given: active stages will run WITHOUT scope enforcement.
  target(s): example.com
  no scope file is being read, checked, or enforced.
  a scan_runs record will be written with scope_mode = "unrestricted_flag".
```

Without `--no-scope`, a scope file that would block an active run gets a
pre-flight block on stderr (the run still starts; passive stages still run and
the exit code is `3`):

```
⚠ scope gate would block active stages for: example.com
  scope.yaml contains: testfire.net, *.testfire.net, testphp.vulnweb.com, zonetransfer.me
  active stages will be SKIPPED for this target.
  options:
    - add example.com to scope.yaml
    - pass --no-scope to ignore the scope file and run active stages unrestricted
    - scan an in-scope target instead
```

The non-interactive exit-3 message is:
`active scan refused: example.com not in scope.yaml. Re-run with --no-scope or add example.com to scope.yaml.`
The interactive equivalent offers `[a]`/`[b]`/`[c]`/`[d]` (section 2b point 9).

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

`doctor` prints one row per tool: `tool`, `stage`, `tier`, `installed`, `path`, `identity`. A `kind: http` or `kind: python` tool needs no binary, so `path` prints `n/a (no binary required)` and `installed` is always `yes`; only `kind: binary` tools can be missing. A binary that exists but fails its identity check prints `wrong program` in `installed` (with its `path`) and counts as not ready. **Doctor shows no version**: `version_cmd` and `version_regex` exist only to prove a copy is the expected program, and the string they read is never displayed (owner ruling 2026-11-17, docs/MASTER_PLAN.md D6). Below the table: per-stage coverage (`subs 6/11 ready`), system packages, the Keys table (names and sign-up URLs, never values), and `Missing tools: N. Scans will use the tools that are installed and skip the rest. Per-tool provenance: docs/10_TOOL_SOURCES.md.` when anything is missing. `--json` writes one document with `type`, `python`, `python_ok`, `config`, `scope`, `db`, `tools`, `stages`, `system_packages`, `keys`, `missing`, `warnings` and `exit_code`, and keeps warnings at exit `0` (docs/10 section 3); each object in `tools` carries `tool`, `stage`, `tier`, `kind`, `installed`, `path` and `identity`, with no version key.

### JSON (`--json`)

One JSON document is written to stdout; tables and progress stay on stderr. The fixed shape is:

```json
{"type":"summary","target":"example.com","exit_code":0,"resumed":false,"scope_denied":false,"scope_mode":"enforced","completion":{"status":"complete","gaps":[]},"warnings":[],"hosts":[{"fqdn":"api.example.com","state":"ALIVE","confidence":"HIGH","sources":["crtsh","subfinder","otx"],"status_code":200,"ports":[80,443],"detail":null}],"stages":[{"stage":"subs","run_id":1,"resumed":false,"dropped_hosts":[],"results":[],"skipped":[]}],"summary":{"hosts":1,"alive":1,"dns_only":0,"shut_down":0,"dead":0,"unknown":0,"tools_ok":1,"tools_failed":0,"tools_skipped":0,"tools_timeout":0}}
```

The `hosts` objects always carry `state`, `confidence` and `sources`; the top-level `summary` object carries the counts. `scope_mode` is the same value written to `scan_runs` (section 3.1).

`completion` is always present (section 6): `status` is `complete` or `complete_with_gaps`, and `gaps` lists one object per requested stage that had no runnable tool, `{"stage": "urls", "reason": "no adapter yet (phase 3)"}`. A consumer that only cares whether the run was usable reads `status`; one that wants to explain the shortfall reads `gaps`.

With a filter flag (`--only-alive`, `--only-states`, `--status-codes`) the
`hosts` array is already filtered and a top-level `filter` object is added:
`{"only_states":["ALIVE"],"matched":3,"total":12}` (plus `"status_codes"`
when `--status-codes` was used). The database write is unchanged: filters only
change what is printed.

With an injectable flag (`--ports`, `--status-codes`, `--header`, `--user-agent`,
`--ffuf-wordlist`, `--resolvers`) a top-level `injections` object is added:
`{"ports":[80,443],"status_codes":[200,301],"headers":{"X-Test":"***"},"user_agent":"reconkit-test","ffuf_wordlist":"/path/common.txt","resolvers":"/path/resolvers.txt"}`
(`ffuf_wordlist` and `resolvers` are `null` unless the flag was given).
Header values are redacted as `***` unless `--show-headers` was given. `ToolResult` objects under `stages[].results` use the schemas in docs/09.

`hosts[].detail` is the bounded, redacted reason recorded with that host's latest status row (docs/04 section 5): `null` unless the latest pass could not decide a better state, in which case it is a one-line string of at most 200 characters with the run's known secrets redacted. It is the machine-readable half of a diagnostic the human table does not show - a script can tell a TLS failure apart from another cause without probing the host again.

`stages[].skipped` lists every tool the engine selected out before it ran, as `{"tool":"<name>","reason":"<why>"}` objects - `no adapter yet (phase N)`, `tool mode not included in <mode> mode`, `tier not included in <mode> mode`, `exploitation tool requires explicit --tools`, `not installed`, or the naabu scope-mode skip from docs/05 rule 6 (resolution failed or resolved outside `in_scope_cidrs`). A stage that has no adapter for any tool in its pool therefore shows its skips instead of an empty `results` array, so `results: []` means "ran, found nothing" only when `skipped` is empty too. `summary.tools_skipped` counts these rows along with any executed tool whose status is `skipped`; it is the total, not a per-tool count of executed results.

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
- **A live status line exists because finished-tool lines are not enough** (added
  2026-11-18). The lines above only appear when a tool *finishes*, so a stage
  holding a 600 s tool looked frozen. While a target runs, one spinner line on
  stderr is rewritten in place with
  `<stage>: <done>/<total> tool(s) done, <n>s elapsed - running: <tools>`; it
  names the tools still in flight, and all of a stage's tools appear at once
  because the stage starts them together. It is transient (erased when the run
  ends, nothing left behind), it is only drawn when stderr is a terminal, and it
  never writes to stdout - a redirected or piped stderr gets exactly the plain
  lines it got before, and `--silent` removes it too. Which tool starts next is
  still not predicted: the line reports what is running, in the order the stage
  started it.

### Saved reports (every scan)
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
- **Every scan writes these two files** (changed 2026-11-18). The interactive
  questions only *choose the columns*; a `-d`/`-l` run has no question to answer,
  so it writes every stored field (`REPORT_FIELDS`, the same set as answering
  `all`). Until this change a flagged run wrote nothing at all, which left the
  operator with a terminal table and no artifact; the inconsistency was reported
  from a real scan on 2026-11-18.
- The report is built from **every host row the run stored**, not from the
  filtered table: `--only-alive`/`--only-states`/`--status-codes` narrow what is
  printed on screen and never what is stored (section 3), so a filtered run's
  `report.txt` can hold more rows than the table you saw. That is deliberate -
  the artifact is the run's record, not a screenshot of one view.
- The same `report: <txt> and <json>` line on stderr announces the files, so a
  run always says where its report went; `--silent` suppresses that line only.
- A report that can not be written is a run error (exit 1), never a silent
  success.

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
| 5 | Partial success (some tools failed or timed out, or a requested stage executed no tools because deliberate rules excluded every tool) |
| 6 | Retired 2026-11-17: was "every requested tool failed to install or update" |
| 130 | Interrupted by user (state saved, resumable) |

Code `6` is retired (2026-11-17, docs/MASTER_PLAN.md D4): it belonged to `install`/`update` only, and both commands are gone. No command can emit it, and the scan path's enum (`engine.ExitCode`) never could - a scan in which every tool failed is code 4. Do not reuse 6.

**A requested stage that executed zero tools is either a completion gap (code 0) or a partial run (code 5), depending on why.** Zero executed tools means every tool in that stage's pool was selected out before running, so the stage created a `scan_runs` row and `tool_runs` skip rows but no result. The engine splits the causes in `Engine._completion_gaps()`:

- **Absence -> gap (exit 0).** The only reasons are `no adapter yet (phase N)` or `not installed`: the scan used every tool that was available. The run exits `0`, and two channels carry the honesty: one warning per stage, `"<stage> stage executed no tools: N tool(s) skipped (<reasons>)"`, and one gaps **block** on stderr (below).
- **Any other cause -> still 5.** `tier not included in <mode> mode`, `tool mode not included in <mode> mode`, `exploitation tool requires explicit --tools`, or the docs/05 rule 6 block are deliberate exclusions or a scope decision, not "the tool was not there". A stage emptied that way keeps exit `5`.
- A stage that is a gap **and** another stage with a failed tool still exits `5`: a gap never masks a failure.

The gaps block is printed by `ui.render_completion_gaps()` and is **stderr-only**, so `--json` stdout stays one clean document. It prints nothing at all when there are no gaps, which keeps every ordinary run's output byte-identical. `--silent` suppresses it like every other message; the exit code and `completion` in `--json` are unaffected.

The block below is the **format**; the counts change with every adapter wave
(2026-11-17, wave 5: `vulns` gained `nuclei` and `subzy`, so on a box with the
usual tools installed a `--full` run has no gaps at all and prints nothing).

```text
⚠ full scan completed with gaps — 4 stage(s) had no runnable tools
  subs: 5 tool(s) skipped (no adapter yet (phase 3))
  dns: 3 tool(s) skipped (no adapter yet (phase 3))
  ports: 4 tool(s) skipped (no adapter yet (phase 3))
  vulns: 5 tool(s) skipped (no adapter yet (phase 3))
  run 'reconkit doctor' to see what is installed; see docs/10_TOOL_SOURCES.md for provenance.
  this is not a failure — the scan used every tool that was available.
```

The count on each line is the number of tools skipped for an absence reason, so a stage whose pool also contains exploitation-class tools reports only the absent ones (that is why `vulns` reads 5, not 8). The same data is in `--json` as `completion` (section 5). This replaced the 2026-11-17 rule that made every zero-tool stage exit 5 (owner ruling, `docs/MASTER_PLAN.md` D9).

**Precedence, highest first** (one decision site, `Engine._exit_code`):

1. `3` - scope denied (passive results already collected are kept).
2. `4` - the run has at least one new stage and selected no tool at all (a run resumed entirely from completed stages still exits 0), **or** every selected tool in the run failed. This wins over the empty-stage rule: a run where nothing usable ran or every tool failed is 4 even if another stage was empty, and a `--full` run on a box with nothing installed is 4, not 0 - "no usable tool" is still its own signal.
3. `5` - at least one requested stage executed zero tools for a non-absence reason, **or** at least one selected tool failed/timed out.
4. `0` - otherwise, including every run whose zero-tool stages were all absence gaps. A resumed run whose requested stages were all already completed keeps 0.

When **every** requested stage is empty, the run follows rule 2 and exits `4`, not 0 or 5: no tool ran anywhere, which is the documented meaning of "no usable tool". A stage dropped by `--tools`/`--exclude` is *not* an empty stage - the engine never creates a stage outcome for it, so it neither warns nor changes the exit code; the same applies to `ports` when there are no hosts to scan (the stage is skipped before it builds a pool).

If passive stages have already completed and an active stage is denied by scope, the run still exits `3`; the passive results already collected are kept and reported.

## 7. Accessibility
- Readable with `--no-color`; no information carried only by color.
- Stable column order and plain-text output when piped.
- `--json` output uses fixed field names (see docs/09_TOOL_CONTRACTS.md).
