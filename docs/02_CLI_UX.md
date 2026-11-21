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

`reconkit <command> [target] [flags]`. Target is `-d DOMAIN` or `-l FILE` (one domain per line). With no command, `reconkit -d X` is shorthand for `passive` (the passive pipeline). Every scan command requires `-d` or `-l`: omitting both is a usage error (`provide a target with -d/--domain or -l/--list`, exit `2`), and bare `reconkit` prints help (exit `2`). There is no prompt and no interactive mode (D104, 2026-11-21).

### Scan modes (source of truth)

A scan mode is three things at once: **which stages run**, **which tool modes
are included** (the `mode:` field in `tools.yaml`), and **which tool tiers are
included** (`tier:` in `tools.yaml`). This table is the single definition. The
engine implements it in `MODE_STAGES` and `MODE_TOOLS` in `reconkit/engine.py`,
and the CLI help strings are generated from those same two dicts.

| Mode | Stages | Tool modes included | Tool tiers included | CLI |
|---|---|---|---|---|
| `passive` | `subs`, `dns`, `urls` | passive only | `core`, `opt_in`* | `passive` command, the bare form, or `run` (default) |
| `active` | `subs`, `dns`, `live`, `tech`, `urls`, `url_probe` | passive + active | `core`, `opt_in`* | `active` command or `run --active` |
| `full` | all: `subs`, `dns`, `live`, `ports`, `tech`, `urls`, `url_probe`, `shots`, `vulns` | passive + active | `core`, `opt_in`, `intrusive` | `full` command or `run --full` |

\*`opt_in` requires `--include-noisy`, unless the mode is `full` (which implies
it). `--full` also implies `--active`.

Stages still run in the fixed `STAGE_ORDER` (`subs`, `dns`, `live`, `ports`,
`tech`, `urls`, `url_probe`, `shots`, `vulns`); a mode only decides which of
them are in scope. So in `passive` the order is `subs`, `dns`, `urls`, and in
`active` it is `subs`, `dns`, `live`, `tech`, `urls`, `url_probe` - `urls`
always runs after `live` when `live` runs. `url_probe` (D23, 2026-11-18) sends
HTTP to the URLs the crawl found, so it is an active stage: `passive` never
requests it, and there is no scope file rule of its own - it goes through the
same scope gate as every other active stage (docs/05 rule 2). `shots` exists in
`full` only (D19) and sits between `url_probe` and `vulns`, so a browser never
delays the findings stage.

**What a urls tool receives depends on its `mode:`** (2026-11-17, D10):

- a **passive** urls tool (`gau`, `waybackurls`) is an archive query by domain,
  so it receives the discovered domain list (`<target>` plus every discovered
  host under it) in every mode. That is what makes `urls` runnable without the
  `live` stage.
- an **active** urls tool (`katana`, and later `hakrawler`, `gospider`, `subjs`)
  crawls what answered, so it receives the alive hosts, as before. In `passive`
  mode it is skipped at selection with `tool mode not included in passive mode`
  before any input is built.

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
and the `vulns` pool still carries three intrusive tools with no adapter
(`dalfox`, `crlfuzz`, `sqlmap`). `subs`, `dns`, `live`, `ports`, `tech` and
`urls` are fully adapted since adapter waves 6-8 (2026-11-17); `vulns` carries
`nuclei`, `subzy`, `dnsreaper`, `nikto` and `ffuf` (2026-11-20, D100); `shots`
has an adapter (`gowitness`) and is in the `full` mode table only (D19). An adapter-less tool reports
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
| `vulns` | vulnerability checks: `nuclei`, `subzy` (core); `nikto`, `ffuf` (opt_in); findings not persisted | yes | 3 |

There is no `url_probe` stage command (D23): the probe is part of a scan, not a
command of its own. A flagged `run -d X --active` (or `--full`) runs it after
`urls`, and `--skip-url-probe` leaves it out.

**What the url_probe stage does (D23, 2026-11-18).** The urls stage records what
the archive and the crawl returned, not whether any of it still answers. The
probe sends one `GET` to each stored URL whose `urls.status_code` is still
`NULL` (the current target only), and stores the HTTP status; a URL that cannot
be reached - connection refused, timeout, DNS failure - is stored as `-1`, and a
server that answers but whose TLS certificate does not verify (hostname mismatch,
untrusted chain) is stored as `-2`: `reconkit` never disables verification, so a
mismatched certificate is recorded as the fact it is instead of passing for a
dead URL. It is engine-owned: there is no adapter and no `tools.yaml` entry, so it
never appears in the Tools table, and it sends the honest `reconkit/<version>`
User-Agent (docs/05 rule 8). Bounds come from the `url_probe:` block in
`config.yaml`: `max_urls` (5000, the probe stops after that many and warns).
`batch_size` (200), `threads` (100) and `timeout_s` (10) shape how it works, and
one HTTP client is reused for the whole pass (D24). `--mock` never sends traffic,
so a mock run leaves every `status_code` at `NULL` and says so;
`--skip-url-probe` does the same deliberately. `--reprobe-urls` probes **every**
stored URL again instead of only the `NULL` ones, which is how a URL that has
since gone dead is found; it overwrites the stored answer in place.

The pass has a deadline (D26): `--phase-timeout`, or `timeouts.url_probe` (600 s)
when the flag is absent. On timeout the batches that finished keep their answers,
the URLs never reached stay `NULL`, the pass is recorded as `partial`, stderr
prints `url_probe: timed out after Ns (M/N URL(s) probed)`, the run reports a
completion gap (so `--json` says `complete_with_gaps`) and the exit code stays
**0** - a probe that ran out of time is a gap, not a failed scan.

**Probe-only runs are the one exception (D28).** A scan whose only stage is
`url_probe` (no other stage produced any result) and which times out produced
nothing usable, so it exits **4** under the existing "nothing usable" rule rather
than 0. A normal scan that includes `url_probe` alongside other stages is
unaffected and still exits 0 (see `test_url_probe_respects_phase_timeout`).

**Vulnerability scanning (current state, 2026-11-20).** The `vulns` stage is
implemented but narrow, and it is **full-only**: `run --active` never includes
it (the `active` entry in the mode table stops at `url_probe`). It runs inside
`--full`, where it is the last stage, or when the stage command is named
explicitly. `nuclei`, `subzy` and `dnsreaper` are `core` and run with the stage;
`nikto` and `ffuf` are `opt_in`, so they need `--include-noisy`, `--full`, or an
explicit `--tools` name. `dalfox`, `crlfuzz` and `sqlmap` are
`exploitation: true` and run only when named with `--tools`; none of the three
has an adapter yet. So a `run --active` stays discovery-only by design, and
findings come from `run --full` or `reconkit vulns`.

```bash
reconkit vulns -d example.com --active
reconkit full -d example.com
```

**Findings are not persisted.** `_persist_stage` has no `VULNS` branch and there
is no `findings` table, so no vulnerability row reaches SQLite, `diff`, or the
saved `report.txt`/`report.json`. What is kept:

```
workspaces/<target>/meta/<run_id>-<tool>.txt
```

one redacted, capped file per executed tool per `vulns` stage run (`run_id` is
that stage's `scan_runs` id). `tool_runs` stores the status, item count and
duration; the run's `--json` exposes the same file as
`stages[].results[].raw_path`. A `vulns` tool that is not installed is a
selection skip, and a stage left with none is a completion gap (exit `0`).

### Workflows
| Command | Pipeline |
|---|---|
| `passive -d X` | passive mode: subs + dns + urls (also `run -d X`, and bare `reconkit -d X`) |
| `active -d X` | active mode: subs + dns + live + tech + urls + url_probe; resumable (also `run -d X --active`) |
| `full -d X` | full mode: all nine stages (`ports`, `url_probe` and `shots` included), `opt_in` enabled; implies `--active` and `--include-noisy` (also `run -d X --full`) |
| `run -d X` | passive mode; `--active`/`--full` select the other two, exactly as the commands above do |

The three modes are also three commands: `passive`, `active` and `full` each run
their own mode's stages with that mode's tool modes and tiers, and are the same
run as `run` with the matching flag. `run` remains the flag-driven form, so
`active -d X` and `run -d X --active` are interchangeable. `lite` was removed on
2026-11-21: it was a second spelling of `passive` with no other difference.

`--active`/`--full` are a usage error (exit `2`) on every passive-only command -
the bare form, `passive`, `subs` and `dns` - because none of them runs an active
stage and accepting the flag would promise work the command cannot do. The message
names `active` as the command that can: use `reconkit active -d X` (or
`run -d X --active`). The active stage commands (`live`, `ports`, `tech`, `urls`,
`vulns`) take `--active` as their permission gate, as before.

**A stage command works on the hosts earlier runs stored.** `live`, `ports`, `tech`, `urls` and `vulns` do not repeat discovery, so they seed their host list from the database (ALIVE hosts for `ports`/`tech`/`urls`/`vulns`, every known name for `live`). Run an active or live pass first: `reconkit live -d X --active`, then `reconkit ports -d X --active`. A `ports` run with no stored ALIVE host now prints `ports: no ALIVE host from an earlier run; run 'reconkit live' first` instead of silently reporting `Ports -` with exit 0 (2026-11-20).

**What `--active` needs depends on whether a scope file exists.** With `--scope PATH` (default `./scope.yaml`):

- **No scope file at that path** - active and full runs are **refused before any traffic** with exit code 3: `Error: No scope.yaml found. Active scanning requires a scope file. If you intend to scan without scope restrictions, you must explicitly pass --no-scope.` Passive stages still work. `--no-scope` is the only way to run actively without a file (docs/05 rule 2, D82).
- **A scope file is present** - it is enforced exactly as before (`authorization`, `expires`, `allow_active`, `in_scope`, `out_of_scope`); a violation exits 3 and the file is only ever read, never rewritten or deleted.

The `--active` `--help` text says this in one sentence: `A scope.yaml is required; without one, active scanning is refused unless --no-scope is passed explicitly.`

**Ports run `pyscan`, `naabu`, `nmap`, `rustscan`, `smap` and `masscan` (wave 6).** `naabu` is scope-mode dependent (owner decision 2026-11-17, superseding the 12i permanent block): with **`--no-scope`** it runs unrestricted like any other active tool, receiving the discovered hostnames; with a **scope file present** the engine resolves each in-scope target itself, verifies every address against `in_scope_cidrs`, and passes `naabu` only those verified IPs - never a bare domain - skipping any target whose resolution fails or resolves out of scope (docs/05 rule 6, docs/09 section 4). Because two port adapters can now run, a port both report can reach `MEDIUM` confidence; a single-scanner result stays `LOW` and the open/closed disagreement rule only fires when both report. When `naabu` is absent or its targets cannot be verified, `pyscan` alone is the fallback and the ceiling is `LOW` again. `nmap` adds a `-sV` service/version fingerprint, `rustscan` a fast greppable sweep, and `smap` passive Shodan data filtered to `--ports`. `masscan` is `opt_in` **and needs root**: as a normal user it is `skipped (requires root / sudo)` and the stage continues; `sudo reconkit full ...` or `setcap cap_net_raw+ep` on the binary is the operator's call, never something the adapter does (docs/09 section 4a6).

### State and output
| Command | Purpose |
|---|---|
| `diff -d X` | New / changed / gone items since the previous run; `GONE` needs two consecutive misses |
| `status [--json]` | Progress of running or finished scans |
| `report --target X [--run ID] [--out DIR]` | Rebuild a saved `report.txt`/`report.json` from stored rows; read-only connection, no network, no adapter (D65, section 5) |
| `db delete --target X [--yes]` | Delete one target, all its rows and `results/X/`; asks first, default no (D81, D85) |
| `db wipe [--yes]` | Delete every row, recreate the current schema; `results/` is kept (D81) |
| `db list\|export -d X [--new-only]` | **Phase 3 stub** in this build: exits 1 with a clear message; no data is read |
| `export -d X --format json\|md\|html` | **Phase 3 stub** in this build: exits 1 with a clear message; no report is written |

**`diff` semantics.** `diff` compares the two latest completed discovery runs for the target: `scan_runs` rows for the `subs` stage whose status is `completed` or `partial`, newest first. Resume does not change which runs these are (a resumed stage produces its own row like any other run); no other stage takes part in the comparison. A host is **`GONE` only after two consecutive misses**: it must have been seen in the run *before* the previous one and be missing from both the previous run and the latest run. One miss is not a change and is never reported as `GONE`, because a single flaky passive source (a CT log timing out, a subfinder run returning fewer names) is indistinguishable from a real removal in one run. Consequences a user will see: a host that is missing from only the latest run is silent in the table and is listed once under `Not reported as GONE yet (needs two consecutive misses)`; a host that comes back after one miss is neither `NEW` (its first sighting is not reset) nor `GONE`; a real removal appears as `GONE` on the run after the second consecutive miss; and with fewer than three completed discovery runs nothing can be confirmed gone, so `gone` is empty and `diff` says so. A host is **`NEW`** when the latest completed discovery run is its first sighting by any discovery tool: a host that the `dns` stage resolved before any discovery tool returned it is stored with `provenance` `dns`, appears in `status` with no sources, and is never reported NEW - the first discovery run that returns it is the run that reports it new.

### Database management (D81, 2026-11-20)

```
reconkit db delete --target <domain> [--yes]
reconkit db wipe [--yes]
```

**`db delete`** removes one target and everything that hangs off it. Without
`--yes` it prints the counts it is about to delete and asks, default **no**:

```
Delete example.com from recon.db:
  1 target, 15 subdomains, 3161 URLs, 190 tool runs, 31 stage runs
  results/example.com/ (will be removed)
This cannot be undone. Delete this target? [y/N]:
```

Answering `n` prints `cancelled; nothing was deleted.` and exits `2`. The rows
are removed in one transaction, children first (`port_sources`,
`host_status_history`, `ports`, `subdomain_sources`, `tool_runs`, `urls`,
`subdomains`, `scan_runs`, `targets`), so a failure cannot leave half a target
behind. `results/<domain>/` and `results/mock/<domain>/` are removed after the
commit, and the summary names what went:

```
Deleted 1 target, 15 subdomains, 3161 URLs, 190 tool runs, 31 stage runs. Removed results/example.com/
```

A target that is not in the database is exit `2` with
`target <domain> is not in <db>`; nothing is written and no folder is removed.

If SQLite reports the database is locked (for example, a scan is running),
`db delete` and `db wipe` print
`Error: Database is locked. Is a scan running?` and exit `1` with no traceback.
If the rows were deleted but `results/<domain>/` could not be removed,
`db delete` prints a warning naming the folder and exits `0`: the database is
already clean, and the leftover folder is a manual filesystem cleanup.

**`db wipe`** is the whole-database reset. It always prints the loud warning,
then asks (default **no** unless `--yes`):

```
⚠ This will delete ALL targets and data from recon.db. Are you sure?
  6 targets, 27631 subdomains, 10181 URLs, 1077 tool runs, 182 stage runs
Wipe the database? [y/N]:
```

It drops every table and recreates the current schema, so `schema_version` is
current and the next scan starts clean. It deliberately **does not** touch
`results/` - deleting report folders is a separate filesystem decision - and
prints:

```
Note: results/ folders are untouched; use "rm -rf results/" manually if you want a full reset.
```

Both commands take the root `--db`/`--config` options, which must come **before**
the `db` subcommand (`reconkit --db /tmp/copy.db db wipe --yes`). `db list` and
`db export` stay Phase 3 stubs (exit 1).

### Existing list: which hosts are live? (D59, 2026-11-19)

**A list of hostnames works today, one hostname per line:**

```bash
reconkit live -l hosts.txt --active --scope scope.yaml
```

`-l` reads the file with `validate_target()` and runs each line as its **own
target**, so every name gets its own row set, its own report and its own pass
through the live stage (`pyprobe`, `httpx`, `httprobe`, `tlsx`). `--active` is
required because `live` is an active stage, and `--scope` gates it exactly like
any other active run: a name that is not in the scope file is refused with exit
`3`, never probed. Very large lists mean very many targets, so run it against a
scope file that names what you are authorized to touch.

**A list of URLs does not work.** The same `-l` parser is a *target* file: a
line like `https://nb.example.com/x` fails validation before any run starts
(`invalid domain label: 'https://nb'`), because `validate_target()` accepts
FQDNs only. The smallest enabler is a new option that reads a file, sends each
line through `validate_host()` rather than `validate_target()`, and probes those
URLs the way the `url_probe` stage does; that is a new flag and needs an owner
ruling, so this build does not have it. There is a second piece beyond the flag:
`Stage.LIVE`'s input is `[target] + that target's stored subdomains`, and
`engine.run()` takes one root target, so a file with no common root also needs
a way to hand the engine an explicit host list (REVIEW_LOG, 2026-11-19 loop
notes). A second attempt on 2026-11-19 tried the standalone route - parse the
file, dedupe hosts, apply the scope gate, run the live pool directly - and hit
the same wall from the other side: `live` is registered from the one shared
`_scan_command` (so a flag there appears on `run`, `subs`, `dns`, ... too), and
running adapters from the CLI would bypass `tool_runs`, the stage budget and
the CLI's layering rule (`tests/test_cli.py` asserts only `engine`, `ui`,
`config`, `core.*` are imported). The enabler is unchanged: an explicit host
list the engine accepts, plus an owner ruling for the flag.

**Getting the list out of a previous run.** `reconkit report --target <domain>`
rebuilds the saved report from the database (D65, section 5). `export`, `db
list` and `db export` remain Phase 3 stubs in this build: they print `... is
not wired in Part 8` and exit `1` without reading the database - `report`
supersedes what they were going to do for the host list. The export every run
already writes is `results/<target>/<timestamp>/report.json`,
where `hosts[].hostname` is the hostname list (and `report.txt` carries the same
names in its first column). That report contains hosts only - a name that
appeared only in `urls` rows is not in it unless D58's second resolve reached it
(see `docs/03` and `docs/09` section 5).

## 3. Flags

| Flag | Meaning |
|---|---|
| `-d, --domain` / `-l, --list` | Target or file of targets. Required on every scan command; omitting both is a usage error (exit `2`) |
| `--version` | Print `reconkit v<version>` and exit 0 (root command; D84) |
| `--active` | Run active stages: `subs`, `dns`, `live`, `tech`, `urls`, `url_probe`. Passive stages still run. Uses passive and active tools; no intrusive/aggressive tools. A `scope.yaml` is required; without one, active scanning is refused unless `--no-scope` is passed explicitly. Full rule: section 2 |
| `--full` | Run a full scan: all stages (`subs`, `dns`, `live`, `ports`, `tech`, `urls`, `shots`, `vulns`), using passive, active and intrusive-tier tools (exploitation-class tools still need `--tools`). Implies `--active` and `--include-noisy`, so `opt_in` tools run, `shots`/`gowitness` included. `shots` is full-only: no other mode and no stage command requests it |
| `--no-scope` | Ignore any scope file and behave as if none existed: active stages run unrestricted, a loud warning is printed, the run records `scope_mode = unrestricted_flag`, and scope.yaml is never modified. If `--scope PATH` is also given, `--no-scope` wins and a warning says `--scope PATH` was ignored. On a passive run it only warns and continues. Section 3.1 |
| `--tools a,b` | Run only these adapters. A named tool bypasses tier gating but not the mode gate |
| `--exclude LIST` | Skip what the list names, matched case-insensitively in this order: a **stage** (`subs`, `dns`, `live`, `ports`, `tech`, `urls`, `url_probe`, `shots`, `vulns`; `url` and `port` are accepted aliases), an **adapter** (`ffuf`, `katana`, ...), or a **report section** (`hosts`, `domains`, `urls`, `tools`). A value that names a stage *and* a section does both - `--exclude urls` prints `--exclude urls: stage skipped, report section hidden`. `hosts` and `tools` hide the console tables too, and `hosts`/`domains`/`urls` hide their part of `report.txt` and `report.json` (with `--exclude hosts` the `hosts` key stays and is empty, so the document keeps its shape). A value that names nothing prints `warning: ... unknown name 'x' ...; ignored` and the run continues: a typo must not abort a scan |
| `--include LIST` | Force a stage or adapter **in**, past the mode, and print `⚠ --include <name> forces target contact; this is no longer a <mode> scan.` The scope gate still applies; the run's report records `mode: active (forced by --include)`. Naming the same value in `--include` and `--exclude` is `contradictory: --include and --exclude both name X` (exit 2) |
| `--include-noisy` | Allow `opt_in` tier tools |
| `--only-alive` | Print only hosts whose state is `ALIVE`. If none match, print `no ALIVE hosts (N scanned)` |
| `--only-states S` | Print only hosts whose state is one of `ALIVE,DNS_ONLY,SHUT_DOWN,DEAD,UNKNOWN` |
| `--ports LIST` | Override the default port list for the ports adapters: `pyscan` and `naabu` replace their own defaults, `nmap` swaps `--top-ports 1000` for `-p`, `rustscan` swaps `--top` for `-p`, `masscan` gets `-p<LIST>`, and `smap` filters its passive results to the list (it cannot choose what it scans). Format `80,443,8000-8100` |
| `--status-codes LIST` | Only keep hosts that responded with one of these HTTP status codes (`200,301,302`) |
| `--header "Name: Value"` | Add an HTTP header for `httpx` and `pyprobe`; repeatable. A tool without `-H` logs `--header not applied to <tool> (no -H support)` and does not fail |
| `--user-agent STR` | Override the User-Agent for `httpx` and `pyprobe`. Without it, `config.yaml` `user_agent` applies, with `{version}` replaced by the package version (default `reconkit/{version}`) |
| `--ffuf-wordlist PATH` | Wordlist for `ffuf` content discovery, replacing the packaged `common.txt` (about 110 paths, D13). The file must exist and be readable; a missing file is a failed `ffuf` result, never a silent fallback |
| `--skip-url-probe` | Skip the `url_probe` stage for this run (D23): the archived URLs keep `status_code = NULL`, exactly as they were before the stage existed. Use it when the target's URL list is huge or the operator only wants discovery. The stage command `urls` never probes (it has no probe stage), so the flag is accepted and has nothing to skip |
| `--reprobe-urls` | Probe every stored URL again, not only the ones with `status_code = NULL` (D24), so a URL that answered once and has since gone dead is found. It overwrites `urls.status_code` in place and keeps the usual `max_urls` cut and warning. With `--skip-url-probe` it has no stage to act on, so that combination prints `warning: --reprobe-urls has no effect with --skip-url-probe` and the run continues |
| `--resolvers PATH` | Resolver list for `massdns` and `puredns`, replacing the packaged `src/reconkit/data/resolvers.txt` (16 public resolvers, D16). The file must exist and be readable; a missing file is a failed `massdns`/`puredns` result, never a silent fallback to the system resolver |
| `--redact-headers` / `--show-headers` | Hide (default) or reveal header values in JSON and UI output |
| `--min-sources N` | Hide results confirmed by fewer than N tools |
| `--phase-timeout SEC` | Stage time limit, applied to **every** stage including the engine-owned `url_probe` (D26). `--timeout-<stage>` is deferred; `--phase-timeout` is the only stage-timeout control in this build. Without it, each stage uses its `timeouts:` entry (`timeouts.url_probe` is 600 s). A stage killed at that deadline is a hard failure and the run exits **5** by design (R13, D45): a tool that did not finish is a real signal, so raise the deadline for a slow target rather than expect a gap. There is no per-tool runtime cap (D52): a tool runs until it exits, until it has been silent past its class's idle window (`config.yaml` `runtime_idle:`, the `class:` in `tools.yaml`), or until this deadline. An idle kill is `killed` (exit 0, partial output kept); reaching the deadline is `timeout` (exit 5, as R13/D45 require). A tool that finishes early is never delayed by either. |
| `--mock` | Use fixtures instead of real tools/network. A mock run is isolated: it stores under the `mock:<target>` target namespace, writes its DB to `~/.reconkit/mock.db` unless `--db` is given, and writes its report under `results/mock/<target>/`, so it can never pollute or overwrite a real run (D30). |
| `--resume` | Continue the latest unfinished run for the target; completed stages are not repeated |
| `--no-keys` | Force free mode on the scan commands: ignore API keys from `.env` (policy in docs/05 §6.1) |
| `--json` | One JSON document on stdout, no colors or progress |
| `--no-color`, `-v/--verbose`, `-q/--silent` | Output control |
| `--config PATH`, `--scope PATH`, `--db PATH` | Override file locations |

`install`, `update` and `doctor --fix` no longer exist (removed 2026-11-17, docs/MASTER_PLAN.md D4). Obtaining a missing tool is entirely up to you and is never a reconkit command; docs/10_TOOL_SOURCES.md is a reference to where each project lives, not a how-to.

`config.yaml` has no `tool_versions` key and no `install:` block (D87): both were accepted and ignored after the installer went, and both keys are now removed, so a config that still carries either is rejected as an unknown key like any other typo.

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

The exit-3 message is:
`active scan refused: example.com not in scope.yaml. Re-run with --no-scope or add example.com to scope.yaml.`

**A scope-limited run says so twice (D64, 2026-11-19).** The pre-flight block
above tells the operator what *will* be skipped; after the run, one more line
states what the run turned out to be, and the saved artifacts carry the same
sentence:

```
⚠ ACTIVE STAGES SKIPPED BY SCOPE — this run is passive-only; the report says so.
```

`report.json` adds `"scope_limited": true` and
`"scope_limited_reason": "active stages skipped by scope gate"`, and `report.txt`
puts the banner directly under its `hosts:` line. Keys are added only when the
gate refused something, so an ordinary report does not change shape.

**The exit code stays `3`.** A scope-limited run did not do what it was asked
(active stages were refused), and code `3` is the documented scope-refusal
signal (section 6, docs/05 rule 2). It is deliberately *not* `0` - passive
results exist, but a pipeline that reads `0` as "the scan I asked for ran"
would be misled. The annotation, not the exit code, carries "there are partial
results you can read".

## 4. Speed Modes (removed 2026-11-17)

The `slow`/`normal`/`fast` presets, `--speed`, `--delay`, the pacer (delays, host/port shuffling, parallel limits, request rate limiting), the `-rl`/`-rate` flags passed to tools and the typed `I AM AUTHORIZED` confirmation for `fast` were all removed at the owner's request (docs/MASTER_PLAN.md D3, reason: "user-requested removal, no throttling desired"). Every tool starts together and runs at its own natural pace. This heading keeps its number so the existing "section 5", "section 6" references elsewhere stay valid. A `scope.yaml` that still carries `max_speed` loads unchanged; the field is accepted and ignored, because there is no speed left to cap.

## 5. Output

### Result table (example `passive` / `diff`)

```
Subdomain          State      Status  Ports    Sources                    Trust       Notes
api.example.com    ALIVE      200     80,443   crtsh, subfinder, otx      HIGH (3)    canonical
vpn.example.com    DNS_ONLY   -       -        assetfinder, naabu         MEDIUM (2)  -
old.example.com    SHUT_DOWN  -       -        crtsh                      LOW (1)     -
new.example.com    UNKNOWN    -       -        certspotter, hackertarget  MEDIUM (2)  -
```

The **Ports** column is `ALIVE`-only (2026-11-21). Only a host that answered
can have been through the `ports` stage, so a `DNS_ONLY`/`SHUT_DOWN`/`DEAD`/
`UNKNOWN` row prints `-` even when the `ports` table still holds rows from an
earlier run. The table and the saved report agree (`report.txt` prints
`not applicable`, `report.json` writes `null`). When no row is `ALIVE` the
column is left out entirely, like **Notes**, because a column of `-` says
nothing.

The **Notes** column (D22, 2026-11-18) explains a www/non-www pair instead of
hiding a row: `-> redirects to <host>` for a 3xx duplicate, `-> duplicate of
<host>` for a same-server duplicate, `canonical` for the host a duplicate points
at, and the informational `has www sibling at <host>` / `www variant on a
different server` when both names serve independently. `-` means no sibling was
found, and when no row has anything to say the column is left out entirely so an
ordinary table keeps its six columns. The state, status and confidence of every row are unchanged; the
`--only-alive` filter still prints both names, now self-explanatory. The summary
line gains the unique count when any duplicate exists:
`20 hosts (18 unique after www-dedup): 12 ALIVE, ...`.

- A final summary line: counts per state and tool statuses. New items are shown by `diff`, not in the stage summary.
- A "Tools" table lists each adapter with stage, status (`ok`, `gap`, `skipped`, `failed`, `timeout`, `killed`), item count, time taken, how stale its last output was and a short detail. The `Last output` column is `-` except for a `killed` row, where it is the number of seconds since the tool last printed anything - what tells a stuck tool apart from a slow one that is still working (D52). The `Unique` column (D77, 2026-11-20) is the number of distinct URLs that tool contributed to the store that the target did not already hold, so `Items 663 / Unique 15` means 648 of its 663 URLs were duplicates; a tool that added nothing shows `0`, and a stage that stores no URLs prints `-`.
- A stop is not a failure: a tool the idle watchdog killed keeps every record it had already produced, the summary line gains `N killed` only when N is above zero, and stderr gains the block below. A run whose tools were all killed still exits `0`.

**`gap` is a tool status, not a failure (owner ruling 2026-11-18).** An adapter whose upstream refused the request for a reason that is not about the tool - HTTP 429/rate limiting, a free-quota message, or an HTTP 5xx from the service it calls - is recorded `gap` with the service's own message in the detail column. It keeps whatever data it did return (usually none), it does **not** make the run partial (exit `5`), and it appears in the completion gaps block: the scan used every tool that was available, the third party simply did not answer. Every other non-zero outcome stays `failed`/`timeout` and still exits `5`.

### Doctor output

`doctor` prints one row per tool: `tool`, `stage`, `tier`, `installed`, `path`, `identity`. A `kind: http` or `kind: python` tool needs no binary, so `path` prints `n/a (no binary required)` and `installed` is always `yes`; only `kind: binary` tools can be missing. A binary that exists but fails its identity check prints `wrong program` in `installed` (with its `path`) and counts as not ready. **Doctor shows no version**: `version_cmd` and `version_regex` exist only to prove a copy is the expected program, and the string they read is never displayed (owner ruling 2026-11-17, docs/MASTER_PLAN.md D6). Below the table: a one-row **Browser** table (`chromium`, `yes`/`missing`, and `shots will produce 0 screenshots` when absent - D35; gowitness cannot screenshot without a Chromium-family browser), per-stage coverage (`subs 6/11 ready`), system packages, the Keys table (names and sign-up URLs, never values), and, when anything is missing, `47 installed, 0 manual, 1 needs attention (amass). Scans will use the tools that are installed and skip the rest. Per-tool provenance: docs/10_TOOL_SOURCES.md.` (D36 - the counts come from `DoctorReport.installed` and `.manual`, the same fields the JSON carries, so the footer and `--json` cannot disagree; a `manual: true` tool is a known by-hand install, not a gap). `--json` writes one document with `type`, `python`, `python_ok`, `config`, `scope`, `db`, `tools`, `stages`, `system_packages`, `keys`, `missing`, `installed`, `manual`, `warnings`, `chromium` and `exit_code`, and keeps warnings at exit `0` (docs/10 section 3); each object in `tools` carries `tool`, `stage`, `tier`, `kind`, `installed`, `path` and `identity`, with no version key.

### JSON (`--json`)

One JSON document is written to stdout; tables and progress stay on stderr. The fixed shape is:

```json
{"type":"summary","target":"example.com","exit_code":0,"resumed":false,"scope_denied":false,"scope_mode":"enforced","completion":{"status":"complete","gaps":[]},"warnings":[],"scope_warnings":[],"hosts":[{"fqdn":"api.example.com","state":"ALIVE","confidence":"HIGH","sources":["crtsh","subfinder","otx"],"status_code":200,"ports":[80,443],"detail":null,"duplicate_of":null,"www_note":null}],"www_dedup":{"applied":false,"pairs":[]},"stages":[{"stage":"subs","run_id":1,"resumed":false,"dropped_hosts":[],"results":[],"skipped":[]}],"summary":{"hosts":1,"alive":1,"dns_only":0,"shut_down":0,"dead":0,"unknown":0,"tools_ok":1,"tools_failed":0,"tools_skipped":0,"tools_timeout":0}}
```

The `hosts` objects always carry `state`, `confidence` and `sources`; the top-level `summary` object carries the counts. `scope_mode` is the same value written to `scan_runs` (section 3.1).

`completion` is always present (section 6): `status` is `complete` or `complete_with_gaps`, and `gaps` lists one object per incomplete stage: either a requested stage that had no runnable tool, `{"stage": "urls", "reason": "no adapter yet (phase 3)"}`, or a stage where an executed tool hit an external-service problem, `{"stage": "subs", "reason": "otx: rate limited (HTTP 429)"}`. A consumer that only cares whether the run was usable reads `status`; one that wants to explain the shortfall reads `gaps`.

The `summary` object also carries `tools_gap`, the number of executed tools with the `gap` status, beside `tools_ok`/`tools_failed`/`tools_skipped`/`tools_timeout`, and `tools_killed` (D52), the tools the idle watchdog stopped with their partial output kept. `tools_timeout` counts the tools the phase deadline stopped (`--phase-timeout`, D38), which is why it can be non-zero even when `records` are empty; a `killed` row carries `last_output_s`, the seconds since it last produced output.

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

`hosts[].duplicate_of` is the canonical hostname when the row is a www/non-www duplicate, `null` otherwise (docs/04 section 5, D22), and `hosts[].www_note` carries the informational sibling text when there is one. The top-level `www_dedup` object is always present: `applied` is `true` when at least one duplicate pair was detected, and `pairs` lists `{"host": "www.example.com", "duplicate_of": "example.com"}` for each one.

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
- **A per-tool heartbeat (added 2026-11-19, D50).** A tool that is still running
  after 10 s prints one durable line to stderr, `<stage>: <tool> running (<n>s)`,
  exactly once per tool; it stops when the tool exits and leaves no closing
  "done" line, because the finished-tool line above already says what happened.
  It reports liveness only - no mid-stream URL counts, because a tool that prints
  1042 URLs in one block has no progress to report - and `--silent` suppresses it
  with every other progress line.

### Saved reports (every scan)
One folder per domain per run, never reused:

```
<results_dir>/<domain>/<YYYYmmddTHHMMSSZ>/
  report.txt          selected fields, one row per host, aligned columns
  report.json         the same rows as objects, plus target, run time and field keys
  subdomains.txt      every stored name, one per line
  alive.txt           ALIVE hosts only, one per line
  dns_resolved.txt    ALIVE + DNS_ONLY; DNS_ONLY = resolves but answers no HTTP
  host-info.txt       domain | state | status | ips | tech (no URLs)
  host-info.json      the same rows as objects
  external_urls.txt   URLs whose host is outside the target (D76)
  hosts/<hostname>/
    urls.txt          this host's URLs, one line each, status appended when probed
    info.json         this host's row from host-info
```

The five top-level lists and the `hosts/` tree are written by default
(`report.emit_lists` and `report.per_host_folders`, both `true`). A
`hosts/<hostname>/` folder is created only for a host that has at least one
stored URL - an empty folder is not evidence. `subdomains.txt`,
`alive.txt` and `dns_resolved.txt` are written even when empty, so a downstream
script can tell "the run found nothing" from "the run did not write this file".
`urls.txt` carries `<url>` alone when the URL was never probed and
`<url>\t<status>` once `url_probe` stored one.

- `results_dir` is the `config.yaml` key of that name (default `results`), used
  by `--config` like every other key.
- A second run for the same domain gets its own folder; an existing folder is
  never written into. When two runs start within the same second the later one
  gets a `-2`, `-3`, ... suffix, so no run can overwrite another.
- Both files are always written, whatever field selection was made. A field the
  run could not observe prints `not applicable` rather than a guessed value.
- **Every scan writes these two files** (changed 2026-11-18). The report always
  carries every stored field (`REPORT_FIELDS`); the display flags narrow what is
  shown, never what is saved. Until this change a flagged run wrote nothing at
  all, which left the operator with a terminal table and no artifact; the
  inconsistency was reported from a real scan on 2026-11-18.
- **The report follows the display filters, and says so.** A run with
  `--only-alive` writes only the `ALIVE` hosts to `report.txt`/`report.json`,
  so the artifact matches the table you just read instead of hiding 34 `DEAD`
  rows under 8. The filters still change nothing in the database (section 3) -
  every host stays stored and `status`/`diff` still see it. Because a filtered
  artifact must never look complete, the report records the selection it used:
  `report.txt` carries `selection: 8 of 42 hosts (ALIVE)`, and `report.json`
  carries `"selection": {"filter": "ALIVE", "matched": 8, "total": 42}`;
  without filters the key is `null` and every stored row is written.
- **A domain tree and the URLs it carries (added 2026-11-19, D62).** The hosts
  table is unchanged; two blocks are added beside it, both read from rows the
  run already stored (no request is made for them). `report.json` gains
  `roots` - one entry per target, because one report covers one target:
  `[{"domain": "example.com", "subdomains": ["a.example.com", ...],
  "host_count": 69}]` - plus `urls_by_host` (`{"<host>": [{"url": ...,
  "status_code": 200|null, "host_state": "ALIVE"}]}`, only for hosts with at
  least one URL), `urls_total`, `urls_shown` and `urls_truncated`.
- **Which URLs a report lists, and how many.** Inside each host the sort keys
  are, in order: (1) an interesting path (`admin`, `login`, `api`, `.git`,
  `.env`, `backup`, `config`, `upload`, `debug`, `phpinfo`, `swagger`,
  `graphql`, `.sql`, `.zip`, `.bak`, `dashboard`, `panel`, `test`, `dev`);
  (2) the URL carries **no** marketing/referral parameter (`utm_*`, `fbclid`,
  `gclid`, `rc`, `ic`, `_branch_match_id`, `_branch_referrer`, `af_xp`, `pid`,
  `deep_link_value`, `deep_link_sub1`); (3) it has a query string; (4) it
  answered `200`/`301`/`302`; then host and URL to make the order total. Noise
  is a tiebreaker, not a filter: a referral URL is still listed, and an
  interesting path keeps key 1 even when it carries one. `config.yaml`
  `report.noise_params` **adds** names to the built-in list; it never replaces
  it. The cap is the
  `config.yaml` key `report.urls_max` (default `0` = no cap, changed 2026-11-19)
  and it applies to the **whole report**, not per host. With `0` every stored URL
  is listed and `urls_truncated` stays `false`; with a cap, `urls_shown` and
  `urls_truncated` say exactly what was cut, and `report.txt` prints
  `urls: 200 of 300 shown (report.urls_max 200)` instead of leaving a short list
  looking complete. `hosts/<hostname>/urls.txt` is never capped: it is that
  host's own list.
- **A repeat scan says what it probed and what was already answered (D73,
  changed 2026-11-20 by D78).** `url_probe` never re-checks a stored answer, so
  after the first scan most of a URL list is already known. The header now
  names both halves: `urls: 5639 total, 88 probed this run, 5551 already probed
  (use --reprobe-urls)`. `report.json` carries `urls_probed_this_run` and, when
  non-zero, `urls_skipped_already_probed`; D73's `urls_already_probed` stays
  beside them for compatibility. Under `--reprobe-urls` nothing is skipped, so
  the skipped key is absent and no note is printed. When a count above zero was
  skipped, the run ends with one line: `ℹ 5551 URL(s) were skipped because
  they already had a status code; use --reprobe-urls to re-check them.` A first
  run writes neither key nor line, and a `report` rebuild (no run context) keeps
  the old `urls: N total, M shown` form.
- **Third-party URLs are stored but kept out of the host report (D76,
  2026-11-20).** A URL stage can return assets on another domain
  (`www.google.com`, `fonts.googleapis.com`, `apps.apple.com`). They are still
  stored - an archive named them, so dropping them would lose evidence - and
  `urls.source` is `'external'`. They never create a `subdomains` row, never
  appear under `urls_by_host`, and never get a `hosts/<hostname>/` folder; the
  list is written to `external_urls.txt` instead. In scope means the target
  itself or a name ending in `.<target>`. `report.json` counts them apart as
  `external_urls_total`, and `urls_total`/`urls_shown`/`urls_truncated` describe
  the in-scope pool only.
- **The text file gets the same two blocks.** After the hosts table,
  `=== Domains ===` lists the root and then one `  <host>   <STATE>  <CONFIDENCE>`
  line per subdomain (a single `69 subdomains, see hosts table` line past 50,
  which is the length at which one line each stops being readable), then
  `=== URLs by host ===` lists each host with its state and its URLs with their
  stored status (`null` = never probed). A report with **no** stored URLs writes
  neither block, and `report.json` omits `urls_by_host` entirely, so an empty
  section is never something a reader has to interpret.
- The same `report: <txt> and <json>` line on stderr announces the files, so a
  run always says where its report went; `--silent` suppresses that line only.
- A report that can not be written is a run error (exit 1), never a silent
  success.
- **A report can be rebuilt from the database, without scanning (added
  2026-11-19, D65).** `reconkit report --target <domain> [--run <id>] [--db
  <path>] [--out <dir>]` runs the same writer over the rows already stored, so
  a run that predates the current report shape can be read in it without
  touching the target again:
  `wrote <dir>/report.txt and <dir>/report.json — 69 hosts, 7421 URLs (200
  shown)`. `--run` defaults to that target's latest `scan_runs` row; an id that
  is not the target's is exit `2` and writes nothing. The database is opened
  `mode=ro`: the connection cannot write, nothing is fetched and no adapter
  runs. `--out` is created if missing; without it the folder is
  `<results_dir>/<domain>/<run stamp>`, with `-rebuilt` appended when a report
  already exists there, because the stored one is evidence of that run. Two
  things it deliberately does *not* do: the hosts are the latest stored state
  and the URL block is every URL stored for the target (the same input a
  scan's own report reads), not a snapshot of that run only; and the header
  carries the run's own timestamp, because the file describes that run.

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
| 3 | Scope violation: a present scope file refuses the target, or an active/full run has no scope file (D82). A **missing** scope file is a refusal, not an implicit permission (section 2) |
| 4 | No usable tool for the stage |
| 5 | Partial success (some tools failed or timed out, or a requested stage executed no tools because deliberate rules excluded every tool). An **external-service** outcome (429, quota, 5xx, or a request that never answered, from a third party) is a completion gap, not a failure, and never produces 5 on its own |
| 6 | Retired 2026-11-17: was "every requested tool failed to install or update" |
| 130 | Interrupted by user (state saved, resumable) |

Code `6` is retired (2026-11-17, docs/MASTER_PLAN.md D4): it belonged to `install`/`update` only, and both commands are gone. No command can emit it, and the scan path's enum (`engine.ExitCode`) never could - a scan in which every tool failed is code 4. Do not reuse 6.

**A requested stage that executed zero tools is either a completion gap (code 0) or a partial run (code 5), depending on why.** Zero executed tools means every tool in that stage's pool was selected out before running, so the stage created a `scan_runs` row and `tool_runs` skip rows but no result. The engine splits the causes in `Engine._completion_gaps()`:

- **Absence -> gap (exit 0).** The only reasons are `no adapter yet (phase N)` or `not installed`: the scan used every tool that was available. The run exits `0`, and two channels carry the honesty: one warning per stage, `"<stage> stage executed no tools: N tool(s) skipped (<reasons>)"`, and one gaps **block** on stderr (below).
- **Any other cause -> still 5.** `tier not included in <mode> mode`, `tool mode not included in <mode> mode`, `exploitation tool requires explicit --tools`, or the docs/05 rule 6 block are deliberate exclusions or a scope decision, not "the tool was not there". A stage emptied that way keeps exit `5`.
- **External-service problems -> gap (exit 0).** A tool that ran and was refused by its upstream is recorded with the `gap` status (section 5) instead of `failed`. R8 (2026-11-18) calls this state **degraded**; the encoded name stays `gap`, so `--json`, `tool_runs.status` and the block all keep one spelling. The signatures are an HTTP 429, a rate-limit/quota/"too many requests"/"api count exceeded" message, or an upstream 5xx in an HTTP context (500, 502, 503, 504, `bad gateway`, `service unavailable`, `gateway timeout`, `internal server error`) - `Engine`/`adapters.base.classify_external_gap` is the only place that list lives. **A request that never answered is in the same class when the adapter is marked `external: true`** (D57, 2026-11-19): a third party that does not answer in time is not a fault on this box, so `HttpAdapter._timeout_failure()` records `gap` with the row `crtsh: request timed out` and the run can exit 0 (measured: 30.71 s was the only failure in the 488 s example.com run). That rule lives in the adapter, not in the text classifier, because a local binary that prints "timed out" is still a local fault. A **local** fault is never degraded: a missing binary, a non-zero exit with no upstream signature, a crash, invalid output, a refused connection (even to an external API - that can be this box's network) or an auth error (401/403) stays `failed` and still produces exit 5. `Engine._completion_gaps()` turns it into one gap entry naming the stage and the service's message, the same block a missing adapter gets. Retry later; there is nothing to fix on this box.
- A stage that is a gap **and** another stage with a failed tool still exits `5`: a gap never masks a failure.
- **No input -> skipped -> gap (exit 0).** A stage tool that needs a host list and is handed an empty one is `skipped` with the detail `no input hosts` and never runs (R10, 2026-11-19): the usual cause is a discovery pass that found nothing alive, which used to make every downstream tool report `failed: no hosts to scan`. A stage whose results are all skips is a completion gap naming the stage; the run exits `0`. A real failure in any other tool still exits `5`, and `skipped` never hides one.


The gaps block is printed by `ui.render_completion_gaps()` and is **stderr-only**, so `--json` stdout stays one clean document. It prints nothing at all when there are no gaps, which keeps every ordinary run's output byte-identical. `--silent` suppresses it like every other message; the exit code and `completion` in `--json` are unaffected.

The block below is the **format**; the counts change with every adapter wave
(2026-11-17, wave 5: `vulns` gained `nuclei` and `subzy`, so on a box with the
usual tools installed a `--full` run has no gaps at all and prints nothing).

```text
⚠ full scan completed with gaps — 4 stage(s) incomplete
  subs: 5 tool(s) skipped (no adapter yet (phase 3))
  dns: 3 tool(s) skipped (no adapter yet (phase 3))
  ports: 4 tool(s) skipped (no adapter yet (phase 3))
  vulns: 5 tool(s) skipped (no adapter yet (phase 3))
  run 'reconkit doctor' to see what is installed; see docs/10_TOOL_SOURCES.md for provenance.
  this is not a failure — the scan used every tool that was available.
```

A stage where executed tools hit an external-service problem reads without a
skip count, because nothing was skipped:

```text
⚠ active scan completed with gaps — 1 stage(s) incomplete
  subs: otx: rate limited (HTTP 429), hackertarget: free quota exceeded, crtsh: server error (HTTP 502)
  run 'reconkit doctor' to see what is installed; see docs/10_TOOL_SOURCES.md for provenance.
  this is not a failure — the scan used every tool that was available.
```

The count on each line is the number of tools skipped for an absence reason, so a stage whose pool also contains exploitation-class tools reports only the absent ones (that is why `vulns` reads 5, not 8). The same data is in `--json` as `completion` (section 5). This replaced the 2026-11-17 rule that made every zero-tool stage exit 5 (owner ruling, `docs/MASTER_PLAN.md` D9).

**The "stopped early" block (D52, 2026-11-19).** A tool the idle watchdog stopped is not a
failure, so it gets its own stderr-only block instead of a gap - the run did use the
tool, it just went quiet. `ui.render_killed_tools()` prints it, nothing at all when
nothing was killed, `--silent` suppresses it, and the exit code stays `0`. A stage
budget timeout is **not** in this block: it keeps `status: timeout` and exit `5`
(R13/D45).

```text
⚠ 2 tool(s) stopped early — partial output kept
  gau: killed after 60s idle at stage 412.3s, 1042 partial
  urlfinder: killed after 180s idle at stage 611.0s, 996 partial
  raise that class's window under runtime_idle: in config.yaml, or the stage budget with --phase-timeout.
```

The same data is in `--json` as `summary.tools_killed` plus one `results[]` object per
tool with `status: "killed"`, `last_output_s` and the detail in `error`.

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
## Scope exclusions and `scope_warnings` (D56, 2026-11-19)

`scope.yaml` accepts `exclude_cidrs`, and an excluded range wins over `in_scope_cidrs`. Because only the
engine-resolved tools (`pyscan`, `naabu`) can honour it, a non-empty `exclude_cidrs` produces one warning at run start
naming the selected tools that resolve inside their own child. The same sentence is stored in the run's artifacts: a
top-level `scope_warnings` array in the `--json` summary document and in `report.json`, and a `scope warnings:` block
in `report.txt`. The key is always present (empty when there is nothing to report), so a consumer never branches on its
absence.
