# UX Flows

Journey overview: **setup -> doctor -> obtain the tools you need -> scope -> passive -> live/ports -> diff -> export**.

## Flow 1 - First run (setup)

1. User follows SETUP.md (native Kali/Ubuntu, the only supported platform).
2. `reconkit doctor`
3. Output: table of tools (installed / path / identity), per-stage coverage, system packages, Python version, `scope.yaml` found?, API key names set/unset.
4. Footer line: `Missing tools: 14. Scans will use the tools that are installed and skip the rest. Per-tool provenance: docs/10_TOOL_SOURCES.md.`

**Choosing a scan mode (2026-11-17).** The first real scan is one of three
modes, defined in the "Scan modes (source of truth)" table in docs/02 section 2:
`passive` (default: `subs` + `dns` + `urls`, passive tools only), `active` (the
same plus `live` and `tech`, passive and active tools), `full` (all eight stages,
`shots` included, `opt_in` enabled, implies `--active` and `--include-noisy`). Exploitation-class tools never run
automatically in any mode. A scan command given neither `-d` nor `-l` is a
usage error (exit `2`); there is no prompt. With no `scope.yaml` an active/full
run is refused (exit `3`) unless `--no-scope` is given; with one present, a
blocked target prints the pre-flight block and exits `3` too (docs/02 section
3.1).

- **Success:** exit code 0 with warnings listed.
- **Failure:** Python < 3.11 or an unreadable `config.yaml`: clear message, exit code 1. `doctor` runs on every platform; reconkit installs nothing anywhere, so there is no platform-specific install path (docs/10 §4).

## Flow 2 - Obtaining tools (your own job)

reconkit installs nothing: `install`, `update` and `doctor --fix` were removed on 2026-11-17 (docs/MASTER_PLAN.md D4). How you obtain a tool is outside reconkit entirely, and this document does not prescribe a route.

1. `reconkit doctor` lists every missing tool and the count in the footer line above.
2. docs/10_TOOL_SOURCES.md §2 shows where each project lives (the same `source:` string as `tools.yaml`): provenance, not a procedure.
3. Obtain whichever tool you want by whatever route you prefer. No reconkit command installs, downloads or updates anything, and reconkit never uses `sudo`.
4. Make sure the binary is on `PATH`, or in `~/.reconkit/bin`, which is checked first (docs/10 §3).
5. Re-run `reconkit doctor` to confirm. A tool that is present but is not the expected program shows `wrong program` in the `installed` column and counts as not ready.

- **Loading state:** none. No process starts, so there is no progress line or summary table.
- **Error state:** your package manager's or download's error; reconkit is not involved. If a namesake binary is first on `PATH`, doctor's `wrong program` row names the path it found.
- **Empty state:** nothing is missing, so doctor prints no `Missing tools:` line at all.

## Flow 3 - Define scope

1. User copies `scope.example.yaml` to `scope.yaml` and edits.
2. `reconkit scope check -d api.example.com`
3. Output: `ALLOWED (matches *.example.com)` or `BLOCKED (out_of_scope: admin.example.com)` or `BLOCKED (scope expired 2027-01-31)`.

## Flow 4 - Passive recon (default, safe)

1. `reconkit passive -d example.com`
2. The scan opens with the ReconKit banner, credits and live version, then a separator (D107); `--json` and `--silent` omit it.
3. The stage runs until it finishes (no estimated time in this build). Progress lines go to stderr (`subs: running 6 tool(s)`, one line per tool); `--silent` is the only thing that suppresses them (docs/02 section 5).
4. The wildcard check runs before results are accepted; an `unknown` detection adds a warning instead of a result line.
5. Result table columns: `Subdomain`, `State`, `Status`, `Ports`, `Sources`, `Trust`, followed by the Tools table.
6. Footer: counts per state and tool statuses. It does not print workspace or DB paths.
7. `report.txt`, `report.json` and `report.pdf` are written under `results/<target>/<stamp>/`; the same moments are recorded in `results/logs/<target>/<stamp>.log` with colored `[HH:MM:SS] [LEVEL]` milestones on stderr (D107).

- **Success:** exit 0.
- **Complete with gaps:** a requested stage had no runnable tool at all (`no adapter yet (phase N)`, `not installed`), or an executed tool was refused by an external service (HTTP 429/rate limit, free quota, upstream 5xx - recorded as the `gap` tool status). Exit 0; one warning per stage plus the `⚠ ... completed with gaps` block on stderr, and `completion.status = complete_with_gaps` in `--json`. The scan used every tool that was available.
- **Partial:** some tools failed or timed out, or a requested stage was emptied by a deliberate rule (tier, tool mode, exploitation, scope). Exit 5, warning names the stage, results still saved.
- **Failure:** no usable tool for stage: exit 4; the message names the stage and the tools that are not installed.
- **Empty:** message listing which tools returned nothing.

## Flow 5 - Live and shut-down detection (active)

1. `reconkit live -d example.com --active`
2. Scope gate runs first. With a `scope.yaml` and no `--no-scope`, a blocked target gets the pre-flight warning and exit `3` (`active scan refused: ... not in scope.yaml`), and no active traffic is sent. With no scope file, an active/full run is refused with exit `3` before traffic; only `--no-scope` runs unrestricted (docs/05 rules 2 and 9, D82).
3. No speed preset: every selected tool starts together and runs at its own pace.
4. Table columns: `Subdomain`, `State` (ALIVE / DNS_ONLY / SHUT_DOWN / DEAD), `Status`, `Ports`, `Sources`, `Trust`. Title and tech are not rendered in this build.
5. State changes are not flagged in the stage table; `diff` shows them later as `STATE` rows (`old -> new`).

- **Speed:** there is no speed control (removed 2026-11-17): no `--speed`, no `--delay`, no confirmation prompt.

## Flow 6 - Port scanning (active)

1. `reconkit ports -d example.com --active` (connect scan, default port set)
2. Each selected port scanner uses its own default port set; results are merged by host, IP and port.
3. Table columns: `Subdomain`, `State`, `Status`, `Ports`, `Sources`, `Trust`; the IP, service and per-port state are stored but not rendered as separate columns.
4. The port set comes from the adapters by default; `--ports 80,443,8000-8100` overrides it for `pyscan` and `naabu` (docs/02 section 3).

## Flow 7 - Diff

1. `reconkit diff -d example.com`
2. Rows are labelled `NEW`, `GONE`, `STATE` (`old -> new`), `PORT OPEN` and `PORT CLOSED`; there are no `[NOW ALIVE]`/`[WENT DOWN]` section labels.
3. `GONE` means the host has been missing for **two consecutive** completed discovery runs (docs/02); a host missing from the latest run only is not a change and is printed once below the table as `Not reported as GONE yet (needs two consecutive misses): a.example.com, b.example.com`.
4. `--json` gives the same data for scripts or AI agents, including `pending_gone`.

- **Empty:** `No changes since run #7.` (no date is printed). A run that has only one or two completed discovery runs prints `No changes since run #7.` / the first-run line plus the note `GONE needs three discovery runs to compare; nothing can be confirmed gone yet.`
- **No previous run:** `No completed discovery run for this target.` when there is no run at all, or `First run for this target (#7). Nothing to compare.` when only one exists.

## Flow 8 - Status of a long scan

1. In a second terminal: `reconkit status --json`
2. Output example:

```json
{"type":"status","runs":[{"id":12,"target":"example.com","stage":"live","status":"running","started_at":"2026-11-12T10:00:00Z","finished_at":null}]}
```

## Flow 9 - Interrupt and resume

1. User presses Ctrl+C. The engine stops launching new tools, marks the stage run `interrupted`, and exits 130. A child process already running is not explicitly killed in this build.
2. `reconkit active -d example.com --resume` continues from the unfinished stage; completed stages are not repeated, and the interrupted stage is rerun from its start.

## Flow 10 - Export (Phase 3 stub in this build)

`export`, `db export`, `db list` and `scope import` exit 1 with a clear "not wired" message; the steps below describe the intended Phase 3 behavior.

1. `reconkit export -d example.com --format md -o report.md`
2. Formats: `json`, `md`, `html`. HTML content is escaped.
3. Report includes scope header (program, authorization note), scan dates, tools used, results with sources and trust.
