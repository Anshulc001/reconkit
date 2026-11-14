# UX Flows

Journey overview: **setup -> doctor -> install -> scope -> passive -> live/ports -> diff -> export**.

## Flow 1 - First run (setup)

1. User follows SETUP.md (native Kali/Ubuntu for real tools, or Windows for mock/passive use and `doctor`).
2. `reconkit doctor`
3. Output: table of tools (installed/missing + version), per-stage coverage, system packages, Python version, `scope.yaml` found?, API key names set/unset.
4. Suggestion line: `Missing tools: 14. Run: reconkit install --all`

- **Success:** exit code 0 with warnings listed.
- **Failure:** Python < 3.11 or an unreadable `config.yaml`: clear message, exit code 1. `doctor` also runs on native Windows; only `install` and `update` refuse there (docs/10 §2).

## Flow 2 - Install tools

1. `reconkit install --all --dry-run` prints one row per tool with `tool`, `method`, `result` and `detail` (the detail carries the destination, release URL or apt command).
2. `reconkit install --all` asks to confirm sudo for apt packages (`libpcap-dev`, `nmap`, ...).
3. Per tool: download, verify checksum, place in `~/.reconkit/bin`, run version command.
4. Final: summary table. `doctor` is a separate command; the installer does not re-run it.

- **Loading state:** a single final table; the installer has no live per-tool progress line.
- **Error state:** `subfinder_...zip: checksum mismatch (expected ..., got ...)` (fails closed), continues with others, exit code 5.
- **Empty state:** every row still prints, each as `already installed` with its version or path; there is no separate "everything installed" line.

## Flow 3 - Define scope

1. User copies `scope.example.yaml` to `scope.yaml` and edits.
2. `reconkit scope check -d api.example.com`
3. Output: `ALLOWED (matches *.example.com)` or `BLOCKED (out_of_scope: admin.example.com)` or `BLOCKED (scope expired 2027-01-31)`.

## Flow 4 - Passive recon (default, safe)

1. `reconkit passive -d example.com` (speed `slow`)
2. The stage runs silently until it finishes (no header or estimated time in this build).
3. There is no live progress line; `ui.render_progress` is not wired.
4. The wildcard check runs before results are accepted; an `unknown` detection adds a warning instead of a result line.
5. Result table columns: `Subdomain`, `State`, `Status`, `Ports`, `Sources`, `Trust`, followed by the Tools table.
6. Footer: counts per state and tool statuses. It does not print workspace or DB paths.

- **Success:** exit 0.
- **Partial:** some tools skipped/failed, or a requested stage executed no tools (warning names it), exit 5, results still saved.
- **Failure:** no usable tool for stage: exit 4, hint to run install.
- **Empty:** message listing which tools returned nothing.

## Flow 5 - Live and shut-down detection (active)

1. `reconkit live -d example.com --active`
2. Scope gate runs first; blocked = exit 3 and no traffic.
3. Slow mode: hosts shuffled, random pause between hosts, rate-limited probes.
4. Table columns: `Subdomain`, `State` (ALIVE / DNS_ONLY / SHUT_DOWN / DEAD), `Status`, `Ports`, `Sources`, `Trust`. Title and tech are not rendered in this build.
5. State changes are not flagged in the stage table; `diff` shows them later as `STATE` rows (`old -> new`).

- **Fast speed:** `--speed fast` prints a warning and requires typing `I AM AUTHORIZED`.

## Flow 6 - Port scanning (active)

1. `reconkit ports -d example.com --active` (connect scan, default port set, slow)
2. Each selected port scanner uses its own default port set; results are merged by host, IP and port.
3. Table columns: `Subdomain`, `State`, `Status`, `Ports`, `Sources`, `Trust`; the IP, service and per-port state are stored but not rendered as separate columns.
4. This build has no `--ports`/`--full` flags; the port set comes from the adapters (docs/02).

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
{"type":"status","runs":[{"id":12,"target":"example.com","stage":"live","speed":"slow","status":"running","started_at":"2026-11-12T10:00:00Z","finished_at":null}]}
```

## Flow 9 - Interrupt and resume

1. User presses Ctrl+C. The engine stops launching new tools, marks the stage run `interrupted`, and exits 130. A child process already running is not explicitly killed in this build.
2. `reconkit run -d example.com --active --resume` continues from the unfinished stage; completed stages are not repeated, and the interrupted stage is rerun from its start.

## Flow 10 - Export (Phase 3 stub in this build)

`export`, `db export`, `db list` and `scope import` exit 1 with a clear "not wired" message; the steps below describe the intended Phase 3 behavior.

1. `reconkit export -d example.com --format md -o report.md`
2. Formats: `json`, `md`, `html`. HTML content is escaped.
3. Report includes scope header (program, authorization note), scan dates, speed used, tools used, results with sources and trust.
