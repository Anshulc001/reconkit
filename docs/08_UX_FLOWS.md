# UX Flows

Journey overview: **setup -> doctor -> install -> scope -> passive -> live/ports -> diff -> export**.

## Flow 1 - First run (setup)

1. User follows SETUP.md (WSL2 Kali, VS Code, venv).
2. `reconkit doctor`
3. Output: table of tools (installed/missing + version), per-stage coverage, system packages, Python version, `scope.yaml` found?, API key names set/unset.
4. Suggestion line: `Missing tools: 14. Run: reconkit install --all`

- **Success:** exit code 0 with warnings listed.
- **Failure:** Python < 3.11 or not Linux: clear message, exit code 1.

## Flow 2 - Install tools

1. `reconkit install --all --dry-run` lists: tool, method, source, destination.
2. `reconkit install --all` asks to confirm sudo for apt packages (`libpcap-dev`, `nmap`, ...).
3. Per tool: download, verify checksum, place in `~/.reconkit/bin`, run version command.
4. Final: summary table and re-run of doctor checks.

- **Loading state:** one progress line per tool.
- **Error state:** `subfinder: checksum mismatch - not installed` (fails closed), continues with others, exit code 5.
- **Empty state:** `Everything already installed.`

## Flow 3 - Define scope

1. User copies `scope.example.yaml` to `scope.yaml` and edits.
2. `reconkit scope check -d api.example.com`
3. Output: `ALLOWED (matches *.example.com)` or `BLOCKED (out_of_scope: admin.example.com)` or `BLOCKED (scope expired 2027-01-31)`.

## Flow 4 - Passive recon (default, safe)

1. `reconkit passive -d example.com` (speed `slow`)
2. Header: target, speed, tools selected, estimated time.
3. Live line: `subs: crtsh done | waiting 14s | next: certspotter (2/6)`.
4. Wildcard check result line.
5. Result table with State / Sources / Trust; tools panel.
6. Footer: counts, new items, workspace and DB paths.

- **Success:** exit 0.
- **Partial:** some tools skipped/failed, exit 5, results still saved.
- **Failure:** no usable tool for stage: exit 4, hint to run install.
- **Empty:** message listing which tools returned nothing.

## Flow 5 - Live and shut-down detection (active)

1. `reconkit live -d example.com --active`
2. Scope gate runs first; blocked = exit 3 and no traffic.
3. Slow mode: hosts shuffled, random pause between hosts, rate-limited probes.
4. Table: State (ALIVE / DNS_ONLY / SHUT_DOWN / DEAD), status code, title, tech, sources, trust.
5. Transitions flagged: `[NOW ALIVE]`, `[WENT DOWN]`.

- **Fast speed:** `--speed fast` prints a warning and requires typing `I AM AUTHORIZED`.

## Flow 6 - Port scanning (active)

1. `reconkit ports -d example.com --active` (top ports, connect scan, slow)
2. Candidate ports from the fast scanner; second tool verifies when available.
3. Table: Host, IP, Port, Service, State (`open`/`unconfirmed`), Sources, Trust.
4. `--ports 80,443,8080` or `--full` change the port set; `--full` warns about duration at the chosen speed.

## Flow 7 - Diff

1. `reconkit diff -d example.com`
2. Sections: `[NEW]` hosts and ports, `[NOW ALIVE]`, `[WENT DOWN]`, `[NOW DEAD]`, `[GONE]`.
3. `--json` gives the same data for scripts or AI agents.

- **Empty:** `No changes since run #7 (2026-11-12).`
- **No previous run:** `First run for this target. Nothing to compare.`

## Flow 8 - Status of a long scan

1. In a second terminal: `reconkit status --json`
2. Output example:

```json
{"target":"example.com","run_id":12,"stage":"live","speed":"slow",
 "current_phase":2,"total_phases":4,"elapsed_s":412,"status":"running"}
```

## Flow 9 - Interrupt and resume

1. User presses Ctrl+C. Engine stops launching tools, kills children, marks run `interrupted`, exit 130.
2. `reconkit run -d example.com --active --resume` continues from the unfinished stage; completed tools are not repeated.

## Flow 10 - Export

1. `reconkit export -d example.com --format md -o report.md`
2. Formats: `json`, `md`, `html`. HTML content is escaped.
3. Report includes scope header (program, authorization note), scan dates, speed used, tools used, results with sources and trust.
