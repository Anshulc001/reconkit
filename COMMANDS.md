# reconkit — Command Reference

Everything reconkit can do in this build, with one line per command. Every flag
below was checked against `reconkit <cmd> --help` on 2026-11-17; the authoritative
text stays in `docs/02_CLI_UX.md`.

---

## Quick start

```bash
source .venv/bin/activate       # activate the venv once per shell

reconkit doctor                 # which tools are installed, with versions
reconkit                        # interactive mode (asks what to scan)
reconkit run -d example.com     # passive scan, no prompts
```

---

## Commands at a glance

| Command | What it does |
|---|---|
| `subs`, `dns`, `live`, `ports`, `tech`, `urls`, `vulns` | run one stage |
| `passive` | the passive pipeline (subs, dns, urls) |
| `lite` | same pipeline as `passive`; also what bare `reconkit -d X` means |
| `run` | the only command that accepts `--active`/`--full` |
| `doctor` | tool inventory (installed, version, path, identity) |
| `status` | recent runs from the DB |
| `diff -d X` | new/gone/changed items vs the previous run |
| `scope check -d X` | is this target allowed by `scope.yaml`? |
| `scope import` | **not in this build** (Phase 3, exits 1) |
| `db list -d X`, `db export -d X` | **not in this build** (Phase 3 stubs, exit 1) |
| `export -d X --format json\|md\|html` | **not in this build** (Phase 3 stub, exits 1) |

---

## Interactive mode (no target flag)

`reconkit` (or any scan command) with neither `-d` nor `-l` on a terminal asks
questions instead of failing:

1. **Target** — a domain, or a path to a file of domains (read like `-l`)
2. **Scope file** — `Do you have a scope file? [Y/n]`, then `Scope file path`
3. **Scan mode** — `passive` / `active` / `full` (no default, re-asked until valid)
4. **Report fields** — numbered menu, answer `all` or `1,3,5`
5. **Scan parameters** *(active/full only)* — ignore scope file?, ports, states,
   status codes, extra headers, custom User-Agent
6. **Aggressive scanning** *(passive/active only)* — `Also run aggressive
   scanning (port scan + version detection)? [y/N]`

Then the plan echo, the out-of-scope prompt if a scope file blocks the target,
and the run. Results go to `results/<domain>/<timestamp>/` as `report.txt` and
`report.json`.

---

## Scan modes

| Mode | Stages that run | Tool modes | Tiers |
|---|---|---|---|
| **passive** (default) | subs, dns, urls | passive | core, opt_in* |
| **active** (`--active`) | subs, dns, live, tech, urls | passive + active | core, opt_in* |
| **full** (`--full`) | all 8: subs, dns, live, ports, tech, urls, shots, vulns | passive + active | core, opt_in, intrusive |

`*` `opt_in` needs `--include-noisy` unless the mode is `full` (which implies it).
`--full` also implies `--active`.

`shots` is **full-only** (D19): no other mode and no stage command requests it.
There is no `shots` command.

**Exploitation tools** (`sqlmap`, `dalfox`, `crlfuzz`) never run automatically in
any mode; they need an explicit `--tools sqlmap` etc.

`--active` and `--full` are usage errors (exit 2) on `passive`, `lite`, `subs`
and `dns`, because those commands run no active stage.

---

## `run` — flags

### Target (one of)

```bash
-d, --domain <domain>          # root domain to scan
-l, --list <path>              # file with one root domain per line
```

### Mode (none = passive)

```bash
--active                       # subs + dns + live + tech + urls
--full                         # all 8 stages (implies --active + --include-noisy)
```

### Scope

```bash
--scope <path>                 # scope file (default: ./scope.yaml if present)
--no-scope                     # ignore any scope file; run records scope_mode=unrestricted_flag
```

> No scope file at all = active/full runs unrestricted against the target you typed.
> Scope file present = target must be allowed; otherwise exit 3.
> `--no-scope` prints a loud warning and never modifies `scope.yaml`.

### Output filtering

```bash
--only-alive                   # print only ALIVE hosts ("no ALIVE hosts (N scanned)" if none)
--only-states <list>           # ALIVE,DNS_ONLY,SHUT_DOWN,DEAD,UNKNOWN
--status-codes <list>          # keep hosts with these HTTP codes, e.g. 200,301,302
--min-sources <N>              # hide results found by fewer than N sources (default 1)
```

### Scan parameters

```bash
--ports <spec>                 # override naabu/pyscan port list, e.g. 80,443,8000-8100
--header "Name: Value"         # repeatable; applied to httpx and pyprobe requests
--user-agent <string>          # override User-Agent for httpx and pyprobe
--redact-headers / --show-headers   # header values hidden in output (default: redact)
--ffuf-wordlist <path>         # wordlist for ffuf (default: bundled)
--resolvers <path>             # resolver list for massdns/puredns (default: bundled)
```

### Tool selection

```bash
--tools <a,b>                  # only these adapters (bypasses the tier gate)
--exclude <a,b>                # skip these adapters
--include-noisy                # allow opt_in tier (nikto, masscan, ffuf, gowitness)
```

### Output

```bash
--json                         # one JSON document on stdout
--silent, -q                   # suppress tables and progress
--no-color                     # disable ANSI colors
--verbose, -v                  # show a traceback for unexpected errors
```

### Behavior and config

```bash
--phase-timeout <seconds>      # stage time limit (config default: 1800s; per-stage overrides in config.yaml)
                               # a timed-out url_probe keeps finished batches, reports a gap, exits 0;
                               # a probe-ONLY run with nothing usable exits 4 (docs/02_CLI_UX.md:132)
--mock                         # fixtures only: no network, no external processes
--no-keys                      # force free-tier behavior even when .env has keys
--resume                       # continue the latest unfinished run
--config <path>                # config.yaml (default: ./config.yaml)
--db <path>                    # SQLite DB (default: ./recon.db)
```

---

## Per-stage commands

```bash
reconkit subs -d <domain>      # subdomain enumeration
reconkit dns -d <domain>       # DNS resolution
reconkit live -d <domain>      # HTTP/TLS/probe state
reconkit ports -d <domain>     # port scanning
reconkit tech -d <domain>      # tech / WAF / CDN
reconkit urls -d <domain>      # URL discovery
reconkit vulns -d <domain>     # vulnerability checks
```

They accept the same flags as `run` but execute only their own stage.
`passive` runs subs+dns+urls; `lite` is the same pipeline (bare `reconkit -d X`
is `lite`). There is no `shots` command.

---

## Management commands

```bash
reconkit doctor                # tool table: stage, tier, installed, path, identity
reconkit doctor --json         # same, as JSON
```

`doctor` footer: `Missing tools: N. Scans will use the tools that are installed
and skip the rest.` — missing tools are not a failure.

```bash
reconkit status                # recent runs table (id, target, stage, status, times)
reconkit status --json         # {"type": "status", "runs": [...]}
reconkit status --db <path>    # inspect another DB
```

```bash
reconkit diff -d <domain>      # new/gone/state-changed/port-changed vs previous run
reconkit diff -d <domain> --json
```

`diff` compares the two latest completed discovery runs; `gone` needs two
consecutive misses before a host is declared gone (`pending_gone` is the
one-miss list). There are no `--from`/`--to` flags.

```bash
reconkit scope check -d <domain> [--scope PATH]   # exit 0 allowed, 3 blocked
```

`scope import` prints `scope import is Phase 3 and is not available in this
build.` and exits 1.

```bash
reconkit export -d <domain> --format json|md|html   # Phase 3 stub: exits 1, writes nothing
reconkit db list -d <domain>                        # Phase 3 stub: exits 1
reconkit db export -d <domain> [--new-only]         # Phase 3 stub: exits 1
```

---

## Common recipes

### Escalate a fresh target

```bash
reconkit run -d example.com --no-scope
reconkit run -d example.com --active --no-scope --only-alive
reconkit run -d example.com --full --no-scope --only-alive
```

### Full scan of an in-scope target (uses `./scope.yaml`)

```bash
reconkit run -d testfire.net --full
```

### Full scan ignoring the scope file

```bash
reconkit run -d target.com --full --no-scope --only-alive --status-codes 200,301,302
```

### Port scan

```bash
reconkit run -d target.com --full --no-scope --ports 80,443,8080,8443 --only-alive
```

### Authenticated requests

```bash
reconkit run -d target.com --active --no-scope \
  --header "Authorization: Bearer $TOKEN" \
  --header "Cookie: session=abc123" \
  --user-agent "Mozilla/5.0 (custom recon)"
```

Only httpx and pyprobe send these headers.

### Specific tools / skip noisy ones

```bash
reconkit run -d target.com --full --no-scope --tools naabu,nuclei,httpx
reconkit run -d target.com --full --no-scope --exclude ffuf,nikto,gowitness
```

### Several domains

```bash
reconkit run -l domains.txt --active --no-scope
```

### Review and compare

```bash
reconkit status
reconkit diff -d example.com
reconkit doctor
```

### No network at all

```bash
reconkit run -d example.com --full --mock --no-scope
```

### With a custom config and DB

```bash
reconkit run -d target.com --active --config my-config.yaml --db my-scan.db
```

### As root (only masscan needs it)

```bash
echo kali | sudo -S env PATH=$PATH HOME=$HOME reconkit run -d target.com --full --no-scope
```

`sudo` changes `HOME`, which breaks `~/.reconkit/bin/` discovery and the tool
config lookups, so pass both `PATH` and `HOME`. Without root, masscan is skipped
at selection with `requires root / sudo` and the run still exits 0.

---

## Exit codes

| Code | Meaning |
|---|---|
| **0** | Success, including "completed with gaps" (a stage whose only tools are absent, or a tool refused by an external service: 429/quota/upstream 5xx) |
| **1** | Unexpected error; also the Phase 3 stubs (`export`, `db *`, `scope import`) |
| **2** | Usage error (bad flags, `--active` on a passive-only command, cancelled prompt) |
| **3** | Scope violation when a scope file is present (blocked, unauthorized, expired) |
| **4** | No usable tool anywhere: every requested stage executed no tools |
| **5** | Partial: some tools failed/timed out, or a stage was emptied by a deliberate rule |
| **6** | Retired 2026-11-17 — no command emits it |
| **130** | Interrupted by the user (state saved, resumable) |

A stage with only absent tools is a **completion gap** (exit 0, warning on
stderr, `completion` block in `--json`). A tool that ran and was refused by its
upstream - HTTP 429, a free-quota message, an HTTP 5xx from the service it calls
- shows status `gap` in the Tools table and counts the same way. A stage emptied
by `--tools`, `--exclude`, tier rules or the exploitation block still exits 5.

---

## API keys (`.env`)

Copy `.env.example` to `.env` and fill what you have. All keys are optional;
they raise limits or unlock a source. `--no-keys` forces free-tier behavior.

| Key | What it unlocks |
|---|---|
| `VT_API_KEY` | VirusTotal sources (assetfinder, subfinder) |
| `CERTSPOTTER_API_KEY` | certspotter / subfinder certspotter |
| `PDCP_API_KEY` | chaos dataset and subfinder chaos |
| `GITHUB_TOKEN` | github_subdomains and subfinder github |
| `OTX_API_KEY` | otx passive DNS |
| `URLSCAN_API_KEY` | urlscan submissions (search works without it) |
| `MONITOR_WEBHOOK_URL` | `monitor` webhook (Phase 3) |

A tool that cannot run without its key is a **selection skip** with the reason
`requires <KEY>` (D18), not a failed tool.

---

## What each stage produces

| Stage | Input | Output | Stored in |
|---|---|---|---|
| **subs** | root domain | subdomains + source list + confidence | `subdomains`, `subdomain_sources` |
| **dns** | subdomains | resolved IPs, dangling-CNAME / wildcard checks | `subdomains.state`, `host_status_history.ips_json` |
| **live** | subdomains | state, status code, title, redirect | `host_status_history` |
| **ports** | ALIVE hosts | open ports, service, version | `ports`, `port_sources` |
| **tech** | ALIVE hosts | technologies, WAF, CDN | `host_status_history.tech_json`, `.waf` |
| **urls** | ALIVE hosts | discovered URLs + patterns | `urls` |
| **shots** | ALIVE hosts | screenshots + `screenshots.jsonl` | `results/<domain>/<ts>/screenshots/` (files, no rows — D17) |
| **vulns** | ALIVE hosts | findings | raw output files and `--json` only (not persisted) |

`confidence` is `HIGH`/`MEDIUM`/`LOW`/`UNCONFIRMED` from how many independent
tools agree plus the stage's evidence rules.

## Reading the results table

```
Subdomain          State    Status  Ports   Sources                Trust       Notes
sakec.ac.in        ALIVE    301     -       crtsh, subfinder       MEDIUM (2)  -> redirects to www.sakec.ac.in
www.sakec.ac.in    ALIVE    200     -       crtsh, subfinder       MEDIUM (2)  canonical
admission.sakec.in ALIVE    403     -       crtsh                  LOW (1)     canonical
www.admission...   ALIVE    403     -       crtsh                  LOW (1)     -> duplicate of admission.sakec.in
```

`Notes` explains a www/non-www pair (D22) without hiding the row: `-> redirects
to <host>`, `-> duplicate of <host>`, `canonical`, or the informational
`has www sibling at <host>` / `www variant on a different server`. The column
only appears when some row has a note. When any duplicate exists the summary
line reads `N hosts (M unique after www-dedup):
...`. State and confidence are unchanged by it, and `--json` carries
`duplicate_of` per host plus a top-level `www_dedup` object.

---

## Checking which URLs still answer (D23)

`run --active` and `run --full` include a `url_probe` stage after `urls`: it
sends one `GET` to every stored URL that has no status yet and records the
answer (`-1` when the URL does not answer, `-2` when it answers with a
certificate that does not verify). No adapter and no `--tools` name is
involved.

```
$ reconkit run -d example.com --active --no-scope         # probe runs after urls
$ reconkit run -d example.com --active --no-scope --skip-url-probe   # leave NULLs alone
$ reconkit run -d example.com --active --no-scope --reprobe-urls     # ask again, even answered URLs
$ sqlite3 recon.db "SELECT status_code, COUNT(*) FROM urls GROUP BY status_code"
200|1184
301|96
404|211
-1|4021
```

Bounds and switches live in `config.yaml` under `url_probe:` (`max_urls` 5000,
`batch_size` 200, `threads` 100, `timeout_s` 10), and one HTTP client is reused
for the whole pass (D24). `--mock` never touches the network, so a mock run
leaves every `status_code` at `NULL`. `--reprobe-urls` overwrites the stored
answer in place, which is how a URL that has since gone dead is found; adding
`--skip-url-probe` makes it a no-op and the run says so.

The pass is bounded by `--phase-timeout`, or by `timeouts.url_probe` (600 s) in
`config.yaml` when the flag is absent (D26). A pass that hits the deadline keeps
every batch it already committed, leaves the rest `NULL`, prints
`url_probe: timed out after Ns (M/N URL(s) probed)`, reports a completion gap and
still exits 0.

**Probe-only runs are the exception (D28):** a run whose only stage is `url_probe`
and which produced zero results is the ordinary "nothing usable" case and exits
`4`, not `0`. A normal scan that includes other stages keeps exit `0` when the
probe times out.

---

## Confirming it works

```bash
reconkit doctor | tail -3
# Expected: "Missing tools: N. Scans will use the tools that are installed..."

reconkit run -d example.com --full --mock --no-scope
# Expected: exit 0, tables for each stage that has an adapter

reconkit run -d testfire.net --active --no-scope --only-alive
# Expected: ALIVE hosts with status codes

reconkit status
reconkit diff -d testfire.net
```

---

## Known limits in this build (2026-11-17)

| Item | Reality | Workaround |
|---|---|---|
| **Screenshots (gowitness)** | Needs a Chrome binary gowitness can exec (`google-chrome`); this box has `/usr/bin/chromium`, which gowitness does not pick up, and even a manual `--chrome-path /usr/bin/chromium` run reported `have-screenshot=false`. The adapter never guesses a browser path, so a real run yields 0 items with an error string, not a failure | install `google-chrome-stable`, or accept the mock/manifest proof |
| **`--active`/`--full` on passive commands** | Rejected by design (exit 2) | use `run` |
| **masscan** | Needs raw sockets; non-root runs skip it with `requires root / sudo` | run as root or `setcap cap_net_raw+ep` on the binary |
| **dnsreaper** | Not adapted (no PyPI package, no console script — D15) | `subzy` covers takeover |
| **sqlmap, dalfox, crlfuzz** | Exploitation-class; never auto-run (no `--intrusive` flag exists) | `--tools sqlmap` explicitly |
| **vulns findings** | Not persisted to the DB | read `--json` or the raw output files |
| **WAF** | One string per host, merged by `waf_priority` (D12) | n/a |
| **`export`, `db list/export`, `scope import`** | Phase 3 stubs: exit 1, do nothing | use `--json` on scan commands or query `recon.db` with sqlite3 |
| **`shots` in passive/active** | Not requested by any other mode (D19) | use `--full` |

48 tools are registered and 44 have adapters; the four without are `dnsreaper`
(D15) and the three exploitation tools.

---

## Agent session start (this repo's protocol)

```bash
cat AGENTS.md                    # hard rules
sed -n '1,60p' docs/PROGRESS.md  # RESUME block and next action
tail -80 docs/REVIEW_LOG.md      # recent evidence; pitfalls table at the top
grep -n "^D" docs/MASTER_PLAN.md # dated deviations

source .venv/bin/activate
pytest -q
ruff check .
ruff format --check .
mypy src/reconkit
```

Raw output before and after any change; no claim without it.

---

## References

- `docs/02_CLI_UX.md` — CLI surface, modes, interactive flow, exit codes
- `docs/03_ARCHITECTURE.md` — pipeline, engine internals, adapter contract
- `docs/04_DATABASE.md` — schema and migrations
- `docs/05_SECURITY.md` — scope model, `--no-scope` semantics, redaction
- `docs/09_TOOL_CONTRACTS.md` — per-tool contracts and stage tables
- `docs/10_TOOL_SOURCES.md` — provenance for every tool
- `docs/MASTER_PLAN.md` — deviations D1–D19
- `docs/tool_manuals/` — captured `-h` output per stage
