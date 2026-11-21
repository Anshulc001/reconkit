# ReconKit

[![tests](https://github.com/Anshulc001/reconkit/actions/workflows/test.yml/badge.svg)](https://github.com/Anshulc001/reconkit/actions/workflows/test.yml)

**ReconKit** is a command-line reconnaissance framework for **authorized** security testing. It orchestrates multiple recon tools per stage, merges and deduplicates their output, scores confidence by how many tools agree, and tracks what changed between scans in SQLite. Every scan produces a text report, a machine-readable JSON report and a professional PDF assessment report.

Developed by **Pritam & Anshul**.

```text
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗██╗████████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║ ██╔╝██║╚══██╔══╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╔╝ ██║   ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔═██╗ ██║   ██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██╗██║   ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝   ╚═╝

              RECONKIT
   Advanced Reconnaissance Framework

   Made with ♥ by Pritam & Anshul
   Version: 1.0.0
```

The banner is printed once for a human scan (not for `--json`/`--silent`, and never from a child process), followed by a separator. The version comes from `reconkit.__version__`, the same value `reconkit --version` prints.

> `scope.yaml` is a safety guard against mistakes, not permission. Use ReconKit only on systems you own or have explicit written authorization to test.

## Features

- **Multi-tool stages** with source attribution and HIGH / MEDIUM / LOW confidence.
- **Three scan modes** — passive, active and full — with a fixed stage order.
- **Host states** ALIVE, DNS_ONLY, SHUT_DOWN, DEAD and UNKNOWN, tracked across runs.
- **Change tracking** in SQLite (`diff`, `status`).
- **Professional terminal output** with Rich tables, colored states, progress and a branded banner.
- **Three report formats per scan**: `report.txt`, `report.json` and a designed `report.pdf`.
- **Per-scan logging** to a persistent file, with colored INFO/SUCCESS/WARNING/ERROR milestones.
- **Tool inventory, not installation**: `reconkit doctor` reports what is installed and what is missing.
- **Mock mode** (`--mock`) for a complete offline scan using packaged fixtures; a target with no matching fixture is skipped, not failed.
- **No pacing/evasion**: tools run at their own natural pace; the User-Agent is honest (`reconkit/<version>`).
- **Core and opt-in tiers are inventory only**; exploitation-class tools never run unless named explicitly with `--tools`.

## Requirements

| Requirement | Details |
|---|---|
| OS | Kali Linux or Ubuntu (native). This is the only supported platform. |
| Python | 3.11 or newer (the project is tested on 3.11–3.13 and runs on newer local interpreters). |
| `git` | To clone the repository. |
| External tools | Optional but expected for real scans; obtain them outside ReconKit, or use `scripts/setup.sh`. |
| PDF dependency | `reportlab` (installed with ReconKit; see `pyproject.toml`). |

ReconKit never installs tools through its own CLI. `scripts/setup.sh` is the convenience path for a fresh Kali/Ubuntu machine; the tool registry and provenance are in `tools.yaml` and [docs/10_TOOL_SOURCES.md](docs/10_TOOL_SOURCES.md).

## Installation

```bash
git clone https://github.com/Anshulc001/reconkit.git
cd reconkit
./scripts/setup.sh                 # venv + dependencies + installable tools + doctor
source .venv/bin/activate
```

If you only want the framework and will install tools yourself:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
reconkit doctor
```

`setup.sh` also accepts `--check`, `--only <tool>`, `--dry-run`, `--update` and `--yes`.
Re-run it after a `git pull`: it re-syncs a venv whose dependencies changed. Activate the venv in every new terminal (`source .venv/bin/activate`); otherwise use `.venv/bin/reconkit`. See [SETUP.md](SETUP.md) for the beginner walkthrough.

Optional API keys go in `.env` (copy `.env.example`). Keys are read from the environment only and are never printed, logged or stored.

## Usage

```bash
cp scope.example.yaml scope.yaml      # edit with YOUR authorized targets
reconkit doctor                       # what is installed, what is missing
reconkit --help                       # every command and flag

reconkit passive -d example.com --mock    # offline demo, no network
reconkit passive -d <authorized-domain>   # passive subs + dns + urls
reconkit active  -d <authorized-domain>   # adds live, tech and url probing
reconkit full    -d <authorized-domain>   # all stages, including ports/shots/vulns
reconkit diff    -d <authorized-domain>   # changes since the previous run
```

Active and full scans need `scope.yaml`; without one they fail closed (exit `3`) unless you explicitly pass `--no-scope`, which is recorded in the database and warns loudly. Passive scans need no scope file.

### Commands

| Command | What it does |
|---|---|
| `passive` | Passive pipeline: `subs`, `dns`, `urls` (passive tools only). Also the bare `reconkit -d X` form. |
| `active` | `subs`, `dns`, `live`, `tech`, `urls`, `url_probe`; needs a scope file or `--no-scope`. |
| `full` | All nine stages (`subs`, `dns`, `live`, `ports`, `tech`, `urls`, `url_probe`, `shots`, `vulns`). |
| `subs`, `dns` | Run one passive stage. |
| `live` | ALIVE / DNS_ONLY / SHUT_DOWN / DEAD classification; needs `--active`. |
| `ports` | Port scan over each adapter's default port set (`--ports` overrides); needs `--active`. |
| `tech` | Technology, WAF and CDN inventory; needs `--active`. |
| `urls` | URL discovery from archives and crawlers; needs `--active`. |
| `vulns` | `nuclei`, `subzy`, `dnsreaper` (core), `nikto`, `ffuf` (`opt_in`); needs `--active`. Findings are not persisted. |
| `run` | Flag-driven form: `run` = passive, `run --active` = active, `run --full` = full. |
| `diff` | New, gone, state-changed and port-changed items vs the previous run. |
| `status` | Recent scans (`--json` for scripts). |
| `report` | Rebuild `report.txt`/`report.json`/`report.pdf` from stored rows; read-only, no network. |
| `doctor` | Tool, version, path, per-stage coverage, system packages and key names. |
| `scope check -d X` | Show whether a target is allowed by `scope.yaml`. |
| `db delete --target X` | Delete one target, every row that belongs to it and its `results/X/` folder. |
| `db wipe` | Delete every row and recreate the schema. |
| `db list`, `db export`, `export`, `scope import` | Documented Phase 3 stubs: exit `1`, no data is read or written. |

**Scan flags:** `--active`, `--full`, `--no-scope`, `--tools`, `--exclude`, `--include`, `--include-noisy`, `--min-sources`, `--phase-timeout`, `--mock`, `--resume`, `--no-keys`, `--only-alive`, `--only-states`, `--ports`, `--status-codes`, `--header`, `--user-agent`, `--redact-headers/--show-headers`, `--ffuf-wordlist`, `--resolvers`, `--skip-url-probe`, `--reprobe-urls`, `--json`, `--no-color`, `-q/--silent`, `-v/--verbose`, and the root `--config/--scope/--db`.

The mode table is the single definition in [docs/02_CLI_UX.md](docs/02_CLI_UX.md) section 2. If you find a contradiction elsewhere, that table wins.

## Reports

Every successful scan writes a new, never-reused folder:

```text
results/example.com/20261121T151509Z/
├── report.txt              # aligned text table, domains and URLs by host
├── report.json             # the same rows as objects, plus metadata
├── report.pdf              # professional PDF assessment report
├── subdomains.txt
├── alive.txt
├── dns_resolved.txt
├── host-info.txt
├── host-info.json
├── external_urls.txt
└── hosts/<hostname>/
    ├── urls.txt
    └── info.json
```

Mock runs write under `results/mock/<target>/<stamp>/` so they cannot overwrite a real run. The text and JSON formats are unchanged and always written; the PDF is added beside them (`report.pdf`, controlled by `report.pdf: true` in `config.yaml`).

### PDF report design

The PDF is generated automatically after a scan (and by `reconkit report`) from the same stored snapshots as the text/JSON files, so the three cannot disagree. Nothing is fabricated: a field the run did not observe prints **N/A**.

| Page | Contents |
|---|---|
| Cover | ReconKit branding, title, target, scan date/time, mode, report status, credits, dark navy theme. |
| Executive Summary | Target, subdomain and unique-host counts, live and non-responsive hosts, scan duration, status, scope enforcement, warnings. |
| Reconnaissance Results | Discovered subdomains, host state, HTTP status, IP addresses, technology/server, page titles, redirects and failure reasons; clickable URL evidence. |
| Technical Details | Tools used with status/items/runtime, scan configuration and parameters, methodology, timestamps, technical observations. |
| Findings & Conclusion | Asset summary, observations derived only from collected data, areas for manual review, limitations and an authorized-use conclusion. |

Formatting: A4, consistent navy/cyan/green palette, professional type scale, running headers and footers, page numbers, alternating table rows, automatic page breaks and repeated table headers. `LongTable` lets thousands of subdomains flow across pages without clipping; the URL table is capped at 500 entries and says so, while the complete list stays in JSON/TXT.

## Logging

Each scan writes `results/logs/<target>/<UTC stamp>.log` (mock: `results/mock/logs/...`) and prints colored milestones to stderr:

```text
[10:15:01] [INFO] Starting reconnaissance on example.com (passive)
[10:15:09] [SUCCESS] 21 subdomains discovered; 0 live hosts identified
[10:15:09] [INFO] Generating PDF report
[10:15:09] [SUCCESS] PDF report generated: results/mock/example.com/.../report.pdf
[10:15:09] [SUCCESS] Reconnaissance completed for example.com
```

- Levels: `DEBUG`, `INFO`, `SUCCESS`, `WARNING`, `ERROR`; the file always uses UTC timestamps.
- Every stage/tool progress line is also recorded in the file, including under `--silent`.
- Messages pass through the same `redact()` helper as every other artifact, so tokens and credentials are masked.
- The console half never writes to stdout, so `--json` stays one clean document.
- Configure with `config.yaml`:

```yaml
logging:
  enabled: true
  console: true
  level: INFO
```

## Example terminal output

```text
$ reconkit passive -d example.com --mock
<banner and separator>

subs: running 9 tool(s)
subs: crtsh ok 6 item(s)
...
21 hosts: 0 ALIVE, 2 DNS_ONLY, 0 SHUT_DOWN, 1 DEAD, 18 UNKNOWN | tools: 18 ok, 0 gap, 0 failed, 6 skipped, 0 timeout
[10:15:09] [SUCCESS] PDF report generated: results/mock/example.com/20261121T151509Z/report.pdf
report: results/mock/example.com/20261121T151509Z/report.txt and report.json (PDF: ...)
```

A second identical run followed by `reconkit diff -d example.com` prints `No changes since run #1.`

## Screenshots

Screenshots are not committed yet. Placeholders for the project page:

| Image | Suggested capture |
|---|---|
| `docs/images/banner.png` | The branded banner and separator on a real terminal. |
| `docs/images/scan-progress.png` | A running passive/active scan with stage and tool lines. |
| `docs/images/results-table.png` | A completed results and Tools table. |
| `docs/images/pdf-cover.png` | Page 1 of `report.pdf`. |
| `docs/images/pdf-summary.png` | Page 2 (Executive Summary) of `report.pdf`. |

## Cleanup

```bash
reconkit db delete --target example.com          # shows counts, then asks [y/N]
reconkit db delete --target example.com --yes    # target + rows + results/example.com/
reconkit db wipe --yes                           # all rows, fresh schema; results/ kept
```

`db delete` removes the target's `scan_runs`, `tool_runs`, `subdomains`, `subdomain_sources`, `host_status_history`, `ports`, `port_sources` and `urls` in one transaction, then removes `results/<target>/` (and `results/mock/<target>/`). `db wipe` never deletes `results/`.

## Development

```bash
source .venv/bin/activate
pytest -q
FORCE_TERMINAL=1 pytest -q   # the way GitHub Actions runs it
ruff check .
ruff format --check .
mypy src/reconkit
```

Tests never touch the network and never require installed tools: adapters use sanitized fixtures under `tests/fixtures/`. `--mock` exercises a full scan offline. See [docs/07_TESTING.md](docs/07_TESTING.md).

Contributions are welcome: open an issue first for anything larger than a typo, branch from `main`, keep each change focused, add tests for behavior changes, and update the matching doc in the same pull request. Never commit real target data, `scope.yaml`, API keys, `.env` values or raw scan output.

## Disclaimer and authorized use

ReconKit is intended for **authorized security testing only**. Use it only on systems you own or where you have explicit written permission (for example an in-scope bug bounty program or a signed engagement). Unauthorized scanning may be illegal. The authors assume no liability for misuse. The `--no-scope` flag is an explicit opt-out of the scope file, **not** permission to scan anything.

## Future improvements

- Persist vulnerability-stage findings in SQLite and include them in the PDF.
- First-class import/export (`db list`, `db export`, `export`) replacing the Phase 3 stubs.
- Optional scheduled scans and change notifications (the webhook configuration exists but is not wired).
- Report branding assets (logo file, custom cover subtitle) configurable per engagement.
- Screenshot gallery page in the PDF for `shots` runs.

## Documentation

| File | Purpose |
|---|---|
| [AGENTS.md](AGENTS.md) | Rules for AI coding agents. |
| [SETUP.md](SETUP.md) | Beginner setup for Kali/Ubuntu. |
| [COMMANDS.md](COMMANDS.md) | Full command reference and recipes. |
| [docs/01_PRD.md](docs/01_PRD.md) | Product scope and acceptance criteria. |
| [docs/02_CLI_UX.md](docs/02_CLI_UX.md) | Commands, flags, output, report and PDF shape, exit codes. |
| [docs/03_ARCHITECTURE.md](docs/03_ARCHITECTURE.md) | Layers, structure, concurrency, consensus. |
| [docs/04_DATABASE.md](docs/04_DATABASE.md) | SQLite schema. |
| [docs/05_SECURITY.md](docs/05_SECURITY.md) | Scope gate, subprocess and tool-source safety. |
| [docs/06_CODE_STYLE.md](docs/06_CODE_STYLE.md) | Code conventions. |
| [docs/07_TESTING.md](docs/07_TESTING.md) | Test strategy. |
| [docs/08_UX_FLOWS.md](docs/08_UX_FLOWS.md) | User journeys. |
| [docs/09_TOOL_CONTRACTS.md](docs/09_TOOL_CONTRACTS.md) | Adapter contract and stage registry. |
| [docs/10_TOOL_SOURCES.md](docs/10_TOOL_SOURCES.md) | Tool reference and doctor checks. |
| [tools.yaml](tools.yaml) / [config.yaml](config.yaml) / [scope.example.yaml](scope.example.yaml) | Registry, settings and scope template. |

## License

MIT. See [LICENSE](LICENSE). Copyright 2026 Anshul.
