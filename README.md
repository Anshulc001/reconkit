# reconkit

A command-line reconnaissance orchestrator for **authorized** security testing. It runs several tools per stage, cross-checks their results, scores confidence by how many tools agree, and tracks what changed between scans in SQLite.

- Natural pace: no speed preset, delay or artificial throttling; tools run at their own rate
- Passive first: `passive` (subs+dns) by default; `--active` adds `live`; `--full` runs every stage. A `scope.yaml`, when present, is enforced - with no scope file (or with `--no-scope`) active scanning runs unrestricted
- Multi-tool stages with source attribution (HIGH / MEDIUM / LOW)
- Host states: ALIVE, DNS_ONLY, SHUT_DOWN, DEAD, tracked across scans
- Tool inventory, not installation: `reconkit doctor` lists what is installed and what is missing; per-tool sources are in [docs/10_TOOL_SOURCES.md](docs/10_TOOL_SOURCES.md)
- State in SQLite, raw output in `workspaces/<target>/`

> `scope.yaml` is a safety guard against mistakes, not permission. Use reconkit only on systems you own or have explicit written authorization to test.

## Status

Phase 2 (working core) is complete: passive discovery (`subs`, `dns`), `live`, `ports`, `diff`, `status` and `doctor` are implemented on Linux and covered by the test suite. `install`, `update` and `doctor --fix` were removed on 2026-11-17: reconkit no longer installs tools, it only reports what you have. Phase 3 adapters and workflows are being added one at a time. These commands exist but are **Phase 3 stubs** in this build and exit `1` with a "not wired" message: `db list`, `db export`, `export`, `scope import`.

## Requirements

| Platform | What works |
|---|---|
| Kali / Ubuntu (native or WSL2) | Everything, including the real tools - obtaining them is your own job, outside reconkit. Python 3.11+ and `git` for the checkout. |
| Windows | `doctor`, `--mock` runs and the pure-Python passive flow. Real tools need a Linux checkout (native Kali/Ubuntu or WSL2); reconkit installs nothing on any platform, so there is no install command to refuse. |

## Quick start (Kali / Ubuntu)

```bash
cd /path/to/reconkit
./scripts/bootstrap.sh
source .venv/bin/activate

reconkit doctor                        # what is installed, what is missing
# obtain any missing tool however you prefer; reconkit installs nothing.
# Provenance for every tool is in docs/10_TOOL_SOURCES.md (and tools.yaml `source:`).
# Optional: cp .env.example .env and add the API keys you have.
cp scope.example.yaml scope.yaml      # edit with YOUR authorized targets
reconkit passive -d example.com --mock
reconkit passive -d <authorized-domain>
reconkit diff -d <authorized-domain>
```

**Activate the venv in every new terminal.** `source .venv/bin/activate` is what puts `reconkit` on `PATH`; without it you get `reconkit: command not found`. The equivalent without activation is `.venv/bin/reconkit ...`. See [SETUP.md](SETUP.md) for the full beginner walkthrough and troubleshooting.

## Quick start (Windows, mock/passive)

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

reconkit doctor
reconkit passive -d example.com --mock
```

In Git Bash, use `./scripts/bootstrap.sh` and `source .venv/Scripts/activate` instead. There is no install command to run on Windows or anywhere else: the real tools need a Linux checkout, and obtaining them is your own job - [docs/10_TOOL_SOURCES.md](docs/10_TOOL_SOURCES.md) shows where each project lives, not how to install it.

## Commands

| Command | What it does |
|---|---|
| `passive` / `lite` | Passive subs + dns pipeline for one target; no scope file needed |
| `subs`, `dns` | Run one passive stage |
| `live` | ALIVE / DNS_ONLY / SHUT_DOWN / DEAD; needs `--active` (uses any present scope file) |
| `ports` | Port scan over each adapter's default port set (`--ports` overrides); needs `--active` |
| `tech`, `urls`, `vulns` | Stage commands whose adapters are Phase 3; may report no usable tool |
| `run` | `passive` (subs+dns) by default; `--active` = subs+dns+live; `--full` = all seven stages with `opt_in` enabled. The mode table is in [docs/02_CLI_UX.md](docs/02_CLI_UX.md) |
| `diff` | New, gone, state-changed and port-changed items vs the previous run |
| `status` | Recent scans (`--json` for scripts) |
| `doctor` | Tool, version, path, per-stage coverage, system packages, key names |
| `scope check -d X` | Show whether a target is allowed by `scope.yaml` |
| `db list`, `db export` | **Phase 3 stub**: exits `1`; no data is read |
| `export -d X --format json\|md\|html` | **Phase 3 stub**: exits `1`; no report is written |
| `scope import` | **Phase 3 stub**: exits `1` |

Scan flags include `--active`, `--full`, `--no-scope`, `--tools`, `--exclude`, `--include-noisy`, `--min-sources`, `--phase-timeout`, `--mock`, `--resume`, `--no-keys`, `--only-alive`, `--only-states`, `--ports`, `--status-codes`, `--header`, `--user-agent`, `--redact-headers/--show-headers`, `--json`, `--no-color`, `-q/--silent`, `-v/--verbose`, and `--config/--scope/--db`. `--json` is available on the scan commands, `doctor`, `diff` and `status`, not on the Phase 3 stubs. `--no-scope` does not skip the gate while reading a scope file: it opts out of the file entirely and warns (docs/02 section 3.1). The mode definitions live in one table in [docs/02_CLI_UX.md](docs/02_CLI_UX.md) section 2.

## Example (real mock run)

With a fresh database, `reconkit passive -d example.com --mock` prints the results table (columns `Subdomain`, `State`, `Status`, `Ports`, `Sources`, `Trust`) and the Tools table, then ends with:

```
10 hosts: 0 ALIVE, 2 DNS_ONLY, 0 SHUT_DOWN, 1 DEAD, 7 UNKNOWN | tools: 7 ok, 0 failed, 0 skipped, 0 timeout
```

A second identical run followed by `reconkit diff -d example.com` prints:

```
No changes since run #1.
```

## Documentation

| File | Purpose |
|---|---|
| AGENTS.md | Rules for AI coding agents (read first) |
| SETUP.md | Beginner setup for Kali/Ubuntu and Windows |
| docs/01_PRD.md | Product scope and acceptance criteria |
| docs/02_CLI_UX.md | Commands, flags, output, exit codes |
| docs/03_ARCHITECTURE.md | Layers, structure, concurrency, consensus |
| docs/04_DATABASE.md | SQLite schema |
| docs/05_SECURITY.md | Scope gate, subprocess and tool-source safety |
| docs/06_CODE_STYLE.md | Code conventions |
| docs/07_TESTING.md | Test strategy |
| docs/08_UX_FLOWS.md | User journeys |
| docs/09_TOOL_CONTRACTS.md | Adapter contract and stage registry |
| docs/10_TOOL_SOURCES.md | Tool reference: every tool, its stage, where the project lives, doctor's checks |
| tools.yaml / config.yaml / scope.example.yaml | Registry, settings, scope template |

## Legal disclaimer

reconkit is intended for **authorized security testing only**. Use it only on systems you own or where you have explicit written permission (for example an in-scope bug bounty program or a signed engagement). Unauthorized scanning may be illegal. The authors assume no liability for misuse.
