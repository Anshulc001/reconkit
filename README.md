# reconkit

A command-line reconnaissance orchestrator for **authorized** security testing. It runs several tools per stage, cross-checks their results, scores confidence by how many tools agree, and tracks what changed between scans in SQLite.

- Polite by default: `--speed slow` (one tool at a time, random delays, shuffled order)
- Passive first: active scans need `--active` **and** a matching `scope.yaml`
- Multi-tool stages with source attribution (HIGH / MEDIUM / LOW)
- Host states: ALIVE, DNS_ONLY, SHUT_DOWN, DEAD, tracked across scans
- Self-installer for Kali/Ubuntu: `reconkit install --all` (tools go to `~/.reconkit/bin`)
- State in SQLite, raw output in `workspaces/<target>/`

> `scope.yaml` is a safety guard against mistakes, not permission. Use reconkit only on systems you own or have explicit written authorization to test.

## Status

Phase 2 (working core) is complete: passive discovery (`subs`, `dns`), `live`, `ports`, `diff`, `status`, `doctor`, `install` and `update` are implemented on Linux and covered by the test suite. Phase 3 adapters and workflows are being added one at a time. These commands exist but are **Phase 3 stubs** in this build and exit `1` with a "not wired" message: `db list`, `db export`, `export`, `scope import`.

## Requirements

| Platform | What works |
|---|---|
| Kali / Ubuntu (native or WSL2) | Everything, including the real tools and installer. Python 3.11+, `git`, `sudo` for apt packages. |
| Windows | `doctor`, `--mock` runs and the pure-Python passive flow. `reconkit install` / `update` refuse with `Use WSL2 Kali (see SETUP.md)` and exit `1`; run real tools from a Linux checkout (native Kali/Ubuntu also works). |

## Quick start (Kali / Ubuntu)

```bash
cd /path/to/reconkit
./scripts/bootstrap.sh
source .venv/bin/activate

reconkit doctor
cp scope.example.yaml scope.yaml      # edit with YOUR authorized targets
reconkit passive -d example.com --mock
reconkit install --all --dry-run
reconkit install --all
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

In Git Bash, use `./scripts/bootstrap.sh` and `source .venv/Scripts/activate` instead. Do not run `reconkit install` on Windows: it prints `Use WSL2 Kali (see SETUP.md)` and exits `1`. A native Kali/Ubuntu machine is equally valid for the full tool install; the message names WSL2 because that is the built-in hint.

## Commands

| Command | What it does |
|---|---|
| `passive` / `lite` | Passive subs + dns pipeline for one target; no scope file needed |
| `subs`, `dns` | Run one passive stage |
| `live` | ALIVE / DNS_ONLY / SHUT_DOWN / DEAD; needs `--active` + scope |
| `ports` | Port scan over each adapter's default port set; needs `--active` + scope |
| `tech`, `urls`, `vulns` | Stage commands whose adapters are Phase 3; may report no usable tool |
| `run` | Passive, then active stages; needs `--active` + scope |
| `diff` | New, gone, state-changed and port-changed items vs the previous run |
| `status` | Recent scans (`--json` for scripts) |
| `doctor` | Tool, version, path, per-stage coverage, system packages, key names |
| `install`, `update` | Install/update tools from `tools.yaml`; `--all` selects core tools |
| `scope check -d X` | Show whether a target is allowed by `scope.yaml` |

Scan flags include `--speed slow|normal|fast` (default `slow`), `--delay MIN-MAX`, `--tools`, `--exclude`, `--include-noisy`, `--min-sources`, `--phase-timeout`, `--mock`, `--resume`, `--no-keys`, `--json`, `--no-color`, `-q/--silent`, `-v/--verbose`, and `--config/--scope/--db`. `--json` is available on the scan commands, `doctor`, `diff` and `status`, not on `install`/`update` or the Phase 3 stubs. There is no flag that skips the scope gate.

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
| docs/03_ARCHITECTURE.md | Layers, structure, pacing, consensus |
| docs/04_DATABASE.md | SQLite schema |
| docs/05_SECURITY.md | Scope gate, subprocess and installer safety |
| docs/06_CODE_STYLE.md | Code conventions |
| docs/07_TESTING.md | Test strategy |
| docs/08_UX_FLOWS.md | User journeys |
| docs/09_TOOL_CONTRACTS.md | Adapter contract and stage registry |
| docs/10_TOOL_INSTALLER.md | Installer design |
| tools.yaml / config.yaml / scope.example.yaml | Registry, settings, scope template |

## Legal disclaimer

reconkit is intended for **authorized security testing only**. Use it only on systems you own or where you have explicit written permission (for example an in-scope bug bounty program or a signed engagement). Unauthorized scanning may be illegal. The authors assume no liability for misuse.
