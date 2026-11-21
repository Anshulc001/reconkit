# reconkit

[![tests](https://github.com/Anshulc001/reconkit/actions/workflows/test.yml/badge.svg)](https://github.com/Anshulc001/reconkit/actions/workflows/test.yml)

A command-line reconnaissance orchestrator for **authorized** security testing. It runs several tools per stage, cross-checks their results, scores confidence by how many tools agree, and tracks what changed between scans in SQLite.

- Natural pace: no speed preset, delay or artificial throttling; tools run at their own rate
- Passive first: `passive` (subs+dns+urls, passive tools only) by default; `--active` adds `live` and `tech`; `--full` runs every stage. A `scope.yaml` is required for active scans; without one, active scanning is refused unless `--no-scope` is passed explicitly
- Multi-tool stages with source attribution (HIGH / MEDIUM / LOW)
- Host states: ALIVE, DNS_ONLY, SHUT_DOWN, DEAD, tracked across scans
- Tool inventory, not installation: `reconkit doctor` lists what is installed and what is missing; per-tool sources are in [docs/10_TOOL_SOURCES.md](docs/10_TOOL_SOURCES.md)
- State in SQLite, raw output in `workspaces/<target>/`

> `scope.yaml` is a safety guard against mistakes, not permission. Use reconkit only on systems you own or have explicit written authorization to test.

## Status

v1.0.0 is stable and feature-complete. `install`, `update` and `doctor --fix` were removed on 2026-11-17: reconkit no longer installs tools, it only reports what you have. The following remain documented **Phase 3 stubs** and exit `1` with a "not wired" message: `db list`, `db export`, `export`, `scope import`. `reconkit report --target <domain>` is implemented (D65): it rebuilds a saved report from the database without scanning.

## Requirements

| Platform | What works |
|---|---|
| Kali / Ubuntu (native) | Everything, including the real tools - obtaining them is your own job, outside reconkit. Python 3.11+ and `git` for the checkout. This is the only supported platform. |

## Quick start (Kali / Ubuntu)

```bash
git clone https://github.com/Anshulc001/reconkit.git
cd reconkit
./scripts/setup.sh                    # venv + dependencies + every installable tool + doctor
source .venv/bin/activate

reconkit doctor                        # what is installed, what is missing
reconkit                               # interactive: asks target, scope, mode, fields
# `setup.sh` forwards --check, --only <tool> and --dry-run to install-tools.sh.
# The reconkit CLI itself installs nothing; tools come from tools.yaml `source:`.
# Provenance for every tool is in docs/10_TOOL_SOURCES.md.
# Optional: cp .env.example .env and add the API keys you have.
cp scope.example.yaml scope.yaml      # edit with YOUR authorized targets
reconkit passive -d example.com --mock
reconkit passive -d <authorized-domain>
reconkit diff -d <authorized-domain>
```

**Activate the venv in every new terminal.** `source .venv/bin/activate` is what puts `reconkit` on `PATH`; without it you get `reconkit: command not found`. The equivalent without activation is `.venv/bin/reconkit ...`. See [SETUP.md](SETUP.md) for the full beginner walkthrough and troubleshooting.

## Commands

| Command | What it does |
|---|---|
| `passive` | Passive subs + dns + urls pipeline for one target (passive tools only); no scope file needed. Also what bare `reconkit -d X` and `run -d X` mean |
| `active` | Active mode: subs+dns+live+tech+urls+url_probe; needs `--active`-equivalent scope rules (scope file or `--no-scope`). Same as `run -d X --active` |
| `full` | Full mode: all nine stages including `ports` and `shots`, `opt_in` enabled. Same as `run -d X --full` |
| `subs`, `dns` | Run one passive stage |
| `live` | ALIVE / DNS_ONLY / SHUT_DOWN / DEAD; needs `--active` (uses any present scope file) |
| `ports` | Port scan over each adapter's default port set (`--ports` overrides); needs `--active` |
| `tech` | Technology, WAF and CDN inventory; needs `--active` |
| `urls` | URL discovery from archives and crawlers; needs `--active` |
| `vulns` | Vulnerability checks: `nuclei`, `subzy`, `dnsreaper` (core), `nikto`, `ffuf` (opt_in); needs `--active`. Findings are not persisted |
| `run` | Flag-driven form of the three modes: `run` = `passive`, `--active` = `active`, `--full` = `full`. The mode table is in [docs/02_CLI_UX.md](docs/02_CLI_UX.md) |
| `diff` | New, gone, state-changed and port-changed items vs the previous run |
| `status` | Recent scans (`--json` for scripts) |
| `report` | Rebuild `report.txt`/`report.json` from stored rows (`--target`, `--run`, `--out`); read-only, no network |
| `doctor` | Tool, version, path, per-stage coverage, system packages, key names |
| `scope check -d X` | Show whether a target is allowed by `scope.yaml` |
| `db delete --target X` | Delete one target, every row that belongs to it, and its `results/X/` folder (asks first; `--yes` skips) |
| `db wipe` | Delete every row and recreate the schema (asks first; `--yes` skips); `results/` is kept |
| `db list`, `db export` | **Phase 3 stub**: exits `1`; no data is read |
| `export -d X --format json\|md\|html` | **Phase 3 stub**: exits `1`; no report is written |
| `scope import` | **Phase 3 stub**: exits `1` |

Scan flags include `--active`, `--full`, `--no-scope`, `--tools`, `--exclude`, `--include-noisy`, `--min-sources`, `--phase-timeout`, `--mock`, `--resume`, `--no-keys`, `--only-alive`, `--only-states`, `--ports`, `--status-codes`, `--header`, `--user-agent`, `--redact-headers/--show-headers`, `--json`, `--no-color`, `-q/--silent`, `-v/--verbose`, and `--config/--scope/--db`. `--json` is available on the scan commands, `doctor`, `diff` and `status`, not on the Phase 3 stubs. `--no-scope` does not skip the gate while reading a scope file: it opts out of the file entirely and warns (docs/02 section 3.1). The mode definitions live in one table in [docs/02_CLI_UX.md](docs/02_CLI_UX.md) section 2.

### Vulnerability scanning (current state)

`vulns` is implemented but deliberately narrow. It runs with `--active` as a
stage command, or as the last stage of `--full`:

```bash
reconkit vulns -d example.com --active
reconkit full -d example.com          # vulns is the last stage
```

- `nuclei`, `subzy` and `dnsreaper` (`core`) run with the stage.
- `nikto` and `ffuf` are `opt_in`: add `--include-noisy`, use `--full`, or name
  them with `--tools`.
- `dalfox`, `crlfuzz` and `sqlmap` are exploitation-class and never run
  automatically (explicit `--tools` only).
- `run --active` does **not** include `vulns` (full-only); use `run --full`
  or `reconkit vulns`.
- Findings are **not stored in SQLite** and do not appear in `report.json` or
  `report.txt`. Raw, redacted output goes to
  `workspaces/<target>/meta/<run_id>-<tool>.txt` (one file per tool per stage
  run); the run's `--json` carries the stage results, including `raw_path`.

## Example (real mock run)

With a fresh database, `reconkit passive -d example.com --mock` prints the results table (columns `Subdomain`, `State`, `Status`, `Ports`, `Sources`, `Trust`) and the Tools table, then ends with:

```
10 hosts: 0 ALIVE, 2 DNS_ONLY, 0 SHUT_DOWN, 1 DEAD, 7 UNKNOWN | tools: 7 ok, 0 failed, 0 skipped, 0 timeout
```

A second identical run followed by `reconkit diff -d example.com` prints:

```
No changes since run #1.
```

### What a report folder contains

Every run writes `results/<target>/<stamp>/` (a mock run writes under
`results/mock/<target>/<stamp>/`):

```text
results/<target>/<stamp>/
  report.txt
  report.json
  subdomains.txt
  alive.txt
  dns_resolved.txt
  host-info.txt
  host-info.json
  external_urls.txt
  hosts/
    <hostname>/
      urls.txt
      info.json
```

`external_urls.txt` holds URLs whose host is outside the target (D76); they
never create a `hosts/` folder. A `hosts/<hostname>/` folder exists only for an
in-scope host that has at least one stored URL. `report.urls_max` is `0` in
`config.yaml`, so every stored URL is listed (`0` = no cap); set a number to
cap the whole report.

## Cleanup

```bash
reconkit db delete --target example.com          # shows counts, then asks [Y/n]
reconkit db delete --target example.com --yes    # target + rows + results/example.com/
reconkit db wipe --yes                           # all rows, fresh schema; results/ kept
```

`db delete` removes the target's `scan_runs`, `tool_runs`, `subdomains`,
`subdomain_sources`, `host_status_history`, `ports`, `port_sources` and `urls`
in one transaction, then removes `results/<target>/` (and
`results/mock/<target>/` when present). `db wipe` drops every table and
recreates the current schema, but never deletes `results/`; it prints the
manual reset line instead. Both commands read the root `--db`/`--config`
options, which go **before** `db`:

```bash
reconkit --db /tmp/copy.db db delete --target example.com --yes
```

`db list` and `db export` remain Phase 3 stubs.

## Contributing

Contributions and collaboration are welcome: bug reports, documentation fixes,
adapter ideas, and code.

- Open an issue first for anything larger than a typo, so the approach can be
  agreed before you write it.
- Fork the repo, branch from `main`, and keep each change focused.
- Run the gate before opening a pull request:

```bash
source .venv/bin/activate
pytest -q
ruff check .
ruff format --check .
mypy src/reconkit
```

- Add tests for behavior changes and update the matching doc in the same PR.
- Never commit real target data, `scope.yaml`, API keys, `.env` values or raw
  scan output; use the fixtures under `tests/fixtures/`.
- reconkit is for authorized testing only. Changes that add evasion, scope
  bypasses or unrequested intrusive behavior will not be accepted.

There is no `LICENSE` file in the repository yet; if you plan to reuse the code,
open an issue to settle licensing first.

## Documentation

| File | Purpose |
|---|---|
| AGENTS.md | Rules for AI coding agents (read first) |
| SETUP.md | Beginner setup for Kali/Ubuntu |
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

## Known environmental limits

Two things do not work on every machine, and neither is a defect in reconkit:

- **Screenshots need a Chrome-family browser.** `gowitness` execs `google-chrome`, so on a box with only `/usr/bin/chromium` `doctor` reports `chromium missing` and the `shots` stage produces no images.
- **`masscan`'s build path is unverified here.** `libpcap-dev` is absent on this box, so only the installed binary has been exercised; a real `masscan` run also needs root.

## Known upstream limitations

- `waybackurls` returns 0 items when archive.org is offline (HTTP 503): it cannot distinguish "no data" from "service down", so its `urls` row can read `ok 0` while the archive actually has data (docs/09 section 4a2b).

## Legal disclaimer

reconkit is intended for **authorized security testing only**. Use it only on systems you own or where you have explicit written permission (for example an in-scope bug bounty program or a signed engagement). Unauthorized scanning may be illegal. The authors assume no liability for misuse.

## License

MIT. See [LICENSE](LICENSE).
