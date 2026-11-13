# reconkit

A command-line reconnaissance orchestrator for **authorized** security testing. It installs its own tools, runs several tools per stage, cross-checks the results, scores confidence by how many tools agree, and shows what changed since the last scan.

- Polite by default: `--speed slow` (one tool at a time, random delays, shuffled order)
- Passive first: active scans need `--active` **and** a matching `scope.yaml`
- Multi-tool stages with source attribution (HIGH / MEDIUM / LOW)
- Host states: ALIVE, DNS_ONLY, SHUT_DOWN, DEAD, tracked across scans
- Self-installer: `reconkit install --all`
- State in SQLite, raw output in `workspaces/<target>/`

## Quick start

See **SETUP.md** (Windows + WSL2 Kali + VS Code), then:

```bash
reconkit doctor
reconkit install --all
cp scope.example.yaml scope.yaml      # edit with YOUR authorized targets
reconkit passive -d example.com --mock
reconkit passive -d <authorized-domain>
reconkit live -d <authorized-domain> --active
reconkit ports -d <authorized-domain> --active
reconkit diff -d <authorized-domain>
```

## Documentation

| File | Purpose |
|---|---|
| AGENTS.md | Rules for AI coding agents (read first) |
| docs/01_PRD.md | Product scope and acceptance criteria |
| docs/02_CLI_UX.md | Commands, flags, speed modes, output |
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

reconkit is intended for **authorized security testing only**. Use it only on systems you own or where you have explicit written permission (for example an in-scope bug bounty program or a signed engagement). Unauthorized scanning may be illegal. `scope.yaml` is a safeguard against mistakes, not a permission. The authors assume no liability for misuse.

## Status

Phase 1 (documentation blueprint) complete. Phase 2 (working core) next. Phase 3 adds the remaining tools one adapter at a time.
