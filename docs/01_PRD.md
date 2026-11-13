# Product Requirements Document

## 1. Product Overview

- **Product name:** reconkit
- **One-line description:** A CLI that runs several recon tools per stage, cross-checks their results, and tracks what changed between scans.
- **Product type:** Command-line tool (single-user, local-first)
- **Primary platform:** Linux (Kali) via WSL2; development in VS Code on Windows (Remote-WSL)

## 2. Problem

- **What problem are we solving?** Recon needs many tools. Each tool misses things, fails silently, rate-limits, or returns noise. Results end up in many loose text files with no history.
- **Why does it matter?** Missed assets mean missed attack surface. Noisy or too-fast scans get IPs banned, break program rate limits, and can disturb targets.
- **How do users solve this today?** Shell scripts chaining tools (for example ReconX-style Bash scripts) or large platforms (AutoAR: Go, dashboard, Postgres, Docker). Scripts lack state and safety; platforms are heavy.

## 3. Goals

- **Primary:** One lightweight command-line tool that installs its own tools, runs several tools per stage, scores results by how many tools agree, and shows only what is new or changed.
- **Secondary:**
  - Polite by default: slow, randomized timing so APIs and targets are not hammered.
  - Safe by default: passive unless explicitly active, and active only inside `scope.yaml`.
  - Easy to extend: one adapter file plus one registry entry per new tool, so AI agents can add tools reliably.

## 4. Target Users

### User Type 1 - Bug bounty hunter
- **Needs:** broad subdomain coverage, change tracking, program-safe rate limits.
- **Pain points:** tool sprawl, banned IPs, losing track of what is new.

### User Type 2 - Penetration tester
- **Needs:** repeatable, scoped recon with exportable evidence.
- **Pain points:** out-of-scope mistakes, inconsistent tool output.

## 5. User Stories

- As a tester, I want `reconkit install --all` so that I do not install 20 tools by hand.
- As a tester, I want `reconkit doctor` so that I know which stages are fully covered.
- As a tester, I want passive discovery from several sources so that no single source hides assets.
- As a tester, I want every result to show which tools found it so that I can trust or verify it.
- As a tester, I want to know which hosts are ALIVE, DNS_ONLY, SHUT_DOWN or DEAD, and when that changed.
- As a tester, I want slow, randomized scanning by default so that I do not get blocked or break program rules.
- As a tester, I want active scans refused outside `scope.yaml` so that I never test something unauthorized by accident.
- As a tester, I want `diff` to show only new or changed assets since the last scan.

## 6. Core Features

### Feature 1 - Installer (`install`, `update`, `doctor --fix`)
- **Purpose:** Install and update tools into `~/.reconkit/bin` from the registry.
- **Acceptance criteria:**
  - Downloads only from sources listed in `tools.yaml`; verifies checksums when available.
  - `--dry-run` prints actions without changing anything.
  - sudo is used only for `apt` packages, with a confirmation prompt.
  - Missing or failed tools are reported, never silently ignored.
- **Edge cases:** no internet, GitHub rate limit, release asset renamed, already installed, unsupported architecture, not Linux.

### Feature 2 - Doctor
- **Purpose:** Report readiness per stage.
- **Acceptance criteria:**
  - Shows each tool: installed, version, path.
  - Shows per-stage coverage (example: `subs 6/9 ready`).
  - Checks system packages (`libpcap-dev`, `jq`), wordlists, Python version, `scope.yaml` presence, and which API keys are set (names only, never values).
- **Edge cases:** tool present but not executable, version command fails, wrong `httpx` program found.

### Feature 3 - Passive recon (`passive`, `subs`, `dns`)
- **Purpose:** Discover subdomains from several third-party sources and resolve them, without sending traffic to the target.
- **Acceptance criteria:**
  - Runs every available `core` adapter of the stage, respecting `--speed`.
  - Dedupes and stores `sources` and `confidence` per subdomain.
  - Filters wildcard DNS results.
  - Works on day one with HTTP-only sources even if no binary is installed.
- **Edge cases:** source returns HTTP 429/5xx, empty results, malformed output, wildcard domain.

### Feature 4 - Host state tracking (`live`)
- **Purpose:** Classify each host as ALIVE, DNS_ONLY, SHUT_DOWN or DEAD, and record changes over time.
- **Acceptance criteria:**
  - Uses at least two methods when available (for example httpx plus the Python probe).
  - SHUT_DOWN is only set for hosts that were ALIVE or resolving in an earlier run.
  - `diff` shows transitions such as `[NOW ALIVE]`, `[WENT DOWN]`.
- **Edge cases:** WAF/CDN blocks, timeouts, redirects, TLS errors, non-HTTP services.

### Feature 5 - Port scanning (`ports`)
- **Purpose:** Find open ports and services on in-scope hosts.
- **Acceptance criteria:**
  - Default scan is a top-ports connect scan (no root needed). `--ports` and `--full` change it.
  - If two scanners disagree, the port is stored as `unconfirmed`, not dropped.
  - Only hosts inside `scope.yaml` (including `in_scope_cidrs` for IPs) are scanned.
- **Edge cases:** filtered ports, rate limiting, IPv6, CDN IPs shared by many hosts.

### Feature 6 - Multi-tool consensus and confidence
- **Purpose:** Make results trustworthy.
- **Acceptance criteria:**
  - Every stored asset keeps its list of source tools.
  - Confidence: HIGH (3+ tools), MEDIUM (2), LOW (1), UNCONFIRMED (tools disagree).
  - `--min-sources N`, `--tools a,b`, `--exclude x` work on every stage command.

### Feature 7 - Speed and pacing (`--speed`)
- **Purpose:** Polite, low-noise scans.
- **Acceptance criteria:**
  - Default `slow`: tools run one at a time with random delays; hosts and ports are shuffled; tool rate flags are set from config.
  - `--delay MIN-MAX` overrides the pause range.
  - `--speed fast` on an active stage requires typed confirmation and is capped by `max_speed` in `scope.yaml`.

### Feature 8 - Change tracking (`diff`, `status`, `db`, `export`)
- **Acceptance criteria:**
  - `diff` shows only NEW/CHANGED/GONE items vs the previous run.
  - `status --json` reports phase, counts and elapsed time of running or finished scans.
  - `export` writes json, md or html; `--json` works on every command.

### Feature 9 - Workflows (`lite`, `run`)
- `lite` = passive pipeline. `run` = passive, live, ports, then selected checks, with per-phase timeouts and resume of an interrupted run.

## 7. Non-Goals (this version)

- Web dashboard, REST API, Docker or Postgres.
- Cloud storage uploads, chat bots, AI agent loops.
- Mobile app analysis (APK/IPA/ADB), GitHub/S3 scanning, AEM or 100+ misconfig checks.
- Exploitation tools in `core` or `opt_in` tiers.
- Native Windows execution of recon tools (use WSL2 Kali).
- Evasion features (User-Agent rotation, proxy rotation).

## 8. MVP Scope

**Phase 1 (docs):** AGENTS.md, SETUP.md, docs 01-10, tools.yaml, config.yaml, scope.example.yaml.

**Phase 2 (working core) - Must have:**
- Skeleton, config, scope gate, SQLite store, pacing engine, consensus engine, `--mock`.
- Commands: `doctor`, `install`, `update`, `passive`, `live`, `ports`, `diff`, `status`, `db`, `export`.
- Adapters: crtsh, certspotter, otx, hackertarget, subfinder, assetfinder, dnspython, pyprobe, httpx, pyscan, naabu.
- Tests passing in WSL and on plain Windows (fixtures).

**Phase 3 (one adapter or feature per prompt):** remaining tools in `tools.yaml`, `urls`/`tech`/`vulns`/`shots`, `lite`/`run` polish, `monitor` with webhook, `scope import`, URL pattern sorting (xss/sqli/ssrf/lfi/redirect candidate lists), intrusive tier.

## 9. Success Metrics

- **Primary:** a fresh WSL2 Kali setup reaches a first passive scan within 15 minutes following SETUP.md; `doctor` is green for the Phase 2 tools.
- **Secondary:** adding a new adapter takes one file + one registry entry + one test; no scan produces out-of-scope traffic in tests.

## 10. Constraints

- **Technical:** Python 3.11+; SQLite only; runs on Linux; no root required for default scans.
- **Business:** none (personal/open-source tool).
- **Design:** terminal only; must be readable without color (`--no-color`).
- **Timeline:** incremental phases.

## 11. Assumptions

- The user owns or has written authorization for every target.
- Third-party sources keep their public APIs; adapters degrade gracefully when they do not.
- ProjectDiscovery releases keep publishing Linux binaries and checksum files.

## 12. Open Questions

- Exact release asset names per tool (verify when building the installer).
- Which optional API keys the user will configure first.
- Whether `run` should include `nuclei` in Phase 2 or Phase 3 (default: Phase 3).

## 13. Definition of Done

- [ ] Requirements implemented
- [ ] Critical user flows (docs/08_UX_FLOWS.md) work
- [ ] Tests, lint, type check pass
- [ ] Scope gate and pacing verified by tests
- [ ] Security rules (docs/05_SECURITY.md) satisfied
- [ ] Documentation updated
