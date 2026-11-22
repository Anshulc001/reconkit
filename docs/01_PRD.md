# Product Requirements Document

## 1. Product Overview

- **Product name:** reconkit
- **One-line description:** A CLI that runs several recon tools per stage, cross-checks their results, and tracks what changed between scans.
- **Product type:** Command-line tool (single-user, local-first)
- **Platform:** Linux (Kali or Ubuntu), native, and nothing else. reconkit installs nothing, so there is no platform-specific install path (docs/10 §4).

## 2. Problem

- **What problem are we solving?** Recon needs many tools. Each tool misses things, fails silently, rate-limits, or returns noise. Results end up in many loose text files with no history.
- **Why does it matter?** Missed assets mean missed attack surface. Noisy or too-fast scans get IPs banned, break program rate limits, and can disturb targets.
- **How do users solve this today?** Shell scripts chaining tools (for example ReconX-style Bash scripts) or large platforms (AutoAR: Go, dashboard, Postgres, Docker). Scripts lack state and safety; platforms are heavy.

## 3. Goals

- **Primary:** One lightweight command-line tool that inventories the recon tools you have installed, runs several of them per stage, scores results by how many tools agree, and shows only what is new or changed.
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

- As a tester, I want `reconkit doctor` to tell me exactly which of the 20 tools I still need, and where to get each one, so that I can install them myself without guessing.
- As a tester, I want `reconkit doctor` so that I know which stages are fully covered.
- As a tester, I want passive discovery from several sources so that no single source hides assets.
- As a tester, I want every result to show which tools found it so that I can trust or verify it.
- As a tester, I want to know which hosts are ALIVE, DNS_ONLY, SHUT_DOWN or DEAD, and when that changed.
- As a tester, I want slow, randomized scanning by default so that I do not get blocked or break program rules.
- As a tester, I want active scans refused outside a present `scope.yaml` so that I never test something unauthorized by accident, with an explicit, loudly-warned `--no-scope` opt-out when I deliberately run without one.
- As a tester, I want `diff` to show only new or changed assets since the last scan.

## 6. Core Features

### Feature 1 - Tool inventory (`doctor`)
- **Purpose:** Report which registry tools are installed and where each one comes from - without installing anything (removed 2026-11-17, docs/MASTER_PLAN.md D4) and without reporting version strings (owner ruling 2026-11-17, docs/MASTER_PLAN.md D6).
- **Acceptance criteria:**
  - One row per tool: installed, resolved path and identity, with the adapter's own check first and the registry's `version_cmd`/`binary` probe otherwise. The probe's version string feeds the identity check only and is never displayed.
  - A same-named program that fails the identity probe is reported as `wrong program`, never as installed.
  - A missing tool is reported by count, with the one-line statement that scans use what is installed and skip the rest, and a pointer to the per-tool table in docs/10_TOOL_SOURCES.md.
  - Every binary tool in `tools.yaml` carries a non-empty `source:` string; reconkit never executes it.
- **Edge cases:** tool present but not executable, version command fails, wrong `httpx` program found, a tool installed by hand outside `~/.reconkit/bin`, no tools installed at all.

### Feature 2 - Doctor
- **Purpose:** Report readiness per stage.
- **Acceptance criteria:**
  - Shows each tool: installed, path, identity (never a version).
  - Shows per-stage coverage (example: `subs 6/9 ready`).
  - Checks system packages (`libpcap-dev`, `jq`), Python version, `scope.yaml` presence, and which API keys are set (names only, never values).
- **Edge cases:** tool present but not executable, version command fails, wrong `httpx` program found.

### Feature 3 - Passive recon (`passive`, `subs`, `dns`)
- **Purpose:** Discover subdomains from several third-party sources and resolve them, without sending traffic to the target.
- **Acceptance criteria:**
  - Runs every available `core` adapter of the stage.
  - Dedupes and stores `sources` and `confidence` per subdomain.
  - Filters wildcard DNS results.
  - Works on day one with HTTP-only sources even if no binary is installed.
- **Edge cases:** source returns HTTP 429/5xx, empty results, malformed output, wildcard domain.

### Feature 4 - Host state tracking (`live`)
- **Purpose:** Classify each host as ALIVE, DNS_ONLY, SHUT_DOWN or DEAD, and record changes over time.
- **Acceptance criteria:**
  - Uses at least two methods when available (for example httpx plus the Python probe).
  - SHUT_DOWN is only set for hosts that were ALIVE or resolving in an earlier run.
  - `diff` shows transitions as `STATE` rows (`old -> new`) alongside `NEW`/`GONE` and port rows.
- **Edge cases:** WAF/CDN blocks, timeouts, redirects, TLS errors, non-HTTP services.

### Feature 5 - Port scanning (`ports`)
- **Purpose:** Find open ports and services on in-scope hosts.
- **Acceptance criteria:**
  - Default scan is a connect scan (no root needed) over each adapter's default port set; `--ports` overrides the list and `--full` runs every stage (docs/02 section 2 is the mode source of truth).
  - If two scanners disagree, the port is stored as `unconfirmed`, not dropped.
  - Only hosts inside `scope.yaml` (including `in_scope_cidrs` for IPs) are scanned.
- **Edge cases:** filtered ports, rate limiting, IPv6, CDN IPs shared by many hosts.

### Feature 6 - Multi-tool consensus and confidence
- **Purpose:** Make results trustworthy.
- **Acceptance criteria:**
  - Every stored asset keeps its list of source tools.
  - Confidence: HIGH (3+ tools), MEDIUM (2), LOW (1), UNCONFIRMED (tools disagree).
  - `--min-sources N`, `--tools a,b`, `--exclude x` work on every stage command.

### Feature 7 - Speed and pacing (removed 2026-11-17)
- **Was:** `--speed`/`--delay` presets, a pacer and rate limiting.
- **Now:** removed at the owner's request (docs/MASTER_PLAN.md D3, "user-requested removal, no throttling desired"). Tools run at their own natural pace; there is no speed flag, delay flag, pacer or rate limiter, and `scope.yaml` `max_speed` is accepted but ignored.

### Feature 8 - Change tracking (`diff`, `status`, `db`, `report`)
- **Acceptance criteria:**
  - `diff` shows only new, gone, state-changed and port-changed items vs the previous run.
  - `status --json` reports phase, counts and elapsed time of running or finished scans.
  - `report --target X` rebuilds `report.txt`/`report.json`/`report.pdf` from stored rows without scanning. The former `export`, `db list`, `db export` and `scope import` stubs were removed on 2026-11-22 (D119): those commands do not exist (docs/02).
  - `--json` is supported on the scan commands, `doctor`, `diff` and `status`; `report` writes files instead and `db delete`/`db wipe` do not take it.

### Feature 9 - Workflows (`passive`, `active`, `full`, `run`)
- `passive`, `active` and `full` are the three modes by name; `run` selects one of them by flag (`--active`, `--full`), with per-phase timeouts and resume of an interrupted run. The old `lite` alias is gone (2026-11-21); it was identical to `passive`.

## 7. Non-Goals (this version)

- Web dashboard, REST API, Docker or Postgres.
- Cloud storage uploads, chat bots, AI agent loops.
- Mobile app analysis (APK/IPA/ADB), GitHub/S3 scanning, AEM or 100+ misconfig checks.
- Exploitation tools in `core` or `opt_in` tiers.
- Support for any platform other than Linux.
- Evasion features (User-Agent rotation, proxy rotation).

## 8. MVP Scope

**Phase 1 (docs):** AGENTS.md, SETUP.md, docs 01-10, tools.yaml, config.yaml, scope.example.yaml.

**Phase 2 (working core) - Must have** (the phase names below are the original
plan; the shipped build is v1.0.0, 2026-11-21):
- Skeleton, config, scope gate, SQLite store, consensus engine, `--mock`.
- Commands: `doctor`, `passive`, `live`, `ports`, `diff`, `status`, `report`, `db delete`, `db wipe`, `scope check`. (`install`, `update` and `doctor --fix` existed in Phase 2 and were removed on 2026-11-17; the `export`, `db list`, `db export` and `scope import` stubs were removed on 2026-11-22, D119.)
- Adapters: crtsh, certspotter, otx, hackertarget, subfinder, assetfinder, dnspython, pyprobe, httpx, pyscan, naabu.
- Tests passing on Linux (fixtures only, no tools needed).

**Phase 3 (one adapter or feature per prompt):** shipped in v1.0.0 - the rest of `tools.yaml` (47 adapters), `urls`/`tech`/`vulns`/`shots`, the `passive`/`active`/`full`/`run` commands, PDF reports and per-scan logging. **Still open:** `monitor` with webhook, a row-level import/export (the `export`/`db list`/`db export` stubs were removed in D119; `report` covers reports), URL candidate-pattern tagging (`urls.patterns_json`, docs/04 section 3.1), adapters for the three intrusive tools (`dalfox`, `crlfuzz`, `sqlmap`), and a findings table (docs/04 section 3).

## 9. Success Metrics

- **Primary:** a fresh Kali/Ubuntu setup reaches a first passive scan within 15 minutes following SETUP.md; `doctor` is green for the Phase 2 tools.
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

No blocking product questions. Tool sources were verified against real releases during Part 10 and are listed in docs/10_TOOL_SOURCES.md §2. Which optional keys a user configures first remains a deployment preference, not a product decision; free mode needs none.

## 13. Definition of Done

**This checklist is the full-product target.** The implemented Phase 2 subset is listed in §8 and tracked in `docs/PROGRESS.md`; the unchecked boxes below are not a statement that Phase 2 is unfinished.

- [ ] Requirements implemented
- [ ] Critical user flows (docs/08_UX_FLOWS.md) work
- [ ] Tests, lint, type check pass
- [ ] Scope gate verified by tests
- [ ] Security rules (docs/05_SECURITY.md) satisfied
- [ ] Documentation updated
