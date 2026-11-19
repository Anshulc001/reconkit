# Security Guidelines

## 1. Purpose and Legal Notice

reconkit is for **authorized security testing only**: targets you own, or have explicit written permission to test (for example an in-scope bug bounty program or a signed engagement). Unauthorized scanning can be illegal. The authors accept no liability for misuse.

`scope.yaml` is a **safety guard against accidents**. It does not grant permission. The user is responsible for authorization.

## 2. Scope Gate

Implemented in `core/scope.py`. Rules:

1. **Passive stages** (`subs`, `dns`, passive parts): no scope file required, because no traffic goes to the target. If `scope.yaml` exists, targets outside it print a warning.
2. **Active stages** require the `--active` flag. What else is required depends on one thing - whether a scope file exists at the resolved location (default `./scope.yaml`, overridable with `--scope`):
   - **No scope file** (the path does not exist): active and full scanning proceed **unrestricted** against the target(s) the operator gave with `-d`/`-l`, and against every host discovered under those targets. Nothing is derived from the target to stand in for a scope file: no scope object is constructed, no implicit restriction is applied, and the run is not refused. The rule is deliberately literal - "no scope given" means "scan freely, I know what I typed" - so the operator's explicit target is the authorization for that run. Owner decision, 2026-11-17 (Task 1); recorded in `docs/MASTER_PLAN.md` as a dated deviation.
   - **Scope file present**: enforced exactly as before and never weakened - `authorization` field non-empty, not past `expires`, `allow_active: true`, target matches `in_scope`, and not in `out_of_scope`. A failure refuses the active stage with exit code 3 (each active tool is recorded `skipped` with the gate's reason when passive stages already ran). A real `scope.yaml` is read only; it is never overwritten or deleted by any code path. When passive stages did run, the results are not silent: the run ends with `⚠ ACTIVE STAGES SKIPPED BY SCOPE — this run is passive-only; the report says so.`, and the saved report carries `scope_limited: true` plus the same line, so partial results cannot be mistaken for a completed active scan after the terminal is gone (D64, 2026-11-19).
3. `out_of_scope` always wins over `in_scope`.
4. Matching: exact host, `*.domain` wildcard (any depth), `re:` regex entries. Hosts are lowercased, trailing dot stripped.
5. **Every host is re-checked** right before it is probed (not only the root target). Out-of-scope hosts are dropped and counted in the summary.
6. **IPs:** with a scope file present, probe an IP only if it is inside `in_scope_cidrs`; no CIDRs means no IPs. **Enforcement (11c-G-7, superseded in part 2026-11-17):** the engine hands each active stage the loaded scope's `ip_allowed` predicate through `RunContext.ip_allowed`, and `pyscan` filters every resolved address with it before connecting: an address outside is never probed, an empty resolution is never retried as a hostname, no CIDRs or an unreadable scope mean no addresses, and each skipped host is counted in `blocked=`. `naabu` cannot filter an address it resolves itself, so it is handled by scope mode: with **no scope file** it runs unrestricted like any other active tool; with a **scope file present** the engine pre-resolves each already-in-scope target itself, verifies every returned address with this same predicate, and passes naabu only the verified IP address(es) - never a bare domain. A target whose resolution fails or whose addresses are all out of scope is left out of that naabu invocation (no hostname fallback); if no target verifies, naabu does not run at all and the skip reason is recorded. `naabu` never runs in passive mode, like every other active tool (owner decision, 2026-11-17; docs/09 section 3 and selection rules). `--mock` is exempt from resolution because it connects to nothing. When **no scope file exists there is no CIDR list and no IP gate**: the engine hands the stage an allow-all `ip_allowed`, so "no scope" cannot silently block every address. That is the same 2026-11-17 decision as rule 2.
7. **Port-scan pre-check:** port scans require a stored `live` result for the host. If no live result is stored, skip that host and print a warning (`run live first`); do not resolve and scan it directly. If the stored host status has `waf` set (the CDN/WAF marker the `httpx` live adapter parses from its JSON output, column `host_status_history.waf`), skip it as CDN/WAF-fronted. Phase 2 has no `cdncheck`; Phase 3 may add `cdncheck`/`wafw00f`.
8. `max_speed` in `scope.yaml` is accepted for compatibility and ignored: speed control was removed on 2026-11-17 (docs/MASTER_PLAN.md D3), so there is nothing left to cap. The program's real rate rules belong in `notes`, and the operator follows them.
9. **No bypass, one documented opt-out.** No flag, env var, or hidden option weakens the gate *while a scope file is being read*. Violations exit with code 3. The no-scope-file path is not a bypass: it is the documented meaning of an absent scope file (rule 2). `--no-scope` (added 2026-11-17, owner-requested) is also not a bypass - it is an explicit **opt-out of the scope file itself**, behaviourally identical to running with no file (D1). It prints the loud block in docs/02 section 3.1, records `scan_runs.scope_mode = 'unrestricted_flag'`, and never reads or writes `scope.yaml`. It must never be used to scan targets the operator is not authorized for. A future flag whose effect is "ignore an in/out list while still reading that list" would be a real bypass and must be refused in review (AGENTS.md rule 2).

## 3. Pacing (removed)

- Speed control was removed on 2026-11-17 at the owner's request (docs/MASTER_PLAN.md D3): there is no `--speed`, no `--delay`, no pacer and no rate limiter. Tools run at their own natural pace. `scope.yaml` `max_speed` still loads but is ignored.
- Requests are still honest and attributable: the User-Agent is `reconkit/<version>`, and the operator is responsible for respecting the program's rate rules (which is what `scope.yaml` `notes` is for).
- `opt_in` tools (`nikto`, `masscan`, `ffuf`, `gowitness`) all have adapters since adapter waves 5-8 (2026-11-17). At selection time they run only with `--tools <name>`, `--include-noisy`, or a `full` run (which implies `--include-noisy`). `gowitness` lives in the `shots` stage, which is in the `full` mode table only (D19), so `--active` never starts a browser (docs/09 section 4a8).
- `intrusive` tier: selected only by a `full` run (or an explicit `--tools <name>`). There is no `--intrusive` flag. **Exploitation-class tools carry `exploitation: true` in `tools.yaml` (`sqlmap`, `dalfox`, `crlfuzz`) and are skipped in every mode, `full` included**, with `exploitation tool requires explicit --tools`; only naming one runs it. That is how the AGENTS "recon only - no exploitation" boundary is enforced for the automatic path: `full` means "all recon tools", not "all tools". No intrusive tool has an adapter in this build, so even a named one reports `no adapter yet (phase 3)`.
- Our own requests use the honest User-Agent `reconkit/<version>`. No User-Agent or IP rotation.

## 4. Subprocess Safety

- All external programs run through `core/runner.run_exec(argv: list[str], timeout, env, ...)`.
- `shell=False` always. No `os.system`, no `shell=True`, no string-built commands.
- Targets are validated before use: domain regex (RFC-1123 labels), no leading `-` (prevents option injection), no whitespace or shell metacharacters. When passing a target to a tool, use the tool's explicit flag form (example `-d value`) or `--` separator when supported.
- Tool names and binary paths come only from `tools.yaml`. Binary lookup order: `~/.reconkit/bin`, then `PATH`.
- Timeouts on every process; on timeout kill the whole process group.
- Child environment is minimal: pass only variables a tool needs (its API key names from the registry). Adapters must also pass `HOME` explicitly for tools that read config or credentials from it (`subfinder`, `httpx`, `nuclei`); verify each tool's own `--help` output before relying on a variable, never guess.
- Output size limits per tool to avoid memory exhaustion.

## 5. Tool Sources (details in docs/10_TOOL_SOURCES.md)

- The `reconkit` **command** installs nothing (removed 2026-11-17, docs/MASTER_PLAN.md D4): no downloads, no checksum handling, no `sudo`, no package-manager call, no rollback. `install`, `update` and `doctor --fix` do not exist, and `src/reconkit/installer/` stays deleted.
- `tools.yaml` `source:` strings are documentation for the operator. They are never executed, never parsed into a command line, and never fetched by reconkit.
- **The one installer is `scripts/install-tools.sh`, run by a human (D21, 2026-11-18).** It is plain bash in this repository, not a reconkit command: it has no catalogue of its own, reads each binary entry's `source:` from `tools.yaml`, runs `apt-get` under **per-command** `sudo` (or `go install`, which needs none) and installs nothing else. It refuses to run as `root` (Go would target `/root`), never pipes a download into a shell, never curls a release archive or checksum, and prints release-only entries as manual with their upstream URL. It ends by running `reconkit doctor --json` and failing when a tool it was asked to install reports `installed != yes` or `identity != ok`, so a wrong-program binary cannot pass. No `curl | bash` anywhere, in the script or out of it.
- Beyond that script, installation is the operator's own action, outside reconkit's trust boundary. `doctor` only reads what is already on disk (lookup order and the "wrong program" rule: docs/10 sections 3-4).

## 6. Secrets

- Never hard-code credentials. Never commit `.env`, `scope.yaml`, `recon.db`, `workspaces/`.
- Keys come from environment or `.env` (loaded at startup). `.env.example` lists names only.
- `doctor` shows key **names** and set/unset, never values (not even partial).
- Redact secrets in logs, errors, stored `tool_runs.error` and every workspace file (`store.redact()` runs before the write).
- **Console exception text gets the same guarantee as stored text.** `redact()` masks the message the last-resort error handler prints and the `-v` traceback, using the pattern list plus the values from `.env` seeded once at startup by `configure_redaction()` (docs/03 section 5, "Redaction API"). A chained exception (`__cause__`/`__context__`) is formatted into the traceback string before redaction, so a key in a nested exception is masked too; printed text is never held to a weaker standard than what is written to the DB or the workspace.

### 6.1 API Keys: Free Mode by Default

This is the API-key policy. Related details live in `docs/02_CLI_UX.md` (§3 flags) and `docs/09_TOOL_CONTRACTS.md` (§2 `keys` schema); key setup itself is `.env.example` and `SETUP.md`.

1. **Free mode is the default.** Every `core` tool must produce useful results with zero keys. Enhanced mode turns on per tool as soon as that tool's key is set.
2. **Keys come only from `.env`** (loaded at startup). Never from CLI flags, never logged, never in URLs or query strings; `redact()` covers them in errors, logs and `tool_runs.error`.
3. **Only keys that are free to obtain are supported.** A tool whose only key is paid gets no key support at all (it runs free or is skipped).
4. **`doctor` always shows a Keys table** (tool, set/missing, what it adds, sign-up URL). On the scan commands, `--no-keys` forces free mode and ignores `.env` (flag list in `docs/02_CLI_UX.md`). Nothing prompts for keys: the removed `install` prompt was the only one, and since 2026-11-17 the docs tell you to `cp .env.example .env` yourself (`SETUP.md`). `.env` is never overwritten by reconkit.
5. **`tools.yaml` schema:** an optional `keys:` list per tool, each entry `{env, url, adds}`. A tool without keys has no `keys` entry. `keys` is the single source of truth for a tool's key environment variables: there is no separate `needs_key` field, and `registry` rejects an entry that still carries one. Tools that read keys from their own config file (`subfinder` reads `$HOME/.config/subfinder/provider-config.yaml`) still list `keys`; the adapter writes the values from the allowed env names into a temporary provider-config file (mode 0600, deleted in a `finally` block) and never puts the value in argv or a log.

## 7. Environment Variables

- **Optional keys:** `CERTSPOTTER_API_KEY`, `OTX_API_KEY`, `VT_API_KEY`, `URLSCAN_API_KEY`, `PDCP_API_KEY` (Chaos), `GITHUB_TOKEN`. Names that no `tools.yaml` entry lists are not supported.
- **Other:** `MONITOR_WEBHOOK_URL` (Phase 3)
- All optional. Missing key means that source runs without it or is skipped.

## 8. Logging

- Never log: API keys, tokens, passwords, full webhook URLs, cookies.
- This build has no file logger; diagnostics and tool status go to the console (Rich), with `-v`/`-q` controlling detail. Console error text - including a `-v` traceback - passes through `store.redact()` before it is printed. A `workspaces/<target>/meta/reconkit.log` file is deferred; `meta/` currently holds run metadata and summaries only.

## 9. Data Protection

- Results can describe a client's infrastructure: keep the workspace and DB private (permissions `0600` for DB, `0700` for workspace).
- This build has no delete command; remove a target's rows manually until one is documented in docs/02.

## 10. Input Handling

- Validate all target input (domain, list files) before any use.
- Treat all tool and HTTP output as untrusted: parse with strict parsers, never `eval`, escape before writing HTML exports.
- `yaml.safe_load` only.

## 11. Security Checklist

- [ ] Active stages call the scope gate; tests prove refusal
- [ ] No `shell=True` anywhere (`ruff` rule + grep test)
- [ ] Targets validated before reaching subprocess
- [ ] No install/download path exists; `tools.yaml` `source:` stays inert text
- [ ] No secrets in logs, DB, errors or exports
- [ ] No hidden throttling: no pacer, delay or rate-limiter path remains
- [ ] Opt-in and intrusive tiers gated by `MODE_TOOLS`; exploitation-class tools gated by `exploitation: true`
- [ ] `--no-scope` prints its warning and records `scope_mode = unrestricted_flag`
- [ ] HTML export escapes content
- [ ] Dependencies reviewed and pinned in `pyproject.toml`
## Rule 6 addendum (D56, 2026-11-19): excluded CIDRs

`scope.yaml` may list `exclude_cidrs` beside `in_scope_cidrs`. An exclusion wins over an inclusion: the IP predicate is
true only inside an included range **and** outside every excluded range, and a malformed CIDR is a `ConfigError` before
any traffic is sent. Name precedence is unchanged (`out_of_scope` still wins over any wildcard in `in_scope`).

Enforcement is partial by construction, and the run says so: only `pyscan` and the engine's pre-resolved `naabu` input
are handed addresses reconkit verified, while every other active tool resolves hostnames inside its own child and never
shows reconkit the address it connected to. With a non-empty `exclude_cidrs` the engine prints one warning at run start
naming the selected tools it cannot gate, and carries the same text into `report.txt`, `report.json` and `--json`
(`scope_warnings`), so the limitation survives after the terminal output is gone. A flag that refuses to run in that
configuration (`--strict-cidr`) is a future decision, deliberately not built (PROGRESS, Open risks).
