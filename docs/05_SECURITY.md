# Security Guidelines

## 1. Purpose and Legal Notice

reconkit is for **authorized security testing only**: targets you own, or have explicit written permission to test (for example an in-scope bug bounty program or a signed engagement). Unauthorized scanning can be illegal. The authors accept no liability for misuse.

`scope.yaml` is a **safety guard against accidents**. It does not grant permission. The user is responsible for authorization.

## 2. Scope Gate

Implemented in `core/scope.py`. Rules:

1. **Passive stages** (`subs`, `dns`, passive parts): no scope file required, because no traffic goes to the target. If `scope.yaml` exists, targets outside it print a warning.
2. **Active stages** require ALL of: `--active` flag, `scope.yaml` present, `authorization` field non-empty, not past `expires`, `allow_active: true`, target matches `in_scope`, and not in `out_of_scope`.
3. `out_of_scope` always wins over `in_scope`.
4. Matching: exact host, `*.domain` wildcard (any depth), `re:` regex entries. Hosts are lowercased, trailing dot stripped.
5. **Every host is re-checked** right before it is probed (not only the root target). Out-of-scope hosts are dropped and counted in the summary.
6. **IPs:** probe an IP only if it is inside `in_scope_cidrs`. If no CIDRs are defined, scan hostnames only and skip resolved IPs.
7. **Port-scan pre-check:** port scans require a stored `live` result for the host. If no live result is stored, skip that host and print a warning (`run live first`); do not resolve and scan it directly. If the stored host status has `waf` set (the CDN/WAF marker the `httpx` live adapter parses from its JSON output, column `host_status_history.waf`), skip it as CDN/WAF-fronted. Phase 2 has no `cdncheck`; Phase 3 may add `cdncheck`/`wafw00f`.
8. `max_speed` in `scope.yaml` caps `--speed`.
9. **No bypass.** No flag, env var, or hidden option may disable the gate. Violations exit with code 3.

## 3. Pacing as a Safety Control

- Default `--speed slow`. All network activity goes through the Pacer.
- `--speed fast` on active stages requires typing `I AM AUTHORIZED`.
- `opt_in` tools (nikto, masscan, ffuf, gowitness) run only with `--tools <name>` or `--include-noisy`. Their rates are hard-capped from config (`masscan_max_rate`, `nmap_timing`).
- `intrusive` tier (Phase 3): requires `--intrusive`, `allow_intrusive: true` in scope, and a typed confirmation. Disabled until built.
- Our own requests use the honest User-Agent `reconkit/<version>`. No User-Agent or IP rotation.

## 4. Subprocess Safety

- All external programs run through `core/runner.run_exec(argv: list[str], timeout, env, ...)`.
- `shell=False` always. No `os.system`, no `shell=True`, no string-built commands.
- Targets are validated before use: domain regex (RFC-1123 labels), no leading `-` (prevents option injection), no whitespace or shell metacharacters. When passing a target to a tool, use the tool's explicit flag form (example `-d value`) or `--` separator when supported.
- Tool names and binary paths come only from `tools.yaml`. Binary lookup order: `~/.reconkit/bin`, then `PATH`.
- Timeouts on every process; on timeout kill the whole process group.
- Child environment is minimal: pass only variables a tool needs (its API key names from the registry). Adapters must also pass `HOME` explicitly for tools that read config or credentials from it (`subfinder`, `httpx`, `nuclei`); verify each tool's own `--help` output before relying on a variable, never guess.
- Output size limits per tool to avoid memory exhaustion.

## 5. Installer Safety (details in docs/10_TOOL_INSTALLER.md)

- Sources only from `tools.yaml`; GitHub releases over HTTPS; checksum verification when published; fail closed.
- No `curl | bash`. No running downloaded scripts.
- sudo only for `apt`, shown to the user with a confirmation prompt. Never run the whole program as root.

## 6. Secrets

- Never hard-code credentials. Never commit `.env`, `scope.yaml`, `recon.db`, `workspaces/`.
- Keys come from environment or `.env` (loaded at startup). `.env.example` lists names only.
- `doctor` shows key **names** and set/unset, never values (not even partial).
- Redact secrets in logs, errors and stored `tool_runs.error`.

## 7. Environment Variables

- **Optional keys:** `CERTSPOTTER_API_KEY`, `OTX_API_KEY`, `URLSCAN_API_KEY`, `CHAOS_API_KEY`, `GITHUB_TOKEN`, `VIRUSTOTAL_API_KEY`, `SECURITYTRAILS_API_KEY`, `SHODAN_API_KEY`
- **Other:** `MONITOR_WEBHOOK_URL` (Phase 3)
- All optional. Missing key means that source runs without it or is skipped.

## 8. Logging

- Never log: API keys, tokens, passwords, full webhook URLs, cookies.
- Log: command start/finish, tool status, scope decisions, errors, installer actions.
- Logs go to `workspaces/<target>/meta/reconkit.log` and the console (Rich). Log level from `-v/-q`.

## 9. Data Protection

- Results can describe a client's infrastructure: keep the workspace and DB private (permissions `0600` for DB, `0700` for workspace).
- `db delete -d X` removes stored data for a target.

## 10. Input Handling

- Validate all target input (domain, list files) before any use.
- Treat all tool and HTTP output as untrusted: parse with strict parsers, never `eval`, escape before writing HTML exports.
- `yaml.safe_load` only.

## 11. Security Checklist

- [ ] Active stages call the scope gate; tests prove refusal
- [ ] No `shell=True` anywhere (`ruff` rule + grep test)
- [ ] Targets validated before reaching subprocess
- [ ] Installer uses registry sources and verifies checksums
- [ ] No secrets in logs, DB, errors or exports
- [ ] Pacer used for all network activity
- [ ] Opt-in and intrusive tiers gated
- [ ] HTML export escapes content
- [ ] Dependencies reviewed and pinned in `pyproject.toml`
