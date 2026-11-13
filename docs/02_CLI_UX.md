# CLI UX (replaces DESIGN_SYSTEM.md)

## 1. Design Direction

- **Style:** Technical, calm, readable. Tables for results, one-line status for progress.
- **Principles:**
  - Safe and polite by default (passive, `--speed slow`).
  - Every result shows where it came from and how much to trust it.
  - Never hide failures: a skipped or failed tool is always reported.
  - Works without color (`--no-color`, or when output is not a terminal).
  - Machine-friendly: `--json` on every command.

## 2. Command Grammar

`reconkit <command> [target] [flags]`. Target is `-d DOMAIN` or `-l FILE` (one domain per line).

### Setup and health
| Command | Purpose | Phase |
|---|---|---|
| `doctor [--fix]` | Tools, versions, system packages, wordlists, API key names, per-stage coverage | 2 |
| `install [TOOL...\|--all] [--dry-run]` | Install missing tools into `~/.reconkit/bin` | 2 |
| `update [TOOL...\|--all] [--dry-run]` | Update tools (and nuclei templates) | 2 |
| `scope check -d DOMAIN` | Show whether a target is allowed by `scope.yaml` | 2 |
| `scope import` | Build `scope.yaml` from a bug bounty program | 3 |

### Stages (single stage per command)
| Command | Mode | Needs `--active` + scope | Phase |
|---|---|---|---|
| `passive` | subs + dns (+ passive ports/CDN info) | no | 2 |
| `subs` / `dns` | single passive stage | no | 2 |
| `live` | ALIVE / DNS_ONLY / SHUT_DOWN / DEAD | yes | 2 |
| `ports` | open ports, services | yes | 2 |
| `tech` | tech, WAF, CDN | yes | 3 |
| `urls` | URLs, params, JS | yes (crawling) | 3 |
| `vulns` | takeover and exposure checks | yes | 3 |

### Workflows
| Command | Pipeline |
|---|---|
| `lite -d X` | passive only (quick) |
| `run -d X --active` | passive, live, ports, then enabled checks; resumable |

`passive` is the stage command: it runs the subs and dns stages (plus passive port/CDN info) for one target. `lite` is the workflow shortcut for exactly that passive pipeline and nothing active; adapters, flags, pacing and exit codes are the same. Only `run` includes active stages.

### State and output
| Command | Purpose |
|---|---|
| `diff -d X` | Only new / changed / gone items since the previous run |
| `status [--json]` | Progress of running or finished scans |
| `db list\|export -d X [--new-only]` | Query stored assets without SQL |
| `export -d X --format json\|md\|html` | Write a report |

## 3. Global Flags

| Flag | Meaning |
|---|---|
| `-d, --domain` / `-l, --list` | Target or file of targets |
| `--active` | Allow active stages (also requires matching `scope.yaml`) |
| `--speed slow\|normal\|fast` | Pacing preset. **Default: `slow`** |
| `--delay MIN-MAX` | Random pause in seconds between tools (example `--delay 5-20`) |
| `--tools a,b` / `--exclude x,y` | Pick or skip adapters |
| `--include-noisy` | Allow `opt_in` tier tools |
| `--min-sources N` | Hide results confirmed by fewer than N tools |
| `--phase-timeout SEC` / `--timeout-<stage> SEC` | Stage time limits |
| `--mock` | Use fixtures instead of real tools/network |
| `--json` | JSON (JSONL for streams) on stdout, no colors or progress |
| `--no-color`, `-v/--verbose`, `-q/--quiet` | Output control |
| `--config PATH`, `--scope PATH`, `--db PATH` | Override file locations |

Not provided (by design): any flag that skips the scope gate.

## 4. Speed Modes

| | `slow` (default) | `normal` | `fast` |
|---|---|---|---|
| Passive tools at once | 1 | up to 3 | all |
| Pause between tools | random 5-30 s passive, 10-60 s active | random 1-5 s passive, 2-10 s active | none |
| Active tools at once | 1 | up to 2 | all |
| Pause between hosts | random 1-5 s | random 0-2 s | none |
| Active request rate | 10/s | 50/s | 300/s |
| Order | hosts and ports shuffled | shuffled | sequential |
| nmap timing | `-T2` | `-T3` | `-T4` |

These numbers mirror `config.yaml`, which is the source of truth: slow `passive.tool_delay` is 5-30 s, slow `active.tool_delay` is 10-60 s and `active.host_delay` is 1-5 s. `--speed fast` on an active stage prints a warning and requires typing `I AM AUTHORIZED`. `scope.yaml` `max_speed` caps the speed. Slow scans can still be detected: the goal is polite and low-noise, not invisible.

## 5. Output

### Result table (example `passive` / `diff`)

```
Subdomain            State      Ports     Sources                           Trust
api.example.com      ALIVE 200  80,443    crtsh, subfinder, otx, dnsx       HIGH (4)
vpn.example.com      DNS_ONLY   443,1194  assetfinder, naabu, nmap          HIGH (3)
old.example.com      SHUT_DOWN  -         crtsh                             LOW (1)
new.example.com      [NEW]      -         certspotter, hackertarget         MEDIUM (2)
```

- A final summary line: counts per state, new items, tools skipped or failed.
- A "Tools" panel lists each adapter: `ok`, `skipped (not installed)`, `failed (reason)`, `timeout`.

### Colors (Rich theme)

| Meaning | Color |
|---|---|
| ALIVE / ok / HIGH | `#22c55e` |
| DNS_ONLY / MEDIUM / warning | `#eab308` |
| SHUT_DOWN | `#f97316` |
| DEAD / error | `#ef4444` |
| NEW / info | `#06b6d4` |
| LOW / UNCONFIRMED / muted | `#9ca3af` |

State words are always printed (never color alone). Symbols are ASCII-safe.

### Progress
One live line per stage: stage name, current tool, `done/total` tools, elapsed, estimated remaining, next planned pause (in slow mode). Disabled with `--json`/`--quiet`.

### Empty, error and success states
- **Empty:** `No results from 3 tools (crtsh, subfinder, otx). Check 'reconkit doctor'.`
- **Error:** one line cause + one line fix, never a raw traceback (traceback with `-v`).
- **Success:** summary line + path of workspace and DB.

## 6. Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Unexpected error |
| 2 | Usage error (bad flags) |
| 3 | Scope violation (target not allowed, scope missing or expired) |
| 4 | No usable tool for the stage |
| 5 | Partial success (some tools failed or timed out) |
| 130 | Interrupted by user (state saved, resumable) |

## 7. Accessibility
- Readable with `--no-color`; no information carried only by color.
- Stable column order and plain-text output when piped.
- `--json` output uses fixed field names (see docs/09_TOOL_CONTRACTS.md).
