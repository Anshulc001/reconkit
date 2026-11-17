# Tool manuals

Official, machine-verified reference for **every** tool in `tools.yaml`, so a
future agent session can learn how a tool actually behaves on this Kali box
without re-reading GitHub.

Verified **2026-11-16** on the canonical checkout `/home/kali/Desktop/reconkit`
(Python 3.14.8). Each entry carries: registry role, official source URL, how it
is (or is not) installed here, the real full `--help`, one real safe test against
`testfire.net` (already in `scope.yaml`), the exit code that test produced, and
every error hit on the way.

Nothing in these files is written from memory: the `--help` blocks and test
blocks are the tools' own captured output.

## Layout

One file per **stage**, not one per tool:

| File | Stage | Tools |
|---|---|---|
| `subs.md` | `subs` (passive discovery) | 11 |
| `dns.md` | `dns` | 5 |
| `live.md` | `live` (active) | 4 |
| `ports.md` | `ports` | 6 |
| `tech.md` | `tech` | 5 |
| `urls.md` | `urls` | 8 |
| `shots.md` | `shots` (opt-in) | 1 |

Seven stage files plus this index. A file-per-tool layout would have meant 40
new files holding one or two screens each; per-stage keeps the count at 8 while
every tool still gets its own `##` section with the same fixed fields, so a
`grep -n '^## `<tool>`' docs/tool_manuals/` finds any tool in one step.

## Authoritative inventory (from `tools.yaml`, 2026-11-16)

`tools.yaml` lists **48 tools**. **11 have a real adapter** in
`src/reconkit/adapters/`; **37 do not** (`no adapter yet (phase N)`). The 8
`vulns`-stage tools are deliberately out of scope for this library (see
"Skipped" below), so **40 tools are documented here**.

| Stage | Total | With adapter | Without adapter |
|---|---|---|---|
| `subs` | 11 | crtsh, certspotter, otx, hackertarget, subfinder, assetfinder (6) | urlscan, amass, findomain, chaos, github_subdomains (5) |
| `dns` | 5 | dnspython (1) | dnsx, puredns, massdns, dig (4) |
| `live` | 4 | pyprobe, httpx (2) | httprobe, tlsx (2) |
| `ports` | 6 | pyscan, naabu (2) | smap, nmap, rustscan, masscan (4) |
| `tech` | 5 | - | httpx_tech, whatweb, wafw00f, cdncheck, webanalyze (5) |
| `urls` | 8 | - | gau, waybackurls, katana, hakrawler, gospider, subjs, unfurl, urlfinder (8) |
| `vulns` | 8 | - | nuclei, subzy, dnsreaper, nikto, ffuf, dalfox, crlfuzz, sqlmap (8) |
| `shots` | 1 | - | gowitness (1) |

Installed on this box (managed directory `~/.reconkit/bin` first, then `PATH`):
**40 of the 40** documented tools have their binary (or are `http`/`python`
kinds with no binary). `rustscan` used to be the one missing binary; the
registry now names 2.3.0 with its real asset name (2026-11-17) and
`reconkit install rustscan` installed it until the command was removed later
that day; install it yourself from the 2.3.0 flat zip (amd64 only; the note in
`docs/tool_manuals/ports.md` explains why the latest release cannot be used).
Six of the installed ones still have no runnable path here without a key, a root
shell or a one-time data file: `chaos` (`PDCP_API_KEY`), `github_subdomains`
(`GITHUB_TOKEN`), `otx` (anonymous 429), `certspotter` (anonymous answers `[]`),
`masscan` (needs root for a real scan; only `--echo` was run), and `webanalyze`
(needs `webanalyze -update` once).

## Skipped: the `vulns` stage (deliberate deferral, not a rejection)

Every tool whose job is active vulnerability detection, exploitation or
takeover checking is **skipped - recon-only scope for now, revisit later**.
No manual, no install, no test in this task:

| Tool | Tier | Why it is out of scope |
|---|---|---|
| `nuclei` | core | runs vulnerability/exposure templates |
| `subzy` | core | subdomain-takeover exploitation check |
| `dnsreaper` | core | DNS takeover checks |
| `nikto` | opt_in | web vulnerability scanner |
| `ffuf` | opt_in | fuzzing for hidden content/parameters |
| `dalfox` | intrusive | XSS payloads |
| `crlfuzz` | intrusive | CRLF-injection payloads |
| `sqlmap` | intrusive | SQL-injection payloads |

`reconkit` stays recon-only for this task; the deferral covers the whole `vulns`
stage because `tools.yaml` itself describes it as "Takeover and exposure/
misconfiguration checks". Expiring this deferral is an owner decision.

## Multi-domain input, per tool (checked against the real `--help`)

Needed by any feature that scans a file of domains. "Native list" means the tool
has its own file-of-domains flag; otherwise it takes one domain per invocation
(or a stdin stream).

| Tool | Native list flag | Source of the claim |
|---|---|---|
| `subfinder` | `-dL, -list` | `subfinder -h` |
| `chaos` | `-dL` | `chaos -h` |
| `findomain` | `-f, --file` | `findomain --help` |
| `dnsx` | `-l, -list` | `dnsx -h` |
| `puredns` | file argument | `puredns --help` |
| `massdns` | file argument / stdin | `massdns -h` |
| `dig` | `-f` (batch mode) | `dig -h` |
| `httpx` / `httpx_tech` | `-l, -list` | `httpx -h` |
| `tlsx` | `-l, -list` | `tlsx -h` |
| `naabu` | `-list, -l` | `naabu -h` |
| `nmap` | `-iL` | `nmap --help` |
| `masscan` | `-iL` | `masscan --help` |
| `smap` | `-iL` (or `-` for stdin) | `smap -h` |
| `cdncheck` | `-i` (list of ip/dns) | `cdncheck -h` |
| `whatweb` | `--input-file`, `-i` | `whatweb --help` |
| `wafw00f` | `-i, --input-file` | `wafw00f -h` |
| `katana` | `-u, -list` | `katana -h` |
| `urlfinder` | `-d, -list` | `urlfinder -h` |
| `gau` | multiple positional args | `gau --help` |
| `waybackurls` | multiple positional args / stdin | `waybackurls -h` |
| `httprobe` | stdin (one host per line) | `httprobe -h` |
| `hakrawler` | stdin | `hakrawler -h` |
| `subjs` | stdin | `subjs -h` |
| `unfurl` | stdin | `unfurl -h` |
| `assetfinder` | **none** - one positional domain | `assetfinder -h` |
| `github_subdomains` | **none** - `-d` takes one domain | `github-subdomains -h` |
| `amass` | not in the top-level `-h` (subcommand flags unverified) | `amass -h` |
| `gospider` | not verified from `-h`; `-S/--site` takes a list | `gospider -h` |
| `webanalyze` | not verified; `-hosts` was not confirmed | `webanalyze -h` |
| `gowitness` | v3 subcommand tree (`scan single`, `scan file`) | `gowitness -h` |
| `pyprobe`, `pyscan`, `dnspython` | n/a - in-process, one host at a time | adapter source |

Nothing in `reconkit` consumes these flags yet: the CLI already loops over the
targets from `-l FILE` and runs one scan per domain, so a per-domain mechanism is
what the engine uses today for every tool.

## Flagged for the owner (no code or registry value was changed)

These are discrepancies found while verifying. Phase 1 is documentation only, so
each one is recorded and left alone.

1. **`rustscan` (closed 2026-11-17).** The placeholder is gone: the registry
   names 2.3.0 with its real asset name. `reconkit install rustscan` installed it
   until the install command was removed later that day; it is yours to install
   now. The latest release (2.4.1) ships a nested `.tar.gz.zip`, so 2.4.1 needs
   a manual unpack; see the rustscan entry in `docs/tool_manuals/ports.md` and
   `docs/10_TOOL_SOURCES.md` section 2.
2. **Seven tools' version column shows ASCII art (closed 2026-11-17).**
   `chaos`, `dnsx`, `httpx`, `tlsx`, `naabu`, `cdncheck` and `wafw00f` now carry
   a `version_regex` derived from their real banners, so `doctor` prints `0.5.2`,
   `1.3.1`, `v1.12.0`, `v1.4.0`, `2.7.0`, `v1.4.0` and `v2.4.2`. The PD six print
   the version to stderr, which `installed_version()` already reads; `wafw00f`
   writes to stdout with an ANSI-wrapped value. See `docs/10` section 3, "The
   version contract".
3. **Tools with no version flag report their *path* as the version (closed
   2026-11-17).** `smap`, `gospider`, `subjs` and `urlfinder` now have a real
   probe and show `1.0.0-beta`, `v1.1.6`, `1.0.1` and `v0.0.3`. The other five
   (`github_subdomains`, `webanalyze`, `unfurl`, `waybackurls`, `httprobe`)
   genuinely print only Go `flag` usage - `-version` answers `flag provided but
   not defined` - so they keep the path in the Version column **by design**;
   `httprobe`'s `-h` version command was removed because `Usage of httprobe:`
   is worse than the documented path. See `docs/10` section 3, "Presence-only
   tools". Cosmetic, but
   it makes the column untrustworthy for those rows.
4. **`assetfinder -h` exits 0, not 2.** `docs/09` section 9 says the Go flag
   package makes it exit 2; on this box (2026-11-16) it printed `Usage of
   .../assetfinder:` to stderr and exited **0**.
5. **`amass` is v5.1.3, a different CLI tree from the v4 the registry note
   describes** (`assoc|engine|enum|subs|track|viz`). `-passive` still exists
   under `amass enum`, and `amass -version` works, but an adapter written from
   the note alone must be checked against `amass enum -h` first.
6. **`webanalyze` fails on a fresh box** until `webanalyze -update` writes
   `technologies.json`; the first run exits 1 (closed 2026-11-17: `tools.yaml`
   and docs/09 now record the step, the file is ~2.1 MB, and it lands in the
   current working directory, so it is once per directory or `-apps`).

Two smaller observations, recorded but not flagged as defects: `run_exec`
redacts the child's own environment values from its output, so a `-h` probe that
prints its path shows `Usage of ***/.reconkit/bin/...` (HOME was a value passed
to the child); and `reconkit doctor` reports `urlscan` as an `http` tool with no
binary while a Python package named `urlscan` happens to be on `PATH` - the
`doctor` row correctly ignores it.

## Keeping this current

When a tool is added, replaced or upgraded:

1. update its stage file with the real new `--help` and one fresh test;
2. keep the header date honest - a stale date is the signal;
3. if the upgrade changes a flag an adapter relies on, that is a `docs/09`
   change in the same commit, not a manual-only edit.
