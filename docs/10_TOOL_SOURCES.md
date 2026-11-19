# Tool Reference

This is a reference of the tools reconkit uses. The `reconkit` CLI never installs
any of them: it runs tools that already exist on your system and skips a missing
one. To see which are present, run `reconkit doctor`.

There is one optional, human-run shortcut for Kali/Debian -
`scripts/install-tools.sh`. It is a shell script, not a CLI command, it reads
this same registry, and it covers what the registry can install automatically
(`apt:`, `go install`, `pipx`). Kali packages `findomain` and `rustscan` in its
signed repositories, so both install with `sudo apt-get` like the rest; only
`dnsreaper` has no automatic source, and the script prints its upstream URL
instead of downloading anything. Skip the script entirely if you prefer to
install tools yourself; nothing else in reconkit depends on it. See section 5.

## 1. What this document is

`tools.yaml` is the registry of every tool reconkit may run, and it is the only
list. This document mirrors that registry for a human reader: one row per tool,
its stage, what it does, and where the upstream project lives. The last column
is provenance only - it is copied from the entry's `source:` string, is never
executed, and is not a procedure. Nothing here tells you how to install
anything, because installing is not something reconkit does or asks for.

## 2. The tool table

| Tool | Stage | What it does | Where the project lives |
|---|---|---|---|
| `crtsh` | subs | Certificate Transparency log search for hostnames | in-tree adapter, no external binary |
| `certspotter` | subs | Cert Spotter API search for issued certificates | in-tree adapter, no external binary |
| `otx` | subs | AlienVault OTX passive DNS lookup (optional key) | in-tree adapter, no external binary |
| `hackertarget` | subs | HackerTarget host-search API | in-tree adapter, no external binary |
| `urlscan` | subs | urlscan.io search API (optional key) | in-tree adapter, no external binary |
| `subfinder` | subs | Passive subdomain enumeration over many sources | https://github.com/projectdiscovery/subfinder/releases |
| `assetfinder` | subs | Subdomain finder built on CT and other public sources | github.com/tomnomnom/assetfinder |
| `amass` | subs | OWASP attack-surface and subdomain enumeration (passive by default in v5) | Debian package `amass` |
| `findomain` | subs | Fast subdomain finder across several passive sources | Kali package `findomain` (11.0.0-beta.2; the GitHub release zip is the non-Debian fallback) |
| `chaos` | subs | ProjectDiscovery Chaos dataset lookup (optional key) | https://github.com/projectdiscovery/chaos-client/releases |
| `github_subdomains` | subs | GitHub code search for domains (optional key) | github.com/gwen001/github-subdomains |
| `dnspython` | dns | Resolver used for A/CNAME/NS lookups and NXDOMAIN classification | in-tree adapter, no external binary |
| `dnsx` | dns | Bulk DNS toolkit for A/CNAME resolution | https://github.com/projectdiscovery/dnsx/releases |
| `puredns` | dns | Mass resolver and wildcard filter built on `massdns` | github.com/d3mondev/puredns (v2) |
| `massdns` | dns | High-throughput bulk DNS resolver used by `puredns` | Debian package `massdns` |
| `dig` | dns | BIND query tool used for CNAME/NS hygiene checks | Debian package `dnsutils` (provides `dig`) |
| `pyprobe` | live | HTTP/TLS probe used for the ALIVE classification | in-tree adapter, no external binary |
| `httpx` | live | HTTP probe: status, title, server, redirects | https://github.com/projectdiscovery/httpx/releases (Kali ships `httpx-toolkit`; the Python `httpx` CLI is a different program) |
| `httprobe` | live | Probes a host list for working HTTP/HTTPS servers | github.com/tomnomnom/httprobe |
| `tlsx` | live | TLS handshake data: SANs, CN, expiry, JARM | https://github.com/projectdiscovery/tlsx/releases |
| `smap` | ports | Passive port data from internet-wide scan datasets | github.com/s0md3v/smap |
| `pyscan` | ports | TCP connect scan gated by the scope CIDR predicate | in-tree adapter, no external binary |
| `naabu` | ports | Fast SYN/connect port scanner | https://github.com/projectdiscovery/naabu/releases (needs `libpcap-dev`) |
| `nmap` | ports | Port scan with service and version fingerprints | Debian package `nmap` |
| `rustscan` | ports | Fast port scanner that hands open ports to `nmap` | Kali package `rustscan` (packaged as 2.4.1, self-reports 2.3.0; the release `.deb` is the fallback) |
| `masscan` | ports | Very fast Internet-wide style port scanner (`opt_in`) | Debian package `masscan` |
| `httpx_tech` | tech | Technology and CDN detection; reuses the `httpx` binary with `-td` | https://github.com/projectdiscovery/httpx/releases (same binary as `httpx`) |
| `whatweb` | tech | Web technology and CMS fingerprinting | Debian package `whatweb` |
| `wafw00f` | tech | WAF product fingerprinting | PyPI package `wafw00f` |
| `cdncheck` | tech | CDN and WAF detection from resolved addresses | https://github.com/projectdiscovery/cdncheck/releases |
| `webanalyze` | tech | Wappalyzer-style technology detection; needs `technologies.json` in the working directory | github.com/rverton/webanalyze |
| `gau` | urls | Historical URLs from Wayback, Common Crawl and OTX | github.com/lc/gau (v2) |
| `waybackurls` | urls | Historical URLs from the Wayback Machine | github.com/tomnomnom/waybackurls |
| `katana` | urls | Crawler for endpoints, forms and JS files | https://github.com/projectdiscovery/katana/releases |
| `hakrawler` | urls | Fast web crawler for links and scripts | github.com/hakluke/hakrawler |
| `gospider` | urls | Web spider for links, scripts and sitemaps | github.com/jaeles-project/gospider |
| `subjs` | urls | Finds JavaScript files referenced by a page | github.com/lc/subjs |
| `unfurl` | urls | Parses and filters URLs into their parts | github.com/tomnomnom/unfurl |
| `urlfinder` | urls | Passive URL discovery over several sources | https://github.com/projectdiscovery/urlfinder/releases |
| `nuclei` | vulns | Template-based takeover and exposure checks | https://github.com/projectdiscovery/nuclei/releases |
| `subzy` | vulns | Subdomain takeover detection | github.com/PentestPad/subzy |
| `dnsreaper` | vulns | **Not adapted (D15):** no PyPI package, no console script, needs `git clone` + `python main.py`; `subzy` covers takeover | https://github.com/punk-security/dnsReaper |
| `nikto` | vulns | Web server misconfiguration and exposure scan (`opt_in`) | Debian package `nikto` |
| `ffuf` | vulns | Content and parameter discovery (`opt_in`) | github.com/ffuf/ffuf (v2) |
| `dalfox` | vulns | XSS scanner (`intrusive`) | github.com/hahwul/dalfox (v2) |
| `crlfuzz` | vulns | CRLF injection scanner (`intrusive`) | github.com/dwisiswant0/crlfuzz |
| `sqlmap` | vulns | SQL injection scanner (`intrusive`) | Debian package `sqlmap` |
| `gowitness` | shots | Screenshots of live hosts (`opt_in`) | github.com/sensepost/gowitness |

The `intrusive` tier is not selectable in this build (there is no `--intrusive`
flag), so `dalfox`, `crlfuzz` and `sqlmap` are listed for completeness only.

## 3. How doctor checks a tool

`doctor` reads the registry and, for every entry, decides whether a usable copy
is already on disk. It runs nothing but a tool's own version command and it
writes nothing.

**What doctor shows.** One row per tool with `installed` (`yes`, `missing` or
`wrong program`), the resolved `path`, and `identity` (`ok`, `failed` or `n/a`).
**Version strings are not shown** (owner ruling 2026-11-17,
docs/MASTER_PLAN.md D6): `version_cmd`/`version_regex` are the identity check,
and the string they read decides `installed`/`identity` only - the table and
`doctor --json` carry no version value at all.

**Lookup order.** `~/.reconkit/bin/<binary>` first (the managed copy), then
`PATH`. The directory is `config.bin_dir()` and is the only definition of the
path; `adapters.base.managed_bin_dir()` returns the same value. A copy in
`~/.reconkit/bin` wins over `PATH` on purpose, so a broken managed copy shadows
a working binary and the mitigation is manual - remove or replace that file.

**The version contract.** An entry may carry `version_cmd` (argv; its first
element is the program that reports the version, defaulting to the tool's
binary) and `version_regex`. `core.toolcheck.installed_copy()` resolves the copy
and `installed_version()` runs `version_cmd` as the identity probe, reading
`stdout`, falling back to `stderr`. With a `version_regex`, the pattern is
searched in the whole output and the first capture group is the version (the
whole match when the pattern has none), so `katana`'s ASCII logo and `nuclei`'s
ANSI `[INF]` line are never mistaken for the banner. An uncompilable pattern is a
`ConfigError` when the registry loads, before any command runs. The pattern
describes a property of the tool, which is why it lives in `tools.yaml` next to
`version_cmd`.

**A declared pattern is a requirement.** If `version_regex` is present and
nothing matches, the copy is treated as not installed - `wrong program` when the
file exists, `missing` when it does not (2026-11-17, V-UNEXPECTED item 1: a
probe that runs but does not print the expected banner is a namesake). Only when
the field is absent is the fallback the first non-empty line of the output. A
probe may exit nonzero and still count, but only when its output names the
program: `masscan --version` exits 1 and is accepted, while a nonzero exit with
unrelated text stays `wrong program` (PIT-35). Every probe gets `HOME` in its
child environment, never the parent environment (PIT-30).

**A probe is retried once** (D42/D46, PIT-63). A single failed probe used to mean
`wrong program`, which silently removed a working tool from every scan: `amass`
answered ten probes and failed one (2026-11-19). `probe_with_retry()` in
`adapters/base.py` runs the probe again after 100 ms, and the second answer is the
verdict; a genuinely wrong program still reads `wrong program`, because it fails
both times. `doctor` and the engine's selection check share that one function -
greshing a tool name is not retried, only its identity probe.

**The "wrong program" rule.** A same-named binary that is not the expected
program must never be driven as if it were. Tools with an adapter enforce it in
`BinaryAdapter.check_installed()`, which requires the tool's identity markers
(ProjectDiscovery `httpx`, never the Python `httpx` CLI). A copy that exists but
fails the check is `wrong program` (identity `failed`) and the engine skips the
tool as `not installed`. Tools without an adapter go through the same
`ToolSpec` path in `doctor`.

**Presence-only tools (known limitation).** Ten binary tools carry no
`version_cmd`, because their real `-version` only prints Go `flag` usage, so
there is nothing to run the name through: `crlfuzz`, `dalfox`, `dnsreaper`,
`github_subdomains`, `gowitness`, `hakrawler`, `httprobe`, `sqlmap`,
`waybackurls`, `webanalyze`. For these, a **same-named program that is
not the expected product is counted as installed**, and doctor's `path` column
shows the resolved copy by design - not a missing version and not a defect.
`httpx_tech` is not in this group: it carries `httpx -version` and a pattern, so
the Python `httpx` CLI is `wrong program` there too. Nine of them
(`httprobe`, `webanalyze`, `waybackurls` in wave 2; `hakrawler`, `gospider`,
`subjs`, `urlfinder` in wave 3; `unfurl` in wave 4; `subzy` in wave 5) gained
adapters on 2026-11-17 and prove their identity through their own
`-h`/`-version` markers instead - `unfurl` uses its stderr `Usage:` block,
`subzy` its `version` subcommand, since neither has a version flag at all.
`doctor` asks the adapter when one exists (`doctor.default_status`), so the
identity column is a real check for those nine; `crlfuzz`, `dalfox`,
`dnsreaper`, `github_subdomains`, `gowitness` and `sqlmap` still have no
adapter and stay presence-only. `smap`, `gospider`, `subjs`
and `urlfinder` have real probes; the ProjectDiscovery tools, `wafw00f`,
`findomain`, `puredns`, `dig`, `massdns`, `whatweb`, `nmap`, `masscan`, `gau`,
`ffuf` and `nikto` report a version from their own banner. `gau` gained a
`version_regex` on 2026-11-17 (`gau version: (\d+\.\d+\.\d+)`, from the real
banner `gau version: 2.2.4`), so a namesake that prints anything else is now
`wrong program` instead of `yes` (Ruling C).

**Everything else doctor prints.** Entries with no `binary:` (all HTTP and
Python adapters) are `yes` with `n/a (no binary required)`. Per-stage coverage
counts usable tools (`subs 6/11 ready`). System packages come from
`system_packages` plus every `requires_apt` (`libpcap-dev` for `naabu`);
`dnsutils` is named only in the `dig` entry's `source:` and `ToolSpec` does not
expose it, so it is not checked. The Keys table lists each documented key by
name and whether it is set, never its value. The `Missing tools: N` footer
appears only when something is missing, and `--json` writes one document with
warnings at exit code `0`.

## 4. What the CLI does NOT do

The `reconkit` command never downloads, installs, updates, or removes any tool.
It runs tools that already exist on your system. If a selected tool is not present, the scan
skips it with reason `not installed` and continues. The same rule covers the
rest of the tool lifecycle: there is no download, no archive or checksum
handling, no `sudo`, no package manager, no rollback, no version pin and no
automatic template or database refresh (`nuclei -ut` and `webanalyze -update`
are yours to run). Nothing in this repository names an official download page
as a procedure or asks you to pipe a script into a shell; the `source:` strings
are provenance and are never executed by the CLI.

## 5. `scripts/install-tools.sh` (optional, Kali/Debian)

A bash script for a fresh machine, run by a human, outside the CLI
(docs/MASTER_PLAN.md D21). It has no tool catalogue of its own: it reads every
`kind: binary` entry in `tools.yaml` and follows its `source:` string.

| `source:` shape | what the script runs |
|---|---|
| `apt: <pkg>` | `sudo apt-get install -y <pkg>` |
| `go install <module>@latest` | `GOBIN=~/.reconkit/bin go install <module>@latest` |
| `pipx install <pkg>` | `pipx install <pkg>` |
| anything else | nothing - the entry is printed as manual with its URL |

Rules it keeps:

- **Run it as your normal user, never with `sudo`.** It escalates for `apt-get`
  itself. Run as root, Go would write to `/root/.reconkit/bin`, which no scan
  looks in, so the script refuses with that explanation.
- **It downloads nothing itself.** `apt-get` and `go install` fetch from their
  own official sources; there is no `curl`, no release archive, no checksum
  handling. The nine ProjectDiscovery release-only entries carry a verified
  `(or: go install ...)` hint that the script uses instead, and `findomain` /
  `rustscan` come from Kali's signed repositories rather than their release
  assets (2026-11-18).
- **Verification is `reconkit doctor --json`**, the adapter's own probe
  (installed / path / identity). A binary that exists but is the wrong program
  is `identity: failed` and fails the script. An entry with no automatic source
  is printed as `manual` **only while it is still missing** (today that is just
  `dnsreaper`), and it is never counted as a failure. That flag is now part of the
  registry contract (D36): `tools.yaml` may carry `manual: true` (a non-bool is a
  `ConfigError`), the registry parses it into `ToolSpec.manual`, and `reconkit
  doctor` counts such a tool as **manual**, separately from the tools that need
  attention - `46 installed, 1 manual (dnsreaper), 1 needs attention (amass)`.
- `--dry-run` prints every command, `--check` reports only, `--update` re-runs
  `apt`/`go`/`pipx` for every tool, `--only <pattern>` narrows to one tool.

It is a bash script for Linux; it is not part of `pytest`, and `doctor` remains
the thing that tells you what is present.
