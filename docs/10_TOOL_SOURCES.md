# Tool Sources

reconkit **does not install tools**. `install`, `update` and `doctor --fix` were
removed on 2026-11-17 at the owner's request (docs/MASTER_PLAN.md D4): no
downloads, no `sudo`, no rollback, no version pins. This document tells you
where each binary comes from, how reconkit finds it, and how `doctor` decides it
is usable.

`tools.yaml` is still the registry. Each binary tool carries a `source:` string,
which is a human-readable hint and is **never executed**. `doctor` prints the
count of missing tools and points here; installing them is your package manager,
`go install`, or a release download.

## 1. Per-tool sources

| Tool | Stage | Binary | Source (`tools.yaml` `source:`) |
|---|---|---|---|
| `subfinder` | subs | `subfinder` | https://github.com/projectdiscovery/subfinder/releases (or: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest) |
| `assetfinder` | subs | `assetfinder` | go install github.com/tomnomnom/assetfinder@latest |
| `amass` | subs | `amass` | apt: amass |
| `findomain` | subs | `findomain` | https://github.com/Findomain/Findomain/releases (findomain-linux.zip; no checksums are published) |
| `chaos` | subs | `chaos` | https://github.com/projectdiscovery/chaos-client/releases (the archive member is chaos-client) |
| `github_subdomains` | subs | `github-subdomains` | go install github.com/gwen001/github-subdomains@latest |
| `dnsx` | dns | `dnsx` | https://github.com/projectdiscovery/dnsx/releases |
| `puredns` | dns | `puredns` | go install github.com/d3mondev/puredns/v2@latest (also needs massdns) |
| `massdns` | dns | `massdns` | apt: massdns |
| `dig` | dns | `dig` | apt: dnsutils (provides dig) |
| `httpx` | live | `httpx` | https://github.com/projectdiscovery/httpx/releases (Kali's apt package is httpx-toolkit; the python 'httpx' CLI is a different program) |
| `httprobe` | live | `httprobe` | go install github.com/tomnomnom/httprobe@latest |
| `tlsx` | live | `tlsx` | https://github.com/projectdiscovery/tlsx/releases |
| `smap` | ports | `smap` | go install github.com/s0md3v/smap/cmd/smap@latest |
| `naabu` | ports | `naabu` | https://github.com/projectdiscovery/naabu/releases (needs libpcap-dev; use connect scan -scan-type c when not root) |
| `nmap` | ports | `nmap` | apt: nmap |
| `rustscan` | ports | `rustscan` | https://github.com/bee-san/RustScan/releases (2.3.0 is the newest flat zip; 2.4.1 ships a nested .tar.gz.zip) |
| `masscan` | ports | `masscan` | apt: masscan |
| `httpx_tech` | tech | `httpx` | https://github.com/projectdiscovery/httpx/releases (same binary as httpx; this row reuses it with -td) |
| `whatweb` | tech | `whatweb` | apt: whatweb |
| `wafw00f` | tech | `wafw00f` | pipx install wafw00f |
| `cdncheck` | tech | `cdncheck` | https://github.com/projectdiscovery/cdncheck/releases |
| `webanalyze` | tech | `webanalyze` | go install github.com/rverton/webanalyze/cmd/webanalyze@latest |
| `gau` | urls | `gau` | go install github.com/lc/gau/v2/cmd/gau@latest |
| `waybackurls` | urls | `waybackurls` | go install github.com/tomnomnom/waybackurls@latest |
| `katana` | urls | `katana` | https://github.com/projectdiscovery/katana/releases |
| `hakrawler` | urls | `hakrawler` | go install github.com/hakluke/hakrawler@latest |
| `gospider` | urls | `gospider` | go install github.com/jaeles-project/gospider@latest |
| `subjs` | urls | `subjs` | go install github.com/lc/subjs@latest |
| `unfurl` | urls | `unfurl` | go install github.com/tomnomnom/unfurl@latest |
| `urlfinder` | urls | `urlfinder` | https://github.com/projectdiscovery/urlfinder/releases |
| `nuclei` | vulns | `nuclei` | https://github.com/projectdiscovery/nuclei/releases |
| `subzy` | vulns | `subzy` | go install github.com/PentestPad/subzy@latest |
| `dnsreaper` | vulns | `dnsreaper` | https://github.com/punk-security/dnsReaper (install by hand: no setup.py/pyproject.toml and no PyPI package) |
| `nikto` | vulns | `nikto` | apt: nikto |
| `ffuf` | vulns | `ffuf` | go install github.com/ffuf/ffuf/v2@latest |
| `gowitness` | shots | `gowitness` | go install github.com/sensepost/gowitness@latest |
| `dalfox` | vulns | `dalfox` | go install github.com/hahwul/dalfox/v2@latest |
| `crlfuzz` | vulns | `crlfuzz` | go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest |
| `sqlmap` | vulns | `sqlmap` | apt: sqlmap |

Eight entries need nothing installed, because they are adapters inside
reconkit: `crtsh`, `certspotter`, `otx`, `hackertarget`, `urlscan` (HTTP) and
`dnspython`, `pyprobe`, `pyscan` (Python). They have no `source:` and doctor
shows them as ready with `n/a (no binary required)`.

A Go install must land somewhere on `PATH` or in `~/.reconkit/bin`; `go install`
uses `~/go/bin` by default. `webanalyze` additionally needs
`webanalyze -update` once per working directory (it writes `technologies.json`
into the current directory; a scan without it exits 1).

`nuclei` templates are refreshed with `nuclei -ut`; reconkit no longer runs that
for you.

**Version pins are accepted and ignored.** `config.yaml` `tool_versions` still
loads (the schema keeps the key so an existing config is not a breaking change)
but nothing reads it: there is no installer left to pin. `doctor` prints one
warning when the block is non-empty. Remove it or leave it, either is fine.

## 2. Lookup order at run time

1. `~/.reconkit/bin/<binary>` - the managed copy, checked first.
2. `PATH`.

The directory is `config.bin_dir()` and is the only definition of the path;
`adapters.base.managed_bin_dir()` returns the same value.

**The "wrong program" rule.** A same-named binary that is not the expected
program must never be driven as if it were. Two layers enforce it:

- Tools with an adapter: `BinaryAdapter.check_installed()` runs the tool's
  version command and requires its identity markers (for example ProjectDiscovery
  `httpx`, never the Python `httpx` CLI). A copy that exists but fails the check
  is reported by `doctor` as `wrong program` (identity `failed`) and the engine
  skips the tool as `not installed`, so a namesake cannot be run by accident.
- Tools without an adapter: `doctor` runs `version_cmd` (the program named by
  its first element, defaulting to the tool binary, plus the remaining
  arguments) against the resolved copy. A copy that exists but whose probe
  fails is `wrong program`, never `installed`.

The managed copy wins over `PATH` on purpose: a broken copy in
`~/.reconkit/bin` shadows a working binary on `PATH` (mitigation is manual -
remove or replace the managed file).

## 3. How doctor computes installed / version / path / identity

`doctor` implements docs/01 Feature 1 and docs/08 Flow 1, and changes nothing:

- tool table: installed, version, resolved path, identity verified, tier
  (rendering rules in docs/02 section 5);
- per-stage coverage (`subs 6/11 ready`);
- system packages (`system_packages` plus every tool's `requires_apt`, for
  example `libpcap-dev`; `dnsutils` lives in the `dig` entry's `source:` string,
  which `ToolSpec` does not expose), Python version, `scope.yaml` presence, DB
  writability and `config.yaml` presence;
- the Keys table (tool, set/missing, what it adds, sign-up URL), names only,
  never values;
- `Missing tools: N. Install them yourself (apt, go install, or release
  download) — per-tool sources in docs/10_TOOL_SOURCES.md. Re-run doctor to
  confirm.` when anything is missing;
- `--json` writes one document; warnings keep exit code `0`. Python < 3.11 or an
  unreadable `config.yaml` exits `1`.

A tool's `installed` state comes from its adapter when it has one. Every other
tool - the 36 without an adapter included - goes through the same `ToolSpec`
path: `core.toolcheck.installed_copy()` resolves the managed copy first, then
`PATH`, and `installed_version()` runs `version_cmd` as the identity probe. A
tool with no `binary:` (every HTTP and Python adapter) is `yes` with
`n/a (no binary required)`. A binary tool with no `version_cmd` reports the
resolved path in the Version column by design (see below).

**`version_regex` is how a banner-first tool reports its version.**
`installed_version()` searches the whole `version_cmd` output with the tool's
`version_regex` and returns the first capture group (or the whole match when the  pattern has no group), so `katana`'s ASCII logo and `nuclei`'s ANSI-coloured
`[INF]` line no longer become the version column. When the field is absent, the
fallback is unchanged: the first non-empty line of the output. When the field is
present and **nothing matches, the copy is treated as not installed** (`wrong
program` when it exists, `missing` when it does not) - since 2026-11-17 a
declared pattern is a requirement, not a formatting hint, because a probe that
runs but does not print the expected banner is a namesake (V-UNEXPECTED item 1:
`httpx_tech` must not accept the Python `httpx` CLI). A pattern that does not
compile is a `ConfigError` when the registry loads, before any command runs. The pattern describes a property of the
tool, which is why it lives in `tools.yaml` next to `version_cmd`; the `katana`
and `nuclei` patterns were taken from their real banners on Kali (12j).

**The 2026-11-17 patterns (chaos, dnsx, httpx, tlsx, naabu, cdncheck, wafw00f).**
The six ProjectDiscovery tools print their banner and `[INF] Current Version:
<v>` line **to stderr** (stdout is empty); `installed_version()` already uses
`stdout or stderr`, so no capture change was needed and the regex is searched
over that text. Their shared pattern is `Current [Vv]ersion:
(v?\d+\.\d+\.\d+)` (`Version` for chaos/dnsx/httpx/naabu, `version` for
tlsx/cdncheck). `wafw00f --version` writes to stdout and wraps the value in ANSI
(`... you have is \x1b[1;94mv2.4.2\x1b[0m`), so its pattern is `WAFW00F you have
is[^\n]*?(v?\d+\.\d+\.\d+)`. All seven were derived from the real binaries on
this box, not from documentation.

**Presence-only tools.** A binary tool with no `version_cmd` is considered
installed when its binary name resolves, because there is nothing to run the
name through. This is a known limitation: a **same-named program that is not the
expected product is counted as installed** for those tools. Twelve are in this
group: `crlfuzz`, `dalfox`, `dnsreaper`, `github_subdomains`, `gowitness`,
`hakrawler`, `httprobe`, `sqlmap`, `subzy`, `unfurl`, `waybackurls`,
`webanalyze` (their real `-version` only prints Go flag usage, see below).
`httpx_tech` **is not one of them**: since 2026-11-17 it carries its own
`version_cmd` (`httpx -version`) and a `version_regex`, so a probe that does not
print ProjectDiscovery's `Current Version:` banner - the Python `httpx` CLI, for
example - is treated as not installed instead of taking the file's existence as
proof.

**Tools with no version output at all (2026-11-17).** `github_subdomains`,
`webanalyze`, `waybackurls`, `unfurl` and `httprobe` print only Go `flag` usage:
`github-subdomains -version` -> `flag provided but not defined: -version` plus
`Usage of github-subdomains:` (exit 2), and the same shape for the others. They
therefore carry no `version_cmd`, so `installed_version()` returns the resolved
path and doctor's Version column shows that path **by design** - it is not a
missing version and not a defect. The four with a real probe are `smap` (`-h`,
stdout, first line `Smap 1.0.0-beta`), `gospider` (`--version`, stdout,
`Version: v1.1.6`), `subjs` (`-version`, stdout, `subjs version: 1.0.1`) and
`urlfinder` (`-version`, **stderr**, `[INF] Current Version: v0.0.3`); each
carries the matching `version_cmd` and `version_regex`.

A version probe may exit nonzero and still count, but only when its output names
the program: `masscan --version` exits 1 and is accepted, while a nonzero exit
with unrelated text stays `wrong program` (PIT-35). Every probe gets `HOME` in
its child environment, never the parent environment (PIT-30).

## 4. What reconkit will not do

- **No downloads.** Nothing fetches a release, an archive or a checksum on your
  behalf. `pip install reconkit` and the scan itself are the only network
  actions reconkit owns (plus the adapters' own API calls).
- **No sudo, no package manager.** `apt`, `pipx` and `go install` are yours.
  reconkit never runs `sudo`, never prompts for a password, and never installs a
  system package.
- **No rollback, no `--dry-run`, no idempotency logic.** There is no managed
  install to roll back and no `.prev` copy; replacing a tool is your call.
- **No version pinning.** `tool_versions` is accepted and ignored (section 1).
- **No automatic template or database refresh.** `nuclei -ut`,
  `webanalyze -update` and tool self-updates are manual.
- **No `curl | bash`.** This document names official release pages and package
  names; it never asks you to pipe a script into a shell.
- The only thing reconkit checks is what is already on disk (section 3), and a
  scan skips a tool that is missing: `not installed` is a normal skip, not a
  failure.

## 5. System packages

`system_packages` in `tools.yaml` is the authoritative list (python3,
python3-venv, python3-pip, git, golang-go, libpcap-dev, jq, curl). `doctor`
reports each as `installed`, `missing` or `unknown` (unknown off Debian-family
Linux, where `/var/lib/dpkg/status` does not exist). Tools that declare
`requires_apt` (only `naabu` -> `libpcap-dev`) add their package to the same
list. The `dig` entry needs `dnsutils`; it is named in its `source:` string and
is not checked by `doctor`.

Python 3.11 or newer is required, from the interpreter that runs reconkit; never
a pinned apt Python. Go tools installed with `go install` land in `~/go/bin`
unless `GOBIN` says otherwise; either put that directory on `PATH` or copy the
binary into `~/.reconkit/bin` (section 2). `scripts/bootstrap.sh` prepends
`~/.reconkit/bin` to the venv `activate` script and to `PATH`.

## 6. `.env` setup (API keys)

Keys are optional; free mode needs none. All keys come from `.env` in the
checkout (or the process environment for the engine's own load; the CLI reads
`.env` only), never from `config.yaml` and never from a command line.

```bash
cp .env.example .env
chmod 600 .env        # optional, recommended
```

Then fill in the keys you have. `doctor` shows each documented key by name and
whether it is set, never its value. The sign-up URLs and what each key adds are
in docs/05 section 6.1, and the per-tool key rows are in `tools.yaml` `keys:`.

## 7. Tests

- Registry parsing: `tools.yaml` loads into `ToolSpec` objects, including
  `binary`, `version_cmd`, `version_regex` and `source`.
- Every binary tool has a non-empty `source:` string; no HTTP/Python-only entry
  has one (tests/test_tools_registry.py).
- Version-pattern tests pin the real banners captured on 2026-11-17.
- A malformed `version_regex` is a `ConfigError` at load time.
- `doctor` is exercised with injected statuses; no test touches the network or
  requires a tool to be installed.
