# Tool Contracts (adapted from API.md)

This is the most-read file for agents. It defines the adapter interface, normalized schemas, the stage registry, and the consensus rules.

## 1. Conventions

- Tools are listed only in `tools.yaml`. Each has a `stage`, `kind` (`http` | `python` | `binary`), `tier` (`core` | `opt_in` | `intrusive`), `mode` (`passive` | `active`).
- A tool may list `keys`: a list of `{env, url, adds}` entries (`env` name, https sign-up URL, what the key adds). `keys` is the only per-tool key list; there is no `needs_key` field, and the loader rejects one. Free mode needs no keys (policy in `docs/05_SECURITY.md` §6.1). `registry.ToolSpec.keys` exposes them; `env` must match `^[A-Z][A-Z0-9_]*$`, `url` must be https, and a malformed entry raises `ConfigError`.
- `registry.load_tools()` returns `dict[str, ToolSpec]` and `registry.load_system_packages()` returns the top-level `system_packages` tuple. `ToolSpec` is a frozen dataclass with `name`, `stage`, `kind`, `tier`, `mode`, `phase`, `rate_flag: str | None = None`, `keys: tuple[ToolKey, ...] = ()` and `requires_apt: tuple[str, ...] = ()`. `requires_apt` is the per-tool apt dependency list (for example `naabu` needs `libpcap-dev`); the installer adds it to the packages it installs. Other entry fields (`install`, `version_cmd`, `binary`, `requires`, `notes`) are not part of `ToolSpec`.
- An adapter is one class in `src/reconkit/adapters/<tool>.py`.
- Adapters never touch the DB, scope gate, or UI. They return data.
- Targets are validated before reaching an adapter (see docs/05_SECURITY.md).
- Never guess a tool's flags: verify with the tool's `--help` and put a sanitized sample output in `tests/fixtures/<tool>/`.

## 2. Enums and Schemas (Pydantic v2)

```python
from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from reconkit.core.pacing import Pacer, RateLimiter


class Stage(str, Enum):  SUBS="subs"; DNS="dns"; LIVE="live"; PORTS="ports"; TECH="tech"; URLS="urls"; VULNS="vulns"; SHOTS="shots"
class Tier(str, Enum):   CORE="core"; OPT_IN="opt_in"; INTRUSIVE="intrusive"
class Mode(str, Enum):   PASSIVE="passive"; ACTIVE="active"
class HostState(str, Enum): ALIVE="ALIVE"; DNS_ONLY="DNS_ONLY"; SHUT_DOWN="SHUT_DOWN"; DEAD="DEAD"; UNKNOWN="UNKNOWN"
class Confidence(str, Enum): HIGH="HIGH"; MEDIUM="MEDIUM"; LOW="LOW"; UNCONFIRMED="UNCONFIRMED"
class ToolStatus(str, Enum): OK="ok"; SKIPPED="skipped"; FAILED="failed"; TIMEOUT="timeout"

class SubdomainRecord(BaseModel):
    fqdn: str                      # lowercase, no trailing dot
    source: str                    # adapter name
    ips: list[str] = []
    cnames: list[str] = []

class HostStatusRecord(BaseModel):
    fqdn: str
    source: str
    state: HostState
    status_code: int | None = None
    title: str | None = None
    location: str | None = None    # raw Location header (redirects are never followed)
    ips: list[str] = []
    tech: list[str] = []
    waf: str | None = None

class PortRecord(BaseModel):
    fqdn: str
    ip: str
    port: int                      # 1..65535
    protocol: Literal["tcp","udp"] = "tcp"
    state: Literal["open","closed"]
    service: str | None = None
    version: str | None = None
    source: str

class UrlRecord(BaseModel):         # Phase 3
    url: str
    source: str

class FindingRecord(BaseModel):     # Phase 3
    fqdn: str
    kind: str
    severity: Literal["info","low","medium","high","critical"]
    title: str
    evidence: str | None = None
    template_id: str | None = None
    source: str

# The union every adapter returns. Import it from reconkit.models; do not
# redefine the record types in adapters.
Record = SubdomainRecord | HostStatusRecord | PortRecord | UrlRecord | FindingRecord

class ToolResult(BaseModel):
    tool: str
    status: ToolStatus
    records: list[Record] = []
    duration_s: float = 0.0
    error: str | None = None        # short, redacted
    raw_path: str | None = None     # raw output file in workspace

class InstallStatus(BaseModel):
    installed: bool
    version: str | None = None      # from the tool's version command (None if unknown)
    path: Path | None = None        # resolved binary path (None for http/python adapters)

class RunContext(BaseModel):
    """Everything an adapter may read for one run. Built by the engine."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    target: str                     # validated root domain
    hosts: list[str] = []           # already scope-checked
    ports: list[int] = []           # port-scan input; empty = adapter default list
    speed: Literal["slow", "normal", "fast"] = "slow"
    pacer: Pacer                    # reconkit.core.pacing.Pacer (import under TYPE_CHECKING)
    limiter: RateLimiter            # shared per stage; HTTP adapters await limiter.wait()
    timeout: float                  # per-tool timeout in seconds
    workspace: Path                 # workspaces/<target>
    mock: bool = False              # load tests/fixtures/<tool>/ instead of running
    env: dict[str, str] = {}        # allowed API-key variables only
```

## 3. Adapter Interface

```python
class BaseToolAdapter(ABC):
    name: ClassVar[str]             # must match the key in tools.yaml
    stage: ClassVar[Stage]
    # tier, mode, kind come from tools.yaml (single source of truth)

    def check_installed(self) -> InstallStatus: ...     # found? version? path
    def build_command(self, ctx: RunContext) -> list[str]: ...   # binary adapters only; argv list, no shell
    async def run(self, ctx: RunContext) -> ToolResult: ...      # default: runner.run_exec(build_command) + parse
    def parse_output(self, raw: str) -> list[Record]: ...        # pure function, fully unit-testable
```

- `RunContext` (above) carries: `target`, `hosts` (already scope-checked), `speed`, `pacer`, `timeout`, `workspace`, `mock` flag, `env` (allowed keys only) and `ip_allowed` (the loaded scope's `in_scope_cidrs` predicate, or `None`). `ip_allowed` exists so an adapter can apply docs/05 rule 6 without importing `core.scope`; `None` means no permission, never allow-all. `env` is the entire child environment: the runner passes only these keys, so adapters must add `HOME` explicitly for tools that read config or provider keys from it (confirm per tool from its own `--help`, do not guess).
- `check_installed()` returns `InstallStatus` (above). For binaries, `installed=False` with a non-null `path` means the program was found but failed its identity check (the `httpx` namesake case), while `installed=False` with `path=None` means it was not found at all. `doctor` reports the first as `wrong program` (a warning that names the path) and the second as `missing`; both count as not ready in per-stage coverage.
- Adapter failures use the exceptions in `reconkit/errors.py` defined by `docs/06_CODE_STYLE.md` §6 (`ScopeError`, `ToolNotInstalled`, `ToolFailed`, `ToolTimeout`, `ParseError`, `ConfigError`, `InstallError`); no other exception names. They are converted into `ToolResult(status=...)`, never raised out of a stage.
- Binary adapters usually implement only `build_command` and `parse_output`; the base `run` handles execution, timeout, output saving and error mapping. They subclass `BinaryAdapter` from `adapters/base.py`, which resolves the binary in `~/.reconkit/bin` first and then `PATH`, and whose `check_installed()` runs the adapter's `version_args` and matches the tool's own banner/version text, so the ProjectDiscovery `httpx` is never confused with the Python `httpx` CLI on `PATH`. Identity markers must **all** appear in the probe output by default (`identity_require_all = True`); the single exception is `subfinder`, which sets `identity_require_all = False` because subfinder < v2.6.4 prints only `[INF] Current Version: vX.Y.Z` and never names the tool (upstream commit `c175790`, 2023-10-30), and rejecting a working old install is worse than accepting one marker match for a binary that is already identified by filename. A binary that is absent at selection time is `skipped (not installed)` and never reaches here; a binary that was present at selection but cannot be spawned at run time, a non-zero exit and a timeout are three different `failed`/`timeout` results with different messages; no exception escapes. `build_command` must launch the resolved path from `binary_path()` (managed directory first, then `PATH`) rather than the bare binary name, because the child receives only the env keys that were passed in and therefore has no `PATH` of its own to search.
- `subfinder` reads provider keys only from its own config file. Its adapter maps the env names in its `keys` entry (`certspotter`, `chaos`, `github`, `virustotal`) to a temporary `provider-config.yaml` with mode 0600, passes it with `-pc`, and deletes it in a `finally` block after success, timeout or exception. Key values never appear in argv, logs or `ToolResult`; deleting the file is best-effort on Windows because `chmod` is weak there.
- `httpx` is ProjectDiscovery's binary. Its adapter passes repeated `-u` targets, `-json`, and the probes `-sc -title -location -td -cdn`; `parse_output` reads the JSONL `input`/`url` host, `status_code`, `title`, `location`, `tech` and `cdn_name` into `HostStatusRecord`. `naabu` runs `-scan-type c` (connect scan, no root), repeated `-host`, `-p` for the supplied ports, and `-json`; `parse_output` reads `ip`, `port` and optional `host` into `PortRecord`. `assetfinder` runs `--subs-only <domain>` and prints plain lines.
- HTTP adapters subclass `HttpAdapter` from `adapters/base.py`. Its `run` awaits `ctx.limiter.wait()`, uses an `httpx.AsyncClient` with an explicit timeout and the honest User-Agent, retries a connection error once with an injected sleep, and maps HTTP 429, 5xx and timeouts to a failed `ToolResult` (never an exception).
- HTTP bodies are read as a stream and capped at `MAX_BODY_BYTES` (10 MiB); exceeding the cap is a failed `ToolResult` (`response too large`), never an exception.
- Per-host adapters (`python` kind) read their inputs from `ctx.hosts` (and `ctx.ports` for port scanners); both are already scope-checked by the engine. `pyscan` calls `ctx.pacer.order(ctx.ports, kind="port")` itself because it owns the scan loop; the engine only fills the lists. `pyscan` also owns the only resolve step in this build, so it applies docs/05 rule 6 itself: every address returned by its resolver is filtered through `ctx.ip_allowed`, only an allowed address is connected to, an empty answer is a block rather than a fallback to the hostname (which would resolve again inside `open_connection`), and every skipped host is counted in `ToolResult.error` as `blocked=N` next to the existing `timeouts=`/`errors=` counts. A resolver answer the predicate cannot parse (`ValueError`) counts as a block. As defense in depth each per-host adapter normalizes its input with `validate_host()`; an invalid or IDN host is skipped and counted, never placed in a request.
- `dnspython` turns A/AAAA answers into `SubdomainRecord.ips` and CNAME into `.cnames`. It keeps the per-host outcome structured (`DnsResult.outcome`: `resolved`, `nxdomain`, `noanswer`, `servfail`, `timeout`, `error`), so a broken resolver is never only a string and never aborts the stage. Only NXDOMAIN maps to `HostStatusRecord(state=DEAD)`; "no answer", SERVFAIL and timeout never do (they are reported as counts in `ToolResult.error`), because a false DEAD is worse than a gap.
- `pyprobe` never follows redirects: it records the status code and the raw `Location` in `HostStatusRecord.location`. A TLS/connect failure becomes `state=UNKNOWN`, never a crash and never `DEAD`.
- `parse_output` normalizes and validates subdomain names; only names equal to or under `ctx.target` are kept before records are returned.
- In `--mock` mode `run` reads `tests/fixtures/<name>/<target>.<ext>` (or the only file in that directory) instead of making a request. HTTP adapters use the raw response text; `python` adapters use JSON fixtures: `dnspython` maps host to `{ips, cnames}` or `{state: DEAD}`, `pyprobe` maps host to `{status_code, title, location}`, and `pyscan` is a list of `{fqdn, ip, port, state}`.
- Rate: if the registry has `rate_flag`, the adapter appends it with the value from `pacer.tool_rate_args(name)`.

## 4. Stage Registry (who runs where)

Phase 2 = working adapter in the first build. Phase 3 = listed in `tools.yaml`, added one at a time.

| Stage | Mode | Pool (tier core unless noted) | Phase 2 working |
|---|---|---|---|
| subs | passive | crtsh, certspotter, otx, hackertarget, urlscan, subfinder, assetfinder, amass, findomain, chaos, github_subdomains | crtsh, certspotter, otx, hackertarget, subfinder, assetfinder |
| dns | passive | dnspython, dnsx, puredns (+massdns), dig | dnspython |
| live | active | pyprobe, httpx, httprobe, tlsx | pyprobe, httpx |
| ports | active (smap passive) | pyscan, naabu, nmap, rustscan, smap; masscan (opt_in) | pyscan (naabu is skipped: its resolver runs inside the binary, see selection rules) |
| tech | active | httpx_tech, whatweb, wafw00f, cdncheck, webanalyze | - |
| urls | passive/active | gau, waybackurls, katana, hakrawler, gospider, subjs, unfurl, urlfinder | - |
| vulns | active | nuclei, subzy, dnsreaper; nikto, ffuf (opt_in); dalfox, crlfuzz, sqlmap (intrusive) | - |
| shots | active | gowitness (opt_in) | - |

Selection rules: use adapters that are installed (or http/python kind), allowed by tier (`opt_in` needs `--tools` or `--include-noisy`; `intrusive` tools are refused in this build because there is no `--intrusive` flag), allowed by mode (active adapters only when `--active`), and filtered by `--tools` / `--exclude`. Missing tools are reported as `skipped`, never fatal unless no adapter remains (exit 4). This is the selection-time rule: a binary that was present at selection but cannot be spawned at run time is a `failed` result instead (see the adapter contract in section 3), not a skip. `naabu` is additionally skipped with `blocked: resolves inside the binary, so in_scope_cidrs cannot be enforced (11c-G-7)` because docs/05 rule 6 cannot be applied to an address that never leaves the child process; `--mock` is exempt because it connects to nothing.

Speed controls how many run at once: slow = 1, normal = 2-3 (passive) / 2 (active), fast = all. In `slow` the pool runs in registry order with random delays.

## 5. Consensus and Confidence Rules

### Discovery stages (subs, urls): union
- Merge all records by key (`fqdn` / `url`).
- `source_count` = number of distinct tools that reported the item in this run.
- Confidence: `>=3` HIGH, `2` MEDIUM, `1` LOW (thresholds in `config.yaml`).
- `--min-sources N` hides items below N.
- Wildcard: if a random non-existent name resolves, mark matches of the wildcard answer `is_wildcard=1` and exclude them from counts by default. A host matches when its CNAME is in the wildcard CNAME set or when all of its IPs are in the wildcard IP set. Detection is `unknown` (not `none`) when no probe resolved and any probe timed out, SERVFAILed, had no answer or errored; the engine warns and does not mark anything.

### Status stages (live, ports): cross-check
- **Host state decision**, using results from all live tools plus DNS:
  - Any tool got an HTTP/HTTPS response -> `ALIVE`.
  - DNS resolves, no web response from any tool -> `DNS_ONLY`.
  - No DNS answer (NXDOMAIN) -> `DEAD`, unless the previous known state was `ALIVE` or `DNS_ONLY` -> `SHUT_DOWN`.
    This state rule is unconditional: no other input can change it.
  - "At least 2 agreeing checks when 2 are available" only sets confidence (LOW when only one check is available). It never changes the state.
  - Responses that look like WAF/CDN blocks (for example 403/429 with CDN markers) still count as `ALIVE`.
- **Port-scan pre-check (Phase 2):** port scans require a stored `live` result for the host. If none is stored, skip the host and print a warning (`run live first`). If the stored `HostStatusRecord.waf` is set (from the `httpx` CDN/WAF JSON fields), skip it as CDN/WAF-fronted. `cdncheck` and `wafw00f` are Phase 3.
- **Ports:** `open` if at least one tool saw it open. If one tool saw open and another (that scanned the same port) saw closed, store `unconfirmed` with both in `port_sources`. Verified by a service fingerprint (nmap -sV, banner) raises confidence by one level.

### Passive ports (smap)
Stored with source `smap` and confidence LOW until an active scan confirms; never counted as active proof.

## 6. JSON Output

`--json` writes ONE JSON document to stdout (shape in docs/02 section 5), not JSONL. Each host object carries `confidence`, `sources` and `state`; the top-level `summary` object carries counts and tool statuses. Human tables and progress stay on stderr.

## 7. Adding a New Tool (checklist)

1. Entry in `tools.yaml` (stage, tier, mode, install, version command, rate flag).
2. Adapter file with `parse_output` first; verify flags with the real tool.
3. Sanitized fixture + tests (normal, empty, malformed).
4. Register in `adapters/__init__.py`.
5. Update stage table above and docs if behavior changes.
6. Run all checks in AGENTS.md section 6.

## 8. Tool Notes (verify before coding)

- ProjectDiscovery tools support `-silent`, JSON output (`-json`/`-jsonl`) and a rate flag; confirm per tool with `--help`.
- `httpx`: the ProjectDiscovery binary, not the Python `httpx` CLI or Kali's differently named package; installer places the right one in `~/.reconkit/bin`.
- `naabu`: needs libpcap; use connect scan when not root.
- `amass`: run passive only; slow, so keep it last in slow mode.
- HTTP sources: free tiers rate-limit; 429 and 5xx are `failed` results carrying the status, with no retry. Only a connection error retries once.

## 9. Verified Tool Contracts (2026-11-14)

Every flag and field below was checked against the real binary on this Kali box or against the tool's official source on 2026-11-14 - not from memory. Raw evidence (commands and output) is in the REVIEW_LOG entry "Tool flags and fields verified against the real tools". Anything not verifiable is listed under PROGRESS Open risks instead of being asserted here.

| Tool | What we rely on | How it was verified | Mismatch found |
|---|---|---|---|
| `crtsh` | `GET https://crt.sh/?q=%.<domain>&output=json`; response array with `name_value` and `common_name` | Live request with the adapter's exact query: HTTP 200, 28,454 bytes, both fields present. crt.sh publishes no API reference, so the live sample is the primary source | none. Note: crt.sh 404s when `%` is not percent-encoded (`q=%.example.com`), and httpx encodes params, so the adapter is safe |
| `certspotter` | `GET https://api.certspotter.com/v1/issuances` with `domain`, `include_subdomains=true`, `expand=dns_names`; response array with `dns_names`; `Authorization: Bearer <key>` | Official APIv1 reference (sslmate.com/help/reference/ct_search_api_v1) plus a live 200 with 17 entries; first entry keys include `dns_names` | none |
| `otx` | `GET /api/v1/indicators/domain/{domain}/passive_dns`; `{"passive_dns": [{"hostname": ...}]}`; header `X-OTX-API-KEY` | Official external-API page (otx.alienvault.com/assets/static/external_api.html) documents the section endpoints; two separate live anonymous calls both returned HTTP 429 with `{"detail": "Anonymous access to this endpoint is limited. Please authenticate."}`, so the response shape comes from published API responses, not from this session | shape still not observed live; carried in Open risks. No code reads the 429 body |
| `hackertarget` | `GET https://api.hackertarget.com/hostsearch/?q=<domain>`; text `host,ip` per line | Two live 200s on 2026-11-14, both `www.example.com,172.66.147.243` (31 bytes). The old docs URL (hackertarget.com/host-search/) is now 404 | the quota message string (`api count exceeded`) is still unobserved because the free quota was not hit; the adapter's quota branch stays unexercised - carried in Open risks |
| `subfinder` | `-d`, `-silent`, `-nc`, `-duc`, `-pc`, `-rl`, `-version`; one host per line with `-silent` | Installed v2.17.0: `-h` and `-version` output; official README flag list confirms the same seven | none |
| `assetfinder` | `--subs-only <domain>`, domain as positional arg; `-h` for the identity probe | Official repo README (`assetfinder [--subs-only] <domain>`) and `main.go` (Go `flag`, so `-h` prints `Usage of .../assetfinder` and exits 2) | binary not installed here: identity probe inferred from the source, not exercised. `check_installed` accepts the nonzero exit because it only rejects spawn failure and timeouts |
| `httpx` | `-u`, `-json`, `-silent`, `-no-stdin`, `-duc`, `-nc`, `-sc`, `-title`, `-location`, `-td`, `-cdn`, `-rl`, `-version`; JSON keys `input`, `url`, `status_code`, `title`, `location`, `tech`, `cdn_name` | Installed v1.12.0: `-h`, `-version`, `-ldv` (lists JSON field keys) and two real localhost probes (200 with title/tech, 301 with `location`) | none. `title` appears only with `-title` and `tech` only with `-td`, both of which the adapter passes; `cdn_name` is a confirmed field but stayed absent on a non-CDN host |
| `naabu` | `-silent`, `-json`, `-no-stdin`, `-duc`, `-nc`, `-scan-type c`, `-host`, `-p`, `-rate`, `-version`; JSON keys `host`, `ip`, `port` | Installed v2.7.0: `-h` and `-version`; real localhost scans with an IP input and with a hostname input | **`host` is omitted when the input is an IP literal** (`{"ip","timestamp","port","protocol","tls"}`); the adapter falls back to `ip`, so the record's `fqdn` becomes the IP for such a host. Documented, not changed: naabu is blocked in this build anyway |
| `nmap` | `-sV`, `-T<0-5>`, `-p`, `--version` | Installed 7.991: `--version` and `--help` | none. Registry `rate_flag: -T` takes a digit (`-T4`), so an adapter must append one rather than pass a bare `-T` |
| `masscan` | `--max-rate`, `--version`; needs root | Installed Masscan 1.3.2: `--version`; `--max-rate 100 -p1234 --echo` shows `rate = 100` without sending packets | **`masscan --version` exits 1** while printing a valid banner, so the installer/doctor identity probe calls a real Masscan "wrong program". Fixed separately, see REVIEW_LOG |
| `rustscan` | `--version`, `-V` | Not installed. Kali's official tool page for the package prints `rustscan -h` with `-V, --version` | not verified against a binary; asset pattern stays a placeholder |
| `massdns` | `-r/--resolvers`, `-t/--type`, `-o/--output` (formats L/S/F/B only - no JSON); version via `dpkg-query` | Installed 1.1.0-0kali2: `massdns -h`; `dpkg-query -W '-f=${Version}' massdns` returns the version | none. A future adapter must parse text (`-o S`/`-o F`), not JSON |
| `katana` | `-rl`, `-version` | Installed v1.8.0: `-h` shows `-rl, -rate-limit`; `-version` prints the banner on stderr | none for the flag. The version line is not the first line (doctor shows the art) - fixed separately |
| `nuclei` | `-rl`, `-tags`, `-version` | Installed v3.11.1: `-h` shows both flags; `-version` prints `Nuclei Engine Version` | none for the flags. Same first-line version display defect as katana |
| `dig` | `-v` as the version command (apt `dnsutils`) | Installed: `dig -v` -> `DiG 9.20.30-1-Debian` | none |
| `dnspython` / `pyprobe` / `pyscan` | library and stdlib only (no external flags) | `dnspython 2.9.2` with `dns.resolver.NXDOMAIN`; stdlib `ssl`/`asyncio`/`socket` import in the active venv | none |

