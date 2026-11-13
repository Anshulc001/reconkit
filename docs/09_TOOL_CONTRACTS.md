# Tool Contracts (adapted from API.md)

This is the most-read file for agents. It defines the adapter interface, normalized schemas, the stage registry, and the consensus rules.

## 1. Conventions

- Tools are listed only in `tools.yaml`. Each has a `stage`, `kind` (`http` | `python` | `binary`), `tier` (`core` | `opt_in` | `intrusive`), `mode` (`passive` | `active`).
- A tool may list `keys`: a list of `{env, url, adds}` entries (`env` name, https sign-up URL, what the key adds). Free mode needs no keys (policy in `docs/05_SECURITY.md` §6.1). `registry.ToolSpec.keys` exposes them; `env` must match `^[A-Z][A-Z0-9_]*$`, `url` must be https, and a malformed entry raises `ConfigError`.
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
    version: str | None = None      # from tools.yaml version_cmd (None if unknown)
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

- `RunContext` (above) carries: `target`, `hosts` (already scope-checked), `speed`, `pacer`, `timeout`, `workspace`, `mock` flag, `env` (allowed keys only). `env` is the entire child environment: the runner passes only these keys, so adapters must add `HOME` explicitly for tools that read config or provider keys from it (confirm per tool from its own `--help`, do not guess).
- `check_installed()` returns `InstallStatus` (above).
- Adapter failures use the exceptions in `reconkit/errors.py` defined by `docs/06_CODE_STYLE.md` §6 (`ScopeError`, `ToolNotInstalled`, `ToolFailed`, `ToolTimeout`, `ParseError`, `ConfigError`, `InstallError`); no other exception names. They are converted into `ToolResult(status=...)`, never raised out of a stage.
- Binary adapters usually implement only `build_command` and `parse_output`; the base `run` handles execution, timeout, output saving and error mapping.
- HTTP adapters subclass `HttpAdapter` from `adapters/base.py`. Its `run` awaits `ctx.limiter.wait()`, uses an `httpx.AsyncClient` with an explicit timeout and the honest User-Agent, retries a connection error once with an injected sleep, and maps HTTP 429, 5xx and timeouts to a failed `ToolResult` (never an exception).
- HTTP bodies are read as a stream and capped at `MAX_BODY_BYTES` (10 MiB); exceeding the cap is a failed `ToolResult` (`response too large`), never an exception.
- Per-host adapters (`python` kind) read their inputs from `ctx.hosts` (and `ctx.ports` for port scanners); both are already scope-checked by the engine. `pyscan` calls `ctx.pacer.order(ctx.ports, kind="port")` itself because it owns the scan loop; the engine only fills the lists.
- `dnspython` turns A/AAAA answers into `SubdomainRecord.ips` and CNAME into `.cnames`. Only NXDOMAIN maps to `HostStatusRecord(state=DEAD)`; "no answer", SERVFAIL and timeout never do (they are reported as counts in `ToolResult.error`), because a false DEAD is worse than a gap.
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
| ports | active (smap passive) | pyscan, naabu, nmap, rustscan, smap; masscan (opt_in) | pyscan, naabu |
| tech | active | httpx_tech, whatweb, wafw00f, cdncheck, webanalyze | - |
| urls | passive/active | gau, waybackurls, katana, hakrawler, gospider, subjs, unfurl, urlfinder | - |
| vulns | active | nuclei, subzy, dnsreaper; nikto, ffuf (opt_in); dalfox, crlfuzz, sqlmap (intrusive) | - |
| shots | active | gowitness (opt_in) | - |

Selection rules: use adapters that are installed (or http/python kind), allowed by tier (`opt_in` needs `--tools` or `--include-noisy`; `intrusive` needs `--intrusive` + scope), allowed by mode (active adapters only when `--active`), and filtered by `--tools` / `--exclude`. Missing tools are reported as `skipped`, never fatal unless no adapter remains (exit 4).

Speed controls how many run at once: slow = 1, normal = 2-3 (passive) / 2 (active), fast = all. In `slow` the pool runs in registry order with random delays.

## 5. Consensus and Confidence Rules

### Discovery stages (subs, urls): union
- Merge all records by key (`fqdn` / `url`).
- `source_count` = number of distinct tools that reported the item in this run.
- Confidence: `>=3` HIGH, `2` MEDIUM, `1` LOW (thresholds in `config.yaml`).
- `--min-sources N` hides items below N.
- Wildcard: if a random non-existent name resolves, mark matches of the wildcard answer `is_wildcard=1` and exclude them from counts by default.

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

`--json` prints JSONL, one object per record, fixed keys from the schemas above plus `confidence`, `sources`, `state`. The final line is a summary object `{"type":"summary", ...}` with counts and tool statuses.

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
- HTTP sources: free tiers rate-limit; treat 429 as `skipped (rate limited)` after one back-off.
