# Tool Contracts (adapted from API.md)

This is the most-read file for agents. It defines the adapter interface, normalized schemas, the stage registry, and the consensus rules.

## 1. Conventions

- Tools are listed only in `tools.yaml`. Each has a `stage`, `kind` (`http` | `python` | `binary`), `tier` (`core` | `opt_in` | `intrusive`), `mode` (`passive` | `active`).
- A tool may list `keys`: a list of `{env, url, adds}` entries (`env` name, https sign-up URL, what the key adds). `keys` is the only per-tool key list; there is no `needs_key` field, and the loader rejects one. Free mode needs no keys (policy in `docs/05_SECURITY.md` §6.1). `registry.ToolSpec.keys` exposes them; `env` must match `^[A-Z][A-Z0-9_]*$`, `url` must be https, and a malformed entry raises `ConfigError`.
- `registry.load_tools()` returns `dict[str, ToolSpec]` and `registry.load_system_packages()` returns the top-level `system_packages` tuple. `ToolSpec` is a frozen dataclass with `name`, `stage`, `kind`, `tier`, `mode`, `phase`, `keys: tuple[ToolKey, ...] = ()` and `requires_apt: tuple[str, ...] = ()`. (The `rate_flag` field was removed with speed control on 2026-11-17.) `requires_apt` is the per-tool apt dependency list (for example `naabu` needs `libpcap-dev`); the installer adds it to the packages it installs. Other entry fields (`install`, `version_cmd`, `binary`, `requires`, `notes`) are not part of `ToolSpec`.
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

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:


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
    detail: str | None = None      # why this pass could not be decided; UNKNOWN only
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
    duration_s: float = 0.0          # own wall seconds; 0.0 = not measured (engine fills, docs/04 s5)
    error: str | None = None        # short, redacted
    raw_path: str | None = None     # raw output file in workspace
    raw_text: str | None = Field(default=None, exclude=True)  # captured output, never serialized

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

- `RunContext` (above) carries: `target`, `hosts` (already scope-checked), `ports`, `timeout`, `workspace`, `mock` flag, `env` (allowed keys only), `ip_allowed` (the loaded scope's `in_scope_cidrs` predicate, or `None`), `headers` (from repeatable `--header "Name: Value"`) and `user_agent` (from `--user-agent`). `headers`/`user_agent` are optional: an adapter that cannot send one ignores them and the engine warns `--header not applied to <tool> (no -H support)` once per executed tool. `ports` is the `--ports` override when given, else empty (each adapter then uses its own default). `ip_allowed` exists so an adapter can apply docs/05 rule 6 without importing `core.scope`; `None` means no permission, never allow-all. **naabu input is scope-mode dependent (2026-11-17):** with no scope file the engine leaves `hosts` as the ordinary names; with a scope file present it resolves each target itself and replaces `hosts` for naabu only with the verified IP addresses. The replacement happens in the engine's per-tool context copy; no other adapter's `hosts` changes. `env` is the entire child environment: the runner passes only these keys, so adapters must add `HOME` explicitly for tools that read config or provider keys from it (confirm per tool from its own `--help`, do not guess).
- `check_installed()` returns `InstallStatus` (above). For binaries, `installed=False` with a non-null `path` means the program was found but failed its identity check (the `httpx` namesake case), while `installed=False` with `path=None` means it was not found at all. `doctor` reports the first as `wrong program` (a warning that names the path) and the second as `missing`; both count as not ready in per-stage coverage.
- Adapter failures use the exceptions in `reconkit/errors.py` defined by `docs/06_CODE_STYLE.md` §6 (`ScopeError`, `ToolNotInstalled`, `ToolFailed`, `ToolTimeout`, `ParseError`, `ConfigError`, `InstallError`); no other exception names. They are converted into `ToolResult(status=...)`, never raised out of a stage.
- Binary adapters usually implement only `build_command` and `parse_output`; the base `run` handles execution, timeout, output saving and error mapping. They subclass `BinaryAdapter` from `adapters/base.py`, which resolves the binary in `~/.reconkit/bin` first and then `PATH`, and whose `check_installed()` runs the adapter's `version_args` and matches the tool's own banner/version text, so the ProjectDiscovery `httpx` is never confused with the Python `httpx` CLI on `PATH`. Identity markers must **all** appear in the probe output by default (`identity_require_all = True`); the single exception is `subfinder`, which sets `identity_require_all = False` because subfinder < v2.6.4 prints only `[INF] Current Version: vX.Y.Z` and never names the tool (upstream commit `c175790`, 2023-10-30), and rejecting a working old install is worse than accepting one marker match for a binary that is already identified by filename. A binary that is absent at selection time is `skipped (not installed)` and never reaches here; a binary that was present at selection but cannot be spawned at run time, a non-zero exit and a timeout are three different `failed`/`timeout` results with different messages; no exception escapes. `build_command` must launch the resolved path from `binary_path()` (managed directory first, then `PATH`) rather than the bare binary name, because the child receives only the env keys that were passed in and therefore has no `PATH` of its own to search.
- `subfinder` reads provider keys only from its own config file. When at least one provider key is present, its adapter maps the env names in its `keys` entry (`certspotter`, `chaos`, `github`, `virustotal`) into a **per-run directory** in the system temp dir named `reconkit-subfinder-<pid>-<random>` with mode 0700, writes `provider-config.yaml` inside it with mode 0600, passes that path with `-pc`, and removes the whole directory in a `finally` block after success, timeout or exception. Key values never appear in argv, logs or `ToolResult`; deleting the directory is best-effort on Windows because `chmod` is weak there. The mode is set explicitly after creation, not left to the umask.
- **Stale provider directories (C-2).** At the start of every run the adapter also removes directories that a killed run left behind: a `reconkit-subfinder-*` directory whose pid is no longer alive is removed, while one whose pid is still alive is left alone unless its mtime is older than `STALE_AFTER_S` (900 s). That age rule is what protects two concurrent runs from deleting each other's live config, and it is also the only rule on Windows, where there is no safe pid-liveness probe (`os.kill(pid, 0)` would terminate the process). Leftover `reconkit-subfinder-*.yaml` files from the pre-12g single-file layout are removed by the same age rule. Cleanup never raises: a removal error is ignored and the run continues, and a provider directory is never reused across runs.
- `httpx` is ProjectDiscovery's binary. Its adapter passes repeated `-u` targets, `-json`, and the probes `-sc -title -location -td -cdn`; `parse_output` reads the JSONL `input`/`url` host, `status_code`, `title`, `location`, `tech` and `cdn_name` into `HostStatusRecord`. `naabu` runs `-scan-type c` (connect scan, no root), `-host` with a comma-separated list, `-p` for the supplied ports, and `-json`; `parse_output` reads `ip`, `port` and optional `host` into `PortRecord`. `naabu -h` documents `-host string[]  hosts to scan ports for (comma-separated)`, and a real run with `-host 127.0.0.1` confirms IP literals are accepted; the JSON then omits `host` (`{"ip":"127.0.0.1",...,"port":18080,...}`), so the record's `fqdn` becomes that IP. `naabu` receives hostnames only when there is no scope file; a scope file makes the engine pass verified IPs only (section 4 selection rules). `assetfinder` runs `--subs-only <domain>` and prints plain lines.
- HTTP adapters subclass `HttpAdapter` from `adapters/base.py`. Its `run` awaits `ctx.limiter.wait()`, uses an `httpx.AsyncClient` with an explicit timeout and the honest User-Agent, retries a connection error once with an injected sleep, and maps HTTP 429, 5xx and timeouts to a failed `ToolResult` (never an exception).
- HTTP bodies are read as a stream and capped at `MAX_BODY_BYTES` (10 MiB); exceeding the cap is a failed `ToolResult` (`response too large`), never an exception.
- Per-host adapters (`python` kind) read their inputs from `ctx.hosts` (and `ctx.ports` for port scanners); both are already scope-checked by the engine. `pyscan` scans its port list in the order it was filled (the engine only fills the lists; there is no shuffling). `pyscan` also owns the only resolve step in this build, so it applies docs/05 rule 6 itself: every address returned by its resolver is filtered through `ctx.ip_allowed`, only an allowed address is connected to, an empty answer is a block rather than a fallback to the hostname (which would resolve again inside `open_connection`), and every skipped host is counted in `ToolResult.error` as `blocked=N` next to the existing `timeouts=`/`errors=` counts. A resolver answer the predicate cannot parse (`ValueError`) counts as a block. As defense in depth each per-host adapter normalizes its input with `validate_host()`; an invalid or IDN host is skipped and counted, never placed in a request.
- `dnspython` turns A/AAAA answers into `SubdomainRecord.ips` and CNAME into `.cnames`. It keeps the per-host outcome structured (`DnsResult.outcome`: `resolved`, `nxdomain`, `noanswer`, `servfail`, `timeout`, `error`), so a broken resolver is never only a string and never aborts the stage. Only NXDOMAIN maps to `HostStatusRecord(state=DEAD)`; "no answer", SERVFAIL and timeout never do (they are reported as counts in `ToolResult.error`), because a false DEAD is worse than a gap.
- `pyprobe` never follows redirects: it records the status code and the raw `Location` in `HostStatusRecord.location`. It tries `https` then `http` per host, and a TLS failure on one scheme must not end the probe: the next scheme is tried, and a working one yields `ALIVE`. Only when no scheme answers and at least one failed with a TLS error is the record `state=UNKNOWN`; a plain connect failure on every scheme is no record (`unreachable=`). Never a crash and never `DEAD`. An `UNKNOWN` record carries the TLS failure text in `HostStatusRecord.detail` so the cause survives the run (`detail` is bounded and redacted by the store, not by the adapter - docs/04 section 5); records of any other state carry no `detail`.
- `parse_output` normalizes and validates subdomain names; only names equal to or under `ctx.target` are kept before records are returned.
- In `--mock` mode `run` reads `tests/fixtures/<name>/<target>.<ext>` (or the only file in that directory) instead of making a request. HTTP adapters use the raw response text; `python` adapters use JSON fixtures: `dnspython` maps host to `{ips, cnames}` or `{state: DEAD}`, `pyprobe` maps host to `{status_code, title, location}`, and `pyscan` is a list of `{fqdn, ip, port, state}`.
- **Raw output (12a).** Every adapter run captures its output in `ToolResult.raw_text`, for every status - `ok`, `failed`, `timeout` and the selection-time skip is not a run at all. A binary adapter captures `stdout` followed by `stderr` under a `--- stderr ---` separator when stderr is non-empty (the runner's own `max_output_bytes` cap already limits each stream); an HTTP adapter captures the response body, or the failure message when the request failed before any body was read; the `python` adapters (`dnspython`, `pyprobe`, `pyscan`) have no child process, so they capture their per-host evidence as a JSON document (`records` plus the `error` counters) instead of hand-rolling a text format. A `--mock` run captures the fixture text it parsed. The field holds unredacted text in memory and is excluded from every serialization, so it never appears in `--json`. The engine, not the adapter, writes it: `Workspace.write` applies `store.redact()` and the `max_output_bytes` cap, and `raw_path` is set on the same result only after that write returns (docs/03 section 5). One executed tool is always exactly one file, even when the capture is empty; a failed write leaves `raw_path` at `None` and changes neither the status nor the error.

## 4. Stage Registry (who runs where)

Phase 2 = working adapter in the first build. Phase 3 = listed in `tools.yaml`, added one at a time.

| Stage | Mode | Pool (tier core unless noted) | Phase 2 working |
|---|---|---|---|
| subs | passive | crtsh, certspotter, otx, hackertarget, urlscan, subfinder, assetfinder, amass, findomain, chaos, github_subdomains | crtsh, certspotter, otx, hackertarget, subfinder, assetfinder |
| dns | passive | dnspython, dnsx, puredns (+massdns), dig | dnspython, dnsx |
| live | active | pyprobe, httpx, httprobe, tlsx | pyprobe, httpx, tlsx |
| ports | active (smap passive) | pyscan, naabu, nmap, rustscan, smap; masscan (opt_in) | pyscan, naabu |
| tech | active | httpx_tech, whatweb, wafw00f, cdncheck, webanalyze | - |
| urls | passive/active | gau, waybackurls, katana, hakrawler, gospider, subjs, unfurl, urlfinder | gau, katana |
| vulns | active | nuclei, subzy, dnsreaper; nikto, ffuf (opt_in); dalfox, crlfuzz, sqlmap (intrusive) | - |
| shots | active | gowitness (opt_in) | - |

Selection rules (2026-11-17: the mode tables in docs/02 section 2 and `MODE_STAGES`/`MODE_TOOLS` in `engine.py` are the source): use adapters that are installed (or http/python kind), allowed by tier for the mode (`allowed_tiers`: `opt_in` only with `--include-noisy` or a `full` run; `intrusive` only with `full` or an explicit `--tools` name), allowed by tool mode (an active tool in `passive` mode is skipped with `tool mode not included in passive mode` even when named), never `exploitation: true` unless named with `--tools`, and filtered by `--tools` / `--exclude`. `tools.yaml` may carry `exploitation: true` on an intrusive entry (`sqlmap`, `dalfox`, `crlfuzz`); the registry parses it into `ToolSpec.exploitation` (a non-bool is a `ConfigError`) and the engine skips such a tool automatically in every mode with `exploitation tool requires explicit --tools`. Missing tools are reported as `skipped`, never fatal unless no adapter remains (exit 4). Every selection-time skip is recorded in `tool_runs` **and** reported to the caller: `stages[].skipped` in the `--json` document and the Tools table list each tool with its reason, and `summary.tools_skipped` counts them (docs/02 section 5), so a stage whose whole pool has no adapter cannot look like a stage that ran and found nothing. This is the selection-time rule: a binary that was present at selection but cannot be spawned at run time is a `failed` result instead (see the adapter contract in section 3), not a skip. **`naabu` is scope-mode dependent (owner decision 2026-11-17; supersedes the permanent block of 11c-G-7/12i):**

- **No scope file** - `naabu` is an ordinary active tool. It is selected, installed-checked and run exactly like `pyscan`, receiving the discovered hostnames. No pre-resolution gate, no IP-only restriction, no special-case skip.
- **Scope file present** - before invoking `naabu`, the engine resolves each already-in-scope target with its own resolver (`adapters.pyscan.default_resolve`, injected in tests), checks every returned address with the same `ip_allowed` predicate `pyscan` uses, and hands `naabu` only the verified IP addresses through `-host` - never a bare domain. A target whose resolution fails or yields no in-scope address is omitted from the list; if no target yields a verified address, `naabu` is removed from the selection with `blocked: no in-scope IP for any target (resolution failed or the address is outside in_scope_cidrs)` and the reason is recorded in `tool_runs`/`stages[].skipped`. When some targets do verify, the run continues and one warning counts the omitted targets.
- **Passive mode** - `naabu` does not run, like every other active tool (`tool mode not included in passive mode`).
- `--mock` skips the resolve step because it connects to nothing.

There is no speed control: every selected adapter of a stage starts together and runs at its own natural pace (2026-11-17, docs/MASTER_PLAN.md D3).

### 4a. Adapter wave 1 (2026-11-17): dnsx, tlsx, katana, gau

Every command below was read off the real binary's `-h` on this box; the
fixtures are `tests/fixtures/adapters/<tool>.synthetic.*` (the only place the
flat `<tool>.synthetic.*` lookup in `base._read_fixture` looks).

| Tool | Stage | Invocation | Records |
|---|---|---|---|
| `dnsx` | dns | `-silent -json -a -or -duc -nc -l <comma-separated hosts>` | `SubdomainRecord(ips=[a...])`; `HostStatusRecord(DEAD)` only for `status_code: NXDOMAIN` (PIT-01) |
| `tlsx` | live | `-silent -json -san -duc -nc -u <host>` (one `-u` per host) | `HostStatusRecord(ALIVE)` when `probe_status` is true, `UNKNOWN` with `detail="tls probe failed"` when false; one `SubdomainRecord(source="tlsx:san")` per certificate SAN, `*.` stripped |
| `katana` | urls | `-silent -jsonl -or -ob -duc -nc -u <host>` (one `-u` per host) | `UrlRecord` from `request.endpoint`; a line carrying only `error` (for example `max depth reached`) is skipped |
| `gau` | urls | `--json --timeout=<n> <host...>` (hosts are positional; gau has no `-silent`/`-nc`/`-duc`) | `UrlRecord` from `{"url": ...}` per line, and from plain URL lines too (older builds); the stderr `level=warning msg="error reading config..."` notice is ignored because only stdout is parsed |

`dnsx` has no repeatable input flag, so its hosts travel in one `-l` list
(`-l` documents "file or comma separated or stdin"); every host is validated
before it is placed there. All four are `kind: binary`, `tier: core`, declare
`needs_home = True` and use both ProjectDiscovery markers (`projectdiscovery`,
`current version`) except `gau`, which requires the `gau version:` marker.

**tlsx cert metadata (Ruling A, 2026-11-17).** Cert metadata (expiry, issuer,
self-signed) is extracted by tlsx but not persisted - future addition if operator
needs it (would require schema 7 + new HostStatusRecord fields). Liveness and
SAN discovery are the only stored facts. The SANs reach `subdomains` through
`Engine._persist_live_discoveries` (PIT-49), which persists every
`SubdomainRecord` a live pass discovered, not only the hosts it was given.

### 4b. Per-tool support for the injected parameters

| Parameter | `httpx` | `pyprobe` | `pyscan` | `naabu` | Every other adapter |
|---|---|---|---|---|---|
| `--ports` | - (live stage) | - | yes, `ctx.ports` replaces `DEFAULT_PORTS` | yes, `-p` (verified: `naabu -h` `-port, -p string`) | ignored |
| `--header` | yes, `-H "Name: Value"` (verified: `httpx -h` `-H, -header string[]`) | yes, request headers | ignored + one warning | ignored + one warning | ignored + one warning |
| `--user-agent` | yes, `-H "User-Agent: ..."` | yes, client header | ignored + one warning | ignored + one warning | ignored + one warning |

The four wave-1 adapters (`dnsx`, `tlsx`, `katana`, `gau`) are in the "every
other adapter" column: they accept a `--header`/`--user-agent` flag upstream
(`tlsx`/`katana` have `-H`) but do not use it in this build, so the flags stay
ignored there rather than half-applied.
| `--status-codes` | filter only (hosts whose stored `status_code` matches) | filter only | - | - | - |

The `--status-codes` filter and `--only-alive`/`--only-states` act on the
already-stored host rows in the CLI, never inside an adapter, so they change
what is printed and never what is stored.

### Per-tool mode and tier (from `tools.yaml`)

| Tool | Stage | `mode` | `tier` | `exploitation` | Runs in passive / active / full |
|---|---|---|---|---|---|
| crtsh, certspotter, otx, hackertarget, urlscan, subfinder, assetfinder, amass, findomain, chaos, github_subdomains | subs | passive | core | no | yes / yes / yes |
| dnspython, dnsx, puredns, massdns, dig | dns | passive | core | no | yes / yes / yes |
| pyprobe, httpx, httprobe, tlsx | live | active | core | no | no / yes / yes |
| smap | ports | passive | core | no | no (stage not in passive) / yes / yes |
| pyscan, naabu, nmap, rustscan | ports | active | core | no | no / yes / yes |
| masscan | ports | active | opt_in | no | no / `--include-noisy` only / yes |
| httpx_tech, whatweb, wafw00f, webanalyze | tech | active | core | no | no (stage not in passive) / yes / yes |
| cdncheck | tech | passive | core | no | no (stage not in passive) / yes / yes |
| gau, waybackurls, unfurl, urlfinder | urls | passive | core | no | yes / yes / yes |
| katana, hakrawler, gospider, subjs | urls | active | core | no | no (tool mode) / yes / yes |
| nuclei, subzy, dnsreaper | vulns | active | core | no | no / no / yes |
| nikto, ffuf | vulns | active | opt_in | no | no / no / yes |
| gowitness | shots | active | opt_in | no | not a mode stage |
| dalfox, crlfuzz, sqlmap | vulns | active | intrusive | **yes** | never automatic; `--tools <name>` only |

"Runs in full" means selected; an adapter that does not exist yet still reports
`no adapter yet (phase 3)`.

**Mode expansion (2026-11-17, D10).** `passive` now includes the `urls` stage
and `active` now includes `tech` and `urls` (docs/02 section 1 is the source of
truth). Two consequences for this table:

- a `mode: active` urls tool in `passive` mode is still skipped at selection with
  `tool mode not included in passive mode`, so the expanded `urls` stage runs its
  passive tools only; that is the "no (tool mode)" cell above.
- the input to the stage follows the tool, not the stage: passive urls tools
  receive the discovered domain list, active urls tools and every `tech` tool
  receive the alive hosts (docs/02 section 1, docs/03 section 5b).

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
- `amass` (v5.1.3, verified 2026-11-17): passive is the **default** in v5, so nothing needs to be turned on; `amass enum -passive` still parses but v5 prints `-passive` / `Deprecated since passive is the default setting`. Keep it last (it is the slowest passive source), and check `amass enum -h` before writing an adapter - v5's CLI is `assoc|engine|enum|subs|track|viz`, not the v4 surface.
- `webanalyze` (verified 2026-11-17): it needs a technologies file **in the current working directory** before it will scan. `webanalyze -update` downloads it (`technologies.json`, ~2.1 MB) and prints `app definition file updated`; without it a scan exits **1** with `error: can not open apps file : could not find the technologies file: technologies.json`. Run the update once per working directory, or point `-apps` at an existing file.
- HTTP sources: free tiers rate-limit; 429 and 5xx are `failed` results carrying the status, with no retry. Only a connection error retries once.

## 9. Verified Tool Contracts (2026-11-14)

Every flag and field below was checked against the real binary on this Kali box or against the tool's official source on 2026-11-14 - not from memory. Raw evidence (commands and output) is in the REVIEW_LOG entry "Tool flags and fields verified against the real tools". Anything not verifiable is listed under PROGRESS Open risks instead of being asserted here.

**Per-tool manuals (2026-11-16).** The full reference for every non-`vulns`
tool - official source URL, install state, the complete real `--help`, one real
safe test on `testfire.net` with its exit code, and every error hit - lives in
`docs/tool_manuals/` (one file per stage, index in its `README.md`). The table
below remains the compact "what the code relies on" contract; the manuals are
the long form. The `vulns` stage is deliberately undocumented for now (recon-only
scope, see that README) and this section says nothing about it.

| Tool | What we rely on | How it was verified | Mismatch found |
|---|---|---|---|
| `crtsh` | `GET https://crt.sh/?q=%.<domain>&output=json`; response array with `name_value` and `common_name` | Live request with the adapter's exact query: HTTP 200, 28,454 bytes, both fields present. crt.sh publishes no API reference, so the live sample is the primary source | none. Note: crt.sh 404s when `%` is not percent-encoded (`q=%.example.com`), and httpx encodes params, so the adapter is safe |
| `certspotter` | `GET https://api.certspotter.com/v1/issuances` with `domain`, `include_subdomains=true`, `expand=dns_names`; response array with `dns_names`; `Authorization: Bearer <key>` | Official APIv1 reference (sslmate.com/help/reference/ct_search_api_v1) plus a live 200 with 17 entries; first entry keys include `dns_names` | none |
| `otx` | `GET /api/v1/indicators/domain/{domain}/passive_dns`; `{"passive_dns": [{"hostname": ...}]}`; header `X-OTX-API-KEY` | Official external-API page (otx.alienvault.com/assets/static/external_api.html) documents the section endpoints; two separate live anonymous calls both returned HTTP 429 with `{"detail": "Anonymous access to this endpoint is limited. Please authenticate."}`, so the response shape comes from published API responses, not from this session | shape still not observed live; carried in Open risks. No code reads the 429 body |
| `hackertarget` | `GET https://api.hackertarget.com/hostsearch/?q=<domain>`; text `host,ip` per line | Two live 200s on 2026-11-14, both `www.example.com,172.66.147.243` (31 bytes). The old docs URL (hackertarget.com/host-search/) is now 404 | the quota message string (`api count exceeded`) is still unobserved because the free quota was not hit; the adapter's quota branch stays unexercised - carried in Open risks |
| `subfinder` | `-d`, `-silent`, `-nc`, `-duc`, `-pc`, `-rl`, `-version`; one host per line with `-silent` | Installed v2.17.0: `-h` and `-version` output; official README flag list confirms the same seven | none |
| `assetfinder` | `--subs-only <domain>`, domain as positional arg; `-h` for the identity probe | Installed 2026-11-17: `assetfinder -h` writes `Usage of assetfinder:` and `  -subs-only` to **stderr** and exits **0** - this row previously said 2, which was inferred from Go `flag` source, not measured. `-version` is not a flag (`flag provided but not defined: -version` then the same usage, exit **2** - measured without a pipe) | none. Identity probe exercised on the real binary; `check_installed` only rejects spawn failure and timeouts, so exit 0 or a nonzero usage exit both pass |
| `httpx` | `-u`, `-json`, `-silent`, `-no-stdin`, `-duc`, `-nc`, `-sc`, `-title`, `-location`, `-td`, `-cdn`, `-rl`, `-version` (stderr banner, `version_regex` `Current [Vv]ersion: (v?\d+\.\d+\.\d+)` since 2026-11-17); JSON keys `input`, `url`, `status_code`, `title`, `location`, `tech`, `cdn_name` | Installed v1.12.0: `-h`, `-version`, `-ldv` (lists JSON field keys) and two real localhost probes (200 with title/tech, 301 with `location`) | none. `title` appears only with `-title` and `tech` only with `-td`, both of which the adapter passes; `cdn_name` is a confirmed field but stayed absent on a non-CDN host |
| `naabu` | `-silent`, `-json`, `-no-stdin`, `-duc`, `-nc`, `-scan-type c`, `-host`, `-p`, `-version` (stderr banner, `version_regex` `Current [Vv]ersion: (v?\d+\.\d+\.\d+)` since 2026-11-17); JSON keys `host`, `ip`, `port` | Installed v2.7.0: `-h` and `-version`; real localhost scans with an IP input and with a hostname input | **`host` is omitted when the input is an IP literal** (`{"ip","timestamp","port","protocol","tls"}`); the adapter falls back to `ip`, so the record's `fqdn` becomes the IP for such a host. This is the normal consequence of the scope-file-present branch (2026-11-17): naabu is given IPs, so its records are keyed by IP there, while a no-scope-file run passes names and keeps the hostname in `fqdn` |
| `nmap` | `-sV`, `-T<0-5>`, `-p`, `--version` | Installed 7.991: `--version` and `--help` | none. `-T` takes a digit (`-T4`) if an adapter ever wants it; reconkit passes no timing flag |
| `masscan` | `--max-rate`, `--version`; needs root | Installed Masscan 1.3.2: `--version`; `--max-rate 100 -p1234 --echo` shows `rate = 100` without sending packets | **`masscan --version` exits 1** while printing a valid banner, so the installer/doctor identity probe calls a real Masscan "wrong program". Fixed separately, see REVIEW_LOG |
| `rustscan` | `--version`, `-V` | Installed 2.3.0 via the pinned `github_release` plan: `rustscan --version` -> `rustscan 2.3.0` | **2.3.0 is pinned (2026-11-17)**: 2.4.1's amd64 asset is a nested `.tar.gz.zip` and the extractor unwraps one layer, the 2.4.1 names use `x86_64`/`aarch64` where `{arch}` is `amd64`/`arm64`, and no recent release publishes checksums. The plan sets `verify_checksums: false`; the amd64-only asset means arm64 is unsupported by this pin |
| `massdns` | `-r/--resolvers`, `-t/--type`, `-o/--output` (formats L/S/F/B only - no JSON); version via `dpkg-query` | Installed 1.1.0-0kali2: `massdns -h`; `dpkg-query -W '-f=${Version}' massdns` returns the version | none. A future adapter must parse text (`-o S`/`-o F`), not JSON |
| `katana` | `-rl`, `-version` | Installed v1.8.0: `-h` shows `-rl, -rate-limit`; `-version` prints the banner on stderr | none for the flag. The version line is not the first line (doctor shows the art) - fixed separately |
| `nuclei` | `-rl`, `-tags`, `-version` | Installed v3.11.1: `-h` shows both flags; `-version` prints `Nuclei Engine Version` | none for the flags. Same first-line version display defect as katana |
| `dig` | `-v` as the version command (apt `dnsutils`) | Installed: `dig -v` -> `DiG 9.20.30-1-Debian` | none |
| `dnspython` / `pyprobe` / `pyscan` | library and stdlib only (no external flags) | `dnspython 2.9.2` with `dns.resolver.NXDOMAIN`; stdlib `ssl`/`asyncio`/`socket` import in the active venv | none |

