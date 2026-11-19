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
class ToolStatus(str, Enum): OK="ok"; GAP="gap"; SKIPPED="skipped"; FAILED="failed"; TIMEOUT="timeout"

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
    # `unknown` is real: 42 of the installed nuclei templates declare it and
    # nuclei can select it with `-severity unknown` (2026-11-17, adapter wave 5).
    severity: Literal["info","low","medium","high","critical","unknown"]
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
    name: ClassVar[str]  # must match the key in tools.yaml
    stage: ClassVar[Stage]
    # tier, mode, kind come from tools.yaml (single source of truth)

    def check_installed(self) -> InstallStatus: ...  # found? version? path
    def build_command(
        self, ctx: RunContext
    ) -> list[str]: ...  # binary adapters only; argv list, no shell
    async def run(
        self, ctx: RunContext
    ) -> ToolResult: ...  # default: runner.run_exec(build_command) + parse
    def parse_output(self, raw: str) -> list[Record]: ...  # pure function, fully unit-testable
```

- `RunContext` (above) carries: `target`, `hosts` (already scope-checked), `ports`, `timeout`, `workspace`, `mock` flag, `env` (allowed keys only), `ip_allowed` (the loaded scope's `in_scope_cidrs` predicate, or `None`), `headers` (from repeatable `--header "Name: Value"`) and `user_agent` (from `--user-agent`). `ports` is the `--ports` override when given, else empty (each adapter then uses its own default). `ip_allowed` exists so an adapter can apply docs/05 rule 6 without importing `core.scope`; `None` means no permission, never allow-all. **naabu input is scope-mode dependent (2026-11-17):** with no scope file the engine leaves `hosts` as the ordinary names; with a scope file present it resolves each target itself and replaces `hosts` for naabu only with the verified IP addresses. The replacement happens in the engine's per-tool context copy; no other adapter's `hosts` changes. `env` is the entire child environment: the runner passes only these keys, so adapters must add `HOME` explicitly for tools that read config or provider keys from it (confirm per tool from its own `--help`, do not guess).
- `check_installed()` returns `InstallStatus` (above). For binaries, `installed=False` with a non-null `path` means the program was found but failed its identity check (the `httpx` namesake case), while `installed=False` with `path=None` means it was not found at all. `doctor` reports the first as `wrong program` (a warning that names the path) and the second as `missing`; both count as not ready in per-stage coverage.
- Adapter failures use the exceptions in `reconkit/errors.py` defined by `docs/06_CODE_STYLE.md` §6 (`ScopeError`, `ToolNotInstalled`, `ToolFailed`, `ToolTimeout`, `ParseError`, `ConfigError`, `InstallError`); no other exception names. They are converted into `ToolResult(status=...)`, never raised out of a stage.
- Binary adapters usually implement only `build_command` and `parse_output`; the base `run` handles execution, timeout, output saving and error mapping. They subclass `BinaryAdapter` from `adapters/base.py`, which resolves the binary in `~/.reconkit/bin` first and then `PATH`, and whose `check_installed()` runs the adapter's `version_args` and matches the tool's own banner/version text, so the ProjectDiscovery `httpx` is never confused with the Python `httpx` CLI on `PATH`. Identity markers must **all** appear in the probe output by default (`identity_require_all = True`); the single exception is `subfinder`, which sets `identity_require_all = False` because subfinder < v2.6.4 prints only `[INF] Current Version: vX.Y.Z` and never names the tool (upstream commit `c175790`, 2023-10-30), and rejecting a working old install is worse than accepting one marker match for a binary that is already identified by filename. A binary that is absent at selection time is `skipped (not installed)` and never reaches here; a binary that was present at selection but cannot be spawned at run time, a non-zero exit and a timeout are three different `failed`/`timeout` results with different messages; no exception escapes. `build_command` must launch the resolved path from `binary_path()` (managed directory first, then `PATH`) rather than the bare binary name, because the child receives only the env keys that were passed in and therefore has no `PATH` of its own to search.
- `subfinder` reads provider keys only from its own config file. When at least one provider key is present, its adapter maps the env names in its `keys` entry (`certspotter`, `chaos`, `github`, `virustotal`) into a **per-run directory** in the system temp dir named `reconkit-subfinder-<pid>-<random>` with mode 0700, writes `provider-config.yaml` inside it with mode 0600, passes that path with `-pc`, and removes the whole directory in a `finally` block after success, timeout or exception. Key values never appear in argv, logs or `ToolResult`; deleting the directory is best-effort, so a failure to remove it never fails the run. The mode is set explicitly after creation, not left to the umask.
- **Stale provider directories (C-2).** At the start of every run the adapter also removes directories that a killed run left behind: a `reconkit-subfinder-*` directory whose pid is no longer alive is removed, while one whose pid is still alive is left alone unless its mtime is older than `STALE_AFTER_S` (900 s). That age rule is what protects two concurrent runs from deleting each other's live config, and it is also the fallback on any host without a safe pid-liveness probe (`os.kill(pid, 0)` is never sent where it would terminate the process). Leftover `reconkit-subfinder-*.yaml` files from the pre-12g single-file layout are removed by the same age rule. Cleanup never raises: a removal error is ignored and the run continues, and a provider directory is never reused across runs.
- `httpx` is ProjectDiscovery's binary. Its adapter passes repeated `-u` targets, `-json`, and the probes `-sc -title -location -td -cdn`; `parse_output` reads the JSONL `input`/`url` host, `status_code`, `title`, `location`, `tech` and `cdn_name` into `HostStatusRecord`. `naabu` runs `-scan-type c` (connect scan, no root), `-host` with a comma-separated list, `-p` for the supplied ports, and `-json`; `parse_output` reads `ip`, `port` and optional `host` into `PortRecord`. `naabu -h` documents `-host string[]  hosts to scan ports for (comma-separated)`, and a real run with `-host 127.0.0.1` confirms IP literals are accepted; the JSON then omits `host` (`{"ip":"127.0.0.1",...,"port":18080,...}`), so the record's `fqdn` becomes that IP. `naabu` receives hostnames only when there is no scope file; a scope file makes the engine pass verified IPs only (section 4 selection rules). `assetfinder` runs `--subs-only <domain>` and prints plain lines.
- HTTP adapters subclass `HttpAdapter` from `adapters/base.py`. Its `run` uses an `httpx.AsyncClient` with an explicit timeout and the honest User-Agent, retries a connection error once with an injected sleep, and never raises: every outcome becomes a `ToolResult`.
- **External-service failures are `gap`, not `failed` (owner ruling 2026-11-18).** One classifier, `base.classify_external_gap(text)`, recognises the signatures a third party produces and nothing about this box: HTTP `429`/`rate limit`/`too many requests`, a free-quota/`quota exceeded` message (`hackertarget` answers HTTP 200 with `API count exceeded`), and an HTTP `5xx` (`502`/`503`/`504` or `server error (HTTP 5xx)`) from the upstream an adapter calls. `HttpAdapter` raises `ExternalServiceGap` for a 429/5xx itself and catches the same exception when a parser recognises a quota body; `BaseToolAdapter.run` classifies a non-zero binary exit's captured stdout+stderr with the same function. All three paths return `ToolResult(status=GAP, error=<the service's message>)`, keeping whatever records were parsed. The engine counts it as a completion gap (exit `0`) and records `tool_runs.status='gap'`; see docs/02 sections 5-6 and docs/04 section 5. A 404 from a local binary or an adapter that is not a third-party API, a refused connection (even to an external
API), a TLS error and a parse error are still `failed`; a whole-response 404 from an adapter marked `external_api` is a
gap instead (D47, next section), and so is a request that never answered (D57, two sections down).
- HTTP bodies are read as a stream and capped at `MAX_BODY_BYTES` (10 MiB); exceeding the cap is a failed `ToolResult` (`response too large`), never an exception.
- Per-host adapters (`python` kind) read their inputs from `ctx.hosts` (and `ctx.ports` for port scanners); both are already scope-checked by the engine. `pyscan` scans its port list in the order it was filled (the engine only fills the lists; there is no shuffling). `pyscan` also owns the only resolve step in this build, so it applies docs/05 rule 6 itself: every address returned by its resolver is filtered through `ctx.ip_allowed`, only an allowed address is connected to, an empty answer is a block rather than a fallback to the hostname (which would resolve again inside `open_connection`), and every skipped host is counted in `ToolResult.error` as `blocked=N` next to the existing `timeouts=`/`errors=` counts. A resolver answer the predicate cannot parse (`ValueError`) counts as a block. As defense in depth each per-host adapter normalizes its input with `validate_host()`; an invalid or IDN host is skipped and counted, never placed in a request.
- `dnspython` turns A/AAAA answers into `SubdomainRecord.ips` and CNAME into `.cnames`. It keeps the per-host outcome structured (`DnsResult.outcome`: `resolved`, `nxdomain`, `noanswer`, `servfail`, `timeout`, `error`), so a broken resolver is never only a string and never aborts the stage. Only NXDOMAIN maps to `HostStatusRecord(state=DEAD)`; "no answer", SERVFAIL and timeout never do (they are reported as counts in `ToolResult.error`), because a false DEAD is worse than a gap.
- `pyprobe` never follows redirects: it records the status code and the raw `Location` in `HostStatusRecord.location`. It tries `https` then `http` per host, and a TLS failure on one scheme must not end the probe: the next scheme is tried, and a working one yields `ALIVE`. Only when no scheme answers and at least one failed with a TLS error is the record `state=UNKNOWN`; a plain connect failure on every scheme is no record (`unreachable=`). Never a crash and never `DEAD`. An `UNKNOWN` record carries the TLS failure text in `HostStatusRecord.detail` so the cause survives the run (`detail` is bounded and redacted by the store, not by the adapter - docs/04 section 5); records of any other state carry no `detail`.
- `parse_output` normalizes and validates subdomain names; only names equal to or under `ctx.target` are kept before records are returned.
- In `--mock` mode `run` reads `tests/fixtures/<name>/<target>.<ext>` (or the only file in that directory) instead of making a request. HTTP adapters use the raw response text; `python` adapters use JSON fixtures: `dnspython` maps host to `{ips, cnames}` or `{state: DEAD}`, `pyprobe` maps host to `{status_code, title, location}`, and `pyscan` is a list of `{fqdn, ip, port, state}`.
- **Fixture statuses are synthetic, never evidence (D41, 2026-11-19).** A mock fixture answers the question "does the code handle this shape?", not "what does the real target say?". `tests/fixtures/pyprobe/testfire.net.synthetic.json` answers `200` for both hosts while the real `https://testfire.net/` answers `-2` (its certificate is issued for `www.testfire.net`); a mock run's status code, state and confidence are only as true as the fixture, and a real-network claim needs a real run recorded in `docs/REVIEW_LOG.md`.

- **Raw output (12a).** Every adapter run captures its output in `ToolResult.raw_text`, for every status - `ok`, `failed`, `timeout` and the selection-time skip is not a run at all. A binary adapter captures `stdout` followed by `stderr` under a `--- stderr ---` separator when stderr is non-empty (the runner's own `max_output_bytes` cap already limits each stream); an HTTP adapter captures the response body, or the failure message when the request failed before any body was read; the `python` adapters (`dnspython`, `pyprobe`, `pyscan`) have no child process, so they capture their per-host evidence as a JSON document (`records` plus the `error` counters) instead of hand-rolling a text format. A `--mock` run captures the fixture text it parsed. The field holds unredacted text in memory and is excluded from every serialization, so it never appears in `--json`. The engine, not the adapter, writes it: `Workspace.write` applies `store.redact()` and the `max_output_bytes` cap, and `raw_path` is set on the same result only after that write returns (docs/03 section 5). One executed tool is always exactly one file, even when the capture is empty; a failed write leaves `raw_path` at `None` and changes neither the status nor the error.

## 4. Stage Registry (who runs where)

Phase 2 = working adapter in the first build. Phase 3 = listed in `tools.yaml`, added one at a time.

| Stage | Mode | Pool (tier core unless noted) | Phase 2 working |
|---|---|---|---|
| subs | passive | crtsh, certspotter, otx, hackertarget, urlscan, subfinder, assetfinder, amass, findomain, chaos, github_subdomains | crtsh, certspotter, otx, hackertarget, subfinder, assetfinder |
| dns | passive | dnspython, dnsx, puredns (+massdns), dig | dnspython, dnsx |
| live | active | pyprobe, httpx, httprobe, tlsx | pyprobe, httpx, tlsx, httprobe |
| ports | active (smap passive) | pyscan, naabu, nmap, rustscan, smap; masscan (opt_in) | pyscan, naabu |
| tech | active | httpx_tech, whatweb, wafw00f, cdncheck, webanalyze | httpx_tech, whatweb, wafw00f, cdncheck, webanalyze |
| urls | passive/active | gau, waybackurls, katana, hakrawler, gospider, subjs, unfurl, urlfinder | gau, katana, waybackurls, hakrawler, gospider, subjs, unfurl, urlfinder |
| vulns | active | nuclei, subzy, dnsreaper; nikto, ffuf (opt_in); dalfox, crlfuzz, sqlmap (intrusive) | nuclei, subzy |
| shots | active | gowitness (opt_in) | full mode only (D19) |

Selection rules (2026-11-17: the mode tables in docs/02 section 2 and `MODE_STAGES`/`MODE_TOOLS` in `engine.py` are the source): use adapters that are installed (or http/python kind), allowed by tier for the mode (`allowed_tiers`: `opt_in` only with `--include-noisy` or a `full` run; `intrusive` only with `full` or an explicit `--tools` name), allowed by tool mode (an active tool in `passive` mode is skipped with `tool mode not included in passive mode` even when named `--tools`, **except** a name in `--include`, which is the one documented override - D63, 2026-11-19; it also prints the forced-contact banner), never `exploitation: true` unless named with `--tools` (`--include` does not lift that rule), and filtered by `--tools` / `--exclude`. `tools.yaml` may carry `exploitation: true` on an intrusive entry (`sqlmap`, `dalfox`, `crlfuzz`); the registry parses it into `ToolSpec.exploitation` (a non-bool is a `ConfigError`) and the engine skips such a tool automatically in every mode with `exploitation tool requires explicit --tools`. Missing tools are reported as `skipped`, never fatal unless no adapter remains (exit 4). A `needs_root` tool in a non-root process is skipped the same way with `requires root / sudo` (section 4a6). Every selection-time skip is recorded in `tool_runs` **and** reported to the caller: `stages[].skipped` in the `--json` document and the Tools table list each tool with its reason, and `summary.tools_skipped` counts them (docs/02 section 5), so a stage whose whole pool has no adapter cannot look like a stage that ran and found nothing. This is the selection-time rule: a binary that was present at selection but cannot be spawned at run time is a `failed` result instead (see the adapter contract in section 3), not a skip. **`naabu` is scope-mode dependent (owner decision 2026-11-17; supersedes the permanent block of 11c-G-7/12i):**

- **No scope file** - `naabu` is an ordinary active tool. It is selected, installed-checked and run exactly like `pyscan`, receiving the discovered hostnames. No pre-resolution gate, no IP-only restriction, no special-case skip.
- **Scope file present** - before invoking `naabu`, the engine resolves each already-in-scope target with its own resolver (`adapters.pyscan.default_resolve`, injected in tests), checks every returned address with the same `ip_allowed` predicate `pyscan` uses, and hands `naabu` only the verified IP addresses through `-host` - never a bare domain. A target whose resolution fails or yields no in-scope address is omitted from the list; if no target yields a verified address, `naabu` is removed from the selection with `blocked: no in-scope IP for any target (resolution failed or the address is outside in_scope_cidrs)` and the reason is recorded in `tool_runs`/`stages[].skipped`. When some targets do verify, the run continues and one warning counts the omitted targets.
- **Passive mode** - `naabu` does not run, like every other active tool (`tool mode not included in passive mode`).
- `--mock` skips the resolve step because it connects to nothing.

**Excluded ranges (D56, 2026-11-19).** `scope.yaml` may now carry
`exclude_cidrs`, and it wins over `in_scope_cidrs`: `ScopeGate.ip_allowed` is
true only inside an included range **and** outside every excluded one, so an
address in both is refused (the same precedence `out_of_scope` already has over
`in_scope` for names). Only `pyscan` and the engine's pre-resolved `naabu` input
receive verified addresses, so only they can honour an excluded range; every
other active tool resolves hostnames inside its own child and never shows
reconkit the address. When `exclude_cidrs` is non-empty, the engine says so once
at run start on stderr and in the same words in the run's report and `--json`
(`scope_warnings`), naming the selected tools it cannot gate. `--no-scope` and a
missing file have nothing to enforce and stay silent. A `--strict-cidr` flag
that refuses to run with in-child resolvers selected is a future decision, not
part of this build (PROGRESS, Open risks).

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
| `gau` | urls | `--json --timeout=<s> --threads=5 --retries=1 <host...>` (hosts are positional; gau has no `-silent`/`-nc`/`-duc`). **`--timeout` is the HTTP client timeout (its default 45), not the run budget** - see the 2026-11-18 note below | `UrlRecord` from `{"url": ...}` per line, and from plain URL lines too (older builds); the stderr `level=warning msg="error reading config..."` notice is ignored because only stdout is parsed |

`dnsx` has no repeatable input flag, so its hosts travel in one `-l` list
(`-l` documents "file or comma separated or stdin"); every host is validated
before it is placed there. All four are `kind: binary`, `tier: core`, declare
`needs_home = True` and use both ProjectDiscovery markers (`projectdiscovery`,
`current version`) except `gau`, which requires the `gau version:` marker.

### 4a2. Adapter wave 2 (2026-11-17): httprobe, webanalyze, cdncheck, waybackurls

| Tool | Stage | Invocation | Records |
|---|---|---|---|
| `httprobe` | live | `-t <milliseconds>`, hosts on **stdin** | `HostStatusRecord(ALIVE)` per answering host (both schemes on one host are one record) |
| `webanalyze` | tech | `-hosts <file> -output json -apps <technologies.json> -silent` | `HostStatusRecord(ALIVE, tech=[app_name...])` |
| `cdncheck` | tech | `-silent -jsonl -i <host>` (one `-i` per host) | `HostStatusRecord(UNKNOWN, tech=[cdn/cloud], waf=<waf_name>)` |
| `waybackurls` | urls | no flags, domains on **stdin** | `UrlRecord` per archived URL |

Three of the four have no `-version` flag (`-version` exits 2 with Go's "flag
provided but not defined"), so their identity probe is `-h` plus markers only
the real tool prints: `httprobe` = `skip the default probes` + `concurrency
level`, `webanalyze` = `technologies definition file` + `update technologies
file`, `waybackurls` = `-no-subs` + `don't include subdomains`. `cdncheck`
keeps `-version` (its own banner) and the ProjectDiscovery markers.

- **stdin input (D11).** `runner.run_exec(..., stdin_text=...)` is the only way a
  child receives data on stdin; the adapter hook is `stdin_text(ctx)`, which
  returns `None` (stdin at EOF) everywhere else. The text is written from its own
  thread so a child that reads lazily cannot block the timeout clock, and a child
  that exits early only sees a broken pipe. No shell, no pipe, no temporary
  input file for these two.
- **webanalyze's file inputs.** `-hosts` is a path, so the adapter writes the
  host list into the run workspace (`webanalyze-hosts-<pid>.txt`) inside
  `prepare()` and deletes it in `finally`. `-apps` points at
  `~/.reconkit/technologies.json` when it exists (one `webanalyze -update`
  serves every directory) and falls back to `./technologies.json`; with neither,
  the tool's own exit 1 (`can not open apps file`) becomes the failed result -
  the adapter never downloads anything.
- **cdncheck semantics.** A WAF match becomes `HostStatusRecord.waf` (the field
  the port pre-check reads), a CDN or cloud match becomes a technology entry.
  Its state is `UNKNOWN`: cdncheck resolves a name and compares ranges, it does
  not fetch a page, so it never claims `ALIVE`. A host that matches nothing
  prints no line at all - an empty output is `ok` with zero records.
- **Technology persistence (D11).** `tech` records are not a status pass: the
  engine's `_persist_tech` merges their `tech`/`waf` into the host's **newest**
  `host_status_history` row (`Store.update_host_extras`), never appending a state
  row. A host with no status row yet (a `tech` run without `live`) stores
  nothing, and a record naming a host outside the target is dropped like every
  other off-target record.

### 4a2b. Passive-tool timeouts (2026-11-18): gau and urlfinder

> **Superseded by 4a2c (D52, 2026-11-19).** Everything below about `runtime_cap_s`,
> the `urls:` block, `urlfinder.max_enumeration_s` and the `cap_s` formula is
> history: those keys and constants no longer exist. What survives from this
> section is the per-request flag fix (`--timeout 45` for `gau`, `-timeout 30`
> for `urlfinder`), the `waybackurls` apex rule, and the fact that a stopped run
> keeps its partial stdout.

Both archive readers were passing the per-tool **run budget** into a flag that
means a **per-request HTTP timeout**, which made them slower than their own
defaults and, for `gau`, fatal:

| tool | old | new | measured on testfire.net (2026-11-18) |
|---|---|---|---|
| `gau` | `--timeout=600` (the budget) | `--timeout=45 --threads=5 --retries=1` | **31 s, 345 URLs** vs `timeout` at 600 s, 0 items |
| `urlfinder` | `-timeout 600` (the budget), no `-max-time` | `-timeout 30 -max-time 10` | **15 s, 996 URLs** vs 554 s, 932 URLs |
| `waybackurls` | all 42 hosts on stdin (42 wildcard queries) | the apex once, other domains as their own line | **2.4 s** vs 302 s, 0 items both ways (archive.org answered 503 all morning) |

`waybackurls` has no timeout flag at all, so the host list is the only lever. Its
own `-h` says `-no-subs` means "don't include subdomains of the target domain",
which proves the default `*.<line>/*` query already covers them - feeding it all
42 discovered hosts therefore asked the same wildcard question 42 times in a row.
The adapter now feeds the apex once and passes through any host that is not under
it (a scope file can name several domains), so nothing is lost.

**2026-11-19: the `ok 0` on sakec.ac.in is the tool's, not the adapter's.** The
adapter's argv is `[<binary>]` with the host on stdin and no flags; the binary
exited **0** with **0 bytes** and empty stderr for `sakec.ac.in`,
`www.sakec.ac.in` and `http://www.sakec.ac.in`, so the parser never saw a line.
The CDX endpoint it builds answered **503 "Internet Archive: Temporarily
Offline"** on one call and **200** with real rows on the next, and `gau`
returned 4 917 URLs from the same archive in the same stage. waybackurls has no
error surface, so a refused archive and an empty archive are the same output;
the finding is recorded under Open risks in PROGRESS, not fixed here.

Both values are capped by the run budget (`min(...)`), so a small
`--phase-timeout` still wins, and `urlfinder -max-time` is the budget rounded up
to minutes (600 s -> 10, its own default). Through the real engine:
`reconkit urls -d testfire.net --active --no-scope --tools gau,urlfinder` finished
the whole `urls` stage in **15 s wall clock** with `gau ok 345` and
`urlfinder ok 933`, where the 2026-11-18 morning run needed 664 s and recorded
`gau timeout 0`.

**Whole-enumeration bounds (2026-11-18).** `urlfinder` is the one tool whose
runtime could not be predicted: with the same command it returned 996 URLs in
15 s, then 206 in 506 s and 932 in 525 s on the next three runs, because a
single slow source holds the whole enumeration. Its own `-max-time` turned out
**not to be enforced** by the binary (still running at 5m52s with `-max-time 3`),
so the adapter bounds the process itself and parses the partial stdout, which
keeps every URL found before the kill (a plain timeout used to discard all of
them).

The first version was a flat `runtime_cap_s = 180`. That is right for
`testfire.net` (43 hosts) and wrong for a target with hundreds of hosts, where
sources are still answering productively at three minutes. The cap is now bounded
by these keys, whichever fires first:

| Key (`config.yaml`) | Default | Meaning |
|---|---|---|
| `urls.urlfinder_min_s` | `180` | Floor: never kill before this many seconds |
| `urls.urlfinder_idle_s` | `60` | Kill once stdout has been silent this long (the floor applies first) |
| `urls.urlfinder_max_s` | `1800` | Hard ceiling on the computed cap, whatever the tool is doing (D27) |
| `urlfinder.max_enumeration_s` | `0` | `0` = compute the cap from the host count; non-zero replaces the formula (D27) |
| `urls.hakrawler_max_s` | `120` | Hard cap for `hakrawler` (2.2) |
| `urls.subjs_max_s` | `60` | Hard cap for `subjs` (2.2) |

The engine hands these to adapters as `RunContext.limits[<tool>]`
(`ToolLimits.max_s`/`idle_s`/`min_s`), so an adapter never reads `config.yaml`
itself. The inactivity clock is the runner's: `run_exec(..., idle_timeout=,
min_runtime=)` kills the process group when stdout has been silent for
`idle_timeout` seconds after `min_runtime` has elapsed, and `ExecResult.idle_killed`
says which clock fired. A silent tool is therefore killed at about
`min_s + idle_s` (240 s by default) and a productive one runs to `max_s`.
`-max-time` gets the computed cap in whole minutes, for the tool's own
bookkeeping.

**The cap scales with the host count (2026-11-18, D27).** A flat ceiling either
wastes a large target or over-serves a small one, so the ceiling is computed per
run:

```
cap_s = min(stage_budget, max(180, 4 * host_count))
```

- `host_count` is the number of rows on urlfinder's stdin for this run:
  `tool_hosts["urlfinder"]` when the stage supplies a per-tool list (the `urls`
  stage gives a passive tool the target plus the discovered names), otherwise
  `RunContext.hosts`. Nothing new records it.
- `stage_budget` is the deadline the stage already has - `--phase-timeout` when
  given, otherwise `timeouts.urls`. No new timeout source is introduced.
- 43 hosts -> `min(1800, max(180, 172))` = **180 s**, exactly the number
  `testfire.net` was tuned at; 100 hosts -> 400 s; 500 hosts -> 2000 s, clipped
  to the 1800 s stage budget.
- `urlfinder.max_enumeration_s` (default `0`) replaces the formula with one fixed
  value when it is non-zero, for debugging and CI.
- `urls.urlfinder_max_s` (default `0`) is an **optional second ceiling** applied
  on top of the formula; `0` means "no extra ceiling", so by default the stage
  budget (`timeouts.urls` / `--phase-timeout`) is the only bound. Raising
  `--phase-timeout` alone now raises the cap for large targets.
- The floor stays 180 s, a capped run keeps its partial stdout, and the detail
  line names the host count and, when the formula was clipped, why:
  `capped at 180s (hosts=43); kept partial output` normally, and
  `capped at 1800s (hosts=2000; formula 8000s clipped to stage budget 1800s); kept partial output`
  when saturation occurs.

`nikto` has the same shape: one process per host, each with its share of the
remaining stage budget, and the tool's own `-maxtime <share>s` so it stops
itself cleanly and writes its JSON instead of being killed by our timeout. A
real `--full` run had nikto killed at 600 s with 0 findings before this.

`nuclei` gets `-or` (`-omit-raw`, verified in its `-help`). The request/response
pair it embeds is never parsed, and on a real run it pushed the JSONL stdout
past the 1 MB output cap, truncating the last line and failing the tool with
`invalid JSON line`.

This is deliberately limited to the **passive** tools and to these two
one-process-per-item tools. Other active tools are bounded by the phase timeout
only, because their work *is* the scan.

### 4a2c. Idle-only runtime: the caps are gone (D52, 2026-11-19)

**There is no per-tool runtime cap anywhere in the code.** A tool runs until one
of exactly three things happens:

1. it produces its own output and exits - the normal case, and nothing delays it;
2. the engine's **idle watchdog** sees it silent past its class window and stops
   it, keeping every record it had already printed (`status: killed`);
3. the **stage budget** fires (`--phase-timeout`, else `timeouts.<stage>`) - still
   `status: timeout`, because a tool that did not finish in the stage's time is a
   real signal (R13, D45 stands unchanged).

Deleted in this batch: `BinaryAdapter.runtime_cap_s`, `min_runtime_s`,
`RuntimeClassConfig.floor`/`per_host`, `UrlsConfig`, `UrlfinderConfig`,
`config.class_cap()`, `ToolLimits.max_s`/`min_s`/`note`, and the `urls:` /
`urlfinder:` blocks of `config.yaml`. `ToolLimits` now holds one field, `idle_s`.
`runner.run_exec` lost its `min_runtime` floor along with them.

**The windows.** `config.yaml` `runtime_idle:` is the only runtime bound, and a
class carries one number - how long the tool may stay **silent**:

| class | idle window | members today |
|---|---|---|
| `crawler` | 60 s | `gau`, `katana`, `hakrawler`, `gospider`, `subjs` |
| `scanner` | 120 s | `nikto` |
| `api` | 60 s | `crtsh`, `certspotter`, `otx`, `hackertarget`, `urlscan`, `chaos`, `github_subdomains` |
| `archive` | 180 s | `urlfinder` |

`subjs` gained `class: crawler` here: it used to carry its own 60 s cap, and a
class window is the only way to keep that behaviour without a cap. A tool with no
`class:` has no window at all and is bounded by the stage budget alone; a typo in
`class:` is a `ConfigError` rather than a silent "no window". One tool may
override its class with `idle_s:` in its own `tools.yaml` row.

**How the kill works.** The engine watches every running tool (`IDLE_WATCH_TICK_S`
= 0.1 s). It stops a tool when *every* running tool in the stage is silent past
its own window, or when the only tool still running is alone and past its window.
It then sets a per-tool `threading.Event` that `run_exec` watches: the child is
killed and its partial stdout returned, so the adapter can still parse it. An
adapter that never looks at the flag (a pure-Python one) is cancelled after
`KILL_GRACE_S` (0.25 s), and the stage's own backstop sits at the budget plus
`STAGE_KILL_GRACE_S` (2.0 s) so the per-tool path always reports first.

**What a stopped tool says.** Idle: `killed after 60s idle at stage 412.3s, 1042
partial`. Stage budget: `timed out at stage budget 1800s, 12 partial, last output
300s ago`. Both keep their records; the difference is the status, because a kill
is the engine ending a stuck tool (exit 0, `tools_killed` in `--json`, the
"stopped early" block on stderr) while a budget timeout stays a failure (exit 5).

**`urlfinder`.** `-max-time` is gone from the argv entirely: the real binary does
not enforce it (measured still running at 5m52s with `-max-time 3`), and with no
cap left to translate into minutes there is nothing to pass. The stage budget and
the `archive` window are its bounds, and its partial stdout is kept either way.

### 4a2d. Per-request vs stage timeouts (D53, 2026-11-19)

`RunContext.timeout` is the **stage budget**. It exists for the hard wall only:
`run_exec(timeout=...)` (`base.py:313` for a read-back command, `base.py:334` for
the tool itself) and the stage's own `asyncio.wait_for`. It is never a
per-request timeout.

A per-request timeout belongs to the adapter that makes the request, as a
module-level constant - the shape `gau.HTTP_TIMEOUT_S` (45 s) and
`urlfinder.REQUEST_TIMEOUT_S` (30 s) already had. This batch gave the seven
adapters that were borrowing the run budget the same shape:

| constant | value | what it bounds |
|---|---|---|
| `hakrawler.REQUEST_TIMEOUT_S` | 10 s | `-timeout`, seconds per URL |
| `gospider.REQUEST_TIMEOUT_S` | 10 s | `-m/--timeout`, seconds per request |
| `subjs.REQUEST_TIMEOUT_S` | 10 s | `-t`, HTTP timeout in seconds |
| `httprobe.PROBE_TIMEOUT_MS` | 10 000 ms | `-t`, milliseconds per probe |
| `pyprobe.HTTP_TIMEOUT_S` | 30 s | the httpx client for one probe |
| `gowitness.PAGE_TIMEOUT_S` | 30 s | one `run_exec` per page/URL |
| `pyscan.CONNECT_TIMEOUT_S` | 5 s | one TCP connect |
| `base.HTTP_TIMEOUT_S` | 30 s | one HTTP request of a `kind: http` tool |

**The bug predates D52.** With `timeouts.per_tool_default: 600` these adapters
were already waiting 600 s per request (`hakrawler` asked 600 s per URL,
`httprobe` 600 000 ms per probe). D52 then made `ctx.timeout` the stage budget,
so an unflagged `urls` run would have handed three crawlers 1800 s per request
and a `vulns` run 7200 s. The constants are not tuning knobs: per-tool tuning
would be a `tools.yaml` field, which does not exist for this and was not added.

Unchanged and still correct: `nikto`'s `deadline = started + ctx.timeout` is a
**total run deadline** (each host's `-maxtime` is its share of what is left of
the budget, `base`-style hard wall), `urlfinder`/`gau` clamp the budget to their
per-request ceilings, and a tool with no request-level flag keeps
`run_exec(timeout=ctx.timeout)`.

### 4a3. Adapter wave 3 (2026-11-17): hakrawler, gospider, subjs, urlfinder

Three are `urls` / `active` / `core` (`hakrawler`, `gospider`, `subjs`), so they
run in `--active` and `--full` and are skipped in `passive` mode by the tool-mode
rule (D10). **`urlfinder` is `mode: passive` in `tools.yaml`** and stays that way
(the registry is the source of truth, same ruling as `gau` in wave 1), so it also
runs in `passive` mode - semantically right, since it queries third-party
archives and never returns to the target. All four receive hostnames from the
engine and turn them into URLs themselves:

| Tool | Invocation | Target form | Records |
|---|---|---|---|
| `hakrawler` | `-d 2 -u -timeout <s>`, URLs on **stdin** | both `https://<host>/` and `http://<host>/` | `UrlRecord` per crawled URL |
| `gospider` | `-S <sites file> -d 2 -q -t 10 -m <s>` | sites file with both schemes | `UrlRecord`; a leading `[tag] - [code-200] - ` is stripped |
| `subjs` | `-c 10 -t <s> -ua <reconkit UA>`, URLs on **stdin** | both schemes | `UrlRecord` per JavaScript URL |
| `urlfinder` | `-all -silent -nc -timeout <s> -max-time <min>`, domains on **stdin** | bare hostnames | `UrlRecord` per archived URL (mode `passive`: runs in all three modes) |

Why the two-scheme form: the engine hands the stage bare hostnames, and these
crawlers need a URL. `https://<host>/` then `http://<host>/` is the same order
`pyprobe` uses for liveness, and it is what makes a host whose certificate does
not cover its name still crawlable over http (`testfire.net` is exactly that:
curl reports `SSL: no alternative certificate subject name matches target
hostname`, and hakrawler printed nothing for the https form). `-insecure` is
never passed: disabling TLS verification would hide a real certificate problem.

Verified per tool: `hakrawler` has **no `-silent`** (real flags `-d`, `-dr`, `-i`,
`-insecure`, `-json`, `-proxy`, `-s`, `-size`, `-subs`, `-t`, `-timeout`, `-u`,
`-w`; `-version` exits 2) and its `-h` is *not* help (it takes custom headers),
so identity is `-version` plus the `depth to crawl` / `show only unique urls`
markers; `gospider -h` exits 0 and `--version` prints only `Version: v1.1.6`, so
identity is `-h` with `fast web spider` / `site to crawl`; `subjs -version`
prints `subjs version: 1.0.1` and it reads URLs on stdin (verified with a local
page that references two scripts); `urlfinder -version` prints
`[INF] Current Version: v0.0.3` and it reads domains on stdin.

- **Links that are not URLs.** A crawl prints the page's own links verbatim, and
the first real hakrawler run on testfire.net produced
`javascript:checkSiteStatus('AltoroMutual')` and made the strict parser fail the
tool. `base.is_non_web_reference()` recognises `javascript:`, `mailto:`,
`tel:`, `data:`, `about:`, `ftp:` and `file:` and every urls parser skips them
(PIT-52).
- **An unusable line is skipped and counted, never fatal (2026-11-18, PIT-58).**
  `katana`, `hakrawler`, `gospider` and `subjs` now keep parsing after a line
  they cannot use (a non-JSON line from katana, a line with no URL from the
  crawlers) instead of failing the whole tool: the real scan showed
  `katana: invalid JSON line` with 0 items while katana was printing warning
  text on stdout. Each parser collects the unusable lines and the adapter puts
  the count in `ToolResult.error`, one message per line up to 10, then a single
  `skipped N unusable line(s); last: ...` summary - so 11 000 junk lines cost
  one line of detail, not 11 000. `status` stays `ok`: the records that did
  parse are the tool's real output. `urlfinder` keeps its stricter rule (a line
  with inner whitespace or a non-web scheme is skipped silently, anything else
  is still a parse error), because its input is an archive, not a live page.
- **Per-tool runtime caps (2026-11-18; deleted by D52, see 4a2c).** `hakrawler`
  was capped at 120 s and `subjs` at 60 s: on the sakec.ac.in scan both hit the phase budget with 0
  items and owned the whole `urls` stage. A capped run keeps its partial stdout,
  records `ok N` with `capped at <n>s; kept partial output` in the detail
  column, and never reports `timeout` - which stays reserved for a tool that
  produced nothing usable before the cap.
- **subjs adds no `.js` filter.** The tool prints JavaScript files only; a second
  filter would drop a `.php`-suffixed script endpoint it deliberately reported.
- **urlfinder is a passive aggregator in an active stage.** It queries third
  party archives and never returns to the target; `-all` is passed, `-rl` is not
  (reconkit has no pacing, and the tool's per-source defaults stay). A source
  failure does not fail the run - exit stays 0 and the URLs found so far are
  printed - so partial results are already the normal path. Archived rows can be
  junk rather than URLs (`http://host/path;curl d9q...oast.live`); a line with
  inner whitespace is skipped, not stored.

**tlsx cert metadata (Ruling A, 2026-11-17).** Cert metadata (expiry, issuer,
self-signed) is extracted by tlsx but not persisted - future addition if operator
needs it (would require schema 7 + new HostStatusRecord fields). Liveness and
SAN discovery are the only stored facts. The SANs reach `subdomains` through
`Engine._persist_live_discoveries` (PIT-49), which persists every
`SubdomainRecord` a live pass discovered, not only the hosts it was given.

### 4a4. Adapter wave 4 (2026-11-17): unfurl, wafw00f, whatweb, httpx_tech

| Tool | Stage | Invocation | Records |
|---|---|---|---|
| `unfurl` | urls | `-u format '%s://%d%:%P%p?%q'`, URLs on **stdin** | `UrlRecord` per canonical URL (normalized and deduplicated) |
| `wafw00f` | tech | `-a -f json -o - <url...>` (positional URLs) | `HostStatusRecord(UNKNOWN, waf=<firewall>)`, only when `detected: true` |
| `whatweb` | tech | `--quiet --log-json=- --no-errors --color=never -a 1 <url...>` | `HostStatusRecord(UNKNOWN, tech=[plugin names])` |
| `httpx_tech` | tech | inherits `httpx`'s command: `-json -silent -td ...` (one URL per host) | `HostStatusRecord(UNKNOWN, tech=<tech>, waf=<cdn_name>)`, no record when both are empty |

`waf_priority` per tool (D12): `wafw00f` 100, `cdncheck` 80, `whatweb` 50,
`httpx_tech` 20; every other entry defaults to 0 (for example the `httpx`
`cdn_name`, which a dedicated detector then corrects).

**`unfurl` is `mode: passive` in `tools.yaml`** (the registry is the source of
truth, as for `gau` and `urlfinder`), so it runs in all three modes even though
this brief listed it as active; that is a reported deviation, not a code change.
Real `unfurl` behaviour on this box, verified by hand:

- `-h` is the identity probe: the usage goes to **stderr** with exit 0
  (`Format URLs provided on stdin`, `Usage:\n  unfurl [OPTIONS] [MODE] [FORMATSTRING]`)
  and there is no `-version` (`flag provided but not defined: -version`, exit 2).
- Choice (b) from the brief: the adapter emits **full URL lines**, not
  components as metadata. `format '%s://%d%:%P%p?%q'` rebuilds one canonical
  URL per input line, which is what a urls stage stores; components would need a
  new model field for facts nothing consumes yet (schema change, rejected).
- Real quirk: `%?` is unconditional, so a bare root comes back as
  `https://host/?`. The adapter runs `normalize_url()` on every line, which drops
  the empty query, and `-u` plus the parser's dedupe collapse repeats.
- Honest limitation: the urls stage hands over hostnames (as for every crawler),
  so unfurl only sees the two scheme roots per host. Its real value is
  canonicalising a URL list; that needs an earlier urls tool's output plumbed
  into the next urls pass, which this build does not do.

**`whatweb`: `--log-json=-` needs `--quiet`.** Verified on the real binary:
`--log-json=-` alone writes the JSON to stdout and then its one-line brief to
the same closed stream, printing a Ruby traceback (`logging.rb:89:in 'write':
closed stream (IOError)`) and exiting 1. `--quiet` (real help: "Do not display
brief logging to STDOUT.") removes that second write, so `--quiet
--log-json=-` prints only the JSON array and exits 0. Plugin names are the
technologies, minus the informational plugins in `NON_TECH_PLUGINS` (IP,
Country, Title, Cookies, HttpOnly, Script, Email, HTML5 and the other
response-describing matches); a plugin name that describes the response is not
software and would otherwise be stored as a technology.

**`wafw00f`: a `detected: false` entry is silence.** The JSON is one object per
URL with `detected`, `firewall`, `manufacturer`, `trigger_url`; only a true
`detected` becomes a record, and `manufacturer` is not stored (it is the
vendor of the firewall name, not a technology). An empty output or a run where
nothing was detected is `ok` with zero records, like `cdncheck`.

**`httpx_tech` shares the `httpx` invocation.** It subclasses `HttpxAdapter` and
overrides only `name`, `stage` and `parse_output`; the command (including `-td`),
stdin, child env, identity probe and the Python-vs-ProjectDiscovery check of
01daa8b all come from `httpx_tool.py` through the new public helpers
`httpx_hosts()` / `httpx_fqdn()`. There is exactly one command builder: a change
to the `httpx` invocation can no longer reach one stage and miss the other.
`parse_output` keeps only `tech`/`cdn_name` (a host with neither a technology
nor a CDN/WAF name produces no record) and every record is `UNKNOWN`, because
reading technology says nothing about liveness (D11).

**Technology merge semantics (answer to the wave-4 question, unchanged code).**
Two rules apply, and they are not symmetric:

- **`tech` is a merged list.** Within a pass `Engine._persist_tech`
  (engine.py:1712) unions every record's `tech` for the same host; across passes
  `Store.update_host_extras` (store.py:612) keeps the row's existing list and
  appends names it does not have. Two tech tools therefore add up, order is
  first-writer-first, and no tool can remove another's finding.
- **`waf` is a single string, merged deterministically by `waf_priority`**
  (D12, owner ruling 2026-11-17). Every `tools.yaml` entry may carry
  `waf_priority` (int, default 0): `wafw00f` 100, `cdncheck` 80, `whatweb` 50,
  `httpx_tech` 20, everything else 0. The highest priority always wins, so
  completion order can never change the stored name and a rerun cannot flip it.
  Equal priorities keep the first writer - inside a pass the first record in
  `results` order, across passes the value already stored; the first detection
  always fills an empty column. `Store.update_host_extras` therefore compares
  against the stored `waf_priority` (schema 7) instead of overwriting, and
  `_persist_tech` picks the pass's highest-priority detection before calling it.
  The three names are still not merged into a list: a list column was rejected
  as a wider schema change than the ruling asked for.

### 4a5. Adapter wave 5 (2026-11-17): nuclei, subzy

Both are `vulns` / `active` / `core`. The stage is not part of `--active`
(`MODE_STAGES`, locked at `756af8e`), so these adapters run under `--full`, the
explicit `reconkit vulns` stage command, or an explicit `--tools` name.

| Tool | Invocation | Records |
|---|---|---|
| `nuclei` | `-l <hosts file> -jsonl -silent -nc -duc -or -tags takeover,exposure,misconfig` | `FindingRecord(kind=<template type>, severity=<info.severity>, template_id=<template-id>, evidence=<matched-at>)` |
| `subzy` | `run --targets <hosts file> --hide_fails --output <json file>` | `FindingRecord(kind="takeover", severity="high", title=<service/documentation>)` for `vulnerable: true` entries only |
| `ffuf` | `-u FHOST/FUZZ -w <hosts file>:FHOST -w <wordlist>:FFUF -mode clusterbomb -of json -o <json file> -mc 200,204,301,302,307,401,403 -t 50 -s -noninteractive` | `FindingRecord(kind="path", severity="info", title=`<status> <path>`, evidence=<url>)` for every match |

**`ffuf` is content discovery, not exploitation.** It replaces `FUZZ` with each
line of `src/reconkit/data/wordlists/common.txt` (~110 paths, packaged as
package data - D13) and reports the responses that match `-mc`. Every record is
`severity="info"` with `kind="path"`: a path that exists is not a confirmed
vulnerability, and the operator decides what matters. `--ffuf-wordlist PATH`
replaces the packaged list; a missing file is a failed result, never a silent
fallback. Hosts travel as the `FHOST` wordlist (one ffuf process for every
host, both schemes via `crawl_urls`), no `-k` is passed, and `-t 50` is
concurrency, not pacing (D3). Two details came from real runs: the URL must use
the keyword the wordlist declares (`-u FHOST/FFUF` with `-w ...:FFUF`; `FUZZ`
there makes ffuf exit 0 with `Keyword FFUF defined, but not found ...` and zero
results - a silent empty answer), and the `FHOST` values must not end in `/`
because the template joins literally (`https://host//admin` otherwise).

**Findings are not persisted yet.** `FindingRecord` and the `vulns` stage
existed as a contract since Phase 2, but `_persist_stage` has no `VULNS`
branch and `docs/04` still defers the `findings` table, so a vulns adapter's
records reach the `--json` document and the run's raw output file and stop
there. That is the documented state of the stage, not new behaviour: making
them durable is the deferred findings table (schema + report work), and no
adapter invented a second persistence path for it.

Verified on this box (`nuclei` v3.11.1 in `~/go/bin`, `subzy` v1.2.0 in
`~/.reconkit/bin`):

- `nuclei -version` prints `[INF] Nuclei Engine Version: v3.11.1`; `-h` lists
  `-l, -list`, `-j, -jsonl`, `-silent`, `-nc, -no-color`, `-duc,
  -disable-update-check`, `-tags`, `-severity`, `-o, -output`, `-rl`.
- `nuclei` reads its target list from a file (`-l`), so the adapter writes
  `nuclei-hosts-<pid>.txt` into the run workspace and removes it in `finally`
  (gospider/webanalyze precedent). `-duc` is always passed: without it nuclei
  checks for template updates before scanning and can block on the network.
- **Tags, not severity, bound the blast radius.** `tools.yaml` already says
  `Run safe tags only (takeover, exposure, misconfig)`, so the adapter passes
  exactly those three and no `-severity` filter: severity is stored on the
  record, and dropping findings by severity in the adapter would silently
  discard evidence the operator asked for. `-rl` is never passed (no pacing,
  D3); nuclei's own default rate applies.
- `nuclei`'s severity vocabulary includes `unknown` (42 installed templates),
  which the `FindingRecord` literal now accepts; anything else is a
  `ParseError`, so a changed vocabulary fails loudly rather than being guessed.
- `subzy run --help` lists `--targets` (file), `--target` (comma list),
  `--output` (JSON file), `--hide_fails`, `--concurrency`, `--timeout`,
  `--vuln`, `--https`, `--verify_ssl`. `subzy version` prints
  `subzy version: v1.2.0`.
- **Two real-output traps, both found by running the tools, not by reading
  `-h`:** (1) nuclei's `host` field is `host:port` when it probed a non-default
  port (`demo.testfire.net:443`), not a URL - the first real run failed with
  `nuclei: invalid host 'demo.testfire.net:443'` and the fix is `finding_host()`
  (PIT-53); (2) subzy writes the literal `null`, not `[]`, when nothing
  matched, which the first real subzy run rejected as "not a JSON array".
  Fixtures written from a doc or a happy-path sample show neither.
- **`subzy` writes its findings only to the `--output` file** - stdout carries
  log lines (`[ * ] Loaded 2 targets`, `[ * ] Saved output to "..."`), and the
  JSON array is in the file. The adapter therefore implements the new
  `read_output(ctx)` hook: after a successful run the base flow asks the
  adapter for the document to parse (and to store as the raw output) instead of
  `stdout`, so timeout/failed/parse handling stays in one place. A
  `--output`-only tool is a real class (`subzy` now, `ffuf`/`dnsreaper` later),
  which is why the hook is generic rather than a `subzy`-only `run()` override.
- **`post_command(ctx)` is the read-back hook (added 2026-11-18, amass).** Some
  tools keep their findings neither on stdout nor in a file they were told to
  write, but in their own local database, and expose them only through a second
  subcommand. `post_command` returns that subcommand's argv, or `None` (every
  adapter but `amass`). The base flow runs it through `core/runner.run_exec`
  right after a successful primary run - only when `read_output` returned `None`
  - and hands its stdout to `parse_output`, storing both streams as the raw
  output. A read-back that times out or exits non-zero turns the tool into
  `FAILED` with a `read-back` error, because findings that can not be read back
  produced nothing usable; it is not a silent zero. Both commands run under the
  same per-tool timeout and child environment, so `needs_home` applies to the
  read-back too.
- subzy needs `HOME` (`needs_home = True`): it stores
  `~/<subzy>/fingerprints.json` beside the user's config and writes it on first
  run.

### 4a6. Adapter wave 6 (2026-11-17): ports stage - nmap, rustscan, smap, masscan

The ports stage was the last one with a partial pool (`pyscan`, `naabu`). These
four close it. `ports` is not part of `--active` (`MODE_STAGES`, locked at
`756af8e`), so the stage runs under `--full` or the explicit
`reconkit ports` / `--tools` name, exactly like `vulns`.

| Tool | Invocation | Records |
|---|---|---|
| `nmap` | `-sV -Pn -oX <xml file> --open` + `--top-ports 1000`, or `-p <list>` when `--ports` is given, then the hosts | `PortRecord(fqdn=<first hostname for the host>, ip=<address>, port=<portid>, state="open", service=<service@name>, version=<product + version>, source="nmap")` |
| `rustscan` | `-g -n --ulimit 5000 -a <comma-separated hosts>` + `-p <list>` or `--top`, one process for the whole stage | `PortRecord(fqdn=<the only input host, else the printed address>, ip=<printed address>, port=<port>, state="open", source="rustscan")` |
| `smap` | `-iL <hosts file> -oJ <json file>` (passive: Shodan data, no packets) | `PortRecord(fqdn=<user_hostname>, ip=<ip>, port=<port>, state="open", service=<ports[].service>, source="smap")`, filtered to `ctx.ports` when `--ports` is given |
| `masscan` | `<ip targets...> -p<list> --rate 1000 -oL <list file>`, **root only** | `PortRecord(fqdn=<ip>, ip=<ip>, port=<port>, state="open", source="masscan")` |

**No `-sS`, no `sudo`, no pacing.** `nmap` is invoked without a scan type: run
unprivileged it does a `-sT` connect scan, which is the default this build
documents (docs/01 Feature 5), and the adapter never asks for `-sS`, `-O` or
scripts. `nmap -sV` is what makes it a verifier: its service/version string arrives on the
`PortRecord` (`service`, `version`), `_persist_ports` writes it to
`ports.service` / `ports.version`, and it is the fingerprint section 5 raises
confidence for. A real run on testfire.net stored
`Apache Tomcat/Coyote JSP engine 1.1` against 80, 443 and 8080. `--rate 1000` is masscan's own packet
rate, not reconkit pacing (D3): masscan does nothing without a rate and 1000
packets/s is its documented default. The other three get no rate flag.

**`--ports` maps to all four, but not identically.** `nmap` swaps
`--top-ports 1000` for `-p`; `rustscan` swaps `--top` for `-p` (both verified in
`-h`/`--help`); `masscan` has no top-ports list at all, so it gets `-p<list>`
when the operator supplies one and the `pyscan` `DEFAULT_PORTS` set otherwise
(12 ports, stated on the record rather than silently scanning 65535). `smap`
cannot be told which ports to scan - it reports what Shodan already observed -
so `--ports` filters its records after parsing. That filter is the one place the
flag is applied to output instead of input, and it is deliberate: dropping the
filter would let a passive answer store ports the operator excluded. A port a
passive tool reports but no active tool confirmed stays `LOW` (section 5).

**`masscan` needs root, and reconkit never asks for the password.** masscan uses
raw sockets: on this box, as `kali`, it exits 2 with `[-] FAIL: permission
denied` and `[hint] need to sudo or run as root or something`. Nothing in the
build shells out to `sudo` (AGENTS rule 1, and a scan must not stop mid-run for
a password) and nothing calls `setcap` on the operator's binary. Running
`sudo reconkit run ...` (or a one-time `sudo setcap cap_net_raw+ep
/usr/bin/masscan`, the operator's choice on their own box) is what enables it;
both are operator actions documented here, not adapter behaviour.

The skip itself happens at **selection**, from the `needs_root: true` the
registry already carried: `ToolSpec.needs_root` is parsed (a non-bool is a
`ConfigError`) and a non-root process skips the tool with `requires root /
sudo`, recorded in `tool_runs` and listed in `stages[].skipped` like any other
skip. That placement is deliberate - the alternative, letting the adapter return
`ToolStatus.SKIPPED` at run time, made every full run of a normal user exit 5
(`partial`), because `_exit_code` counts any non-OK executed tool as a failure
while this is an environment fact, not a broken tool. `requires root / sudo` is
not one of the two absence-only gap reasons, so the ports stage keeps running
its other tools and the run stays `complete`. The adapter keeps the same
effective-uid guard as a second line of defence (`running_as_root()` from
`adapters/base.py`, shared with the selection rule): invoked directly it returns
`SKIPPED` with the same reason instead of spawning a masscan that can only fail.

**`rustscan` does not need `nmap`, verified rather than assumed.** rustscan's
`-g/--greppable` mode prints `Cartesian ...`-free machine output
(`65.61.137.117 -> [443,80,8080]`) and its own `--help` says `Greppable mode.
Only output the ports. No Nmap.` Running it with `PATH` emptied of `nmap`
returned the same line (2026-11-17), so the adapter uses `-g` and there is no
"requires nmap" skip to implement: the service detection lives in the `nmap`
adapter (`-sV`), which is where a version fingerprint belongs. rustscan 2.3.0
has no `-- <nmap args>` passthrough, so the alternative (drive `nmap -oX`
through rustscan) is not available in this version and is not pretended. Because
`-g` prints the **resolved address**, the adapter uses the single input host as
the `fqdn` when the stage ran one host, and the printed address otherwise (the
same IP-keyed fallback `naabu` documents in scope mode). `-n/--no-config` keeps
a user's `rustscan.toml` from changing the scan, and `--ulimit 5000` is the
value its own docs recommend for the open-file limit.

**Output files, not stdout, for three of the four.** `nmap -oX`, `smap -oJ` and
`masscan -oL` all write a document; the adapters implement `read_output(ctx)`
(the `subzy`/`ffuf` hook) and parse the file, so log lines on stdout cannot
corrupt a parse. `rustscan -g` is the exception: its machine output is stdout.

Verified on this box (`nmap` 7.991 in `/usr/bin`, `rustscan` 2.3.0 in
`~/.reconkit/bin`, `smap` 1.0.0-beta in `~/.reconkit/bin`, `masscan` 1.3.2 in
`/usr/bin`):

- `nmap -sV -Pn -p 80,443,8080 --open -oX out.xml testfire.net` produced
  `<port protocol="tcp" portid="80"><state state="open" .../><service
  name="http" product="Apache Tomcat/Coyote JSP engine" version="1.1"/>` for
  all three ports; the fixture keeps that shape. The parser reads
  `.//host` elements, takes `address[@addrtype="ipv4"]` (or `ipv6`), the first
  `<hostname name=...>`, and only `state[@state="open"]` ports. Missing address
  or portid is a `ParseError`, never a guessed record.
- `masscan --help` states `'-p80' is the same as '--ports 80'`, and
  `/usr/share/doc/masscan/README.md.gz` documents the list format as
  `open tcp 80 XXX.XXX.XXX.XXX 1390380064`; the adapter parses exactly that
  (state, protocol, port, address, timestamp) and ignores the timestamp. The
  manpage accepts **IP addresses and ranges only** as targets ("anything on the
  command-line not prefixed with a '-' is assumed to be an IP address or
  range"), so the adapter resolves each `ctx.hosts` name locally and keeps only
  addresses `ctx.ip_allowed` permits (docs/05 rule 6, the `pyscan` rule) - a
  hostname is never handed to masscan to resolve a second time. With no
  resolvable, permitted address the adapter skips instead of scanning nothing.
  **`masscan`'s own JSON output (`-oJ`) is unverified on this box**: producing
  it needs root, `sudo -n` asks for a password here, and this session does not
  run interactive sudo, so the adapter writes the list format whose example is
  installed in `/usr/share/doc` rather than a JSON schema nobody has seen.
- `smap`'s JSON is an array of hosts (`ip`, `hostnames[]`, `user_hostname`,
  `ports[{port, service, protocol, ...}]`); the fixture is the real response for
  `testfire.net` (ports 80, 443, 8080), trimmed. `user_hostname` is the name
  the operator asked for and is what the record stores, so a passive answer
  joins the same host rows the active tools write.
- `nmap` was launched as `kali` and nmap still chose `-sS` on this box (its
  binary carries `cap_net_raw`), which is the OS packaging's choice, not ours:
  the adapter passes no scan type, so a host where nmap is unprivileged gets a
  connect scan and no root is ever required from the operator.

### 4a7. Adapter wave 7 (2026-11-17): subs stage - urlscan, amass, findomain, chaos, github_subdomains

All five are `subs` / `passive` / `core` and return `SubdomainRecord`s. This
closes the stage: every `subs` tool in `tools.yaml` now has an adapter
(`dnsreaper` stays unadapted by D15).

| Tool | Invocation | Notes |
|---|---|---|
| `urlscan` | `GET https://urlscan.io/api/v1/search/?q=domain:<target>&size=100`, optional `api-key` header | `kind: http`, no binary; names from `results[].page.domain` then `task.domain` |
| `amass` | `enum -d <target>` (v5 subcommand) | stdout is decorative; only lines that validate as hostnames become records |
| `findomain` | `-t <target> -q` | bare names on stdout, one per line, no output file |
| `chaos` | `-d <target> -silent -duc` | **requires `PDCP_API_KEY`**; skipped, not failed, without it |
| `github_subdomains` | `-d <target> -o <workspace file>` | **requires `GITHUB_TOKEN`**; findings read from `-o`, never the CWD default |

**A key that the tool cannot run without is a selection skip, not a failure.**
`chaos` exits 1 with `[FTL] PDCP_API_KEY not specified` and
`github-subdomains` has no keyless path either, so both adapters declare
`requires_env` (a class attribute next to `needs_root`) and the engine skips
them at selection with `requires <NAME>`, recorded in `tool_runs` and
`stages[].skipped`. The reason is not one of the two absence-only gap reasons,
so the stage keeps running its other tools and the run stays `complete` (D18).
`--no-keys` skips them the same way. This is deliberately not a runtime
`ToolStatus.SKIPPED`: an executed non-OK tool counts as failed and would exit 5
for a credential the operator can supply (the wave-6 lesson, D14).

Verified on this box (urlscan.io search API without a key, amass 5.1.3,
findomain 11.0.0, chaos 0.5.2, github-subdomains with no version flag):

- **urlscan is `kind: http`; `/usr/bin/urlscan` is a different program** (the
  Python "parse and display URLs" CLI). The registry row needs no binary, so the
  adapter never looks at `PATH`. A keyless search returns `results[]` {HTTP 200},
  and `URLSCAN_API_KEY` is for submissions - the adapter sends it when present
  and still runs when it is not.
- **amass v5's stdout carries no findings at all.** A real `amass enum -d
  testfire.net` prints a `Session Scope` block (`Session Scope`, `FQDN:`, the
  target) and nothing else, and `amass --version` prints only `v5.1.3` with no
  program name. The identity probe is therefore `amass enum -h` (banner:
  `OWASP Amass Project - @owaspamass`).
  v5 is a thin client for its own engine (`POST /api/v1/sessions`), and the
  findings land in that session, not on stdout. Corrected 2026-11-18 from a real
  completed run (was: "documented from the header shape, not from a completed
  run"): the raw capture of run 84 was the header alone while 187 names were
  scanned on stderr, so the parser turned the header's target into one record -
  **amass always reported exactly 1 item, always the target itself**. The
  read-back is `amass subs -d DOMAIN -names`, which prints one name per line from
  the engine's graph database; the adapter declares `post_command` for it (see
  the hook note above) and the parser still tolerates the header, since a future
  version may print it again. `subs` returns every name the database holds for
  the domain, not only this run's additions, and the engine dedupes it. `-o`
  does not exist in v5 (`-oA`, `-dir` do) and `-dir` only writes the config
  templates, so neither is a findings channel.
- **`dig` prefixes every comment and diagnostic with `;`, and a real run emitted
  one** (2026-11-18): `;; communications error to 192.168.31.1#53: timed out`
  from the local resolver made the strict parser fail the whole tool
  (`dig failed 0 item(s)`). Those lines are now skipped, so a resolver timeout
  costs that lookup only; a line that is not `;`-prefixed and still does not
  parse stays a hard `ParseError`.
- **findomain writes nothing to the CWD** without `-o`/`-u`; a real run printed
  35 names for testfire.net.
- **github-subdomains' `-o` default is `<domain>.txt` in the current directory**,
  so the adapter always passes a workspace path and reads that file
  (`read_output`), leaving the operator's directory untouched. `-version` is not
  defined (`flag provided but not defined: -version`), hence the `-h` probe.

`dnsreaper` (D15) is not adapted: no PyPI package, no `setup.py`, no console
script - it is `main.py` + `requirements.txt` and would need a script-launching
adapter kind. `subzy` covers takeover; revisit only if that kind is added.

### 4a8. Adapter wave 8 (2026-11-17): dns - dig, massdns, puredns; shots - gowitness; vulns - nikto

`dig`, `massdns` and `puredns` are `dns` / `passive` / `core` and return
`SubdomainRecord`s with addresses; `nikto` is `vulns` / `active` / `opt_in` and
returns `FindingRecord`s; `gowitness` is `shots` / `active` / `opt_in` and
returns `UrlRecord`s for the URLs it actually screenshotted. After this wave the
registry has **48 tools and 44 adapters**.

| Tool | Invocation | Notes |
|---|---|---|
| `dig` | `+noall +answer -f <workspace hosts file>` | one process per stage; labelled answers keep the name next to the address |
| `massdns` | `-r <resolvers> -t A -o S -w <workspace file> <workspace hosts file>` | `S` (simple) lines; finds are read from `-w`, never stdout |
| `puredns` | `resolve <hosts file> -r <resolvers> -b <massdns> -w <workspace file>` | shells out to massdns; `-b` is always the absolute path |
| `gowitness` | `scan single -u <url> -s <screenshots dir> --screenshot-format png` | one process per URL (https, then http if no PNG); files plus JSONL manifest, **no DB rows** (D17); `shots` is `--full` only (D19) |
| `nikto` | `-h <host> -nointeractive -Format json -output <workspace file>` | one process per host (`-h` takes one target), each with its share of the remaining stage budget (2026-11-18: a single slow host used to consume the whole budget and the engine cancelled the tool with 0 results); `severity="info"`, `kind="nikto"` |

**`dig` stays next to `dnspython` on purpose.** `dnspython` is the resolver with
the wildcard probe and dangling-CNAME logic; `dig` is an independent second DNS
source for the same names, which is what lifts a `DNS_ONLY` host's confidence
from LOW to MEDIUM (section 5). It is deliberately narrow - A/AAAA/CNAME only -
and it is faster over a list because `-f` resolves the whole file in one
process.

**Resolvers are packaged (D16).** `massdns` and `puredns` need a resolver list;
the build ships `src/reconkit/data/resolvers.txt` (16 public resolvers, no
download at runtime) and `--resolvers PATH` replaces it. A missing file is a
failed result, never a silent fallback to the system resolver. `puredns` also
needs `massdns`: the adapter resolves it with the same lookup every tool uses
(`~/.reconkit/bin` first, then `PATH`) and passes `-b <abs path>`, because a
child process sees only the env keys the engine passes and a bare `massdns`
would not be found.

**Screenshots are per-run files, not database rows (D17).** `gowitness` writes
`results/<target>/<UTC stamp>/screenshots/*.png` plus `screenshots.jsonl` beside
that folder, one `{"url", "path", "timestamp"}` object per line. There is no
`screenshots` table and no `ScreenshotRecord`; `reconkit status` and
`reconkit diff` do not show screenshots. The adapter gets the results root from
the engine (`RunContext.results_dir`, the configured `results_dir`), so `--config`
and the reports agree and the adapter never reads `config.yaml` itself.

**The `shots` stage is full-only (D19, owner ruling).** `Stage.SHOTS` is in
`STAGE_ORDER` between `urls` and `vulns` (screenshots need the alive hosts the
live stage produced, and a slow browser must not delay the findings stage) and
therefore in `MODE_STAGES["full"]`; it is in neither `passive` nor `active`, and
there is no `shots` stage command. `gowitness` is `tier: opt_in`/`mode: active`,
and a `full` run implies `--include-noisy`, so it runs there; `--tools gowitness`
bypasses the tier gate in the same run.

**gowitness requires a Chrome/Chromium binary on the box for PNG output.** Kali:
`apt install chromium` (the operator installs it; docs/10 section 2 is
provenance only). Without Chrome, gowitness returns 0 items with a clear error
string (`failed to initialize chrome context`), not a failure - the adapter
works, the screenshot step can't produce images. On this box `/usr/bin/chromium`
is installed but gowitness execs `google-chrome` and the adapter never guesses a
`--chrome-path`; even a manual run with `--chrome-path /usr/bin/chromium`
reported `have-screenshot=false`, so the PNG/manifest path is proven by the
adapter test with a stand-in binary, not by a real screenshot.

**The no-browser case is a gap, not a failure (D35, 2026-11-18).** When a run
produced zero screenshots **and** gowitness's own output names a missing browser
(`failed to initialize chrome context`, `chrome context`, `no chrome`, `chrome
not found`, `could not find chrome`, `browser is not installed`, `executable not
found in $path` - one tuple, `gowitness.NO_BROWSER_MARKERS`), the adapter returns
`ToolStatus.GAP` with `no chromium; 0 screenshots`. The run exits `0` and the
gaps block names it; `doctor` grows a one-row **Browser** table saying `chromium
missing` and `shots will produce 0 screenshots`. Zero PNGs **without** such a
message stays `ok 0` with the per-host note, because the tool then did its job and
the page simply produced nothing.

Verified on this box (DiG 9.20.30, massdns 1.1.0, puredns v2.1.1,
gowitness 3.2.2, Nikto 2.6.1):

- `dig +noall +answer -f hosts.txt` printed
  `testfire.net. 75048 IN A 65.61.137.117` and
  `www.testfire.net. 72983 IN CNAME testfire.net.`; `+short` was rejected as a
  parse source because it drops the name and an address can then not be
  attributed to a host.
- a real massdns run with the packaged resolvers printed
  `demo.testfire.net. A 65.61.137.117`, `testfire.net. A 65.61.137.117`,
  `www.testfire.net. CNAME testfire.net.`; `massdns --version` prints only
  `massdns ` (no number), so the identity probe is `--help`.
- `gowitness` 3.2.2 takes `scan single -u <url> -s <dir>`; **its screenshot
  format defaults to `jpeg`**, so the adapter passes `--screenshot-format png`
  (D17 files are `.png`). A real run on this box answered the probe (status 200)
  but reported `failed to initialize chrome context: exec: "google-chrome":
  executable file not found in $PATH`, so it honestly produced no file and the
  result carries `no screenshot (no browser available?)` as its error text. The
  adapter never guesses a `--chrome-path`.
- `nikto -h` lists `-Format+` with `json JSON Format`, so **the JSON path is the
  one taken** and the pre-approved plain-text fallback was not needed. A real run
  wrote `[{"host", "ip", "port", "vulnerabilities": [{"id": "999967", ...}]}]`.
  Every finding is `severity="info"`: a Nikto message is a lead for the
  operator, not a confirmed exploit, and the tier is already `opt_in`.

### 4b. Per-tool support for the injected parameters

| Parameter | `httpx` | `pyprobe` | `pyscan` | `naabu` | Every other adapter |
|---|---|---|---|---|---|
| `--ports` | - (live stage) | - | yes, `ctx.ports` replaces `DEFAULT_PORTS` | yes, `-p` (verified: `naabu -h` `-port, -p string`) | `nmap`/`rustscan`/`masscan`: `-p <list>` instead of their top-ports default; `smap`: filters its passive records |
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
| nuclei, subzy | vulns | active | core | no | no / no / yes |
| dnsreaper | vulns | active | core | no | **no adapter (D15)** |
| nikto, ffuf | vulns | active | opt_in | no | no / no / yes |
| gowitness | shots | active | opt_in | no | full only (D19) |
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
- **Port-scan pre-check (Phase 2):** port scans require a stored `live` result for the host. If none is stored, skip the host and print a warning (`run live first`). If the stored `HostStatusRecord.waf` is set (from the `httpx` CDN/WAF JSON fields), skip it as CDN/WAF-fronted. `cdncheck` and `wafw00f` both write that field
  (wave 2 and wave 4), so either tool's match can trigger the skip.
- **Ports:** `open` if at least one tool saw it open. If one tool saw open and another (that scanned the same port) saw closed, store `unconfirmed` with both in `port_sources`. A service fingerprint (`nmap -sV`, a banner) raises confidence by one level and is stored in `ports.service` / `ports.version`; when two tools disagree (`nmap` says `http`, `smap` says `http?`) both fields stay empty rather than picking a winner, and a fingerprint never lifts an `unconfirmed` state. Before wave 6 `_persist_ports` discarded `service`/`version`, so the bump never fired; it now does.

### Which status code a host row keeps (D69, 2026-11-19)

The live pool has adapters that do not observe a status (`httprobe` prints a
URL, `tlsx` reads a certificate) and adapters that do (`pyprobe`'s local probe
and the `httpx` binary). `_persist_live` used to pass the **first ALIVE record
in completion order** to `_write_host`, so the stored `status_code` depended on
which tool finished first: a 200 from `pyprobe` was discarded whenever
`httprobe`'s statusless record landed first. Measured on `slice.bank.in` run
203: four live tools, 9 ALIVE hosts, every `status_code` `NULL`, while the URL
probe stored 200 for `https://b.slice.bank.in/` in the same scan.

One rule now picks the record whose fields the row keeps:

1. a known 2xx beats a 3xx, which beats any other known code, which beats no
   code at all;
2. between two codes of the same class the lower code wins (`200` over `204`),
   and the tool name breaks a remaining tie, so completion order can never
   change a row;
3. a record with no code never displaces one that has a code: the merge only
   ever fills a status, it never clears one.

The chosen record supplies `status_code`, `title`, `location` and `detail`; the
state itself still comes from `decide_host_state`, and `tech`/`waf` are still
merged by the `tech` stage (`Store.update_host_extras`), which never writes
`status_code` (docs/04 section 5).

### Passive ports (smap)
Stored with source `smap` and confidence LOW until an active scan confirms; never counted as active proof.

### www / non-www deduplication (D22, 2026-11-18)

`www.example.com` and `example.com` are usually the same website, and a scan
that lists both inflates the "ALIVE" count. A post-`live` pass,
`Engine._dedupe_www_variants()`, reads the stored host rows of the current run
and only writes **metadata** on the newest status row of each host:

| Situation | Result |
|---|---|
| both ALIVE, one 3xx (301/302/303/307/308) and the other 2xx | the 3xx name is `duplicate_of` the 2xx name |
| both ALIVE, both 2xx | neither is marked; both get `www_note = "has www sibling at <other>"` (both serve content) |
| both ALIVE, the **same known** non-2xx status, sharing an IP | `www.X` is `duplicate_of X` (the bare name is preferred). `NULL` is "no status observed", not a shared status, so a pair with no code on either side is never marked |
| both ALIVE, same status, different known IPs | neither is marked; both get `www_note = "www variant on a different server"` |
| both ALIVE, same status, an IP set unknown for either name | nothing (no DNS evidence, so no claim about the server) |
| one ALIVE, the other DEAD/DNS_ONLY/SHUT_DOWN/UNKNOWN | nothing: a dead variant is a name that does not resolve, not a duplicate |
| only one of the pair present | nothing |

**It never changes host state, confidence or any count query.** `state`,
`status_code`, `confidence` and `source_count` are exactly what the live and dns
stages decided; `diff`, `status` and the confidence formula are untouched. The
only visible effects are the new "Notes" column in the results table (added
only when some row has a note, so an ordinary table keeps its six columns), the
`N hosts (M unique after www-dedup)` summary and the `duplicate_of` field plus
`www_dedup` block in `--json` (docs/02 section 5).

### URL-derived hosts: one bounded resolve after `urls` (D58, 2026-11-19)

The `urls` stage stores URLs, not hosts. A name that only an archive reported -
no `subs` tool and no `dns` answer - therefore had no `subdomains` row, no state
and no line in `report.json`, and in passive mode nothing ever read its URL back
(measured 2026-11-19: 3 such hosts, 43 URLs, on `slice.bank.in`). After `urls`
completes, the engine runs exactly one extra pass for the hosts in that run's
URL rows that have no `subdomains` row (`Store.url_only_hosts()`):

| Mode | What the pass does | Log line |
|---|---|---|
| passive | `dnspython` resolves the hosts; `_persist_dns()` applies the normal state rule | `urls: N host(s) found only in URLs; resolved` |
| active / full | the same resolve, then `pyprobe` probes the in-scope ones through `_persist_live()` | `urls: N host(s) found only in URLs; resolved, M now ALIVE` |

Rules that keep it bounded and honest:

- **One pass, no iteration.** Candidates are read once before any DNS work and
  are never re-extracted, so a host that shows up during the pass cannot start a
  second round. The pass is not a stage: no `scan_runs` row, no `tool_runs` row,
  and the hosts it writes record `first_seen_run` as the `urls` run that named
  them.
- **Passive does not contact.** Resolution is DNS, which the `dns` stage already
  does in passive; the live probe runs only when `--active`/`--full` is set.
- **The gate applies.** The active live check calls `require_active()` for the
  new hosts first; a dropped host is reported and never probed.
- **No new config key.** The pass runs under a stage budget - `urls` for passive,
  `url_probe` for active/full - and a budget that fires leaves rows untouched
  and says so; it never fails the run.
- **Origin label.** Rows keep `provenance = 'dns'` and carry one
  `subdomain_sources` entry whose tool is the sentinel `url-derived` (not a
  `tools.yaml` tool), so `report.json` sources show where the name came from.
- **Mock.** Both steps use the existing adapters in mock form: fixtures, no
  network, no subprocess. A missing fixture means no records and the found count
  is still reported.

### What a saved report reads back (D62, 2026-11-19)

A report never asks a tool for anything. The domain tree and the URL block are
read from what the run already stored, through `Store.url_report_rows()`:
`urls.url` (as stored) and `urls.status_code` (`NULL` = never probed) joined in
Python with `subdomains.state` by the same `_url_host()` parser the D55 filter
uses; a host with no `subdomains` row reports `UNKNOWN`. `Engine.url_rows()` is
the only door for it, so `ui` still sees no `Store`. The cap is a report
setting (`config.yaml` `report.urls_max`), never a stage or probe bound: it
changes what is printed, never what is stored, and `urls_total` /
`urls_shown` / `urls_truncated` make a cut visible. Order inside a host:
interesting path, then a query string, then a `200`/`301`/`302`, then the rest
(docs/02 section 5).

### URL liveness probe (D23, 2026-11-18)

The `urls` stage records what the archives and the crawler returned; it never
says whether a URL still answers. The `url_probe` stage fills that in and is
**engine-owned**: there is no adapter, no `tools.yaml` entry, and no row in the
Tools table, because there is no external program to run.

| Item | Value |
|---|---|
| Position | `STAGE_ORDER` after `urls`, before `shots` |
| Modes | `active` and `full`; never `passive` (it sends HTTP) |
| Input | `urls` rows of the current target whose `status_code` is `NULL` |
| Write | `urls.status_code` = the HTTP status, `-1` when unreachable, `-2` when its certificate did not verify |
| Transport | one `GET` per URL through httpx, honest `reconkit/<version>` UA, no retries |
| Bounds | `config.yaml` `url_probe:` - `max_urls` 5000, `batch_size` 200, `threads` 100, `timeout_s` 10 |
| Off switch | `--skip-url-probe`; `--reprobe-urls` probes every stored URL, not only the `NULL` ones |
| Mock | sends nothing, leaves `status_code` `NULL`, says so on stderr |

**Transport: Python httpx, not the PD `httpx` binary (D24, 2026-11-18).** The
owner asked for a faster probe and suggested `httpx -l file -threads 100`. That
was measured and rejected: PD httpx v1.12.0 has **no `-insecure` flag** and skips
TLS verification by default (`https://testfire.net/`, whose certificate is issued
for `www.testfire.net`, returns `200`), it emits **no JSON line at all** for a URL
that fails (so "cert failed" and "never answered" are the same absence), and its
default User-Agent is a random browser string, which docs/05 rule 8 forbids. On
the same 158 stored URLs it took **9.19 s** and called the 58 certificate-invalid
URLs `200`, while the Python transport took **3.44 s** with `-2` for all 58. The
probe therefore keeps the Python client, reuses one client per pass and raises
`threads` from 50 to 100.

**DEAD-host filter (D54, 2026-11-19).** The probe skips a URL whose host the latest
state pass already recorded as `DEAD` - that host did not resolve or went silent, so
its URLs can only be paid for and thrown away. `Store.probe_candidates` applies the
filter **before** the `max_urls` limit is filled (a skipped row never eats a probe
slot) and reports how many it dropped; the engine prints
`url_probe: skipping N URL(s) whose host is DEAD` (D55 widened it to
`...whose host is unreachable`) when that number is non-zero. Only
a **known** DEAD state is enough to skip: a URL whose host has no `subdomains` row
(never resolved), whose host is ALIVE/DNS_ONLY/SHUT_DOWN/UNKNOWN, or whose host
cannot be parsed is still probed. Measured on the one sakec.ac.in run: **0 of the
2 147 `NULL` URLs** pointed at a DEAD host (2 147 -> 2 147 candidates) and 58 of
5 001 under `--reprobe-urls`; the pass's real cost is the 4 982 `-1` answers out of
5 000 probes, not dead hosts.

**DNS_ONLY hosts too (D55, 2026-11-19).** The same skip now covers `DNS_ONLY` as
well: those hosts resolved in the DNS stage but never answered an HTTP probe, so
their URLs cannot answer either. Measured on the one sakec.ac.in run: **4 916 of
the 4 982 `-1` answers (98.7%) sat on DNS_ONLY hosts** - 4 861 of them on
`www.sakec.ac.in` alone, which resolves and then times out - and **0 of the 20
randomly sampled `-1` URLs was "ALIVE host, wrong scheme"** (the 6 ALIVE-host
`-1` rows are paths that time out or reset by peer, not a scheme mismatch). With
both states skipped the unprobed candidate set goes 2 147 -> **707** (-67%) and
`--reprobe-urls` 5 001 -> 733, and the progress line reads
`url_probe: skipping N URL(s) whose host is unreachable`. Only DEAD and DNS_ONLY
skip; ALIVE, SHUT_DOWN, UNKNOWN and hosts with no row are still probed.

`-1` and `-2` are *stored answers* ("no answer" and "answered with a certificate that does not verify"), so neither is retried;
`NULL` keeps its single meaning of "not probed yet". The probe runs through the
same active-stage scope gate as every other active stage (docs/05 rule 2) and
writes one integer per URL row - no host state, confidence or `diff` input is
touched.

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

**A 404 from an external API is a gap, not a failure (D47, 2026-11-19).** crt.sh is a free third party with no SLA: on
2026-11-19 its front end answered **404** to a query it had served a second earlier (1 of 10 identical calls for
`example.com`, 0 of 10 for `testfire.net`, plus **502** on its own root), and the closing capstone exited 5 because that
404 was read as a broken tool. `external: true` in `tools.yaml` marks a tool whose every request goes to somebody else's
API (`registry.external_tools()` answers it, so there is no per-adapter flag as of D48); `crtsh`, `certspotter`, `otx`,
`hackertarget`, `urlscan`, `chaos` and `github_subdomains` carry it. For
such an adapter a whole-response 404 raises `ExternalServiceGap` -> `ToolResult(status=GAP, error="crtsh: HTTP 404")`,
so the engine records a completion gap and the run can exit 0. Nothing else moves: a 404 from a local binary or a
non-API adapter is still `failed`, a 404 inside a parsed body (a crawler's page-not-found) is untouched, and the 404 is
**not** retried - the retry in `probe_with_retry()` is for identity probes (D46), not for HTTP status.

**A timeout from an external API is a gap too (D57, 2026-11-19).** The closing 2026-11-19 run on the complete build
exited 5 over exactly one row, `crtsh: request timed out` after 30.71 s, in a 488 s run whose other 25 executed tools
were ok, gap, skipped or killed - one slow third party made a good run look broken. A third party that never answers is
the same class of "upstream is slow" as its 502, so `HttpAdapter._request` now raises through one helper,
`_timeout_failure()`: `ExternalServiceGap(f"{name}: request timed out")` when `_is_external_api()` is true, and the old
`FetchFailed` otherwise. It fires at both timeout sites, including the second attempt after a connection retry, and it
is **not** retried again. The boundary is deliberate: a `ConnectError` that survives its one retry stays `failed`,
because a refused connection can be this box's network and says nothing about the service; 400/401/403 and
`response too large` are unchanged; and local binaries never reach this path - `BaseToolAdapter.run` classifies their
captured output with `classify_external_gap`, whose pattern list has no timeout rule, so a binary stopped by the stage
budget keeps `timeout`/`failed` and exit 5. The rule lives in the adapter rather than in the text classifier for that
reason: one place per kind of evidence, no pattern that could match a tool's own "timed out" line.

**Tool classes and per-tool runtime caps (D48, 2026-11-19).** A tool's runtime cap used to be a per-adapter constant
(`urlfinder.runtime_cap_s`, `hakrawler.runtime_cap_s`) plus three hard-coded names in the engine's limits dict, so a new
slow tool needed a code edit. Now the shape lives in the registry: `tools.yaml` gives a tool a `class:` (`crawler`,
`scanner`, `api`, `archive`, or any name `config.yaml` defines) and `config.yaml` `runtime_caps:` gives that class a
`floor`, a `per_host` scale and an `idle` silence kill:

```
cap_s = min(stage budget, max(class.floor, class.per_host * hosts))
ToolLimits(max_s=cap_s, idle_s=class.idle, min_s=min(class.floor, cap_s), note=...)
```

| class | floor | per_host | idle | members today |
|---|---|---|---|---|
| `crawler` | 90 s | 2 s/host | 60 s | `gau`, `katana`, `hakrawler`, `gospider` |
| `scanner` | 300 s | 30 s/host | 120 s | `nikto` |
| `api` | 60 s | 1 s/host | 30 s | `crtsh`, `certspotter`, `otx`, `hackertarget`, `urlscan`, `chaos`, `github_subdomains` |
| `archive` | 180 s | 4 s/host | 60 s | `urlfinder` |

It is a **ceiling, not a timer**: nothing waits, sleeps or pads a run, a tool that finishes early exits immediately, and
the cap only decides when a tool that is *still running* is stopped (its partial output is kept and the row says
`capped at Ns`). A tool with no `class:` gets no cap, exactly as before. The formula is clipped by the stage deadline and
the row names the clip (`formula 2000s clipped to stage budget 1800s`), so saturation is never silent (D29). The three
explicit `urls:` entries (`urlfinder_*`, `hakrawler_max_s`, `subjs_max_s`) still win over a class for those three tools,
which is why D27's numbers did not move. **A new tool is one `tools.yaml` row** - `class: crawler` and the adapter file -
with no `engine.py` edit; `tests/test_engine.py::test_a_new_tool_with_class_in_tools_yaml_needs_no_engine_edit` proves
it against a synthetic registry.

> **D52 (2026-11-19) keeps the classes and deletes the caps.** `class:` is still the one registry field that shapes a
tool's runtime, and the zero-edit claim still holds, but a class now carries only an idle window (`runtime_idle:` in
`config.yaml`); `floor`, `per_host`, the `cap_s` formula and every `max_s`/`min_s` are gone. The table above is kept as
the record of what the caps were - see 4a2c for what replaced them.

