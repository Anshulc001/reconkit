"""BaseToolAdapter interface and shared HTTP behavior (docs/09_TOOL_CONTRACTS.md).

Adapters return data only: no database, scope gate, UI or subprocess of their
own (binary execution goes through core/runner).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import time
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Iterable, Mapping
from contextlib import AbstractContextManager, nullcontext
from pathlib import Path
from typing import ClassVar, TypeVar
from urllib.parse import urlsplit, urlunsplit

import httpx

from reconkit.core.runner import run_exec, validate_host
from reconkit.errors import ParseError, ToolFailed
from reconkit.models import (
    InstallStatus,
    Record,
    RunContext,
    Stage,
    SubdomainRecord,
    ToolResult,
    ToolStatus,
)

USER_AGENT = "reconkit/0.1"
RETRY_DELAY = 1.0
MAX_BODY_BYTES = 10 * 1024 * 1024
MAX_ERROR_CHARS = 200
# How many unusable parser lines are named one by one in the detail column.
SKIP_WARNINGS = 10
IDENTITY_TIMEOUT = 10.0
# A probe that fails once must not drop a working tool from every scan (D42):
# one retry after a short pause, then today's verdict stands.
IDENTITY_RETRY_DELAY = 0.1
FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures"

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# Two-part versions are real (`nmap --version` prints `Nmap version 7.991`), so the
# patch part is optional rather than required.
_VERSION = re.compile(r"v?\d+\.\d+(?:\.\d+)?")

Sleep = Callable[[float], Awaitable[None]]
Finder = Callable[[str], str | None]


ProbeResult = TypeVar("ProbeResult")


def probe_with_retry(
    probe: Callable[[], ProbeResult],
    *,
    ok: Callable[[ProbeResult], bool],
    delay: float = IDENTITY_RETRY_DELAY,
) -> ProbeResult:
    """Run an identity probe once, and once more when it did not identify the tool.

    A single failed probe used to mean `wrong program`, and that silently removed
    the tool from every scan - it looks like the tool ran and found nothing. The
    failure is transient in practice (D42: amass answered 10/10 probes and failed
    one), so the second attempt decides. After it, the verdict is exactly today's:
    no new status, no enum change. `ok` says what a successful probe looks like.
    """
    try:
        result = probe()
    except RuntimeError:
        time.sleep(delay)
        return probe()
    if ok(result):
        return result
    time.sleep(delay)
    return probe()


class FetchFailed(Exception):
    """One HTTP attempt failed; adapters turn it into a failed ToolResult."""


class ExternalServiceGap(FetchFailed):
    """A third party refused the request: 429, quota, or an upstream 5xx.

    Not a failure of the tool or of this box, so it becomes `ToolStatus.GAP`
    (a completion gap) instead of `FAILED` (owner ruling 2026-11-18).
    """


# Signatures a third party produces, never a local fault. Matched against an
# HTTP failure message or a binary's captured stdout+stderr.
_GAP_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bhttp\s*429\b", re.IGNORECASE),
    re.compile(r"\brate[- ]?limit(?:ed|ing)?\b", re.IGNORECASE),
    re.compile(r"\btoo many requests\b", re.IGNORECASE),
    re.compile(r"\bquota\b", re.IGNORECASE),
    re.compile(r"\bapi count exceeded\b", re.IGNORECASE),
    # R8 (2026-11-18) names 429/500/502/503 explicitly, so any upstream 5xx in
    # an HTTP context counts; a bare number (an item count, a port) never does.
    re.compile(
        r"\bhttp\s*5\d{2}\b|\bserver error \(http 5\d\d\)|\bbad gateway\b|"
        r"\bservice unavailable\b|\bgateway time-?out\b|"
        r"\binternal server error\b",
        re.IGNORECASE,
    ),
)


def classify_external_gap(text: str) -> str | None:
    """Return the service message when `text` is an external-service problem.

    `None` means "this is a real failure". A 429, a rate-limit/quota message, or
    an upstream 5xx says nothing about the binary or the network here, so the
    engine records a gap rather than a failed run (docs/09 section 3).
    """
    if not text:
        return None
    collapsed = " ".join(strip_ansi(text).split())
    for pattern in _GAP_PATTERNS:
        if pattern.search(collapsed):
            return collapsed[:MAX_ERROR_CHARS]
    return None


RAW_STDERR_MARK = "--- stderr ---"


def strip_ansi(text: str) -> str:
    """Remove terminal colour codes before parsing tool output."""
    return _ANSI.sub("", text)


def capture_output(stdout: str, stderr: str) -> str:
    """One raw text per run: stdout, then stderr under a marker (docs/09 section 3)."""
    if not stderr:
        return stdout
    if not stdout.strip():
        return stderr
    return f"{stdout.rstrip()}\n{RAW_STDERR_MARK}\n{stderr}"


def records_output(records: list[Record], error: str | None = None) -> str:
    """Raw evidence for a python adapter, which has no child process to capture.

    The document is what the adapter observed per host plus its counters, so a
    parse or TLS bug can be read off disk instead of reproduced by hand (12a).
    """
    document = {
        "records": [record.model_dump(mode="json") for record in records],
        "error": error,
    }
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def parse_subdomain_lines(raw: str, source: str) -> list[Record]:
    """Parse one-subdomain-per-line output; log noise is skipped, garbage fails."""
    records: list[Record] = []
    seen: set[str] = set()
    for line in strip_ansi(raw).splitlines():
        name = line.strip()
        if not name or name.startswith("["):
            continue
        try:
            fqdn = validate_host(name)
        except (TypeError, ValueError):
            raise ParseError(f"{source}: invalid subdomain line {name!r}") from None
        if fqdn not in seen:
            seen.add(fqdn)
            records.append(SubdomainRecord(fqdn=fqdn, source=source))
    return records


# Links a page carries that are not HTTP requests at all. Crawlers print them
# verbatim (hakrawler emitted `javascript:checkSiteStatus('AltoroMutual')` on the
# first real testfire.net crawl), so a parser must skip them, not fail on them.
_NON_WEB_PREFIXES = ("javascript:", "mailto:", "tel:", "data:", "about:", "ftp:", "file:")


def is_non_web_reference(value: str) -> bool:
    """True when a line is a page link but not an HTTP(S) URL."""
    return value.strip().lower().startswith(_NON_WEB_PREFIXES)


def normalize_url(value: str) -> str | None:
    """Return one http(s) URL without its fragment, or None for anything else.

    Crawlers and archives emit `http://host:80/path?q#frag`; the stored URL keeps
    every meaningful part and drops the fragment, which never reaches a server.
    """
    parts = urlsplit(value.strip())
    if parts.scheme not in ("http", "https") or not parts.netloc or not parts.hostname:
        return None
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, ""))


def normalize_subdomains(candidates: Iterable[str], source: str) -> list[Record]:
    """Lowercase, strip `*.` and trailing dots, validate, dedupe, sort.

    Domain filtering happens in `HttpAdapter.run`, which knows `ctx.target`.
    """
    kept: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        try:
            kept.add(validate_host(candidate))
        except (TypeError, ValueError):
            continue
    return [SubdomainRecord(fqdn=name, source=source) for name in sorted(kept)]


class BaseToolAdapter(ABC):
    """Contract from docs/09 section 3; tier, mode and kind come from tools.yaml."""

    name: ClassVar[str] = ""
    stage: ClassVar[Stage] = Stage.SUBS
    # Env vars the tool cannot run without at all (chaos, github-subdomains). The
    # engine skips such a tool at selection with `requires <NAME>` when the key is
    # absent, so a keyless run records the reason instead of spawning a binary
    # that can only fail (pre-approved, D18). Unlike `tools.yaml` `keys`, which
    # describes an optional upgrade, this is a hard requirement.
    requires_env: ClassVar[tuple[str, ...]] = ()
    # D52: there is no per-tool runtime cap. A tool runs until it exits, until
    # the engine's idle watchdog kills it (silent past its class window), or
    # until the stage budget fires; a killed run keeps its partial output. The
    # window reaches the adapter through `ctx.limits`, never as a ClassVar: the
    # class lives in tools.yaml and the number in config.yaml `runtime_idle:`.

    def __init__(self, *, fixtures_dir: Path | None = None) -> None:
        self._fixtures_dir = fixtures_dir if fixtures_dir is not None else FIXTURES
        # Unusable lines a parser skipped instead of failing the tool (PIT-58).
        # Per run; `_skip_note()` turns the list into the detail line.
        self.skipped_lines: list[str] = []

    def _skip_note(self) -> str | None:
        """One detail line for the lines a parser could not use, or None.

        Up to ten skipped lines are listed one by one; beyond that a single
        summary keeps a 11 000-line log from becoming 11 000 warnings.
        """
        if not self.skipped_lines:
            return None
        if len(self.skipped_lines) <= SKIP_WARNINGS:
            return "; ".join(f"skipped unusable line {line!r}" for line in self.skipped_lines)[
                :MAX_ERROR_CHARS
            ]
        count = len(self.skipped_lines)
        return f"skipped {count} unusable line(s); last: {self.skipped_lines[-1]!r}"

    def check_installed(self) -> InstallStatus:
        """HTTP and python adapters need nothing installed; binaries override this."""
        return InstallStatus(installed=True)

    def build_command(self, ctx: RunContext) -> list[str]:
        raise NotImplementedError(f"{self.name} does not build a command")

    def child_env(self, ctx: RunContext) -> dict[str, str]:
        """Environment for the child: only the keys the engine allowed."""
        return dict(ctx.env)

    def stdin_text(self, ctx: RunContext) -> str | None:
        """Input for a tool that reads its host list on stdin (docs/09 section 3).

        `None` keeps stdin at EOF, which is what every tool that takes flags
        needs; `httprobe` and `waybackurls` are the only readers so far.
        """
        return None

    def read_output(self, ctx: RunContext) -> str | None:
        """Document a tool wrote to a file instead of stdout (docs/09 section 3).

        `None` means "parse stdout", which is every adapter but `subzy`: it only
        writes its findings to the `--output` file and puts log lines on stdout.
        Called after a successful run, before `parse_output`, so a file-output
        tool keeps the base flow's timeout/failed/parse handling.
        """
        return None

    def post_command(self, ctx: RunContext) -> list[str] | None:
        """A read-back command to run after a successful primary run (docs/09 3).

        `None` means "parse the primary command's stdout", which is every adapter
        but `amass`: v5.1.3 `amass enum` hands its findings to its own engine and
        prints only a `Session Scope` header, so the names have to be read back
        with `amass subs -names`. The follow-up is only reached when
        `read_output` returned `None`, and its stdout - not the primary's - is
        what `parse_output` receives. A follow-up that fails makes the tool
        FAILED, because a run whose findings can not be read back produced
        nothing usable.
        """
        return None

    def prepare(self, ctx: RunContext) -> AbstractContextManager[None]:
        """Optional per-run setup (for example a temporary config file)."""
        return nullcontext()

    async def _post_output(self, ctx: RunContext) -> str | None:
        """Run `post_command`, if any, and return its stdout."""
        argv = self.post_command(ctx)
        if argv is None:
            return None
        outcome = await asyncio.to_thread(
            run_exec, argv, timeout=ctx.timeout, env=self.child_env(ctx)
        )
        if outcome.timed_out:
            raise ToolFailed(f"{self.name}: read-back command timed out")
        if outcome.returncode:
            detail = outcome.stderr.strip()[:MAX_ERROR_CHARS] or "no output"
            raise ToolFailed(f"{self.name}: read-back exit {outcome.returncode}: {detail}")
        return str(outcome.stdout)

    async def run(self, ctx: RunContext) -> ToolResult:
        """Default binary flow: mock fixture or run_exec, then parse."""
        started = time.perf_counter()
        duration = 0.0
        truncated = False
        raw_text = ""
        self.skipped_lines = []
        limits = ctx.limits.get(self.name)
        # D52: no runtime cap. The only hard wall is the stage budget the engine
        # put in `ctx.timeout`; `idle` is the silence window after which the tool
        # is assumed stuck. `run_exec` kills the child for either reason and keeps
        # the partial stdout, which is parsed below.
        budget = ctx.timeout
        idle = limits.idle_s if limits is not None and limits.idle_s else None
        try:
            if ctx.mock:
                raw_text = self._read_fixture(ctx)
                records = self.parse_output(raw_text)
            else:
                with self.prepare(ctx):
                    outcome = await asyncio.to_thread(
                        run_exec,
                        self.build_command(ctx),
                        timeout=budget,
                        env=self.child_env(ctx),
                        stdin_text=self.stdin_text(ctx),
                        idle_timeout=idle,
                        stop_event=ctx.stop,
                        on_output=ctx.activity,
                    )
                    duration = outcome.duration_s
                    raw_text = capture_output(outcome.stdout, outcome.stderr)
                    if outcome.timed_out:
                        # A stopped run keeps what arrived, either way. D52 draws
                        # the line: silence past the class window is a deliberate
                        # `killed` (the engine ended a stuck tool, the run is
                        # still a completion); the stage budget firing is the old
                        # `timeout`, because a tool that did not finish in the
                        # stage's time is a real signal (R13, D45 stands).
                        partial = self.parse_output(outcome.stdout)
                        elapsed = (
                            time.perf_counter() - ctx.stage_started
                            if ctx.stage_started
                            else duration
                        )
                        idle_kill = outcome.idle_killed and idle is not None
                        if idle_kill:
                            note = (
                                f"killed after {idle:g}s idle at stage {elapsed:.1f}s, "
                                f"{len(partial)} partial"
                            )
                        else:
                            note = (
                                f"timed out at stage budget {budget:g}s, "
                                f"{len(partial)} partial, last output "
                                f"{outcome.last_output_s:g}s ago"
                            )
                        detail = "; ".join(part for part in (note, self._skip_note()) if part)
                        return ToolResult(
                            tool=self.name,
                            status=ToolStatus.KILLED if idle_kill else ToolStatus.TIMEOUT,
                            records=partial,
                            duration_s=duration,
                            error=detail,
                            last_output_s=outcome.last_output_s,
                            raw_text=raw_text,
                        )
                    detail = outcome.stderr.strip()[:MAX_ERROR_CHARS] or "no output"
                    if outcome.returncode is None:
                        return ToolResult(
                            tool=self.name,
                            status=ToolStatus.FAILED,
                            error=f"not installed or not executable: {detail}",
                            duration_s=duration,
                            raw_text=raw_text,
                        )
                    if outcome.returncode != 0:
                        # A third party refusing the tool (429, quota, upstream 5xx)
                        # is a gap: the binary worked, the service did not
                        # (owner ruling 2026-11-18).
                        gap = classify_external_gap(capture_output(outcome.stdout, outcome.stderr))
                        return ToolResult(
                            tool=self.name,
                            status=ToolStatus.GAP if gap else ToolStatus.FAILED,
                            error=gap or f"exit {outcome.returncode}: {detail}",
                            duration_s=duration,
                            raw_text=raw_text,
                        )
                    truncated = outcome.truncated
                    produced = self.read_output(ctx)
                    if produced is not None:
                        raw_text = capture_output(produced, outcome.stderr)
                    else:
                        # Only reached by a tool that keeps its findings elsewhere
                        # than stdout and than a file (amass, docs/09 section 3).
                        produced = await self._post_output(ctx)
                        if produced is not None:
                            raw_text = capture_output(outcome.stdout, produced)
                    records = self.parse_output(outcome.stdout if produced is None else produced)
        except (ParseError, FetchFailed, ToolFailed) as exc:
            return ToolResult(
                tool=self.name,
                status=ToolStatus.FAILED,
                error=str(exc),
                duration_s=duration or time.perf_counter() - started,
                raw_text=raw_text,
            )
        except RuntimeError as exc:
            # runner.run_exec only raises when its pipes cannot be created;
            # keep that a failed result instead of a traceback.
            return ToolResult(
                tool=self.name,
                status=ToolStatus.FAILED,
                error=f"runner error: {exc}",
                duration_s=duration or time.perf_counter() - started,
                raw_text=raw_text,
            )
        elapsed = duration or time.perf_counter() - started
        return ToolResult(
            tool=self.name,
            status=ToolStatus.OK,
            records=records,
            duration_s=elapsed,
            error="; ".join(
                part
                for part in ("output truncated" if truncated else None, self._skip_note())
                if part
            )
            or None,
            raw_text=raw_text,
        )

    @abstractmethod
    def parse_output(self, raw: str) -> list[Record]:
        """Pure parser: normalize one raw response into records (never network)."""
        raise NotImplementedError(f"{self.name} does not parse output")

    def _read_fixture(self, ctx: RunContext) -> str:
        directory = self._fixtures_dir / self.name
        exact = sorted(path for path in directory.glob(f"{ctx.target}.*") if path.is_file())
        if exact:
            return exact[0].read_text(encoding="utf-8")
        files = (
            sorted(path for path in directory.iterdir() if path.is_file())
            if directory.is_dir()
            else []
        )
        if len(files) == 1:
            return files[0].read_text(encoding="utf-8")
        # The adapter-wave tools keep one flat `<tool>.synthetic.*` fixture instead
        # of a per-tool directory; it is the only file, so there is nothing to pick.
        flat = sorted((self._fixtures_dir / "adapters").glob(f"{self.name}.synthetic.*"))
        if len(flat) == 1:
            return flat[0].read_text(encoding="utf-8")
        raise FetchFailed(f"{self.name}: no fixture for {ctx.target}")


def running_as_root() -> bool:
    """True when the effective uid is 0.

    Used by the registry's `needs_root` selection rule (docs/09 section 4a6) and
    by the masscan adapter's own guard, so both ask the same question once.
    """
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid is not None and geteuid() == 0)


def managed_bin_dir() -> Path:
    """`~/.reconkit/bin`, the first place every binary lookup looks.

    `config` can be imported at module level (it only reads config.yaml), and
    there is exactly one definition of the path: `config.bin_dir`. A test pins
    the two to the same value (docs/10 section 3).
    """
    from reconkit.config import bin_dir

    return bin_dir()


class BinaryAdapter(BaseToolAdapter):
    """Binary tool with an identity check and an optional HOME for config."""

    binary: ClassVar[str] = ""
    version_args: ClassVar[list[str]] = ["-version"]
    identity_markers: ClassVar[tuple[str, ...]] = ()
    # Every marker must appear unless an adapter opts out (docs/09 contract).
    identity_require_all: ClassVar[bool] = True
    needs_home: ClassVar[bool] = False

    def __init__(self, *, finder: Finder | None = None, fixtures_dir: Path | None = None) -> None:
        super().__init__(fixtures_dir=fixtures_dir)
        self._finder = finder if finder is not None else shutil.which

    def child_env(self, ctx: RunContext) -> dict[str, str]:
        env = dict(ctx.env)
        if self.needs_home:
            home = str(Path.home())
            env.setdefault("HOME", home)
            env.setdefault("USERPROFILE", home)
        return env

    def binary_path(self) -> str | None:
        own = managed_bin_dir() / self.binary
        own_paths = [own, own.with_name(f"{own.name}.exe")] if os.name == "nt" else [own]
        for candidate in own_paths:
            if candidate.is_file():
                return str(candidate)
        return self._finder(self.binary)

    def check_installed(self) -> InstallStatus:
        """Resolve the binary and prove it is the expected program, not a namesake.

        The probe is retried once (D42): a transient failure must not silently
        drop a working tool from every scan. A missing binary is not retried.
        """
        path = self.binary_path()
        if path is None:
            return InstallStatus(installed=False)
        try:
            return probe_with_retry(
                lambda: self._probe_identity(path), ok=lambda status: status.installed
            )
        except RuntimeError:
            return InstallStatus(installed=False, path=Path(path))

    def _probe_identity(self, path: str) -> InstallStatus:
        """One identity attempt: run the version command and read what it says.

        The probe gets `HOME` because ProjectDiscovery tools write their config
        under `$HOME/.config`; with no HOME they fall back to the current
        directory and create or move `subfinder/` and `naabu/` into it.
        """
        outcome = run_exec(
            [path, *self.version_args],
            timeout=IDENTITY_TIMEOUT,
            env={"HOME": str(Path.home())},
        )
        text = f"{outcome.stdout}\n{outcome.stderr}"
        if outcome.timed_out or outcome.returncode is None:
            return InstallStatus(installed=False, path=Path(path))
        lowered = text.lower()
        if self.identity_markers:
            matched = [marker in lowered for marker in self.identity_markers]
            passed = all(matched) if self.identity_require_all else any(matched)
            if not passed:
                return InstallStatus(installed=False, path=Path(path))
        match = _VERSION.search(text)
        return InstallStatus(
            installed=True,
            version=match.group(0) if match is not None else None,
            path=Path(path),
        )


class HttpAdapter(BaseToolAdapter):
    """Async HTTP adapter: one retry on connection errors, never hammer on 429/5xx."""

    def _is_external_api(self) -> bool:
        """Whether every request goes to a third party's API (D47, D48).

        Then the service can be the thing that is wrong: a whole-response 404
        says "that front end did not find its own endpoint", not "this box is
        broken" (measured: crt.sh answered 404 on 1 of 10 identical calls and
        502 on its own root). A local tool's 404 stays a failure. The answer
        comes from `external: true` in tools.yaml, not from a per-adapter flag.
        """
        # Deferred: `registry` imports the adapter package, which imports this
        # module, so a top-level import would be a cycle.
        from reconkit.adapters.registry import external_tools

        return self.name in external_tools()

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Sleep | None = None,
        fixtures_dir: Path | None = None,
    ) -> None:
        super().__init__(fixtures_dir=fixtures_dir)
        self._transport = transport
        self._sleep = sleep if sleep is not None else asyncio.sleep

    def url(self, ctx: RunContext) -> str:
        raise NotImplementedError(f"{self.name} has no request URL")

    def params(self, ctx: RunContext) -> Mapping[str, str]:
        return {}

    def headers(self, ctx: RunContext) -> dict[str, str]:
        return {"User-Agent": USER_AGENT, "Accept": "application/json"}

    async def run(self, ctx: RunContext) -> ToolResult:
        started = time.perf_counter()
        raw_text = ""
        try:
            raw_text = self._read_fixture(ctx) if ctx.mock else await self._request(ctx)
            records = self._within_target(self.parse_output(raw_text), ctx.target)
        except ExternalServiceGap as exc:
            # The upstream refused us; no records were read. A gap, not a
            # failure (owner ruling 2026-11-18).
            return ToolResult(
                tool=self.name,
                status=ToolStatus.GAP,
                error=str(exc),
                duration_s=time.perf_counter() - started,
                raw_text=raw_text or str(exc),
            )
        except ParseError as exc:
            # A parse failure is still work this adapter did, so it times it too.
            return ToolResult(
                tool=self.name,
                status=ToolStatus.FAILED,
                error=str(exc),
                duration_s=time.perf_counter() - started,
                raw_text=raw_text,
            )
        except FetchFailed as exc:
            # No body was read (429, 5xx, timeout, refused): the failure message
            # is the only evidence this run produced, so it is the raw file.
            return ToolResult(
                tool=self.name,
                status=ToolStatus.FAILED,
                error=str(exc),
                duration_s=time.perf_counter() - started,
                raw_text=raw_text or str(exc),
            )
        return ToolResult(
            tool=self.name,
            status=ToolStatus.OK,
            records=records,
            duration_s=time.perf_counter() - started,
            raw_text=raw_text,
        )

    async def _request(self, ctx: RunContext) -> str:
        try:
            return await self._attempt(ctx)
        except httpx.ConnectError:
            await self._sleep(RETRY_DELAY)
            try:
                return await self._attempt(ctx)
            except httpx.ConnectError:
                raise FetchFailed(f"{self.name}: connection failed after one retry") from None
            except httpx.TimeoutException:
                raise FetchFailed(f"{self.name}: request timed out") from None
            except httpx.HTTPError as exc:
                raise FetchFailed(f"{self.name}: {type(exc).__name__}") from None
        except httpx.TimeoutException:
            raise FetchFailed(f"{self.name}: request timed out") from None
        except httpx.HTTPError as exc:
            raise FetchFailed(f"{self.name}: {type(exc).__name__}") from None

    async def _attempt(self, ctx: RunContext) -> str:
        # D52: there is no per-tool cap left to borrow, so an HTTP tool's request
        # timeout is the stage budget. A stalled request is caught there.
        timeout = ctx.timeout
        async with httpx.AsyncClient(
            timeout=timeout,
            headers=self.headers(ctx),
            transport=self._transport,
            follow_redirects=True,
        ) as client:
            async with client.stream(
                "GET", self.url(ctx), params=dict(self.params(ctx))
            ) as response:
                if response.status_code == 429:
                    raise ExternalServiceGap(f"{self.name}: rate limited (HTTP 429)")
                if response.status_code >= 500:
                    raise ExternalServiceGap(
                        f"{self.name}: server error (HTTP {response.status_code})"
                    )
                if response.status_code == 404 and self._is_external_api():
                    # An external API pane that 404s its own query is the service
                    # being wrong, not this scan: a gap, never a failure, and
                    # never retried (the retry above is for connections only).
                    raise ExternalServiceGap(f"{self.name}: HTTP 404")
                if response.status_code >= 400:
                    raise FetchFailed(f"{self.name}: HTTP {response.status_code}")
                declared = response.headers.get("content-length")
                if declared is not None and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
                    raise FetchFailed(f"{self.name}: response too large")
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_BODY_BYTES:
                        raise FetchFailed(f"{self.name}: response too large")
                    chunks.append(chunk)
                body = b"".join(chunks)
                return body.decode(response.encoding or "utf-8", errors="replace")

    @staticmethod
    def _within_target(records: list[Record], target: str) -> list[Record]:
        root = target.strip().lower().rstrip(".")
        kept: list[Record] = []
        for record in records:
            if isinstance(record, SubdomainRecord) and not (
                record.fqdn == root or record.fqdn.endswith(f".{root}")
            ):
                continue
            kept.append(record)
        return kept
