"""BaseToolAdapter interface and shared HTTP behavior (docs/09_TOOL_CONTRACTS.md).

Adapters return data only: no database, scope gate, UI or subprocess of their
own (binary execution goes through core/runner).
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import time
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Iterable, Mapping
from contextlib import AbstractContextManager, nullcontext
from pathlib import Path
from typing import ClassVar

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
IDENTITY_TIMEOUT = 10.0
FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures"

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_VERSION = re.compile(r"v?\d+\.\d+\.\d+")

Sleep = Callable[[float], Awaitable[None]]
Finder = Callable[[str], str | None]


class FetchFailed(Exception):
    """One HTTP attempt failed; adapters turn it into a failed ToolResult."""


def strip_ansi(text: str) -> str:
    """Remove terminal colour codes before parsing tool output."""
    return _ANSI.sub("", text)


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

    def __init__(self, *, fixtures_dir: Path | None = None) -> None:
        self._fixtures_dir = fixtures_dir if fixtures_dir is not None else FIXTURES

    def check_installed(self) -> InstallStatus:
        """HTTP and python adapters need nothing installed; binaries override this."""
        return InstallStatus(installed=True)

    def build_command(self, ctx: RunContext) -> list[str]:
        raise NotImplementedError(f"{self.name} does not build a command")

    def child_env(self, ctx: RunContext) -> dict[str, str]:
        """Environment for the child: only the keys the engine allowed."""
        return dict(ctx.env)

    def prepare(self, ctx: RunContext) -> AbstractContextManager[None]:
        """Optional per-run setup (for example a temporary config file)."""
        return nullcontext()

    async def run(self, ctx: RunContext) -> ToolResult:
        """Default binary flow: mock fixture or run_exec, then parse."""
        started = time.perf_counter()
        duration = 0.0
        truncated = False
        try:
            if ctx.mock:
                records = self.parse_output(self._read_fixture(ctx))
            else:
                with self.prepare(ctx):
                    outcome = await asyncio.to_thread(
                        run_exec,
                        self.build_command(ctx),
                        timeout=ctx.timeout,
                        env=self.child_env(ctx),
                    )
                    duration = outcome.duration_s
                    if outcome.timed_out:
                        return ToolResult(
                            tool=self.name,
                            status=ToolStatus.TIMEOUT,
                            error="timed out",
                            duration_s=duration,
                        )
                    detail = outcome.stderr.strip()[:MAX_ERROR_CHARS] or "no output"
                    if outcome.returncode is None:
                        return ToolResult(
                            tool=self.name,
                            status=ToolStatus.FAILED,
                            error=f"not installed or not executable: {detail}",
                            duration_s=duration,
                        )
                    if outcome.returncode != 0:
                        return ToolResult(
                            tool=self.name,
                            status=ToolStatus.FAILED,
                            error=f"exit {outcome.returncode}: {detail}",
                            duration_s=duration,
                        )
                    truncated = outcome.truncated
                    records = self.parse_output(outcome.stdout)
        except (ParseError, FetchFailed, ToolFailed) as exc:
            return ToolResult(tool=self.name, status=ToolStatus.FAILED, error=str(exc))
        except RuntimeError as exc:
            # runner.run_exec only raises when its pipes cannot be created;
            # keep that a failed result instead of a traceback.
            return ToolResult(
                tool=self.name, status=ToolStatus.FAILED, error=f"runner error: {exc}"
            )
        elapsed = duration or time.perf_counter() - started
        return ToolResult(
            tool=self.name,
            status=ToolStatus.OK,
            records=records,
            duration_s=elapsed,
            error="output truncated" if truncated else None,
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
        raise FetchFailed(f"{self.name}: no fixture for {ctx.target}")


class BinaryAdapter(BaseToolAdapter):
    """Binary tool with an identity check and an optional HOME for config."""

    binary: ClassVar[str] = ""
    version_args: ClassVar[list[str]] = ["-version"]
    identity_markers: ClassVar[tuple[str, ...]] = ()
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
        own = Path.home() / ".reconkit" / "bin" / self.binary
        own_paths = [own, own.with_name(f"{own.name}.exe")] if os.name == "nt" else [own]
        for candidate in own_paths:
            if candidate.is_file():
                return str(candidate)
        return self._finder(self.binary)

    def check_installed(self) -> InstallStatus:
        """Resolve the binary and prove it is the expected program, not a namesake."""
        path = self.binary_path()
        if path is None:
            return InstallStatus(installed=False)
        try:
            outcome = run_exec([path, *self.version_args], timeout=IDENTITY_TIMEOUT, env={})
        except RuntimeError:
            return InstallStatus(installed=False, path=Path(path))
        text = f"{outcome.stdout}\n{outcome.stderr}"
        if outcome.timed_out or outcome.returncode is None:
            return InstallStatus(installed=False, path=Path(path))
        lowered = text.lower()
        if self.identity_markers and not any(marker in lowered for marker in self.identity_markers):
            return InstallStatus(installed=False, path=Path(path))
        match = _VERSION.search(text)
        return InstallStatus(
            installed=True,
            version=match.group(0) if match is not None else None,
            path=Path(path),
        )


class HttpAdapter(BaseToolAdapter):
    """Async HTTP adapter: one retry on connection errors, never hammer on 429/5xx."""

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
        try:
            raw = self._read_fixture(ctx) if ctx.mock else await self._request(ctx)
            records = self._within_target(self.parse_output(raw), ctx.target)
        except ParseError as exc:
            return ToolResult(tool=self.name, status=ToolStatus.FAILED, error=str(exc))
        except FetchFailed as exc:
            return ToolResult(tool=self.name, status=ToolStatus.FAILED, error=str(exc))
        return ToolResult(
            tool=self.name,
            status=ToolStatus.OK,
            records=records,
            duration_s=time.perf_counter() - started,
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
        await ctx.limiter.wait()
        async with httpx.AsyncClient(
            timeout=ctx.timeout,
            headers=self.headers(ctx),
            transport=self._transport,
            follow_redirects=True,
        ) as client:
            async with client.stream(
                "GET", self.url(ctx), params=dict(self.params(ctx))
            ) as response:
                if response.status_code == 429:
                    raise FetchFailed(f"{self.name}: rate limited (HTTP 429)")
                if response.status_code >= 500:
                    raise FetchFailed(f"{self.name}: server error (HTTP {response.status_code})")
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
