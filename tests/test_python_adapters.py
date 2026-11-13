"""Pure-Python adapter tests: fake resolver/opener and MockTransport, no network."""

from __future__ import annotations

import ast
import asyncio
from collections.abc import Iterator
from pathlib import Path

import dns.exception
import dns.resolver
import httpx
import pytest

from reconkit.adapters.base import BaseToolAdapter
from reconkit.adapters.dnspython import DnsOutcome, DnsPythonAdapter
from reconkit.adapters.pyprobe import TITLE_LIMIT, PyprobeAdapter
from reconkit.adapters.pyscan import PyscanAdapter
from reconkit.config import load_config, resolve_speed
from reconkit.core.pacing import Pacer, RateLimiter
from reconkit.models import (
    HostState,
    HostStatusRecord,
    PortRecord,
    RunContext,
    SubdomainRecord,
    ToolStatus,
)

REPO = Path(__file__).resolve().parents[1]
CONFIG = REPO / "config.yaml"
ADAPTER_DIR = REPO / "src" / "reconkit" / "adapters"


async def _no_sleep(_seconds: float) -> None:
    return None


class CountingLimiter(RateLimiter):
    def __init__(self) -> None:
        super().__init__(1_000_000, clock=lambda: 0.0, sleep=_no_sleep)
        self.waits = 0

    async def wait(self) -> float:
        self.waits += 1
        return 0.0


def make_ctx(
    *,
    hosts: list[str] | None = None,
    ports: list[int] | None = None,
    mock: bool = False,
    limiter: RateLimiter | None = None,
) -> RunContext:
    config = load_config(CONFIG, speed="fast")
    return RunContext(
        target="example.com",
        hosts=hosts or [],
        ports=ports or [],
        pacer=Pacer(resolve_speed(config)),
        limiter=limiter if limiter is not None else CountingLimiter(),
        timeout=5.0,
        workspace=REPO / "workspaces" / "example.com",
        mock=mock,
    )


class Rdata:
    def __init__(self, value: str) -> None:
        self.address = value
        self.target = value

    def __str__(self) -> str:
        return self.address


class Answer:
    def __init__(self, values: list[str] | None) -> None:
        self.rrset = None if values is None else True
        self._values = values or []

    def __iter__(self) -> Iterator[Rdata]:
        return iter(Rdata(value) for value in self._values)


class FakeResolver:
    def __init__(self, answers: dict[tuple[str, str], object]) -> None:
        self.answers = answers
        self.queries: list[tuple[str, str]] = []

    async def resolve(
        self, host: str, rtype: str, *, lifetime: float, raise_on_no_answer: bool = True
    ) -> Answer:
        self.queries.append((host, rtype))
        value = self.answers.get((host, rtype), [])
        if isinstance(value, BaseException):
            raise value
        if value is None:
            return Answer(None)
        assert isinstance(value, list)
        return Answer(value)


# ------------------------------------------------------------------ dnspython


async def test_dnspython_normal() -> None:
    resolver = FakeResolver(
        {
            ("www.example.com", "A"): ["203.0.113.5"],
            ("www.example.com", "AAAA"): ["2001:db8::5"],
            ("alias.example.com", "CNAME"): ["www.example.com"],
        }
    )
    adapter = DnsPythonAdapter(resolver=resolver)
    result = await adapter.run(make_ctx(hosts=["www.example.com", "alias.example.com"]))
    assert result.status == ToolStatus.OK
    www = next(
        r for r in result.records if isinstance(r, SubdomainRecord) and r.fqdn == "www.example.com"
    )
    alias = next(
        r
        for r in result.records
        if isinstance(r, SubdomainRecord) and r.fqdn == "alias.example.com"
    )
    assert www.ips == ["203.0.113.5", "2001:db8::5"]
    assert alias.cnames == ["www.example.com"]


async def test_dnspython_empty() -> None:
    adapter = DnsPythonAdapter(resolver=FakeResolver({}))
    result = await adapter.run(make_ctx(hosts=[]))
    assert result.status == ToolStatus.OK
    assert result.records == []
    assert result.error is None


async def test_dnspython_nxdomain_timeout_servfail_are_distinct() -> None:
    resolver = FakeResolver(
        {
            ("nx.example.com", "A"): dns.resolver.NXDOMAIN(),
            ("slow.example.com", "A"): dns.exception.Timeout(),
            ("broken.example.com", "A"): dns.resolver.NoNameservers(),
        }
    )
    adapter = DnsPythonAdapter(resolver=resolver)
    ctx = make_ctx(hosts=["nx.example.com", "slow.example.com", "broken.example.com"])
    assert (await adapter.resolve_host(ctx, "nx.example.com")).outcome is DnsOutcome.NXDOMAIN
    assert (await adapter.resolve_host(ctx, "slow.example.com")).outcome is DnsOutcome.TIMEOUT
    assert (await adapter.resolve_host(ctx, "broken.example.com")).outcome is DnsOutcome.SERVFAIL

    result = await adapter.run(ctx)
    dead = [r for r in result.records if isinstance(r, HostStatusRecord)]
    assert [r.fqdn for r in dead] == ["nx.example.com"]
    assert dead[0].state is HostState.DEAD
    assert "servfail=1" in (result.error or "")
    assert "timeout=1" in (result.error or "")


async def test_dnspython_no_answer_is_not_dead() -> None:
    resolver = FakeResolver({})
    adapter = DnsPythonAdapter(resolver=resolver)
    ctx = make_ctx(hosts=["empty.example.com"])
    assert (await adapter.resolve_host(ctx, "empty.example.com")).outcome is DnsOutcome.NOANSWER
    result = await adapter.run(ctx)
    assert result.records == []
    assert result.error is None


async def test_dnspython_outcomes_are_all_distinct() -> None:
    assert [outcome.value for outcome in DnsOutcome] == [
        "resolved",
        "nxdomain",
        "noanswer",
        "servfail",
        "timeout",
        "error",
    ]
    assert len(set(DnsOutcome)) == len(DnsOutcome)


async def test_dnspython_cname_loop_is_error_not_dead() -> None:
    resolver = FakeResolver(
        {("loop.example.com", "A"): dns.exception.DNSException("CNAME loop detected")}
    )
    adapter = DnsPythonAdapter(resolver=resolver)
    ctx = make_ctx(hosts=["loop.example.com"])
    assert (await adapter.resolve_host(ctx, "loop.example.com")).outcome is DnsOutcome.ERROR
    result = await adapter.run(ctx)
    assert result.status == ToolStatus.OK
    assert result.records == []
    assert "error=1" in (result.error or "")


async def test_dnspython_unexpected_exception_is_error_not_crash() -> None:
    resolver = FakeResolver({("boom.example.com", "A"): RuntimeError("resolver bug")})
    adapter = DnsPythonAdapter(resolver=resolver)
    ctx = make_ctx(hosts=["boom.example.com"])
    assert (await adapter.resolve_host(ctx, "boom.example.com")).outcome is DnsOutcome.ERROR
    result = await adapter.run(ctx)
    assert result.status == ToolStatus.OK
    assert result.records == []
    assert "error=1" in (result.error or "")


async def test_dnspython_uppercase_host_is_normalized() -> None:
    resolver = FakeResolver({("www.example.com", "A"): ["203.0.113.5"]})
    adapter = DnsPythonAdapter(resolver=resolver)
    result = await adapter.run(make_ctx(hosts=["WWW.Example.COM."]))
    assert resolver.queries == [
        ("www.example.com", "A"),
        ("www.example.com", "AAAA"),
        ("www.example.com", "CNAME"),
    ]
    assert [r.fqdn for r in result.records] == ["www.example.com"]


async def test_dnspython_idn_host_is_counted_not_resolved() -> None:
    resolver = FakeResolver({})
    adapter = DnsPythonAdapter(resolver=resolver)
    ctx = make_ctx(hosts=["bücher.example.com"])
    assert (await adapter.resolve_host(ctx, "bücher.example.com")).outcome is DnsOutcome.ERROR
    result = await adapter.run(ctx)
    assert resolver.queries == []
    assert result.records == []
    assert "invalid=1" in (result.error or "")


async def test_dnspython_awaits_limiter_per_query() -> None:
    limiter = CountingLimiter()
    resolver = FakeResolver({("www.example.com", "A"): ["203.0.113.5"]})
    adapter = DnsPythonAdapter(resolver=resolver)
    await adapter.run(make_ctx(hosts=["www.example.com"], limiter=limiter))
    assert len(resolver.queries) == 3
    assert limiter.waits == 3


async def test_dnspython_mock_mode_reads_fixture() -> None:
    class ExplodingResolver:
        async def resolve(self, *args, **kwargs) -> Answer:
            raise AssertionError("mock mode must not resolve")

    adapter = DnsPythonAdapter(resolver=ExplodingResolver())
    result = await adapter.run(make_ctx(mock=True))
    assert result.status == ToolStatus.OK
    assert {r.fqdn for r in result.records} == {
        "www.example.com",
        "alias.example.com",
        "gone.example.com",
    }


# ------------------------------------------------------------------- pyprobe


async def test_pyprobe_normal() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html><title> Example  Domain </title></html>")

    adapter = PyprobeAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx(hosts=["www.example.com"]))
    record = result.records[0]
    assert isinstance(record, HostStatusRecord)
    assert record.state is HostState.ALIVE
    assert record.status_code == 200
    assert record.title == "Example Domain"


async def test_pyprobe_redirect_is_not_followed() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(302, headers={"location": "https://outside.example.net/"})

    adapter = PyprobeAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx(hosts=["www.example.com"]))
    record = result.records[0]
    assert isinstance(record, HostStatusRecord)
    assert record.status_code == 302
    assert record.location == "https://outside.example.net/"
    assert len(calls) == 1


class _BigBody(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.sent = 0

    async def __aiter__(self) -> Iterator[bytes]:
        for _ in range(40):
            self.sent += 1
            yield b"x" * (16 * 1024)


async def test_pyprobe_oversized_body_is_capped() -> None:
    body = _BigBody()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=body)

    adapter = PyprobeAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx(hosts=["www.example.com"]))
    record = result.records[0]
    assert isinstance(record, HostStatusRecord)
    assert record.state is HostState.ALIVE
    assert body.sent < 40, "probe must stop reading at TITLE_LIMIT"
    assert body.sent * 16 * 1024 >= TITLE_LIMIT


async def test_pyprobe_tls_error_is_a_result() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("SSL: CERTIFICATE_VERIFY_FAILED", request=request)

    adapter = PyprobeAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx(hosts=["bad.example.com"]))
    record = result.records[0]
    assert isinstance(record, HostStatusRecord)
    assert record.state is HostState.UNKNOWN


async def test_pyprobe_connection_refused_has_no_record() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    adapter = PyprobeAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx(hosts=["down.example.com"]))
    assert result.records == []
    assert "unreachable=1" in (result.error or "")


async def test_pyprobe_empty_hosts() -> None:
    adapter = PyprobeAdapter(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, text="ok"))
    )
    result = await adapter.run(make_ctx(hosts=[]))
    assert result.records == []
    assert result.error is None


async def test_pyprobe_uppercase_host_is_normalized() -> None:
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        return httpx.Response(200, text="<title>ok</title>")

    adapter = PyprobeAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx(hosts=["WWW.Example.COM."]))
    assert urls == ["https://www.example.com/"]
    assert result.records[0].fqdn == "www.example.com"


async def test_pyprobe_idn_host_is_skipped_without_a_request() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, text="ok")

    adapter = PyprobeAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx(hosts=["bücher.example.com"]))
    assert calls == []
    assert result.records == []
    assert "unreachable=1" in (result.error or "")


async def test_pyprobe_awaits_limiter() -> None:
    limiter = CountingLimiter()
    adapter = PyprobeAdapter(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, text="<title>ok</title>"))
    )
    await adapter.run(make_ctx(hosts=["www.example.com"], limiter=limiter))
    assert limiter.waits == 1


async def test_pyprobe_mock_mode_reads_fixture() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("mock mode must not hit the network")

    adapter = PyprobeAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx(mock=True))
    assert {r.fqdn for r in result.records} == {"www.example.com", "old.example.com"}


# -------------------------------------------------------------------- pyscan


class FakeWriter:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


def make_connect(open_ports: set[int], errors: dict[int, BaseException]):
    async def connect(_ip: str, port: int) -> tuple[None, FakeWriter]:
        if port in errors:
            raise errors[port]
        if port in open_ports:
            return None, FakeWriter()
        raise ConnectionRefusedError(port)

    return connect


async def test_pyscan_open_and_closed() -> None:
    adapter = PyscanAdapter(
        connect=make_connect({443}, {}),
        resolve=lambda _host: asyncio.sleep(0, result=["203.0.113.5"]),
    )
    result = await adapter.run(make_ctx(hosts=["www.example.com"], ports=[443, 80]))
    assert result.status == ToolStatus.OK
    by_port = {r.port: r for r in result.records if isinstance(r, PortRecord)}
    assert by_port[443].state == "open"
    assert by_port[80].state == "closed"
    assert by_port[443].ip == "203.0.113.5"


async def test_pyscan_refused_vs_timeout() -> None:
    adapter = PyscanAdapter(
        connect=make_connect(set(), {81: TimeoutError()}),
        resolve=lambda _host: asyncio.sleep(0, result=["203.0.113.5"]),
    )
    result = await adapter.run(make_ctx(hosts=["www.example.com"], ports=[80, 81]))
    records = [r for r in result.records if isinstance(r, PortRecord)]
    assert [(r.port, r.state) for r in records] == [(80, "closed")]
    assert "timeouts=1" in (result.error or "")


async def test_pyscan_uses_pacer_order_for_ports() -> None:
    kinds: list[str] = []
    ctx = make_ctx(hosts=["www.example.com"], ports=[443, 80])
    original = ctx.pacer.order

    def spy(items, *, kind="host"):
        kinds.append(kind)
        return original(items, kind=kind)

    ctx.pacer.order = spy
    adapter = PyscanAdapter(
        connect=make_connect({443, 80}, {}),
        resolve=lambda _host: asyncio.sleep(0, result=["203.0.113.5"]),
    )
    await adapter.run(ctx)
    assert kinds == ["port"]


async def test_pyscan_ignores_out_of_range_ports() -> None:
    seen: list[int] = []

    async def connect(_ip: str, port: int) -> tuple[None, FakeWriter]:
        seen.append(port)
        raise ConnectionRefusedError(port)

    adapter = PyscanAdapter(
        connect=connect,
        resolve=lambda _host: asyncio.sleep(0, result=["203.0.113.5"]),
    )
    result = await adapter.run(
        make_ctx(hosts=["www.example.com"], ports=[0, -1, 65536, 70000, 443])
    )
    assert seen == [443]
    assert [(r.port, r.state) for r in result.records] == [(443, "closed")]


async def test_pyscan_respects_the_pacer_parallel_limit() -> None:
    ctx = make_ctx(hosts=["www.example.com"], ports=list(range(1000, 1010)))
    ctx.pacer.parallel_limit = lambda _mode: 2  # type: ignore[method-assign]
    active = 0
    peak = 0

    async def connect(_ip: str, port: int) -> tuple[None, FakeWriter]:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0.01)
            raise ConnectionRefusedError(port)
        finally:
            active -= 1

    adapter = PyscanAdapter(
        connect=connect,
        resolve=lambda _host: asyncio.sleep(0, result=["203.0.113.5"]),
    )
    await adapter.run(ctx)
    assert peak == 2


class BannerReader:
    def read(self, *_args) -> bytes:
        raise AssertionError("pyscan must not read a service banner")


async def test_pyscan_never_reads_binary_banner_bytes() -> None:
    async def connect(_ip: str, port: int) -> tuple[BannerReader, FakeWriter]:
        return BannerReader(), FakeWriter()

    adapter = PyscanAdapter(
        connect=connect,
        resolve=lambda _host: asyncio.sleep(0, result=["203.0.113.5"]),
    )
    result = await adapter.run(make_ctx(hosts=["www.example.com"], ports=[443]))
    assert [(r.port, r.state) for r in result.records] == [(443, "open")]
    assert "banner" not in result.model_dump_json()


class DrainingWriter(FakeWriter):
    def __init__(self) -> None:
        super().__init__()
        self.waiting = asyncio.Event()

    async def wait_closed(self) -> None:
        self.waiting.set()
        await asyncio.Event().wait()


async def test_pyscan_cancellation_closes_the_connection() -> None:
    writer = DrainingWriter()

    async def connect(_ip: str, port: int) -> tuple[None, DrainingWriter]:
        return None, writer

    adapter = PyscanAdapter(
        connect=connect,
        resolve=lambda _host: asyncio.sleep(0, result=["203.0.113.5"]),
    )
    task = asyncio.create_task(adapter.run(make_ctx(hosts=["www.example.com"], ports=[443])))
    await asyncio.wait_for(writer.waiting.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert writer.closed is True


async def test_pyscan_awaits_limiter_per_query_and_connection() -> None:
    limiter = CountingLimiter()
    adapter = PyscanAdapter(
        connect=make_connect({443, 80}, {}),
        resolve=lambda _host: asyncio.sleep(0, result=["203.0.113.5"]),
    )
    await adapter.run(make_ctx(hosts=["www.example.com"], ports=[443, 80], limiter=limiter))
    assert limiter.waits == 3


async def test_pyscan_empty_hosts() -> None:
    adapter = PyscanAdapter(
        connect=make_connect(set(), {}),
        resolve=lambda _host: asyncio.sleep(0, result=["203.0.113.5"]),
    )
    result = await adapter.run(make_ctx(hosts=[], ports=[80]))
    assert result.records == []
    assert result.error is None


async def test_pyscan_mock_mode_reads_fixture() -> None:
    class ExplodingOpener:
        async def __call__(self, *_args, **_kwargs) -> tuple[None, FakeWriter]:
            raise AssertionError("mock mode must not connect")

    adapter = PyscanAdapter(connect=ExplodingOpener())
    result = await adapter.run(make_ctx(mock=True))
    assert {(r.fqdn, r.port, r.state) for r in result.records} == {
        ("www.example.com", 443, "open"),
        ("www.example.com", 80, "closed"),
    }


# ----------------------------------------------------------- dependency rule

FORBIDDEN = (
    "reconkit.core.store",
    "reconkit.core.scope",
    "reconkit.ui",
    "reconkit.cli",
    "subprocess",
)


@pytest.mark.parametrize("module", ["dnspython", "pyprobe", "pyscan"])
def test_python_adapters_import_no_forbidden_modules(module: str) -> None:
    path = ADAPTER_DIR / f"{module}.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [node.module or ""]
        else:
            continue
        for name in modules:
            assert not any(
                name == forbidden or name.startswith(f"{forbidden}.") for forbidden in FORBIDDEN
            ), f"{path.name} imports {name}"


def test_python_adapters_are_base_adapters() -> None:
    for adapter in (DnsPythonAdapter, PyprobeAdapter, PyscanAdapter):
        assert issubclass(adapter, BaseToolAdapter)
