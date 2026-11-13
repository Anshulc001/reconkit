"""Adapter tests: MockTransport only, no real network, fixtures for shapes."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import httpx
import pytest

from reconkit.adapters.base import RETRY_DELAY, BaseToolAdapter, HttpAdapter
from reconkit.adapters.certspotter import CertspotterAdapter
from reconkit.adapters.crtsh import CrtshAdapter
from reconkit.adapters.hackertarget import HackertargetAdapter
from reconkit.adapters.otx import OtxAdapter
from reconkit.config import load_config, resolve_speed
from reconkit.core.pacing import Pacer, RateLimiter
from reconkit.models import RunContext, ToolResult, ToolStatus

REPO = Path(__file__).resolve().parents[1]
CONFIG = REPO / "config.yaml"
FIXTURES = REPO / "tests" / "fixtures"
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
    *, mock: bool = False, env: dict[str, str] | None = None, limiter: RateLimiter | None = None
) -> RunContext:
    config = load_config(CONFIG, speed="fast")
    return RunContext(
        target="example.com",
        pacer=Pacer(resolve_speed(config)),
        limiter=limiter if limiter is not None else CountingLimiter(),
        timeout=5.0,
        workspace=REPO / "workspaces" / "example.com",
        mock=mock,
        env=env or {},
    )


def fixture(*parts: str) -> str:
    return (FIXTURES.joinpath(*parts)).read_text(encoding="utf-8")


def fqdns(result: ToolResult) -> list[str]:
    return [record.fqdn for record in result.records]


# ---------------------------------------------------------------- normal shapes

FIXTURE_CASES = [
    (
        CrtshAdapter,
        ("crtsh", "example.com.json"),
        {
            "example.com",
            "www.example.com",
            "dev.example.com",
            "products.example.com",
            "support.example.com",
            "emudhra-lab.example.com",
        },
    ),
    (CertspotterAdapter, ("certspotter", "example.com.json"), {"example.com", "www.example.com"}),
    (OtxAdapter, ("otx", "example.com.synthetic.json"), {"www.example.com", "api.example.com"}),
    (HackertargetAdapter, ("hackertarget", "example.com.txt"), {"www.example.com"}),
]


@pytest.mark.parametrize(("cls", "path", "expected"), FIXTURE_CASES)
async def test_real_fixture_shapes(
    cls: type[HttpAdapter], path: tuple[str, str], expected: set[str]
) -> None:
    raw = fixture(*path)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=raw)

    adapter = cls(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.OK
    assert set(fqdns(result)) == expected


@pytest.mark.parametrize(
    ("cls", "empty"),
    [
        (CrtshAdapter, "[]"),
        (CertspotterAdapter, "[]"),
        (OtxAdapter, '{"passive_dns": []}'),
        (HackertargetAdapter, ""),
    ],
)
async def test_empty_response(cls: type[HttpAdapter], empty: str) -> None:
    adapter = cls(transport=httpx.MockTransport(lambda _request: httpx.Response(200, text=empty)))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.OK
    assert result.records == []


async def test_crtsh_normalizes_wildcards_case_and_trailing_dots() -> None:
    payload = json.dumps(
        [
            {"name_value": "*.Example.COM.\nAPI.Example.COM.\nuser@example.com\nbad host"},
            {"common_name": "WWW.EXAMPLE.COM."},
        ]
    )
    adapter = CrtshAdapter(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, text=payload))
    )
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.OK
    assert fqdns(result) == ["api.example.com", "example.com", "www.example.com"]


async def test_out_of_domain_names_are_dropped() -> None:
    payload = json.dumps([{"name_value": "*.example.net\nexample.com\nm.testexample.com"}])
    adapter = CrtshAdapter(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, text=payload))
    )
    result = await adapter.run(make_ctx())
    assert fqdns(result) == ["example.com"]


async def test_invalid_names_are_dropped() -> None:
    payload = json.dumps([{"name_value": "user@example.com\nbad host\nok.example.com"}])
    adapter = CrtshAdapter(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, text=payload))
    )
    result = await adapter.run(make_ctx())
    assert fqdns(result) == ["ok.example.com"]


async def test_duplicate_names_are_merged() -> None:
    payload = json.dumps(
        [{"name_value": "a.example.com\na.example.com"}, {"common_name": "A.EXAMPLE.COM"}]
    )
    adapter = CrtshAdapter(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, text=payload))
    )
    result = await adapter.run(make_ctx())
    assert fqdns(result) == ["a.example.com"]


# ---------------------------------------------------------------- malformed data


@pytest.mark.parametrize(
    ("cls", "raw"),
    [
        (CrtshAdapter, "{not json"),
        (CrtshAdapter, '{"unexpected": "object"}'),
        (CrtshAdapter, '["not-an-object"]'),
        (CertspotterAdapter, "{not json"),
        (CertspotterAdapter, '{"dns_names": []}'),
        (CertspotterAdapter, '[{"dns_names": "example.com"}]'),
        (OtxAdapter, "{not json"),
        (OtxAdapter, '{"passive_dns": "example.com"}'),
        (OtxAdapter, '[{"hostname": "example.com"}]'),
        (HackertargetAdapter, "API count exceeded - Increase Quota with Membership"),
    ],
)
async def test_malformed_responses_fail_without_raising(cls: type[HttpAdapter], raw: str) -> None:
    adapter = cls(transport=httpx.MockTransport(lambda _r: httpx.Response(200, text=raw)))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.FAILED
    assert result.error
    assert result.records == []


# ---------------------------------------------------------------- HTTP failures


async def test_429_is_failed_and_not_retried() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(429, text="slow down")

    adapter = CrtshAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.FAILED
    assert "429" in (result.error or "")
    assert len(calls) == 1


async def test_500_is_failed_and_not_retried() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(503, text="nope")

    adapter = CrtshAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.FAILED
    assert "503" in (result.error or "")
    assert len(calls) == 1


async def test_timeout_is_failed() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    adapter = CrtshAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.FAILED
    assert "timed out" in (result.error or "")


async def test_connection_error_retries_once_with_injected_sleep() -> None:
    calls: list[httpx.Request] = []
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            raise httpx.ConnectError("refused", request=request)
        return httpx.Response(200, text="[]")

    adapter = CrtshAdapter(transport=httpx.MockTransport(handler), sleep=fake_sleep)
    limiter = CountingLimiter()
    result = await adapter.run(make_ctx(limiter=limiter))
    assert result.status == ToolStatus.OK
    assert len(calls) == 2
    assert sleeps == [RETRY_DELAY]
    assert limiter.waits == 2


async def test_connection_error_twice_fails_after_one_retry() -> None:
    calls: list[httpx.Request] = []
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        raise httpx.ConnectError("refused", request=request)

    adapter = CrtshAdapter(transport=httpx.MockTransport(handler), sleep=fake_sleep)
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.FAILED
    assert len(calls) == 2
    assert sleeps == [RETRY_DELAY]


async def test_rate_limiter_is_used_before_the_request() -> None:
    limiter = CountingLimiter()
    adapter = CrtshAdapter(transport=httpx.MockTransport(lambda _r: httpx.Response(200, text="[]")))
    await adapter.run(make_ctx(limiter=limiter))
    assert limiter.waits == 1


# ---------------------------------------------------------------- keys and mock


async def test_certspotter_sends_key_in_header_and_never_leaks_it() -> None:
    key = "sk-certspotter-test-123"
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text=fixture("certspotter", "example.com.json"))

    adapter = CertspotterAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx(env={"CERTSPOTTER_API_KEY": key}))
    assert result.status == ToolStatus.OK
    assert seen[0].headers["Authorization"] == f"Bearer {key}"
    assert key not in result.model_dump_json()
    assert key not in str(seen[0].url)


async def test_otx_sends_key_in_header_and_never_leaks_it() -> None:
    key = "otx-test-key-456"
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(500, text=f"upstream error for {key}")

    adapter = OtxAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx(env={"OTX_API_KEY": key}))
    assert seen[0].headers["X-OTX-API-KEY"] == key
    assert result.status == ToolStatus.FAILED
    assert key not in (result.error or "")
    assert key not in result.model_dump_json()


async def test_mock_mode_reads_fixture_and_skips_network() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        raise AssertionError("mock mode must not hit the network")

    adapter = CrtshAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx(mock=True))
    assert result.status == ToolStatus.OK
    assert "example.com" in fqdns(result)
    assert calls == []


async def test_mock_mode_without_fixture_fails(tmp_path: Path) -> None:
    adapter = CrtshAdapter(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, text="[]")),
        fixtures_dir=tmp_path,
    )
    result = await adapter.run(make_ctx(mock=True))
    assert result.status == ToolStatus.FAILED
    assert "no fixture" in (result.error or "")


def test_http_adapters_need_nothing_installed() -> None:
    assert CrtshAdapter().check_installed().installed is True


# ---------------------------------------------------------------- dependency rule

FORBIDDEN = (
    "reconkit.core.store",
    "reconkit.core.scope",
    "reconkit.ui",
    "reconkit.cli",
    "subprocess",
)


def test_adapters_import_no_forbidden_modules() -> None:
    for path in ADAPTER_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                modules = [node.module or ""]
            else:
                continue
            for module in modules:
                assert not any(
                    module == forbidden or module.startswith(f"{forbidden}.")
                    for forbidden in FORBIDDEN
                ), f"{path.name} imports {module}"


def test_base_contract_is_abstract() -> None:
    assert issubclass(HttpAdapter, BaseToolAdapter)
    with pytest.raises(TypeError):
        BaseToolAdapter()
