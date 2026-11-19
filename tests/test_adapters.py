"""Adapter tests: MockTransport only, no real network, fixtures for shapes."""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path

import httpx
import pytest

from reconkit.adapters.base import MAX_BODY_BYTES, RETRY_DELAY, BaseToolAdapter, HttpAdapter
from reconkit.adapters.certspotter import CertspotterAdapter
from reconkit.adapters.crtsh import CrtshAdapter
from reconkit.adapters.hackertarget import HackertargetAdapter
from reconkit.adapters.otx import OtxAdapter
from reconkit.adapters.urlscan import UrlscanAdapter
from reconkit.models import RunContext, ToolResult, ToolStatus

REPO = Path(__file__).resolve().parents[1]
CONFIG = REPO / "config.yaml"
FIXTURES = REPO / "tests" / "fixtures"
ADAPTER_DIR = REPO / "src" / "reconkit" / "adapters"


def make_ctx(
    *, mock: bool = False, env: dict[str, str] | None = None, target: str = "example.com"
) -> RunContext:
    return RunContext(
        target=target,
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
    ],
)
async def test_malformed_responses_fail_without_raising(cls: type[HttpAdapter], raw: str) -> None:
    adapter = cls(transport=httpx.MockTransport(lambda _r: httpx.Response(200, text=raw)))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.FAILED
    assert result.error
    assert result.records == []


# ---------------------------------------------------------------- HTTP failures


async def test_429_is_a_gap_and_not_retried() -> None:
    """Owner ruling 2026-11-18: a 429 is an external-service gap, not a failure."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(429, text="slow down")

    adapter = CrtshAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.GAP
    assert "429" in (result.error or "")
    assert len(calls) == 1


async def test_a_5xx_from_the_upstream_is_a_gap() -> None:
    """The real sakec.ac.in evidence: crt.sh answered 502 to every request."""
    adapter = CrtshAdapter(transport=httpx.MockTransport(lambda _r: httpx.Response(502)))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.GAP
    assert "502" in (result.error or "")


async def test_a_404_from_an_external_tool_is_a_gap() -> None:
    """D47: an API pane answering 404 for its own query is the service, not us.

    Measured (2026-11-19): crt.sh answered 404 on 1 of 10 identical calls for
    example.com, 0 of 10 for testfire.net, and 502 on its own root - the run
    that exited 5 was reading a flaky front end as a broken tool.
    """
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(404)

    adapter = CrtshAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.GAP
    assert result.error == "crtsh: HTTP 404"
    # A gap is not a failure that makes the run exit 5, and it is not retried.
    assert len(calls) == 1


async def test_a_404_from_a_local_binary_is_still_a_failure() -> None:
    """D47 is scoped to external APIs; a 404 anywhere else keeps its old meaning."""
    from reconkit.adapters.base import classify_external_gap

    # A local tool that prints a 404 is still a failure, through the text path.
    assert classify_external_gap("localhttp: HTTP 404") is None

    class LocalAdapter(HttpAdapter):
        """An HTTP adapter with no third-party API behind it."""

        name = "localhttp"

        def url(self, ctx: RunContext) -> str:
            return "http://127.0.0.1/"

        def parse_output(self, raw: str) -> list[object]:
            return []

    adapter = LocalAdapter(transport=httpx.MockTransport(lambda _r: httpx.Response(404)))
    assert LocalAdapter.external_api is False
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.FAILED
    assert result.error == "localhttp: HTTP 404"


async def test_crtsh_404_is_a_gap_not_a_retry() -> None:
    """The 404 fix is a classification, not the identity retry (D46) leaking in."""
    assert CrtshAdapter.external_api is True
    assert HttpAdapter.external_api is False

    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(404)

    async def no_sleep(_seconds: float) -> None:
        raise AssertionError("a 404 must not be retried")

    adapter = CrtshAdapter(transport=httpx.MockTransport(handler), sleep=no_sleep)
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.GAP
    assert len(calls) == 1


async def test_hackertarget_quota_answer_is_a_gap() -> None:
    """HTTP 200 with a quota sentence (the real free-tier shape) is a gap."""
    body = "API count exceeded - Increase Quota with Premium purchase"
    adapter = HackertargetAdapter(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, text=body))
    )
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.GAP
    assert "quota" in (result.error or "")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("otx: rate limited (HTTP 429)", True),
        ("HTTP 429 Too Many Requests", True),
        ("hackertarget: free quota exceeded", True),
        ("crtsh: server error (HTTP 502)", True),
        ("503 Service Unavailable", True),
        ("504 Gateway Timeout", True),
        # R8 (2026-11-18) names 500 explicitly; the http context is required so
        # a bare count never reads as an upstream failure.
        ("HTTP 500 Internal Server Error", True),
        ("server error (HTTP 500)", True),
        ("500 items parsed", False),
        ("401 Unauthorized", False),
        ("403 Forbidden", False),
        ("connect ECONNREFUSED 1.2.3.4:443", False),
        ("invalid JSON line", False),
        ("tool is not installed", False),
        ("", False),
    ],
)
def test_classify_external_gap_matches_only_third_party_signatures(
    text: str, expected: bool
) -> None:
    """docs/09 section 3: one classifier, and it never calls a local fault a gap."""
    from reconkit.adapters.base import classify_external_gap

    assert (classify_external_gap(text) is not None) is expected


async def test_a_429_gap_still_reports_its_own_duration() -> None:
    """12c: a refusal is work that took real time, gap or not."""
    adapter = CrtshAdapter(transport=httpx.MockTransport(lambda _r: httpx.Response(429)))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.GAP
    assert result.duration_s > 0


async def test_a_parse_error_still_reports_its_own_duration() -> None:
    adapter = CrtshAdapter(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, text="}not json"))
    )
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.FAILED
    assert result.duration_s > 0


async def test_a_successful_run_reports_the_adapters_own_duration() -> None:
    payload = fixture("crtsh", "example.com.json")
    adapter = CrtshAdapter(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, text=payload))
    )
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.OK
    assert result.duration_s > 0


async def test_a_mock_run_duration_is_small_and_measured() -> None:
    """docs/04 section 5: mock = fixture read + parse, small and positive."""
    adapter = CrtshAdapter(fixtures_dir=FIXTURES)
    result = await adapter.run(make_ctx(mock=True))
    assert result.status == ToolStatus.OK
    assert 0 < result.duration_s < 5.0


async def test_500_is_a_gap_and_not_retried() -> None:
    """Owner ruling 2026-11-18: an upstream 5xx is an external-service gap."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(503, text="nope")

    adapter = CrtshAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.GAP
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
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.OK
    assert len(calls) == 2
    assert sleeps == [RETRY_DELAY]


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


class _BodyStream(httpx.AsyncByteStream):
    """A chunked body of exactly `total` bytes, with no Content-Length header."""

    def __init__(self, total: int, chunk: int = 4096) -> None:
        self.total = total
        self.chunk = chunk

    async def __aiter__(self):
        remaining = self.total
        while remaining:
            size = min(self.chunk, remaining)
            yield b"x" * size
            remaining -= size


async def test_body_exactly_at_the_cap_passes() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * MAX_BODY_BYTES)

    adapter = CrtshAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx())
    assert "response too large" not in (result.error or "")


async def test_body_one_byte_over_the_cap_is_failed() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=_BodyStream(MAX_BODY_BYTES + 1))

    adapter = CrtshAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.FAILED
    assert "response too large" in (result.error or "")


async def test_chunked_body_without_content_length_is_capped() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=_BodyStream(MAX_BODY_BYTES + 4096))

    adapter = CrtshAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.FAILED
    assert "response too large" in (result.error or "")


async def test_lying_small_content_length_is_still_capped() -> None:
    """Regression: PIT-20 a lying small Content-Length cannot bypass the byte cap."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-length": "16"},
            stream=_BodyStream(MAX_BODY_BYTES + 4096),
        )

    adapter = CrtshAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.FAILED
    assert "response too large" in (result.error or "")


async def test_declared_oversized_length_is_failed() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-length": str(MAX_BODY_BYTES + 1)},
            content=b"",
        )

    adapter = CrtshAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.FAILED
    assert "response too large" in (result.error or "")


async def test_hackertarget_free_quota_is_a_gap() -> None:
    """The real free-tier answer is HTTP 200 with a quota sentence."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="API count Exceeded - Increase Quota with Membership")

    adapter = HackertargetAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.GAP
    assert "free quota exceeded" in (result.error or "")


async def test_hackertarget_other_text_is_unexpected() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="error check your search parameter")

    adapter = HackertargetAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.run(make_ctx())
    assert result.status == ToolStatus.FAILED
    assert "unexpected response" in (result.error or "")


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
    # A 500 from the provider is a gap; the key must still never leak.
    assert result.status == ToolStatus.GAP
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


# ------------------------------------------------------ urlscan (wave 7)


def test_urlscan_adapter_parses_json() -> None:
    """One result per scan; the domain comes from page, then task."""
    adapter = UrlscanAdapter()
    records = adapter.parse_output(fixture("adapters", "urlscan.synthetic.json"))
    assert [record.fqdn for record in records] == ["demo.testfire.net", "www.testfire.net"]
    assert all(record.source == "urlscan" for record in records)


def test_urlscan_works_without_key() -> None:
    """`URLSCAN_API_KEY` is for submissions: a keyless search still runs."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text=fixture("adapters", "urlscan.synthetic.json"))

    adapter = UrlscanAdapter(transport=httpx.MockTransport(handler))
    result = asyncio.run(adapter.run(make_ctx(target="testfire.net")))
    assert result.status is ToolStatus.OK
    assert fqdns(result) == ["demo.testfire.net", "www.testfire.net"]
    assert "api-key" not in seen[0].headers
    assert seen[0].url.params["q"] == "domain:testfire.net"


def test_urlscan_sends_the_key_when_set() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text=fixture("adapters", "urlscan.synthetic.json"))

    adapter = UrlscanAdapter(transport=httpx.MockTransport(handler))
    asyncio.run(adapter.run(make_ctx(env={"URLSCAN_API_KEY": "secret-key"})))
    assert seen[0].headers["api-key"] == "secret-key"
