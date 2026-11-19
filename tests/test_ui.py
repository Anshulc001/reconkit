"""Part 7: UI tables, JSON document, silence and color safety."""

from __future__ import annotations

import ast
import json
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console
from rich.text import Text

import reconkit.ui as ui
from reconkit.engine import (
    CompletionGap,
    ExitCode,
    HostSnapshot,
    ScanSummary,
    StageOutcome,
    UrlSnapshot,
)
from reconkit.models import (
    Confidence,
    HostState,
    Stage,
    SubdomainRecord,
    ToolResult,
    ToolStatus,
)

REPO = Path(__file__).resolve().parents[1]


class TtyBuffer(StringIO):
    """A StringIO that claims to be a terminal, for NO_COLOR checks."""

    def isatty(self) -> bool:
        return True


def make_summary(
    *,
    stages: list[StageOutcome] | None = None,
    warnings: list[str] | None = None,
    exit_code: ExitCode = ExitCode.SUCCESS,
) -> ScanSummary:
    return ScanSummary(
        target="example.com",
        target_id=1,
        stages=stages if stages is not None else [],
        warnings=warnings if warnings is not None else [],
        exit_code=exit_code,
    )


def sample_summary(exit_code: ExitCode = ExitCode.SUCCESS) -> ScanSummary:
    return make_summary(
        stages=[
            StageOutcome(
                Stage.SUBS,
                1,
                results=[
                    ToolResult(
                        tool="crtsh",
                        status=ToolStatus.OK,
                        records=[SubdomainRecord(fqdn="api.example.com", source="crtsh")],
                    ),
                    ToolResult(tool="subfinder", status=ToolStatus.FAILED, error="timed out"),
                ],
            )
        ],
        warnings=["wildcard DNS is unknown; filter skipped"],
        exit_code=exit_code,
    )


def host_rows() -> list[ui.HostRow]:
    return [
        ui.HostRow(
            "api.example.com",
            HostState.ALIVE,
            Confidence.HIGH,
            ("crtsh", "subfinder", "otx"),
            200,
            (80, 443),
        ),
        ui.HostRow(
            "vpn.example.com", HostState.DNS_ONLY, Confidence.MEDIUM, ("a", "b"), None, (443,)
        ),
        ui.HostRow("old.example.com", HostState.SHUT_DOWN, Confidence.LOW, ("crtsh",)),
        ui.HostRow("dead.example.com", HostState.DEAD, Confidence.UNCONFIRMED, ("a", "b"), 404),
        ui.HostRow("mystery.example.com", HostState.UNKNOWN, Confidence.LOW, ("crtsh",)),
    ]


def render_text(
    summary: ScanSummary | None = None,
    hosts: list[ui.HostRow] | None = None,
    **kwargs: object,
) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    code = ui.render(
        summary if summary is not None else sample_summary(),
        host_rows() if hosts is None else hosts,
        stdout=stdout,
        stderr=stderr,
        **kwargs,
    )
    return code, stdout.getvalue(), stderr.getvalue()


def test_json_output_is_one_valid_document_with_documented_schema() -> None:
    code, raw, err = render_text(json_output=True)
    assert code == int(ExitCode.SUCCESS)
    assert err == ""
    assert raw.count("\n") == 1
    document = json.loads(raw)
    assert document["type"] == "summary"
    assert document["target"] == "example.com"
    assert document["exit_code"] == 0
    assert document["resumed"] is False
    assert document["scope_denied"] is False
    assert set(document) == {
        "type",
        "target",
        "exit_code",
        "resumed",
        "scope_denied",
        "scope_mode",
        "completion",
        "warnings",
        # Added 2026-11-19 (D56): scope facts worth keeping after the terminal
        # (a partial CIDR exclusion), always present even when empty.
        "scope_warnings",
        # Added 2026-11-18 (D22): the www/non-www pairs, always present.
        "www_dedup",
        "hosts",
        "stages",
        "summary",
    }
    assert document["scope_warnings"] == []
    assert document["www_dedup"] == {"applied": False, "pairs": []}
    # Added 2026-11-17 with the owner's completion ruling: a run with no gaps
    # still carries the key, so consumers never branch on its absence.
    assert document["completion"] == {"status": "complete", "gaps": []}
    assert set(document["hosts"][0]) == {
        "fqdn",
        "state",
        "confidence",
        "sources",
        "status_code",
        "ports",
        "detail",
        "duplicate_of",
        "www_note",
    }
    assert document["hosts"][0]["detail"] is None
    assert document["hosts"][0]["duplicate_of"] is None
    assert document["stages"][0]["stage"] == "subs"
    assert document["stages"][0]["results"][0]["tool"] == "crtsh"
    assert document["stages"][0]["results"][0]["status"] == "ok"
    assert set(document["summary"]) == {
        "hosts",
        "alive",
        "dns_only",
        "shut_down",
        "dead",
        "unknown",
        "tools_ok",
        # Added 2026-11-18: a tool refused by its upstream is a gap, not a
        # failure (owner ruling).
        "tools_gap",
        "tools_failed",
        "tools_skipped",
        "tools_timeout",
        # D52: stopped by the engine, partial output kept.
        "tools_killed",
    }
    assert document["summary"]["hosts"] == 5
    assert document["summary"]["tools_ok"] == 1
    assert document["summary"]["tools_gap"] == 0
    assert document["summary"]["tools_failed"] == 1


def test_json_host_row_carries_the_stored_detail() -> None:
    """12d: the bounded reason is visible through --json (docs/02 section 5)."""
    row = ui.HostRow(
        "mystery.example.com",
        HostState.UNKNOWN,
        Confidence.LOW,
        ("pyprobe",),
        detail="tls: certificate has expired",
    )
    document = ui.summary_document(sample_summary(), [row])
    hosts = document["hosts"]
    assert isinstance(hosts, list)
    assert hosts[0]["detail"] == "tls: certificate has expired"


def test_json_hosts_carry_confidence_state_and_sources() -> None:
    _, raw, _ = render_text(json_output=True)
    document = json.loads(raw)
    hosts = document["hosts"]
    assert {host["state"] for host in hosts} == {state.value for state in HostState}
    assert {host["confidence"] for host in hosts} == {confidence.value for confidence in Confidence}
    for host in hosts:
        assert isinstance(host["sources"], list)
        assert host["sources"]
    assert document["summary"]["alive"] == 1
    assert document["summary"]["dns_only"] == 1
    assert document["summary"]["shut_down"] == 1
    assert document["summary"]["dead"] == 1
    assert document["summary"]["unknown"] == 1


def test_an_empty_stage_warning_reaches_the_table_and_the_json() -> None:
    """12k: one warning channel, both surfaces, 5 carried through."""
    note = "tech stage executed no tools: 5 tool(s) skipped (no adapter yet (phase 2))"
    summary = make_summary(
        stages=[StageOutcome(Stage.TECH, 2)], warnings=[note], exit_code=ExitCode.PARTIAL
    )
    code, _, err = render_text(summary, hosts=[])
    assert code == int(ExitCode.PARTIAL)
    assert "warning: tech stage executed no tools" in err

    code_json, raw, json_err = render_text(summary, hosts=[], json_output=True)
    assert code_json == int(ExitCode.PARTIAL)
    assert json_err == ""
    assert json.loads(raw)["warnings"] == [note]


def test_silent_suppresses_tables_but_returns_the_exit_code() -> None:
    code, out, err = render_text(sample_summary(ExitCode.PARTIAL), silent=True)
    assert code == int(ExitCode.PARTIAL)
    assert out == ""
    assert err == ""


def test_silent_mode_in_a_non_tty_context_does_not_crash_or_hang() -> None:
    code, out, err = render_text(sample_summary(), silent=True)
    assert code == int(ExitCode.SUCCESS)
    assert out == ""
    assert err == ""


def test_silent_json_still_writes_one_usable_document() -> None:
    code, raw, err = render_text(
        sample_summary(ExitCode.INTERRUPTED), json_output=True, silent=True
    )
    assert code == int(ExitCode.INTERRUPTED)
    assert err == ""
    assert json.loads(raw)["exit_code"] == int(ExitCode.INTERRUPTED)


def test_non_tty_output_has_no_ansi_codes() -> None:
    _, out, err = render_text()
    assert "\x1b[" not in out
    assert "\x1b[" not in err
    assert "Results" in err
    assert "Tools" in err


def test_no_color_env_suppresses_ansi_on_a_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    stream = TtyBuffer()
    console = ui.make_console(stream)
    console.print(Text("ALIVE", style="green"))
    assert "ALIVE" in stream.getvalue()
    assert "\x1b[" not in stream.getvalue()


def test_redacted_engine_values_stay_redacted_through_rendering() -> None:
    summary = make_summary(
        stages=[
            StageOutcome(
                Stage.SUBS,
                1,
                results=[
                    ToolResult(
                        tool="crtsh",
                        status=ToolStatus.FAILED,
                        error="request failed with token ***",
                    )
                ],
            )
        ],
        warnings=["dangling CNAME: ***"],
    )
    _, raw, err = render_text(summary, json_output=True)
    assert "***" in raw
    assert "dangling CNAME: ***" in raw
    assert "sk-live-abc" not in raw
    _, _, table = render_text(summary)
    assert "***" in table
    assert "sk-live-abc" not in table
    assert "ToolResult(" not in table


def test_every_state_has_a_distinct_label() -> None:
    labels = [ui.format_state(state) for state in HostState]
    assert labels == [
        "ALIVE",
        "DNS_ONLY",
        "SHUT_DOWN",
        "DEAD",
        "UNKNOWN",
    ]
    assert len(set(labels)) == len(labels)


def test_every_confidence_has_a_distinct_label() -> None:
    labels = [ui.format_confidence(confidence, ("a", "b")) for confidence in Confidence]
    assert labels == ["HIGH (2)", "MEDIUM (2)", "LOW (2)", "UNCONFIRMED (2)"]
    assert len(set(labels)) == len(labels)


def test_all_state_and_confidence_labels_render_in_tables() -> None:
    stream = StringIO()
    console = Console(file=stream, width=200, force_terminal=False, color_system=None)
    ui.render(sample_summary(), host_rows(), console=console)
    rendered = stream.getvalue()
    for state in HostState:
        assert ui.format_state(state) in rendered
    for row in host_rows():
        assert ui.format_confidence(row.confidence, row.sources) in rendered


def test_zero_hosts_renders_the_documented_empty_state() -> None:
    _, out, err = render_text(make_summary(), [])
    assert out == ""
    assert "No results" in err
    assert "Check 'reconkit doctor'" in err


def test_stage_with_zero_tools_renders_a_clear_empty_state() -> None:
    summary = make_summary(stages=[StageOutcome(Stage.SUBS, 1, results=[])])
    _, _, err = render_text(summary, [])
    assert "No results" in err
    assert "skipped or excluded" in err


def test_one_and_many_warnings_are_all_rendered() -> None:
    one = make_summary(warnings=["one warning"])
    _, _, one_text = render_text(one, [])
    assert one_text.count("warning:") == 1
    assert "one warning" in one_text

    many = make_summary(warnings=["first", "second", "third"])
    _, _, many_text = render_text(many, [])
    assert many_text.count("warning:") == 3
    for warning in ("first", "second", "third"):
        assert warning in many_text


def test_www_duplicate_rows_get_notes_and_the_summary_counts_unique() -> None:
    """D22: the Notes column explains each pair and the summary counts unique hosts."""
    rows = [
        ui.HostRow("example.com", HostState.ALIVE, Confidence.HIGH, ("dnsx", "httpx"), 200),
        ui.HostRow(
            "www.example.com",
            HostState.ALIVE,
            Confidence.HIGH,
            ("dnsx", "httpx"),
            301,
            duplicate_of="example.com",
        ),
        ui.HostRow("api.example.com", HostState.ALIVE, Confidence.HIGH, ("dnsx",), 403),
    ]
    canonical = {row.duplicate_of for row in rows if row.duplicate_of is not None}
    assert ui.host_note(rows[0], canonical) == "canonical"
    assert ui.host_note(rows[1], canonical) == "-> redirects to example.com"
    assert ui.host_note(rows[2], canonical) == "-"
    _, _, err = render_text(make_summary(), rows)
    # The table wraps at the terminal width, so compare on collapsed whitespace.
    flat = " ".join(err.split())
    assert "Notes" in flat
    assert "canonical" in flat
    assert "3 hosts (2 unique after www-dedup): 3 ALIVE" in flat
    _, raw, _ = render_text(make_summary(), rows, json_output=True)
    document = json.loads(raw)
    assert document["www_dedup"] == {
        "applied": True,
        "pairs": [{"host": "www.example.com", "duplicate_of": "example.com"}],
    }
    assert document["hosts"][1]["duplicate_of"] == "example.com"


def test_www_notes_without_any_duplicate_leave_the_summary_line_alone() -> None:
    rows = [
        ui.HostRow(
            "example.com",
            HostState.ALIVE,
            Confidence.HIGH,
            ("dnsx",),
            200,
            www_note="has www sibling at www.example.com",
        ),
        ui.HostRow(
            "www.example.com",
            HostState.ALIVE,
            Confidence.HIGH,
            ("dnsx",),
            200,
            www_note="has www sibling at example.com",
        ),
    ]
    canonical: set[str] = set()
    assert ui.host_note(rows[0], canonical) == "has www sibling at www.example.com"
    _, _, err = render_text(make_summary(), rows)
    flat = " ".join(err.split())
    assert "2 hosts: 2 ALIVE" in flat
    assert "sibling" in flat
    _, raw, _ = render_text(make_summary(), rows, json_output=True)
    assert json.loads(raw)["www_dedup"] == {"applied": False, "pairs": []}


def test_no_notes_column_when_no_pair_was_found() -> None:
    """An ordinary run keeps its six columns; Notes appears only when used."""
    _, _, err = render_text(make_summary(), host_rows())
    assert "Notes" not in err
    assert "Subdomain" in err


def test_rich_markup_in_host_data_is_printed_literally() -> None:
    row = ui.HostRow(
        "[red]x[/]",
        HostState.ALIVE,
        Confidence.HIGH,
        ("[bold]src[/]",),
        200,
    )
    _, _, err = render_text(make_summary(), [row])
    assert "[red]x[/]" in err
    assert "[bold]src[/]" in err
    assert "\x1b[" not in err


def test_unicode_and_wide_hostnames_stay_intact_in_json() -> None:
    name = "münich." + ("a" * 120) + ".example.com"
    row = ui.HostRow(name, HostState.ALIVE, Confidence.HIGH, ("crtsh",), 200)
    _, raw, _ = render_text(make_summary(), [row], json_output=True)
    assert json.loads(raw)["hosts"][0]["fqdn"] == name
    _, _, rendered = render_text(make_summary(), [row])
    assert "münich" in rendered
    assert "\x1b[" not in rendered


def test_rate_limit_hint_is_shown_only_when_the_key_is_unset() -> None:
    hint = ui.rate_limit_hint(
        "subfinder",
        "SUBFINDER_API_KEY",
        "https://example.com/key",
        key_set=False,
    )
    assert hint is not None
    assert "SUBFINDER_API_KEY" in hint
    assert "https://example.com/key" in hint
    assert (
        ui.rate_limit_hint(
            "subfinder",
            "SUBFINDER_API_KEY",
            "https://example.com/key",
            key_set=True,
        )
        is None
    )

    stream = StringIO()
    console = ui.make_console(stream)
    ui.render_rate_limit_hint(
        "subfinder",
        "SUBFINDER_API_KEY",
        "https://example.com/key",
        key_set=True,
        console=console,
    )
    assert stream.getvalue() == ""
    ui.render_rate_limit_hint(
        "subfinder",
        "SUBFINDER_API_KEY",
        "https://example.com/key",
        key_set=False,
        console=console,
    )
    assert "SUBFINDER_API_KEY" in stream.getvalue()


def test_progress_is_suppressed_only_in_silent_mode() -> None:
    """Part 13: progress is a stderr concern; `--json` no longer silences it.

    docs/02 section 5 was changed first (the old text said `--json` suppresses
    progress, which is what made a slow `--json` run print nothing at all for
    minutes). Only `--silent` suppresses it now, and stdout is never involved.
    """
    stream = StringIO()
    console = ui.make_console(stream)
    ui.render_progress("subs: running 3 tool(s)", console=console, silent=True)
    assert stream.getvalue() == ""
    ui.render_progress("subs: running 3 tool(s)", console=console)
    assert "subs: running 3 tool(s)" in stream.getvalue()
    ui.render_progress("subs: running 3 tool(s)", console=console, elapsed_s=4.0)
    assert "(4s)" in stream.getvalue()


def test_activity_spinner_writes_nothing_to_a_non_terminal() -> None:
    """2026-11-18: the live status line stays out of piped output and stdout.

    A spinner frame in a redirect target would be garbage in every log, so a
    non-terminal console gets the no-op updater and the durable progress lines
    remain the only thing written.
    """
    stream = StringIO()
    console = ui.make_console(stream)
    with ui.activity_spinner(console) as update:
        update("subs: 0/9 tool(s) done, 3s elapsed - running: amass, otx")
    assert stream.getvalue() == ""


def test_the_gaps_block_goes_to_stderr_and_the_json_carries_completion() -> None:
    """Added 2026-11-17: the owner's completion block (docs/02 section 6)."""
    summary = sample_summary()
    summary.mode = "full"
    summary.gaps = [
        CompletionGap(Stage.TECH, "no adapter yet (phase 3)", 5),
        CompletionGap(Stage.URLS, "not installed", 2),
    ]

    code, raw, err = render_text(summary=summary, json_output=True)
    assert code == 0
    # stdout stays one clean document; the block is stderr-only.
    assert raw.count("\n") == 1
    assert json.loads(raw)["completion"] == {
        "status": "complete_with_gaps",
        "gaps": [
            {"stage": "tech", "reason": "no adapter yet (phase 3)"},
            {"stage": "urls", "reason": "not installed"},
        ],
    }
    assert "⚠ full scan completed with gaps — 2 stage(s)" in err
    assert "tech: 5 tool(s) skipped (no adapter yet (phase 3))" in err
    assert "urls: 2 tool(s) skipped (not installed)" in err
    assert "this is not a failure" in err
    assert "reconkit doctor" in err

    code, _, err = render_text(summary=summary)
    assert code == 0
    assert "completed with gaps" in err


def test_a_gap_tool_is_shown_as_gap_and_named_in_the_block() -> None:
    """Owner ruling 2026-11-18: an external refusal reads `gap`, not `failed`."""
    summary = sample_summary()
    summary.stages[0].results = [
        ToolResult(tool="crtsh", status=ToolStatus.OK, records=[]),
        ToolResult(tool="otx", status=ToolStatus.GAP, error="otx: rate limited (HTTP 429)"),
    ]
    summary.gaps = [CompletionGap(Stage.SUBS, "otx: rate limited (HTTP 429)")]
    summary.exit_code = ExitCode.SUCCESS

    code, raw, err = render_text(summary=summary)
    assert code == 0
    assert "gap" in err
    # The line wraps at 80 columns, so the counts are asserted one by one.
    assert "tools: 1 ok, 1" in err
    assert "gap, 0 failed" in err
    assert "⚠ passive scan completed with gaps — 1 stage(s) incomplete" in err
    # No skip count for an external gap: nothing was skipped.
    assert "subs: otx: rate limited (HTTP 429)" in err
    assert "tool(s) skipped (otx" not in err

    _, document, _ = render_text(summary=summary, json_output=True)
    assert json.loads(document)["summary"]["tools_gap"] == 1
    assert json.loads(document)["completion"]["gaps"] == [
        {"stage": "subs", "reason": "otx: rate limited (HTTP 429)"}
    ]


def test_a_complete_run_prints_no_gaps_block() -> None:
    """The block is silent for every run that has no gaps (byte-identical output)."""
    _, raw, err = render_text(json_output=True)
    assert "completed with gaps" not in err
    assert json.loads(raw)["completion"]["status"] == "complete"


def test_a_killed_tool_is_counted_named_and_given_a_stale_output_column() -> None:
    """D52: a kill shows up in the summary line, the table and "what got stuck"."""
    summary = make_summary(
        stages=[
            StageOutcome(
                Stage.URLS,
                1,
                results=[
                    ToolResult(
                        tool="gau",
                        status=ToolStatus.KILLED,
                        duration_s=412.3,
                        last_output_s=60.0,
                        error="killed after 60s idle at stage 412.3s, 1042 partial",
                    ),
                    ToolResult(tool="katana", status=ToolStatus.OK, duration_s=8.0),
                ],
            )
        ]
    )
    code, _, err = render_text(summary=summary)
    assert code == int(ExitCode.SUCCESS)
    assert "1 killed" in err
    assert "60s ago" in err  # the `Last output` column, killed rows only
    assert "⚠ 1 tool(s) stopped early — partial output kept" in err
    assert "gau: killed after 60s idle at stage 412.3s, 1042 partial" in err
    assert "412.3s" in err  # the `Time` column

    _, raw, _ = render_text(summary=summary, json_output=True)
    document = json.loads(raw)
    assert document["summary"]["tools_killed"] == 1
    assert document["summary"]["tools_timeout"] == 0
    assert document["stages"][0]["results"][0]["last_output_s"] == 60.0


def test_a_run_with_no_kill_prints_no_stopped_early_block() -> None:
    """The block is silent unless something was stopped (byte-identical output)."""
    _, _, err = render_text()
    assert "stopped early" not in err
    assert "killed" not in err


def test_ui_does_not_import_store_scope_adapters_or_cli() -> None:
    source = (REPO / "src" / "reconkit" / "ui.py").read_text(encoding="utf-8")
    modules: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.append(node.module)
    forbidden = ("reconkit.core.store", "reconkit.core.scope", "reconkit.cli")
    assert not any(module == name for module in modules for name in forbidden)
    assert not any(module.startswith("reconkit.adapters") for module in modules)
    assert "reconkit.engine" in modules


# ------------------------------- (D62) report domain tree and URLs by host


def _snapshot(
    fqdn: str,
    state: HostState = HostState.ALIVE,
    confidence: Confidence = Confidence.HIGH,
) -> HostSnapshot:
    return HostSnapshot(
        fqdn=fqdn,
        state=state,
        confidence=confidence,
        sources=("crtsh",),
        status_code=200 if state is HostState.ALIVE else None,
        ports=(),
    )


def _url(url: str, status_code: int | None = None, host_state: str = "ALIVE") -> UrlSnapshot:
    host = url.split("//", 1)[1].split("/", 1)[0]
    return UrlSnapshot(url=url, host=host, status_code=status_code, host_state=host_state)


def _document(
    rows: list[HostSnapshot], urls: list[UrlSnapshot], *, urls_max: int = 200
) -> dict[str, object]:
    return ui.report_document(
        "example.com",
        rows,
        ui.REPORT_FIELDS,
        run_at=datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC),
        urls=urls,
        urls_max=urls_max,
    )


def test_report_json_has_roots_and_urls_by_host() -> None:
    """D62: the tree and the URL block live beside the unchanged hosts table."""
    rows = [_snapshot("www.example.com"), _snapshot("api.example.com", HostState.DNS_ONLY)]
    urls = [
        _url("https://www.example.com/admin/login.php", None),
        _url("https://api.example.com/v1/users?id=1", 200, "DNS_ONLY"),
    ]
    document = _document(rows, urls)
    assert document["roots"] == [
        {
            "domain": "example.com",
            "subdomains": ["www.example.com", "api.example.com"],
            "host_count": 2,
        }
    ]
    grouped = document["urls_by_host"]
    assert isinstance(grouped, dict)
    assert set(grouped) == {"www.example.com", "api.example.com"}
    assert grouped["api.example.com"] == [
        {
            "url": "https://api.example.com/v1/users?id=1",
            "status_code": 200,
            "host_state": "DNS_ONLY",
        }
    ]
    assert document["urls_total"] == 2
    assert document["urls_shown"] == 2
    assert document["urls_truncated"] is False
    # The hosts table keeps its shape.
    assert [host["hostname"] for host in document["hosts"]] == [
        "www.example.com",
        "api.example.com",
    ]


def test_urls_by_host_ranks_interesting_paths_first() -> None:
    """docs/02 s5: path, then query, then a live status decides the order."""
    urls = [
        _url("https://example.com/about", 404),
        _url("https://example.com/plain?page=2", None),
        _url("https://example.com/index.php", 200),
        _url("https://example.com/.env", None),
    ]
    document = _document([_snapshot("example.com")], urls)
    grouped = document["urls_by_host"]
    assert isinstance(grouped, dict)
    assert [item["url"] for item in grouped["example.com"]] == [
        "https://example.com/.env",  # interesting path
        "https://example.com/plain?page=2",  # query string
        "https://example.com/index.php",  # a live status
        "https://example.com/about",  # the rest
    ]


def test_urls_cap_is_per_report_and_says_so() -> None:
    """D62: `report.urls_max` bounds the whole report, and the cut is visible."""
    rows = [_snapshot(f"h{index}.example.com") for index in range(5)]
    urls = [
        _url(f"https://h{index}.example.com/page{page}", 404)
        for index in range(5)
        for page in range(60)
    ]
    document = _document(rows, urls, urls_max=200)
    assert document["urls_total"] == 300
    assert document["urls_shown"] == 200
    assert document["urls_truncated"] is True
    grouped = document["urls_by_host"]
    assert isinstance(grouped, dict)
    assert sum(len(items) for items in grouped.values()) == 200


def test_report_txt_has_domains_and_urls_by_host_sections() -> None:
    """D62: both sections follow the hosts table, with state and status shown."""
    rows = [_snapshot("www.example.com"), _snapshot("api.example.com", HostState.DNS_ONLY)]
    urls = [_url("https://www.example.com/admin/login.php", None, "ALIVE")]
    text = ui.report_text(
        "example.com",
        rows,
        ui.REPORT_FIELDS,
        run_at=datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC),
        urls=urls,
    )
    assert "=== Domains ===" in text
    assert "example.com  -  2 host(s)" in text
    assert "  api.example.com   DNS_ONLY  HIGH" in text
    assert "=== URLs by host ===" in text
    assert "www.example.com  (ALIVE)" in text
    assert "  https://www.example.com/admin/login.php  null" in text


def test_report_with_no_urls_omits_both_new_sections() -> None:
    """D62: no stored URLs means no tree and no URL block, in either file."""
    rows = [_snapshot("www.example.com")]
    document = _document(rows, [])
    assert "urls_by_host" not in document
    assert document["urls_total"] == 0
    assert document["urls_shown"] == 0
    assert document["urls_truncated"] is False
    text = ui.report_text(
        "example.com",
        rows,
        ui.REPORT_FIELDS,
        run_at=datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC),
        urls=[],
    )
    assert "=== Domains ===" not in text
    assert "=== URLs by host ===" not in text


def test_roots_has_one_entry_for_single_target() -> None:
    """A report covers one target, so `roots` is one entry (docs/02 s5)."""
    document = _document([_snapshot("a.example.com"), _snapshot("b.example.com")], [])
    roots = document["roots"]
    assert isinstance(roots, list) and len(roots) == 1
    assert roots[0]["domain"] == "example.com"
    assert roots[0]["host_count"] == 2


# ------------------------------- (D71) lists, per-host folders, no URL cap


def _info_row(
    fqdn: str,
    state: HostState = HostState.ALIVE,
    *,
    status_code: int | None = 200,
    ips: tuple[str, ...] = ("192.0.2.1",),
    tech: tuple[str, ...] = ("nginx",),
) -> HostSnapshot:
    return HostSnapshot(
        fqdn=fqdn,
        state=state,
        confidence=Confidence.HIGH,
        sources=("crtsh",),
        status_code=status_code,
        ports=(),
        ips=ips,
        tech=tech,
    )


def _write_report(
    tmp_path: Path,
    rows: list[HostSnapshot],
    urls: list[UrlSnapshot],
    **kwargs: object,
) -> Path:
    directory = tmp_path / "20261119T120000Z"
    directory.mkdir()
    ui.write_field_report(
        directory,
        "example.com",
        rows,
        ui.REPORT_FIELDS,
        run_at=datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC),
        urls=urls,
        **kwargs,  # type: ignore[arg-type]
    )
    return directory


def test_report_no_url_cap_by_default(tmp_path: Path) -> None:
    """D71: `urls_max` defaults to 0, so every stored URL is listed."""
    urls = [_url(f"https://example.com/page{index}", 404) for index in range(500)]
    directory = _write_report(tmp_path, [_info_row("example.com")], urls)
    document = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    assert document["urls_total"] == 500
    assert document["urls_shown"] == 500
    assert document["urls_truncated"] is False
    assert len(document["urls_by_host"]["example.com"]) == 500


def test_report_emits_per_host_folders(tmp_path: Path) -> None:
    """D71: one `hosts/<name>/` per host with URLs, none for a host without."""
    rows = [_info_row(f"h{index}.example.com") for index in range(3)]
    rows.append(_info_row("quiet.example.com"))
    urls = [_url(f"https://h{index}.example.com/a", 200) for index in range(3)]
    directory = _write_report(tmp_path, rows, urls)
    folders = sorted(path.name for path in (directory / "hosts").iterdir())
    assert folders == ["h0.example.com", "h1.example.com", "h2.example.com"]
    assert not (directory / "hosts" / "quiet.example.com").exists()


def test_per_host_urls_file_contains_only_that_hosts_urls(tmp_path: Path) -> None:
    """D71: each `urls.txt` is that host's list, with the status when probed."""
    rows = [_info_row("a.example.com"), _info_row("b.example.com")]
    urls = [
        _url("https://a.example.com/one", 200),
        _url("https://a.example.com/two", None),
        _url("https://b.example.com/three", 301),
    ]
    directory = _write_report(tmp_path, rows, urls)
    first = (directory / "hosts" / "a.example.com" / "urls.txt").read_text(encoding="utf-8")
    second = (directory / "hosts" / "b.example.com" / "urls.txt").read_text(encoding="utf-8")
    assert first.splitlines() == ["https://a.example.com/one\t200", "https://a.example.com/two"]
    assert second.splitlines() == ["https://b.example.com/three\t301"]


def test_report_emits_subdomains_alive_dns_resolved_lists(tmp_path: Path) -> None:
    """D71: `dns_resolved.txt` is ALIVE + DNS_ONLY; `alive.txt` is ALIVE only."""
    rows = [
        _info_row("a.example.com", HostState.ALIVE),
        _info_row("b.example.com", HostState.DNS_ONLY, status_code=None),
        _info_row("c.example.com", HostState.DEAD, status_code=None),
        _info_row("d.example.com", HostState.UNKNOWN, status_code=None),
    ]
    directory = _write_report(tmp_path, rows, [])

    def lines(name: str) -> list[str]:
        return (directory / name).read_text(encoding="utf-8").splitlines()

    assert lines("subdomains.txt") == [
        "a.example.com",
        "b.example.com",
        "c.example.com",
        "d.example.com",
    ]
    assert lines("alive.txt") == ["a.example.com"]
    assert lines("dns_resolved.txt") == ["a.example.com", "b.example.com"]


def test_report_emits_host_info_without_urls(tmp_path: Path) -> None:
    """D71: host-info carries no URL, in either the text or the JSON file."""
    rows = [_info_row("a.example.com", ips=("192.0.2.1", "192.0.2.2"), tech=("nginx", "HSTS"))]
    directory = _write_report(tmp_path, rows, [_url("https://a.example.com/admin", 200)])
    text = (directory / "host-info.txt").read_text(encoding="utf-8")
    assert "://" not in text
    assert "a.example.com | ALIVE | 200 | 192.0.2.1, 192.0.2.2 | nginx, HSTS" in text
    entries = json.loads((directory / "host-info.json").read_text(encoding="utf-8"))
    assert entries == [
        {
            "domain": "a.example.com",
            "state": "ALIVE",
            "status": 200,
            "ips": ["192.0.2.1", "192.0.2.2"],
            "tech": ["nginx", "HSTS"],
        }
    ]


def test_emit_lists_disabled_skips_lists(tmp_path: Path) -> None:
    """D71: `report.emit_lists: false` leaves only the two report files."""
    directory = _write_report(
        tmp_path, [_info_row("a.example.com")], [], emit_lists=False, per_host_folders=False
    )
    assert sorted(path.name for path in directory.iterdir()) == ["report.json", "report.txt"]


def test_urls_max_still_respected_when_set(tmp_path: Path) -> None:
    """D71: setting `urls_max` still caps the report and says it did."""
    urls = [_url(f"https://example.com/page{index}", 404) for index in range(500)]
    directory = _write_report(tmp_path, [_info_row("example.com")], urls, urls_max=100)
    document = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    assert document["urls_shown"] == 100
    assert document["urls_truncated"] is True
    text = (directory / "report.txt").read_text(encoding="utf-8")
    assert "urls: 100 of 500 shown (report.urls_max 100)" in text


# ------------------------------- (D72) marketing/referral params rank last


def test_referral_urls_rank_below_interesting_urls() -> None:
    """D72: a referral parameter sorts below every clean, non-interesting URL."""
    urls = [
        _url("https://example.com/product?utm_source=newsletter&utm_medium=email", 200),
        _url("https://example.com/about", 404),
        _url("https://example.com/admin", 404),
    ]
    grouped, _shown = ui.report_urls(urls, 0)
    assert [item["url"] for item in grouped["example.com"]] == [
        "https://example.com/admin",
        "https://example.com/about",
        "https://example.com/product?utm_source=newsletter&utm_medium=email",
    ]


def test_referral_urls_are_not_dropped() -> None:
    """D72: noise is a tiebreaker, never a filter - the URL still appears."""
    urls = [_url("https://example.com/product?fbclid=abc", 200)]
    grouped, shown = ui.report_urls(urls, 0)
    assert shown == 1
    assert grouped["example.com"] == [
        {"url": "https://example.com/product?fbclid=abc", "status_code": 200, "host_state": "ALIVE"}
    ]


def test_referral_param_on_interesting_path_keeps_interesting_rank() -> None:
    """D72: an interesting path is not demoted for carrying a noise parameter."""
    urls = [
        _url("https://example.com/about", 404),
        _url("https://example.com/admin?utm_source=mail", 404),
    ]
    grouped, _shown = ui.report_urls(urls, 0)
    assert [item["url"] for item in grouped["example.com"]] == [
        "https://example.com/admin?utm_source=mail",
        "https://example.com/about",
    ]


def test_noise_params_config_extends_builtin() -> None:
    """D72: `report.noise_params` adds names; the built-in list still applies."""
    urls = [
        _url("https://example.com/a?campaign=spring", 404),
        _url("https://example.com/a?gclid=x", 404),
        _url("https://example.com/a", 404),
    ]
    grouped, shown = ui.report_urls(urls, 0, ["campaign"])
    assert shown == 3
    assert [item["url"] for item in grouped["example.com"]] == [
        "https://example.com/a",
        "https://example.com/a?campaign=spring",
        "https://example.com/a?gclid=x",
    ]


# ------------------------------- (D73) how many URLs were probed before


def _repeat_document(urls: list[UrlSnapshot], already: int) -> tuple[dict[str, object], str]:
    kwargs = {
        "run_at": datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC),
        "urls_already_probed": already,
    }
    document = ui.report_document(
        "example.com", [_snapshot("example.com")], ui.REPORT_FIELDS, urls=urls, **kwargs
    )
    text = ui.report_text(
        "example.com", [_snapshot("example.com")], ui.REPORT_FIELDS, urls=urls, **kwargs
    )
    return document, text


def test_report_surfaces_already_probed_count_on_repeat_runs() -> None:
    """D73: a repeat scan says how many URL answers came from earlier runs."""
    urls = [_url("https://example.com/a", 200), _url("https://example.com/b", None)]
    document, text = _repeat_document(urls, 1)
    assert document["urls_already_probed"] == 1
    assert (
        "urls: 2 total, 2 shown (1 already probed in earlier runs; "
        "use --reprobe-urls to re-check)" in text
    )


def test_report_omits_already_probed_when_zero() -> None:
    """D73: nothing was probed before, so neither file mentions it."""
    document, text = _repeat_document([_url("https://example.com/a", 200)], 0)
    assert "urls_already_probed" not in document
    assert "already probed" not in text
