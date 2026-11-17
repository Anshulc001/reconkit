"""Part 7: UI tables, JSON document, silence and color safety."""

from __future__ import annotations

import ast
import json
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console
from rich.text import Text

import reconkit.ui as ui
from reconkit.engine import ExitCode, ScanSummary, StageOutcome
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
        "warnings",
        "hosts",
        "stages",
        "summary",
    }
    assert set(document["hosts"][0]) == {
        "fqdn",
        "state",
        "confidence",
        "sources",
        "status_code",
        "ports",
        "detail",
    }
    assert document["hosts"][0]["detail"] is None
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
        "tools_failed",
        "tools_skipped",
        "tools_timeout",
    }
    assert document["summary"]["hosts"] == 5
    assert document["summary"]["tools_ok"] == 1
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
