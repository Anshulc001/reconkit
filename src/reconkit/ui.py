"""Rich console, tables and JSON output (docs/02_CLI_UX.md)."""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TextIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from reconkit.engine import ScanSummary
from reconkit.models import Confidence, HostState, ToolResult, ToolStatus

_STATE_STYLES: dict[HostState, str] = {
    HostState.ALIVE: "green",
    HostState.DNS_ONLY: "yellow",
    HostState.SHUT_DOWN: "dark_orange",
    HostState.DEAD: "red",
    HostState.UNKNOWN: "grey50",
}
_CONFIDENCE_STYLES: dict[Confidence, str] = {
    Confidence.HIGH: "green",
    Confidence.MEDIUM: "yellow",
    Confidence.LOW: "grey50",
    Confidence.UNCONFIRMED: "grey50",
}
_STATUS_STYLES: dict[ToolStatus, str] = {
    ToolStatus.OK: "green",
    ToolStatus.SKIPPED: "yellow",
    ToolStatus.FAILED: "red",
    ToolStatus.TIMEOUT: "red",
}


@dataclass(frozen=True)
class HostRow:
    """A host row already computed by the engine or CLI."""

    fqdn: str
    state: HostState
    confidence: Confidence
    sources: tuple[str, ...] = ()
    status_code: int | None = None
    ports: tuple[int, ...] = ()


def format_state(state: HostState) -> str:
    """Return the stable, color-independent state label."""

    return state.value


def format_confidence(confidence: Confidence, sources: Iterable[str] = ()) -> str:
    """Return the confidence label with the distinct-source count."""

    return f"{confidence.value} ({len(list(sources))})"


def format_ports(ports: Iterable[int]) -> str:
    """Return a compact port list, or ``-`` when there are none."""

    values = sorted(set(ports))
    return ",".join(str(port) for port in values) if values else "-"


def _host_document(row: HostRow) -> dict[str, object]:
    return {
        "fqdn": row.fqdn,
        "state": row.state.value,
        "confidence": row.confidence.value,
        "sources": list(row.sources),
        "status_code": row.status_code,
        "ports": sorted(set(row.ports)),
    }


def _tool_document(result: ToolResult) -> dict[str, object]:
    return result.model_dump(mode="json")


def summary_document(summary: ScanSummary, hosts: Iterable[HostRow] = ()) -> dict[str, object]:
    """Build the one-document JSON shape documented in docs/02 section 5."""

    rows = list(hosts)
    state_counts: Counter[HostState] = Counter(row.state for row in rows)
    tool_counts: Counter[ToolStatus] = Counter(result.status for result in summary.results)
    return {
        "type": "summary",
        "target": summary.target,
        "exit_code": int(summary.exit_code),
        "resumed": summary.resumed,
        "scope_denied": summary.scope_denied,
        "warnings": list(summary.warnings),
        "hosts": [_host_document(row) for row in rows],
        "stages": [
            {
                "stage": stage.stage.value,
                "run_id": stage.run_id,
                "resumed": stage.resumed,
                "dropped_hosts": list(stage.dropped_hosts),
                "results": [_tool_document(result) for result in stage.results],
            }
            for stage in summary.stages
        ],
        "summary": {
            "hosts": len(rows),
            "alive": state_counts[HostState.ALIVE],
            "dns_only": state_counts[HostState.DNS_ONLY],
            "shut_down": state_counts[HostState.SHUT_DOWN],
            "dead": state_counts[HostState.DEAD],
            "unknown": state_counts[HostState.UNKNOWN],
            "tools_ok": tool_counts[ToolStatus.OK],
            "tools_failed": tool_counts[ToolStatus.FAILED],
            "tools_skipped": tool_counts[ToolStatus.SKIPPED],
            "tools_timeout": tool_counts[ToolStatus.TIMEOUT],
        },
    }


def write_json(
    summary: ScanSummary, hosts: Iterable[HostRow] = (), *, stream: TextIO | None = None
) -> int:
    """Write exactly one JSON document to stdout (or ``stream``) and return the exit code."""

    target = stream if stream is not None else sys.stdout
    document = summary_document(summary, hosts)
    target.write(json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n")
    target.flush()
    return int(summary.exit_code)


def make_console(stream: TextIO | None = None, *, no_color: bool = False) -> Console:
    """Build a stderr console that disables color for NO_COLOR and non-TTY streams."""

    target = stream if stream is not None else sys.stderr
    is_tty = bool(getattr(target, "isatty", lambda: False)())
    disabled = no_color or os.environ.get("NO_COLOR") is not None or not is_tty
    return Console(
        file=target,
        color_system=None if disabled else "auto",
        no_color=disabled,
        force_terminal=False if disabled else None,
        highlight=False,
        markup=False,
    )


def _host_table(rows: list[HostRow]) -> Table:
    table = Table(title="Results", header_style="bold")
    table.add_column("Subdomain")
    table.add_column("State", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Ports")
    table.add_column("Sources")
    table.add_column("Trust", no_wrap=True, min_width=15)
    for row in rows:
        table.add_row(
            Text(row.fqdn),
            Text(format_state(row.state), style=_STATE_STYLES[row.state]),
            Text(str(row.status_code) if row.status_code is not None else "-"),
            Text(format_ports(row.ports)),
            Text(", ".join(row.sources) if row.sources else "-"),
            Text(
                format_confidence(row.confidence, row.sources),
                style=_CONFIDENCE_STYLES[row.confidence],
            ),
        )
    return table


def _tool_table(summary: ScanSummary) -> Table:
    table = Table(title="Tools", header_style="bold")
    table.add_column("Tool")
    table.add_column("Stage")
    table.add_column("Status")
    table.add_column("Items")
    table.add_column("Details")
    for stage in summary.stages:
        for result in stage.results:
            table.add_row(
                Text(result.tool),
                Text(stage.stage.value),
                Text(result.status.value, style=_STATUS_STYLES[result.status]),
                Text(str(len(result.records))),
                Text(result.error or "-"),
            )
    return table


def render_empty(tools: Iterable[str], *, console: Console) -> None:
    """Render the documented empty-state line."""

    names = list(dict.fromkeys(tools))
    if names:
        message = (
            f"No results from {len(names)} tools ({', '.join(names)}). Check 'reconkit doctor'."
        )
    else:
        message = "No results; every tool was skipped or excluded. Check 'reconkit doctor'."
    console.print(Text(message, style="yellow"))


def render_progress(
    stage: str,
    tool: str,
    done: int,
    total: int,
    *,
    elapsed_s: float = 0.0,
    eta_s: float | None = None,
    next_pause_s: float | None = None,
    console: Console | None = None,
    silent: bool = False,
    json_output: bool = False,
) -> None:
    """Render one progress line to stderr, disabled by silent/JSON modes."""

    if silent or json_output:
        return
    target_console = console if console is not None else make_console()
    remaining = f" eta {eta_s:.0f}s" if eta_s is not None else ""
    pause = f" pause {next_pause_s:.0f}-{next_pause_s:.0f}s" if next_pause_s is not None else ""
    line = f"{stage}: {tool} {done}/{total} tools {elapsed_s:.0f}s{remaining}{pause}"
    target_console.print(Text(line), soft_wrap=True)


def rate_limit_hint(tool: str, env: str, url: str, *, key_set: bool) -> str | None:
    """Return the free-key hint only when the tool is running without its key."""

    if key_set:
        return None
    return f"{tool}: rate limited. Set {env} for a free key ({url})."


def render_rate_limit_hint(
    tool: str,
    env: str,
    url: str,
    *,
    key_set: bool,
    console: Console | None = None,
) -> None:
    """Print the free-key hint on stderr when the key is unset."""

    hint = rate_limit_hint(tool, env, url, key_set=key_set)
    if hint is not None:
        target = console if console is not None else make_console()
        target.print(Text(hint, style="yellow"))


def render_error(message: str, *, console: Console | None = None, no_color: bool = False) -> None:
    """Render one error line on stderr; errors are never silenced."""

    target = console if console is not None else make_console(no_color=no_color)
    target.print(Text(message, style="red"))


def render(
    summary: ScanSummary,
    hosts: Iterable[HostRow] = (),
    *,
    json_output: bool = False,
    silent: bool = False,
    no_color: bool = False,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    console: Console | None = None,
) -> int:
    """Render a scan result and return the documented exit code."""

    rows = list(hosts)
    if json_output:
        return write_json(summary, rows, stream=stdout)
    if silent:
        return int(summary.exit_code)

    target = console if console is not None else make_console(stderr, no_color=no_color)
    if not rows and not summary.results:
        render_empty([], console=target)
    else:
        if rows:
            target.print(_host_table(rows))
        else:
            target.print(Text("No hosts found.", style="yellow"))
        if summary.results:
            target.print(_tool_table(summary))
        counts: Counter[HostState] = Counter(row.state for row in rows)
        tools: Counter[ToolStatus] = Counter(result.status for result in summary.results)
        summary_line = (
            f"{len(rows)} hosts: "
            + ", ".join(f"{counts[state]} {state.value}" for state in HostState)
            + " | tools: "
            + f"{tools[ToolStatus.OK]} ok, {tools[ToolStatus.FAILED]} failed, "
            + f"{tools[ToolStatus.SKIPPED]} skipped, {tools[ToolStatus.TIMEOUT]} timeout"
        )
        target.print(Text(summary_line))
    for warning in summary.warnings:
        target.print(Text(f"warning: {warning}", style="yellow"))
    return int(summary.exit_code)
