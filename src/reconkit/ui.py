"""Rich console, tables and JSON output (docs/02_CLI_UX.md)."""

from __future__ import annotations

import json
import os
import secrets
import sys
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TextIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from reconkit.doctor import YES, DoctorReport, KeyCheck
from reconkit.engine import DiffSnapshot, HostSnapshot, RunSnapshot, ScanSummary
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
    # A gap is an external service refusal (429/quota/5xx), not a failure.
    ToolStatus.GAP: "yellow",
    ToolStatus.SKIPPED: "yellow",
    ToolStatus.FAILED: "red",
    ToolStatus.TIMEOUT: "red",
    # D52: a kill is a deliberate stop, not a broken tool, so it is not red.
    ToolStatus.KILLED: "yellow",
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
    detail: str | None = None
    # www/non-www metadata (D22): canonical host when this row is a duplicate.
    duplicate_of: str | None = None
    www_note: str | None = None


ReportGate = Literal["always", "alive", "unknown"]


@dataclass(frozen=True)
class ReportField:
    """One selectable report column, backed by a value `reconkit` stores.

    `gate` says when the value is meaningful: `alive` fields are only populated
    for a host whose state is `ALIVE`, `unknown` only for `UNKNOWN`, and `always`
    for every row. A gated field is written as `not applicable`, never guessed.
    """

    key: str
    label: str
    gate: ReportGate = "always"


# The interactive report menu (docs/02 section 2b). Every key maps to a stored
# value in `subdomains`/`host_status_history`: nothing here is computed here.
REPORT_FIELDS: tuple[ReportField, ...] = (
    ReportField("hostname", "Hostname"),
    ReportField("state", "Host state"),
    ReportField("confidence", "Confidence"),
    ReportField("sources", "Discovery sources"),
    ReportField("source_count", "Source count"),
    ReportField("ips", "IP addresses"),
    ReportField("status_code", "HTTP status code", "alive"),
    ReportField("title", "Page title", "alive"),
    ReportField("location", "Redirect location", "alive"),
    ReportField("ports", "Open ports", "alive"),
    ReportField("tech", "Technology", "alive"),
    ReportField("detail", "Reason (UNKNOWN only)", "unknown"),
)

NOT_APPLICABLE = "not applicable"


def report_fields(numbers: Iterable[int]) -> tuple[ReportField, ...]:
    """Map 1-based menu numbers to fields, keeping menu order and no duplicates."""

    wanted = {number - 1 for number in numbers}
    return tuple(field for index, field in enumerate(REPORT_FIELDS) if index in wanted)


def _applicable(row: HostSnapshot, field: ReportField) -> bool:
    if field.gate == "alive":
        return row.state is HostState.ALIVE
    if field.gate == "unknown":
        return row.state is HostState.UNKNOWN
    return True


def _raw_value(row: HostSnapshot, field: ReportField) -> list[str] | list[int] | int | str | None:
    if field.key == "hostname":
        return row.fqdn
    if field.key == "state":
        return row.state.value
    if field.key == "confidence":
        return row.confidence.value
    if field.key == "sources":
        return list(row.sources)
    if field.key == "source_count":
        return row.source_count
    if field.key == "ips":
        return list(row.ips)
    if field.key == "status_code":
        return row.status_code
    if field.key == "title":
        return row.title
    if field.key == "location":
        return row.location
    if field.key == "ports":
        return list(row.ports)
    if field.key == "tech":
        return list(row.tech)
    if field.key == "detail":
        return row.detail
    raise ValueError(f"unknown report field {field.key!r}")


def field_value(row: HostSnapshot, field: ReportField) -> list[str] | list[int] | int | str | None:
    """The stored value for one field, or `None` when it does not apply."""

    if not _applicable(row, field):
        return None
    return _raw_value(row, field)


def format_field_value(row: HostSnapshot, field: ReportField) -> str:
    """Render one field for the text report; gated and empty values stay honest."""

    value = field_value(row, field)
    if value is None:
        return NOT_APPLICABLE if not _applicable(row, field) else "-"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) if value else "-"
    return str(value)


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
        "detail": row.detail,
        "duplicate_of": row.duplicate_of,
        "www_note": row.www_note,
    }


def _tool_document(result: ToolResult) -> dict[str, object]:
    return result.model_dump(mode="json")


def summary_document(
    summary: ScanSummary,
    hosts: Iterable[HostRow] = (),
    *,
    filter_info: dict[str, object] | None = None,
    injections: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build the one-document JSON shape documented in docs/02 section 5."""

    rows = list(hosts)
    state_counts: Counter[HostState] = Counter(row.state for row in rows)
    tool_counts: Counter[ToolStatus] = Counter(result.status for result in summary.results)
    pairs = [
        {"host": row.fqdn, "duplicate_of": row.duplicate_of}
        for row in rows
        if row.duplicate_of is not None
    ]
    document: dict[str, object] = {
        "type": "summary",
        "target": summary.target,
        "exit_code": int(summary.exit_code),
        "resumed": summary.resumed,
        "scope_denied": summary.scope_denied,
        "scope_mode": summary.scope_mode,
        # docs/02 section 5 (owner ruling 2026-11-17): a stage that had no
        # runnable tool is a gap, not a failure; the exit code stays 0.
        "completion": {
            "status": summary.completion_status,
            "gaps": [{"stage": gap.stage.value, "reason": gap.reason} for gap in summary.gaps],
        },
        "warnings": list(summary.warnings),
        # D56: scope facts that outlive the terminal (partial CIDR enforcement).
        "scope_warnings": list(summary.scope_warnings),
        # docs/02 section 5 (D22): every detected www/non-www duplicate pair, so
        # a consumer never has to re-derive it from the hosts array.
        "www_dedup": {"applied": bool(pairs), "pairs": pairs},
        "hosts": [_host_document(row) for row in rows],
        "stages": [
            {
                "stage": stage.stage.value,
                "run_id": stage.run_id,
                "resumed": stage.resumed,
                "dropped_hosts": list(stage.dropped_hosts),
                "results": [_tool_document(result) for result in stage.results],
                "skipped": [{"tool": skip.tool, "reason": skip.reason} for skip in stage.skipped],
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
            # docs/02 section 5: a tool refused by its upstream is a gap, not a
            # failure (owner ruling 2026-11-18).
            "tools_gap": tool_counts[ToolStatus.GAP],
            "tools_failed": tool_counts[ToolStatus.FAILED],
            # docs/02 section 5: selection-time skips are counted here too, so a
            # stage that built nothing cannot read as a stage that found nothing.
            "tools_skipped": tool_counts[ToolStatus.SKIPPED] + len(summary.skipped),
            "tools_timeout": tool_counts[ToolStatus.TIMEOUT],
            # D52: stopped by the engine (idle window or stage budget), partial
            # output kept. Counted separately from `timeout`, which stays 0.
            "tools_killed": tool_counts[ToolStatus.KILLED],
        },
    }
    if filter_info is not None:
        document["filter"] = filter_info
    if injections is not None:
        document["injections"] = injections
    return document


def write_json(
    summary: ScanSummary,
    hosts: Iterable[HostRow] = (),
    *,
    stream: TextIO | None = None,
    filter_info: dict[str, object] | None = None,
    injections: dict[str, object] | None = None,
) -> int:
    """Write exactly one JSON document to stdout (or ``stream``) and return the exit code."""

    target = stream if stream is not None else sys.stdout
    document = summary_document(summary, hosts, filter_info=filter_info, injections=injections)
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


def host_note(row: HostRow, canonical: set[str]) -> str:
    """The Notes cell: how a www/non-www row relates to its sibling (D22)."""

    if row.duplicate_of is not None:
        if row.status_code in _REDIRECT_CODES:
            return f"-> redirects to {row.duplicate_of}"
        return f"-> duplicate of {row.duplicate_of}"
    if row.fqdn in canonical:
        return "canonical"
    return row.www_note or "-"


_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


def _host_table(rows: list[HostRow]) -> Table:
    table = Table(title="Results", header_style="bold")
    table.add_column("Subdomain")
    table.add_column("State", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Ports")
    table.add_column("Sources")
    table.add_column("Trust", no_wrap=True, min_width=15)
    canonical = {row.duplicate_of for row in rows if row.duplicate_of is not None}
    # Only when there is something to say, so an ordinary run's table keeps its
    # six columns (D22). Wraps rather than ellipsizing: a clipped note reads as
    # no note at all.
    notes = any(host_note(row, canonical) != "-" for row in rows)
    if notes:
        table.add_column("Notes", overflow="fold")
    for row in rows:
        cells = [
            Text(row.fqdn),
            Text(format_state(row.state), style=_STATE_STYLES[row.state]),
            Text(str(row.status_code) if row.status_code is not None else "-"),
            Text(format_ports(row.ports)),
            Text(", ".join(row.sources) if row.sources else "-"),
            Text(
                format_confidence(row.confidence, row.sources),
                style=_CONFIDENCE_STYLES[row.confidence],
            ),
        ]
        if notes:
            cells.append(Text(host_note(row, canonical)))
        table.add_row(*cells)
    return table


def _tool_table(summary: ScanSummary) -> Table:
    """The per-tool table: what ran, how long, and how stale its last output was.

    D52: the `Last output` column is what tells a killed tool apart from a slow
    one that is still working; it is `-` for a tool that never had a window.
    """
    table = Table(title="Tools", header_style="bold")
    table.add_column("Tool")
    table.add_column("Stage")
    table.add_column("Status")
    table.add_column("Items")
    table.add_column("Time")
    table.add_column("Last output")
    table.add_column("Details")
    for stage in summary.stages:
        for result in stage.results:
            table.add_row(
                Text(result.tool),
                Text(stage.stage.value),
                Text(result.status.value, style=_STATUS_STYLES[result.status]),
                Text(str(len(result.records))),
                Text(f"{result.duration_s:.1f}s"),
                Text(
                    f"{result.last_output_s:.0f}s ago"
                    if result.status is ToolStatus.KILLED
                    else "-"
                ),
                Text(result.error or "-"),
            )
        for skip in stage.skipped:
            table.add_row(
                Text(skip.tool),
                Text(stage.stage.value),
                Text(ToolStatus.SKIPPED.value, style=_STATUS_STYLES[ToolStatus.SKIPPED]),
                Text("-"),
                Text("-"),
                Text("-"),
                Text(skip.reason),
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
    message: str,
    *,
    elapsed_s: float = 0.0,
    eta_s: float | None = None,
    next_pause_s: float | None = None,
    console: Console | None = None,
    silent: bool = False,
) -> None:
    """Render one progress line on stderr.

    Progress is human output for a human stream, so `--silent` suppresses it and
    `--json` does not: the JSON document on stdout stays the only thing written
    there (docs/02 section 5). This never writes to stdout.
    """

    if silent:
        return
    target_console = console if console is not None else make_console()
    extra: list[str] = []
    if elapsed_s:
        extra.append(f"{elapsed_s:.0f}s")
    if eta_s is not None:
        extra.append(f"eta {eta_s:.0f}s")
    if next_pause_s is not None:
        extra.append(f"pause {next_pause_s:.0f}s")
    suffix = f" ({' '.join(extra)})" if extra else ""
    target_console.print(Text(f"{message}{suffix}"), soft_wrap=True)


def _ignore_activity(_message: str) -> None:
    """No-op updater for a run that has no spinner (piped stderr, `--silent`)."""


@contextmanager
def activity_spinner(
    console: Console | None = None,
    *,
    enabled: bool = True,
) -> Iterator[Callable[[str], None]]:
    """A spinning status line on stderr: what the scan is doing right now.

    The durable `<stage>: <tool> ok N item(s)` lines are unchanged; this adds the
    "still working" indicator a long stage needs, because those lines only appear
    when a tool *finishes* and a 600 s tool would otherwise look like a hang. The
    caller gets an updater for the status text (the engine's running-tool
    snapshot). The spinner is transient, so it erases itself and leaves no frame
    behind.

    A stderr that is not a terminal, or `--silent`, gets a no-op updater: piped
    output and the tests keep exactly the lines they had before. Nothing here
    writes to stdout, so the `--json` contract stays intact (docs/02 section 5).
    """

    target_console = console if console is not None else make_console()
    if not enabled or not target_console.is_terminal:
        yield _ignore_activity
        return
    status = target_console.status("starting", spinner="dots", spinner_style="cyan")
    with status:
        yield status.update


def report_directory(results_root: Path | str, target: str, run_at: datetime) -> Path:
    """Create and return this run's report folder for one domain.

    One folder per domain per run, named from the run clock in UTC. A name that
    already exists (two runs in the same second) gets a `-2`, `-3`, ... suffix, so
    a previous run's folder is never reopened or written into (docs/02 section 5).
    """

    if not target or target in {".", ".."} or "/" in target or "\\" in target:
        raise ValueError(f"unsafe report target {target!r}")
    base = Path(results_root) / target
    stamp = run_at.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    candidate = base / stamp
    suffix = 2
    while candidate.exists():
        candidate = base / f"{stamp}-{suffix}"
        suffix += 1
    candidate.mkdir(parents=True, exist_ok=True)
    return candidate


def _write_atomically(path: Path, text: str) -> None:
    """Write `text` to `path` through a temporary file, mode 0600."""

    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    with open(temporary, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


@dataclass(frozen=True)
class ReportSelection:
    """What the display filters left in a report (docs/02 section 5).

    A report that honoured `--only-alive` must not look like a complete scan, so
    the size of the whole run travels with it. `description` is the human form of
    the filter (`ALIVE`, `ALIVE + status 200`), `matched` the rows written and
    `total` every host the run stored.
    """

    description: str
    matched: int
    total: int

    def as_document(self) -> dict[str, object]:
        return {"filter": self.description, "matched": self.matched, "total": self.total}

    def as_line(self) -> str:
        return f"selection: {self.matched} of {self.total} hosts ({self.description})"


def report_document(
    target: str,
    rows: Sequence[HostSnapshot],
    fields: Sequence[ReportField],
    *,
    run_at: datetime,
    selection: ReportSelection | None = None,
    scope_warnings: Sequence[str] = (),
) -> dict[str, object]:
    """Build the report's JSON document from stored values only."""

    return {
        "type": "report",
        "target": target,
        "generated_at": run_at.astimezone(UTC).isoformat(timespec="seconds"),
        "selection": None if selection is None else selection.as_document(),
        # D56: the same warning stderr showed at run start, so a reader of the
        # artifact learns the exclusion was partial.
        "scope_warnings": list(scope_warnings),
        "fields": [field.key for field in fields],
        "hosts": [{field.key: field_value(row, field) for field in fields} for row in rows],
    }


# One cell of the text table stays readable: a host with twelve IPv6 addresses
# must not stretch the table past the terminal. The JSON keeps the full value.
_MAX_CELL = 60


def _cell(row: HostSnapshot, field: ReportField) -> str:
    value = format_field_value(row, field)
    if len(value) <= _MAX_CELL:
        return value
    return value[: _MAX_CELL - 3] + "..."


def report_text(
    target: str,
    rows: Sequence[HostSnapshot],
    fields: Sequence[ReportField],
    *,
    run_at: datetime,
    selection: ReportSelection | None = None,
    scope_warnings: Sequence[str] = (),
) -> str:
    """Build the report's plain-text table from stored values only."""

    header = [field.label for field in fields]
    table = [[_cell(row, field) for field in fields] for row in rows]
    widths = [len(label) for label in header]
    for line in table:
        widths = [max(width, len(cell)) for width, cell in zip(widths, line, strict=True)]
    lines = [
        "reconkit report",
        f"target: {target}",
        f"generated: {run_at.astimezone(UTC).isoformat(timespec='seconds')}",
        f"hosts: {len(rows)}",
        *([selection.as_line()] if selection is not None else []),
        *(
            ["scope warnings:", *(f"  - {note}" for note in scope_warnings)]
            if scope_warnings
            else []
        ),
        "",
        "  ".join(label.ljust(width) for label, width in zip(header, widths, strict=True)),
    ]
    for line in table:
        lines.append("  ".join(cell.ljust(width) for cell, width in zip(line, widths, strict=True)))
    if not table:
        lines.append("(no hosts)")
    return "\n".join(lines) + "\n"


def write_field_report(
    directory: Path,
    target: str,
    rows: Sequence[HostSnapshot],
    fields: Sequence[ReportField],
    *,
    run_at: datetime,
    selection: ReportSelection | None = None,
    scope_warnings: Sequence[str] = (),
) -> tuple[Path, Path]:
    """Write `report.txt` and `report.json` into this run's folder.

    Both files are always written, whatever the field selection was, and both come
    from the same snapshots, so they cannot disagree. `selection` is not None only
    when a display filter narrowed the rows (docs/02 section 5).
    """

    json_path = directory / "report.json"
    text_path = directory / "report.txt"
    document = report_document(
        target, rows, fields, run_at=run_at, selection=selection, scope_warnings=scope_warnings
    )
    _write_atomically(json_path, json.dumps(document, indent=2, sort_keys=False) + "\n")
    _write_atomically(
        text_path,
        report_text(
            target, rows, fields, run_at=run_at, selection=selection, scope_warnings=scope_warnings
        ),
    )
    return text_path, json_path


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


def render_message(
    message: str,
    *,
    console: Console | None = None,
    no_color: bool = False,
) -> None:
    """Render one non-error line on stderr."""

    target = console if console is not None else make_console(no_color=no_color)
    target.print(Text(message))


def render_error(message: str, *, console: Console | None = None, no_color: bool = False) -> None:
    """Render one error line on stderr; errors are never silenced."""

    target = console if console is not None else make_console(no_color=no_color)
    target.print(Text(message, style="red"))


def diff_document(report: DiffSnapshot) -> dict[str, object]:
    """Build the one-document diff shape documented in docs/02."""

    return {
        "type": "diff",
        "target": report.target,
        "baseline_run_id": report.baseline_run_id,
        "previous_run_id": report.previous_run_id,
        "latest_run_id": report.latest_run_id,
        "new": list(report.new),
        "gone": list(report.gone),
        "pending_gone": list(report.pending_gone),
        "state_changes": [
            {"fqdn": fqdn, "old_state": old, "new_state": new}
            for fqdn, old, new in report.state_changes
        ],
        "ports_opened": [{"fqdn": fqdn, "port": port} for fqdn, port in report.ports_opened],
        "ports_closed": [{"fqdn": fqdn, "port": port} for fqdn, port in report.ports_closed],
    }


def render_diff(
    report: DiffSnapshot,
    *,
    json_output: bool = False,
    silent: bool = False,
    no_color: bool = False,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    console: Console | None = None,
) -> int:
    """Render a diff report and return 0; data has no failure exit state."""

    if json_output:
        target = stdout if stdout is not None else sys.stdout
        target.write(
            json.dumps(diff_document(report), ensure_ascii=False, separators=(",", ":")) + "\n"
        )
        target.flush()
        return 0
    if silent:
        return 0
    target = console if console is not None else make_console(stderr, no_color=no_color)
    if report.latest_run_id is None:
        target.print(Text("No completed discovery run for this target.", style="yellow"))
        return 0
    if report.previous_run_id is None:
        target.print(
            Text(f"First run for this target (#{report.latest_run_id}). Nothing to compare.")
        )
        return 0
    changes = (
        len(report.new)
        + len(report.gone)
        + len(report.state_changes)
        + len(report.ports_opened)
        + len(report.ports_closed)
    )
    if not changes:
        target.print(Text(f"No changes since run #{report.previous_run_id}."))
        _print_pending_gone(report, target)
        _print_gone_baseline_note(report, target)
        return 0
    table = Table(title="Changes", header_style="bold")
    table.add_column("Change")
    table.add_column("Item")
    table.add_column("Detail")
    for fqdn in report.new:
        table.add_row(Text("NEW"), Text(fqdn), Text("-"))
    for fqdn in report.gone:
        table.add_row(Text("GONE"), Text(fqdn), Text("-"))
    for fqdn, old, new in report.state_changes:
        table.add_row(Text("STATE"), Text(fqdn), Text(f"{old} -> {new}"))
    for fqdn, port in report.ports_opened:
        table.add_row(Text("PORT OPEN"), Text(fqdn), Text(str(port)))
    for fqdn, port in report.ports_closed:
        table.add_row(Text("PORT CLOSED"), Text(fqdn), Text(str(port)))
    target.print(table)
    _print_pending_gone(report, target)
    _print_gone_baseline_note(report, target)
    return 0


def _print_pending_gone(report: DiffSnapshot, target: Console) -> None:
    """docs/02: a single miss is not GONE; say so instead of staying silent."""
    if not report.pending_gone:
        return
    names = ", ".join(report.pending_gone)
    target.print(
        Text(
            f"Not reported as GONE yet (needs two consecutive misses): {names}",
            style="yellow",
        )
    )


def _print_gone_baseline_note(report: DiffSnapshot, target: Console) -> None:
    """docs/08 Flow 7: with fewer than three runs nothing can be confirmed gone."""
    if report.baseline_run_id is not None or report.latest_run_id is None:
        return
    target.print(
        Text("GONE needs three discovery runs to compare; nothing can be confirmed gone yet.")
    )


def status_document(runs: Iterable[RunSnapshot]) -> dict[str, object]:
    """Build the one-document status shape documented in docs/02."""

    return {
        "type": "status",
        "runs": [
            {
                "id": run.id,
                "target": run.target,
                "stage": run.stage,
                "status": run.status,
                "started_at": run.started_at,
                "finished_at": run.finished_at,
            }
            for run in runs
        ],
    }


def render_status(
    runs: Iterable[RunSnapshot],
    *,
    json_output: bool = False,
    silent: bool = False,
    no_color: bool = False,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    console: Console | None = None,
) -> int:
    """Render recent stage runs and return 0."""

    items = list(runs)
    if json_output:
        target = stdout if stdout is not None else sys.stdout
        target.write(
            json.dumps(status_document(items), ensure_ascii=False, separators=(",", ":")) + "\n"
        )
        target.flush()
        return 0
    if silent:
        return 0
    target = console if console is not None else make_console(stderr, no_color=no_color)
    if not items:
        target.print(Text("No runs yet.", style="yellow"))
        return 0
    table = Table(title="Runs", header_style="bold")
    table.add_column("ID")
    table.add_column("Target")
    table.add_column("Stage")
    table.add_column("Status")
    table.add_column("Started")
    table.add_column("Finished")
    for run in items:
        table.add_row(
            Text(str(run.id)),
            Text(run.target),
            Text(run.stage),
            Text(run.status),
            Text(run.started_at),
            Text(run.finished_at or "-"),
        )
    target.print(table)
    return 0


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
    filter_info: dict[str, object] | None = None,
    injections: dict[str, object] | None = None,
) -> int:
    """Render a scan result and return the documented exit code."""

    rows = list(hosts)
    if json_output:
        code = write_json(
            summary,
            rows,
            stream=stdout,
            filter_info=filter_info,
            injections=injections,
        )
        # The blocks are stderr-only, so stdout stays a single clean document.
        if not silent:
            side_console = make_console(stderr, no_color=no_color)
            render_killed_tools(summary, console=side_console)
            render_completion_gaps(summary, console=side_console)
        return code
    if silent:
        return int(summary.exit_code)

    target = console if console is not None else make_console(stderr, no_color=no_color)
    if not rows and not summary.results and not summary.skipped:
        render_empty([], console=target)
    else:
        if rows:
            target.print(_host_table(rows))
        elif filter_info is not None and filter_info.get("only_states"):
            states = filter_info.get("only_states")
            label = (
                ", ".join(str(value) for value in states)
                if isinstance(states, list)
                else "matching"
            )
            target.print(Text(f"no {label} hosts ({filter_info['total']} scanned)", style="yellow"))
        elif filter_info is not None:
            target.print(
                Text(f"no matching hosts ({filter_info['total']} scanned)", style="yellow")
            )
        else:
            target.print(Text("No hosts found.", style="yellow"))
        if summary.results or summary.skipped:
            target.print(_tool_table(summary))
        counts: Counter[HostState] = Counter(row.state for row in rows)
        tools: Counter[ToolStatus] = Counter(result.status for result in summary.results)
        duplicates = sum(1 for row in rows if row.duplicate_of is not None)
        # Only shown when a pair was found, so an ordinary run's line is unchanged.
        head = (
            f"{len(rows)} hosts ({len(rows) - duplicates} unique after www-dedup): "
            if duplicates
            else f"{len(rows)} hosts: "
        )
        summary_line = (
            head
            + ", ".join(f"{counts[state]} {state.value}" for state in HostState)
            + " | tools: "
            + f"{tools[ToolStatus.OK]} ok, {tools[ToolStatus.GAP]} gap, "
            + f"{tools[ToolStatus.FAILED]} failed, "
            + f"{tools[ToolStatus.SKIPPED] + len(summary.skipped)} skipped"
            # D52: only shown when something was stopped, so an ordinary run's
            # line is byte-identical to before the batch.
            + (f", {tools[ToolStatus.KILLED]} killed" if tools[ToolStatus.KILLED] else "")
            + f", {tools[ToolStatus.TIMEOUT]} timeout"
        )
        target.print(Text(summary_line))
    for warning in summary.warnings:
        target.print(Text(f"warning: {warning}", style="yellow"))
    render_killed_tools(summary, console=target)
    render_completion_gaps(summary, console=target)
    return int(summary.exit_code)


def render_killed_tools(
    summary: ScanSummary,
    *,
    console: Console | None = None,
    no_color: bool = False,
) -> None:
    """Render the "what got stuck" block on stderr (docs/02 section 6, D52).

    A killed tool is not a failure: the engine stopped it and kept the output it
    had already produced. Silence when nothing was killed, so an ordinary run's
    output is byte-identical to before this batch.
    """
    killed = [result for result in summary.results if result.status is ToolStatus.KILLED]
    if not killed:
        return
    target = console if console is not None else make_console(no_color=no_color)
    target.print(
        Text(
            f"⚠ {len(killed)} tool(s) stopped early — partial output kept",
            style="yellow",
        )
    )
    for result in killed:
        target.print(Text(f"  {result.tool}: {result.error or 'stopped'}"))
    target.print(
        Text(
            "  raise that class's window under runtime_idle: in config.yaml, or the "
            "stage budget with --phase-timeout."
        )
    )


def render_completion_gaps(
    summary: ScanSummary,
    *,
    console: Console | None = None,
    no_color: bool = False,
) -> None:
    """Render the completion-gaps block on stderr (docs/02 section 6).

    Silence means nothing: with no gaps, not a single line is printed, so an
    ordinary run's output is byte-identical to before the 2026-11-17 ruling.
    """
    if not summary.gaps:
        return
    target = console if console is not None else make_console(no_color=no_color)
    count = len(summary.gaps)
    target.print(
        Text(
            f"⚠ {summary.mode} scan completed with gaps — {count} stage(s) incomplete",
            style="yellow",
        )
    )
    for gap in summary.gaps:
        if gap.skipped:
            line = f"  {gap.stage.value}: {gap.skipped} tool(s) skipped ({gap.reason})"
        else:
            # An external-service gap: nothing was skipped, a service refused us.
            line = f"  {gap.stage.value}: {gap.reason}"
        target.print(Text(line))
    target.print(
        Text(
            "  run 'reconkit doctor' to see what is installed; see "
            "docs/10_TOOL_SOURCES.md for provenance."
        )
    )
    target.print(Text("  this is not a failure — the scan used every tool that was available."))


def doctor_document(report: DoctorReport) -> dict[str, object]:
    """Build the one-document doctor shape documented in docs/02 section 5."""

    return {
        "type": "doctor",
        "python": report.python_version,
        "python_ok": report.python_ok,
        "config": {"path": report.config_path, "ok": report.config_ok},
        "scope": {"path": report.scope_path, "found": report.scope_found},
        "db": {"path": report.db_path, "writable": report.db_writable},
        "tools": [
            {
                "tool": check.name,
                "stage": check.stage.value,
                "tier": check.tier.value,
                "kind": check.kind,
                "installed": check.installed,
                "path": check.path,
                "identity": check.identity,
            }
            for check in report.tools
        ],
        "stages": [
            {"stage": coverage.stage.value, "ready": coverage.ready, "total": coverage.total}
            for coverage in report.stages
        ],
        "system_packages": [
            {"package": package.package, "state": package.state} for package in report.packages
        ],
        "keys": [
            {
                "tool": key.tool,
                "env": key.env,
                "set": key.set,
                "url": key.url,
                "adds": key.adds,
            }
            for key in report.keys
        ],
        "missing": report.missing,
        # D36: same numbers the footer prints, so the two can never disagree.
        "installed": report.installed,
        "manual": list(report.manual),
        "warnings": list(report.warnings),
        # D35: absent browser = shots produces 0, and the run stays exit 0.
        "chromium": report.chromium,
        "exit_code": 0,
    }


def render_doctor(
    report: DoctorReport,
    *,
    json_output: bool = False,
    no_color: bool = False,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    console: Console | None = None,
) -> int:
    """Render the doctor report; warnings never change the exit code."""

    if json_output:
        target = stdout if stdout is not None else sys.stdout
        target.write(
            json.dumps(doctor_document(report), ensure_ascii=False, separators=(",", ":")) + "\n"
        )
        target.flush()
        return 0
    out = console if console is not None else make_console(stderr, no_color=no_color)
    table = Table(title="Tools", header_style="bold")
    table.add_column("Tool")
    table.add_column("Stage", no_wrap=True)
    table.add_column("Tier", no_wrap=True)
    table.add_column("Installed", no_wrap=True)
    table.add_column("Path")
    table.add_column("Identity", no_wrap=True)
    for check in report.tools:
        style = {"yes": "green", "missing": "red"}.get(check.installed, "yellow")
        table.add_row(
            Text(check.name),
            Text(check.stage.value),
            Text(check.tier.value),
            Text(check.installed, style=style),
            Text(check.path),
            Text(check.identity),
        )
    out.print(table)
    out.print(
        Text(
            "coverage: "
            + ", ".join(
                f"{coverage.stage.value} {coverage.ready}/{coverage.total} ready"
                for coverage in report.stages
            )
        )
    )
    out.print(
        Text(
            "system packages: "
            + ", ".join(f"{package.package} {package.state}" for package in report.packages)
        ),
        soft_wrap=True,
    )
    browser = Table(title="Browser", header_style="bold")
    browser.add_column("Dependency", no_wrap=True)
    browser.add_column("State", no_wrap=True)
    browser.add_column("Effect")
    browser.add_row(
        Text("chromium"),
        Text(report.chromium, style="green" if report.chromium == YES else "red"),
        Text("-" if report.chromium == YES else "shots will produce 0 screenshots"),
    )
    out.print(browser)
    environment = (
        f"python {report.python_version}{'' if report.python_ok else ' (too old; need 3.11+)'}"
        + f" | {report.scope_path} {'found' if report.scope_found else 'not found'}"
        + f" | db {report.db_path} {'writable' if report.db_writable else 'not writable'}"
    )
    out.print(Text(environment), soft_wrap=True)
    if report.keys:
        keys = Table(title="Keys", header_style="bold")
        keys.add_column("Tool")
        keys.add_column("Key")
        keys.add_column("Set", no_wrap=True)
        keys.add_column("Adds")
        keys.add_column("URL")
        for key in report.keys:
            keys.add_row(
                Text(key.tool),
                Text(key.env),
                Text("yes" if key.set else "no", style="green" if key.set else "yellow"),
                Text(key.adds),
                Text(key.url),
            )
        out.print(keys)
    if report.missing:
        # D36: one footer, one source of numbers (`DoctorReport.installed`/
        # `.manual`), so the table and `--json` cannot disagree.
        manual = f" ({', '.join(report.manual)})" if report.manual else ""
        parts = [f"{report.installed} installed", f"{len(report.manual)} manual{manual}"]
        rest = sorted(
            check.name
            for check in report.tools
            if check.installed != YES and check.name not in report.manual
        )
        if rest:
            verb = "needs" if len(rest) == 1 else "need"
            parts.append(f"{len(rest)} {verb} attention ({', '.join(rest)})")
        out.print(
            Text(
                (
                    ", ".join(parts)
                    + ". Scans will use the tools that are installed and skip the rest. "
                    "Per-tool provenance: docs/10_TOOL_SOURCES.md."
                ),
                style="yellow",
            )
        )
    for warning in report.warnings:
        out.print(Text(f"warning: {warning}", style="yellow"))
    return 0


def render_keys(checks: Iterable[KeyCheck], *, console: Console | None = None) -> None:
    """The Keys table: tool, env name, set/missing, what it adds, sign-up URL."""
    target = console or make_console()
    table = Table(box=None, show_header=True, header_style="bold", pad_edge=False)
    table.add_column("tool")
    table.add_column("key")
    table.add_column("state")
    table.add_column("adds")
    table.add_column("sign up")
    for check in checks:
        table.add_row(
            check.tool,
            check.env,
            "set" if check.set else "missing",
            check.adds,
            check.url,
        )
    target.print(table)
