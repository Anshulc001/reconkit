"""Rich console, tables and JSON output (docs/02_CLI_UX.md)."""

from __future__ import annotations

import json
import os
import secrets
import sys
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TextIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from reconkit.doctor import DoctorReport, KeyCheck
from reconkit.engine import DiffSnapshot, HostSnapshot, RunSnapshot, ScanSummary
from reconkit.installer.github_release import InstallOutcome
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
    detail: str | None = None


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
            "tools_failed": tool_counts[ToolStatus.FAILED],
            # docs/02 section 5: selection-time skips are counted here too, so a
            # stage that built nothing cannot read as a stage that found nothing.
            "tools_skipped": tool_counts[ToolStatus.SKIPPED] + len(summary.skipped),
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
        for skip in stage.skipped:
            table.add_row(
                Text(skip.tool),
                Text(stage.stage.value),
                Text(ToolStatus.SKIPPED.value, style=_STATUS_STYLES[ToolStatus.SKIPPED]),
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


def report_document(
    target: str,
    rows: Sequence[HostSnapshot],
    fields: Sequence[ReportField],
    *,
    run_at: datetime,
) -> dict[str, object]:
    """Build the report's JSON document from stored values only."""

    return {
        "type": "report",
        "target": target,
        "generated_at": run_at.astimezone(UTC).isoformat(timespec="seconds"),
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
) -> tuple[Path, Path]:
    """Write `report.txt` and `report.json` into this run's folder.

    Both files are always written, whatever the field selection was, and both come
    from the same snapshots, so they cannot disagree.
    """

    json_path = directory / "report.json"
    text_path = directory / "report.txt"
    document = report_document(target, rows, fields, run_at=run_at)
    _write_atomically(json_path, json.dumps(document, indent=2, sort_keys=False) + "\n")
    _write_atomically(text_path, report_text(target, rows, fields, run_at=run_at))
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
                "speed": run.speed,
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
    table.add_column("Speed")
    table.add_column("Status")
    table.add_column("Started")
    table.add_column("Finished")
    for run in items:
        table.add_row(
            Text(str(run.id)),
            Text(run.target),
            Text(run.stage),
            Text(run.speed),
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
) -> int:
    """Render a scan result and return the documented exit code."""

    rows = list(hosts)
    if json_output:
        return write_json(summary, rows, stream=stdout)
    if silent:
        return int(summary.exit_code)

    target = console if console is not None else make_console(stderr, no_color=no_color)
    if not rows and not summary.results and not summary.skipped:
        render_empty([], console=target)
    else:
        if rows:
            target.print(_host_table(rows))
        else:
            target.print(Text("No hosts found.", style="yellow"))
        if summary.results or summary.skipped:
            target.print(_tool_table(summary))
        counts: Counter[HostState] = Counter(row.state for row in rows)
        tools: Counter[ToolStatus] = Counter(result.status for result in summary.results)
        summary_line = (
            f"{len(rows)} hosts: "
            + ", ".join(f"{counts[state]} {state.value}" for state in HostState)
            + " | tools: "
            + f"{tools[ToolStatus.OK]} ok, {tools[ToolStatus.FAILED]} failed, "
            + f"{tools[ToolStatus.SKIPPED] + len(summary.skipped)} skipped, "
            + f"{tools[ToolStatus.TIMEOUT]} timeout"
        )
        target.print(Text(summary_line))
    for warning in summary.warnings:
        target.print(Text(f"warning: {warning}", style="yellow"))
    return int(summary.exit_code)


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
                "version": check.version,
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
        "warnings": list(report.warnings),
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
    table.add_column("Version")
    table.add_column("Path")
    table.add_column("Identity", no_wrap=True)
    for check in report.tools:
        style = {"yes": "green", "missing": "red"}.get(check.installed, "yellow")
        table.add_row(
            Text(check.name),
            Text(check.stage.value),
            Text(check.tier.value),
            Text(check.installed, style=style),
            Text(check.version),
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
        out.print(
            Text(f"Missing tools: {report.missing}. Run: reconkit install --all", style="yellow")
        )
    for warning in report.warnings:
        out.print(Text(f"warning: {warning}", style="yellow"))
    return 0


def _install_result(outcome: InstallOutcome, *, dry_run: bool) -> str:
    if outcome.method == "none" and outcome.ok:
        return "nothing to install"
    if dry_run and outcome.ok:
        return "would install"
    if outcome.skipped:
        return "skipped"
    if outcome.up_to_date:
        first = outcome.steps[0] if outcome.steps else ""
        return "up to date" if "is current" in first else "already installed"
    return "installed" if outcome.ok else "failed"


def _install_detail(outcome: InstallOutcome) -> str:
    if outcome.error:
        return outcome.error
    if outcome.destination:
        return outcome.destination
    return outcome.steps[-1] if outcome.steps else ""


def render_install(
    outcomes: Iterable[InstallOutcome],
    *,
    dry_run: bool,
    console: Console | None = None,
) -> None:
    """One row per tool: tool, method, result, detail (docs/10 section 1)."""
    target = console or make_console()
    table = Table(box=None, show_header=True, header_style="bold", pad_edge=False)
    table.add_column("tool")
    table.add_column("method")
    table.add_column("result")
    table.add_column("detail")
    for outcome in outcomes:
        table.add_row(
            outcome.tool,
            outcome.method or "-",
            _install_result(outcome, dry_run=dry_run),
            _install_detail(outcome),
        )
    target.print(table)


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
