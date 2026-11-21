"""Rich console, tables and JSON output (docs/02_CLI_UX.md)."""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TextIO
from urllib.parse import urlsplit

from rich.console import Console
from rich.table import Table
from rich.text import Text

from reconkit.doctor import MISSING, YES, DoctorReport, KeyCheck
from reconkit.engine import DiffSnapshot, HostSnapshot, RunSnapshot, ScanSummary, UrlSnapshot
from reconkit.models import Confidence, HostState, Stage, ToolResult, ToolStatus

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


# The saved-report fields (docs/02 section 5). Every key maps to a stored value
# in `subdomains`/`host_status_history`: nothing here is computed here.
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
    # Stored ports are only meaningful for a host that answered (D104). A
    # DNS_ONLY/DEAD host keeps the rows an earlier run wrote, but no ports
    # stage ran on it now, so showing them next to a passive run would claim
    # knowledge this run does not have. The saved report already gates them the
    # same way; the two outputs must agree. With no ALIVE host there is nothing
    # to show, so the column is omitted rather than printed empty.
    alive = any(row.state is HostState.ALIVE for row in rows)
    if alive:
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
        ]
        if alive:
            cells.append(Text(format_ports(row.ports) if row.state is HostState.ALIVE else "-"))
        cells.extend(
            [
                Text(", ".join(row.sources) if row.sources else "-"),
                Text(
                    format_confidence(row.confidence, row.sources),
                    style=_CONFIDENCE_STYLES[row.confidence],
                ),
            ]
        )
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
    table.add_column("Unique")
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
                # D77: only the `urls` pool writes rows whose novelty is
                # counted; every other stage prints `-` rather than a fake 0.
                Text(str(result.unique_count) if stage.stage is Stage.URLS else "-"),
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


# D62: the paths an operator opens first. Matched against `urlsplit(url).path`
# only, so a hit is about the resource and not about a hostname or a token.
# D64: the one sentence a scope-limited run says, on stderr at run end and as the
# first line of the saved report, so the two never drift apart.
SCOPE_LIMITED_BANNER = (
    "⚠ ACTIVE STAGES SKIPPED BY SCOPE — this run is passive-only; the report says so."
)
SCOPE_LIMITED_REASON = "active stages skipped by scope gate"

_INTERESTING_PATH = re.compile(
    r"(admin|login|api|\.git|\.env|backup|config|upload|debug|phpinfo|swagger"
    r"|graphql|\.sql|\.zip|\.bak|dashboard|panel|test|dev)",
    re.IGNORECASE,
)


# D72: query parameters that say where a visitor came from, not what the URL is.
# They are a ranking tiebreaker, never a filter: the URL is still reported.
NOISE_PARAMS: tuple[str, ...] = (
    "rc",
    "ic",
    "_branch_match_id",
    "_branch_referrer",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_content",
    "utm_term",
    "af_xp",
    "pid",
    "deep_link_value",
    "deep_link_sub1",
    "gclid",
    "fbclid",
)

NOISE_PARAM_RE = re.compile(
    r"(^|&)(" + "|".join(NOISE_PARAMS) + r")=",
    re.IGNORECASE,
)


def _noise_re(extra: Sequence[str]) -> re.Pattern[str] | None:
    """One regex for the config's extra names, or None when it adds none."""

    names = [name for name in extra if name]
    if not names:
        return None
    return re.compile(r"(^|&)(" + "|".join(re.escape(name) for name in names) + r")=", re.I)


def _url_rank(
    item: UrlSnapshot, extra_noise: re.Pattern[str] | None = None
) -> tuple[int, int, int, int, str, str]:
    """docs/02 section 5: path, then noise, then query, then a live status.

    Ascending, so the most useful URL sorts first. A marketing/referral
    parameter (D72) sorts below every clean URL that is not interesting on its
    path, but an interesting path keeps its rank: noise is a tiebreaker, not a
    veto, and no URL is dropped for carrying one. `host`/`url` make the order
    total, which is what keeps two runs byte-identical.
    """

    parsed = urlsplit(item.url)
    noisy = bool(NOISE_PARAM_RE.search(parsed.query)) or (
        extra_noise is not None and bool(extra_noise.search(parsed.query))
    )
    return (
        0 if _INTERESTING_PATH.search(parsed.path) else 1,
        1 if noisy else 0,
        0 if parsed.query else 1,
        0 if item.status_code in (200, 301, 302) else 1,
        item.host,
        item.url,
    )


def report_urls(
    urls: Sequence[UrlSnapshot], urls_max: int, noise_params: Sequence[str] = ()
) -> tuple[dict[str, list[dict[str, object]]], int]:
    """Group the report's URLs by host, best first, capped across the report.

    `urls_max` is the whole report's budget, not a per-host one; `0` means no
    cap. `noise_params` extends the built-in D72 list, it never replaces it.
    Returns the groups (hosts that lost every URL to the cap are absent) and how
    many URLs were kept, which is what `urls_shown` reports.
    """

    extra = _noise_re(noise_params)
    # D76: a third-party URL is stored but belongs to `external_urls.txt`, not
    # to a host block or a `hosts/<host>/` folder.
    ordered = sorted(
        (item for item in urls if not item.external), key=lambda item: _url_rank(item, extra)
    )
    if urls_max > 0:
        ordered = ordered[:urls_max]
    grouped: dict[str, list[dict[str, object]]] = {}
    for item in ordered:
        grouped.setdefault(item.host, []).append(
            {
                "url": item.url,
                "status_code": item.status_code,
                "host_state": item.host_state,
            }
        )
    return grouped, len(ordered)


def report_document(
    target: str,
    rows: Sequence[HostSnapshot],
    fields: Sequence[ReportField],
    *,
    run_at: datetime,
    selection: ReportSelection | None = None,
    scope_warnings: Sequence[str] = (),
    urls: Sequence[UrlSnapshot] = (),
    urls_max: int = 0,
    noise_params: Sequence[str] = (),
    urls_already_probed: int = 0,
    urls_probed_this_run: int | None = None,
    urls_skipped_already_probed: int = 0,
    mode: str | None = None,
    scope_limited: bool = False,
    hidden: frozenset[str] = frozenset(),
) -> dict[str, object]:
    """Build the report's JSON document from stored values only."""

    grouped, shown = report_urls(urls, urls_max, noise_params)
    scoped = [item for item in urls if not item.external]
    document: dict[str, object] = {
        "type": "report",
        "target": target,
        "generated_at": run_at.astimezone(UTC).isoformat(timespec="seconds"),
        "selection": None if selection is None else selection.as_document(),
        # D56: the same warning stderr showed at run start, so a reader of the
        # artifact learns the exclusion was partial.
        "scope_warnings": list(scope_warnings),
        "fields": [field.key for field in fields],
        # D63: `--exclude hosts` is the operator asking for no host list, so the
        # key stays (shape unchanged) and the list is what disappears.
        "hosts": (
            []
            if "hosts" in hidden
            else [{field.key: field_value(row, field) for field in fields} for row in rows]
        ),
        # D76: the report's URL list is the in-scope pool; third-party URLs are
        # counted apart (and listed in `external_urls.txt`), never mixed in.
        "urls_total": len(scoped),
        "urls_shown": shown,
        "urls_truncated": len(scoped) > shown,
    }
    if len(urls) > len(scoped):
        document["external_urls_total"] = len(urls) - len(scoped)
    if urls_already_probed:
        # D73: says how much of the list was answered before this run, so a
        # repeat scan does not read as if it had re-probed everything.
        document["urls_already_probed"] = urls_already_probed
    if urls_probed_this_run is not None:
        # D78: what this run sent, and what it left alone. `None` means a
        # rebuilt report with no run context, which omits both.
        document["urls_probed_this_run"] = urls_probed_this_run
        if urls_skipped_already_probed:
            document["urls_skipped_already_probed"] = urls_skipped_already_probed
    if mode is not None:
        # D63: a run whose mode `--include` changed says so in the artifact.
        document["mode"] = mode
    if scope_limited:
        # D64: a requested active run whose active stages the scope gate refused
        # still produces passive results. The artifact says so, once, so it
        # cannot be read as a normal scan later.
        document["scope_limited"] = True
        document["scope_limited_reason"] = SCOPE_LIMITED_REASON
    if "domains" not in hidden:
        # D62: one root per report, because one report covers one target
        # (docs/02 section 5); the hosts table itself is unchanged.
        document["roots"] = [
            {
                "domain": target,
                "subdomains": [row.fqdn for row in rows],
                "host_count": len(rows),
            }
        ]
    # docs/02 section 5: a report with no URLs has no URL block at all, rather
    # than an empty one a reader has to interpret.
    if grouped and "urls" not in hidden:
        document["urls_by_host"] = grouped
    return document


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
    urls: Sequence[UrlSnapshot] = (),
    urls_max: int = 0,
    noise_params: Sequence[str] = (),
    urls_already_probed: int = 0,
    urls_probed_this_run: int | None = None,
    urls_skipped_already_probed: int = 0,
    mode: str | None = None,
    scope_limited: bool = False,
    hidden: frozenset[str] = frozenset(),
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
        *([SCOPE_LIMITED_BANNER] if scope_limited else []),
        *([f"mode: {mode}"] if mode is not None else []),
        *([selection.as_line()] if selection is not None else []),
        *(
            ["scope warnings:", *(f"  - {note}" for note in scope_warnings)]
            if scope_warnings
            else []
        ),
        "",
        "  ".join(label.ljust(width) for label, width in zip(header, widths, strict=True)),
    ]
    if "hosts" in hidden:
        lines[-1] = "(hosts hidden by --exclude hosts)"
        table = []
    for line in table:
        lines.append("  ".join(cell.ljust(width) for cell, width in zip(line, widths, strict=True)))
    if not table and "hosts" not in hidden:
        lines.append("(no hosts)")
    lines.extend(
        _report_tree_sections(
            target,
            rows,
            urls,
            urls_max,
            hidden,
            noise_params,
            urls_already_probed,
            urls_probed_this_run,
            urls_skipped_already_probed,
        )
    )
    return "\n".join(lines) + "\n"


# docs/02 section 5: past this many names one line each is noise, so the
# section points at the table that already lists them.
_TREE_LIST_MAX = 50


def _report_tree_sections(
    target: str,
    rows: Sequence[HostSnapshot],
    urls: Sequence[UrlSnapshot],
    urls_max: int,
    hidden: frozenset[str] = frozenset(),
    noise_params: Sequence[str] = (),
    urls_already_probed: int = 0,
    urls_probed_this_run: int | None = None,
    urls_skipped_already_probed: int = 0,
) -> list[str]:
    """The two D62 sections, minus any D63-hidden one, or nothing without URLs."""

    # D76: a third-party URL is not "a URL this report has"; a report whose
    # whole pool is external writes neither block, exactly like an empty one.
    scoped = [item for item in urls if not item.external]
    if not scoped or {"domains", "urls"} <= hidden:
        return []
    lines: list[str] = []
    if "domains" not in hidden:
        lines = ["", "=== Domains ===", f"{target}  -  {len(rows)} host(s)"]
        if len(rows) > _TREE_LIST_MAX:
            lines.append(f"  {len(rows)} subdomains, see hosts table")
        else:
            for row in rows:
                lines.append(f"  {row.fqdn}   {row.state.value}  {row.confidence.value}")
    if "urls" not in hidden:
        grouped, shown = report_urls(urls, urls_max, noise_params)
        lines.extend(["", "=== URLs by host ==="])
        if urls_probed_this_run is not None:
            # D78: separate what this run sent from what an earlier run had
            # already answered, so a short probe does not read as a lost list.
            head = f"urls: {len(scoped)} total, {urls_probed_this_run} probed this run"
            if urls_skipped_already_probed:
                head += f", {urls_skipped_already_probed} already probed (use --reprobe-urls)"
            if shown < len(scoped):
                head += f" ({shown} shown; report.urls_max {urls_max})"
        elif shown < len(scoped):
            head = f"urls: {shown} of {len(scoped)} shown (report.urls_max {urls_max})"
        else:
            head = f"urls: {len(scoped)} total, {shown} shown"
            if urls_already_probed:
                head += (
                    f" ({urls_already_probed} already probed in earlier runs;"
                    " use --reprobe-urls to re-check)"
                )
        lines.append(head)
        for host, items in grouped.items():
            lines.append(f"{host}  ({items[0]['host_state']})")
            for item in items:
                status = "null" if item["status_code"] is None else str(item["status_code"])
                lines.append(f"  {item['url']}  {status}")
    return lines


def _host_info_entry(row: HostSnapshot) -> dict[str, object]:
    """One row of `host-info.json`, and the object a host's `info.json` copies."""

    return {
        "domain": row.fqdn,
        "state": row.state.value,
        "status": row.status_code,
        "ips": list(row.ips),
        "tech": list(row.tech),
    }


def _line(value: object) -> str:
    """The `-` an empty cell prints in a list file."""

    if value is None or value == "" or value == []:
        return "-"
    if isinstance(value, list | tuple):
        return ", ".join(str(item) for item in value) if value else "-"
    return str(value)


def _write_report_lists(
    directory: Path, rows: Sequence[HostSnapshot], urls: Sequence[UrlSnapshot] = ()
) -> None:
    """`subdomains.txt`, `alive.txt`, `dns_resolved.txt`, `host-info.*` (D71).

    Empty lists are written as empty files, not skipped: a script must be able
    to tell "the run found nothing" from "the run did not write this file".
    "DNS_ONLY" means the name resolves but answers no HTTP (docs/02 section 5).
    """

    _write_atomically(directory / "subdomains.txt", "".join(f"{row.fqdn}\n" for row in rows))
    _write_atomically(
        directory / "alive.txt",
        "".join(f"{row.fqdn}\n" for row in rows if row.state is HostState.ALIVE),
    )
    _write_atomically(
        directory / "dns_resolved.txt",
        "".join(
            f"{row.fqdn}\n" for row in rows if row.state in (HostState.ALIVE, HostState.DNS_ONLY)
        ),
    )
    entries = [_host_info_entry(row) for row in rows]
    # D76: third-party URLs are still evidence, just not this target's hosts.
    _write_atomically(
        directory / "external_urls.txt",
        "".join(
            f"{item.url}\n" for item in sorted(urls, key=lambda item: item.url) if item.external
        ),
    )
    _write_atomically(directory / "host-info.json", json.dumps(entries, indent=2) + "\n")
    lines = ["domain | state | status | ips | tech"]
    for row in rows:
        lines.append(
            " | ".join(
                [
                    row.fqdn,
                    row.state.value,
                    _line(row.status_code),
                    _line(list(row.ips)),
                    _line(list(row.tech)),
                ]
            )
        )
    _write_atomically(directory / "host-info.txt", "".join(f"{line}\n" for line in lines))


def _write_per_host_folders(
    directory: Path,
    rows: Sequence[HostSnapshot],
    urls: Sequence[UrlSnapshot],
    noise_params: Sequence[str] = (),
) -> None:
    """`hosts/<hostname>/{urls.txt,info.json}` for hosts that have URLs (D71).

    A host with no stored URL gets no folder: an empty directory is not
    evidence, and the top-level lists already name every host. `urls.txt` is
    that host's own list, so `report.urls_max` does not apply; a probed URL
    carries its status after a tab, an unprobed one is the URL alone.
    """

    by_host: dict[str, list[UrlSnapshot]] = {}
    for item in urls:
        if item.external:
            # D76: a third-party asset gets no folder; it is named in
            # `external_urls.txt` instead.
            continue
        by_host.setdefault(item.host, []).append(item)
    info = {row.fqdn: _host_info_entry(row) for row in rows}
    for host, items in sorted(by_host.items()):
        if not items or not host or host in {".", ".."} or "/" in host or "\\" in host:
            continue
        folder = directory / "hosts" / host
        folder.mkdir(parents=True, exist_ok=True)
        extra = _noise_re(noise_params)
        lines = [
            item.url if item.status_code is None else f"{item.url}\t{item.status_code}"
            for item in sorted(items, key=lambda item: _url_rank(item, extra))
        ]
        _write_atomically(folder / "urls.txt", "".join(f"{line}\n" for line in lines))
        entry = info.get(
            host,
            {"domain": host, "state": "UNKNOWN", "status": None, "ips": [], "tech": []},
        )
        _write_atomically(folder / "info.json", json.dumps(entry, indent=2) + "\n")


def write_field_report(
    directory: Path,
    target: str,
    rows: Sequence[HostSnapshot],
    fields: Sequence[ReportField],
    *,
    run_at: datetime,
    selection: ReportSelection | None = None,
    scope_warnings: Sequence[str] = (),
    urls: Sequence[UrlSnapshot] = (),
    urls_max: int = 0,
    noise_params: Sequence[str] = (),
    urls_already_probed: int = 0,
    urls_probed_this_run: int | None = None,
    urls_skipped_already_probed: int = 0,
    mode: str | None = None,
    scope_limited: bool = False,
    hidden: frozenset[str] = frozenset(),
    emit_lists: bool = True,
    per_host_folders: bool = True,
) -> tuple[Path, Path]:
    """Write the whole report directory, not just `report.txt`/`report.json`.

    Both files are always written, whatever the field selection was, and both come
    from the same snapshots, so they cannot disagree. `selection` is not None only
    when a display filter narrowed the rows (docs/02 section 5). The list files
    (`emit_lists`) and `hosts/<hostname>/` (`per_host_folders`) are on by
    default; both read the same snapshots and make no request (D71).
    """

    json_path = directory / "report.json"
    text_path = directory / "report.txt"
    document = report_document(
        target,
        rows,
        fields,
        run_at=run_at,
        selection=selection,
        scope_warnings=scope_warnings,
        urls=urls,
        urls_max=urls_max,
        noise_params=noise_params,
        urls_already_probed=urls_already_probed,
        urls_probed_this_run=urls_probed_this_run,
        urls_skipped_already_probed=urls_skipped_already_probed,
        mode=mode,
        scope_limited=scope_limited,
        hidden=hidden,
    )
    _write_atomically(json_path, json.dumps(document, indent=2, sort_keys=False) + "\n")
    _write_atomically(
        text_path,
        report_text(
            target,
            rows,
            fields,
            run_at=run_at,
            selection=selection,
            scope_warnings=scope_warnings,
            urls=urls,
            urls_max=urls_max,
            noise_params=noise_params,
            urls_already_probed=urls_already_probed,
            urls_probed_this_run=urls_probed_this_run,
            urls_skipped_already_probed=urls_skipped_already_probed,
            mode=mode,
            scope_limited=scope_limited,
            hidden=hidden,
        ),
    )
    # D71: the lists and per-host folders come from the same snapshots, so a
    # reader can never find a URL in `hosts/<name>/urls.txt` that `report.txt`
    # says the run did not store.
    if emit_lists:
        _write_report_lists(directory, rows, urls)
    if per_host_folders:
        _write_per_host_folders(directory, rows, urls, noise_params)
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
    hidden: frozenset[str] = frozenset(),
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
            render_skipped_urls(summary, console=side_console)
        return code
    if silent:
        return int(summary.exit_code)

    target = console if console is not None else make_console(stderr, no_color=no_color)
    if not rows and not summary.results and not summary.skipped:
        render_empty([], console=target)
    else:
        if "hosts" in hidden:
            pass
        elif rows:
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
        if (summary.results or summary.skipped) and "tools" not in hidden:
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
    render_skipped_urls(summary, console=target)
    return int(summary.exit_code)


def render_skipped_urls(
    summary: ScanSummary,
    *,
    console: Console | None = None,
    no_color: bool = False,
) -> None:
    """One line when a `url_probe` pass left stored answers alone (D78).

    Silence when nothing was skipped, so a first run's output is unchanged.
    `--reprobe-urls` makes the count 0, because then nothing was skipped.
    """

    if not summary.urls_skipped_already_probed:
        return
    target = console if console is not None else make_console(no_color=no_color)
    target.print(
        Text(
            f"\u2139 {summary.urls_skipped_already_probed} URL(s) were skipped because they "
            "already had a status code; use --reprobe-urls to re-check them."
        )
    )


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
        # D108: the PDF writer's dependency, next to the browser row.
        "pdf": report.pdf,
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
    dependencies = Table(title="Dependencies", header_style="bold")
    dependencies.add_column("Dependency", no_wrap=True)
    dependencies.add_column("State", no_wrap=True)
    dependencies.add_column("Effect")
    dependencies.add_row(
        Text("chromium"),
        Text(report.chromium, style="green" if report.chromium == YES else "red"),
        Text("-" if report.chromium == YES else "shots will produce 0 screenshots"),
    )
    dependencies.add_row(
        Text("reportlab"),
        Text(report.pdf, style="green" if report.pdf != MISSING else "red"),
        Text(
            "-"
            if report.pdf != MISSING
            else "PDF reports fail; report.txt and report.json are still written"
        ),
    )
    out.print(dependencies)
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
