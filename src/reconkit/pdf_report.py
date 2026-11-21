"""Professional PDF scan report (docs/02_CLI_UX.md section 5).

Every value in the document comes from the same stored snapshots the text and
JSON reports use: nothing is re-probed, inferred or invented. A value the run
did not observe is written as ``N/A``. The report is generated beside
``report.txt``/``report.json`` as ``report.pdf``.

Long host lists are rendered with ``LongTable``, which repeats the header and
splits rows across pages, so a scan with thousands of subdomains stays readable
and no cell is clipped. The URL evidence table is capped (``max_urls``) and says
so; the complete URL list remains in ``report.json``/``report.txt``.
"""

from __future__ import annotations

import os
import re
import secrets
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from urllib.parse import urlsplit
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    LongTable,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from reconkit.branding import DEVELOPERS
from reconkit.engine import HostSnapshot, UrlSnapshot
from reconkit.models import HostState, ToolResult

NAVY = colors.HexColor("#0B1F3A")
NAVY_LIGHT = colors.HexColor("#15365F")
CYAN = colors.HexColor("#22D3EE")
GREEN = colors.HexColor("#22C55E")
AMBER = colors.HexColor("#EAB308")
RED = colors.HexColor("#EF4444")
GREY = colors.HexColor("#64748B")
GRID = colors.HexColor("#CBD5E1")
ROW_ALT = colors.HexColor("#F1F5F9")
INK = colors.HexColor("#0F172A")
WHITE = colors.white

REPORT_FILENAME = "report.pdf"
DEFAULT_MAX_URLS = 500

# Same "interesting path" vocabulary the text report ranks by (ui.py). It is a
# prompt for manual review, not a vulnerability finding.
_INTERESTING_PATH = re.compile(
    r"(admin|login|api|\.git|\.env|backup|config|upload|debug|phpinfo|swagger"
    r"|graphql|\.sql|\.zip|\.bak|dashboard|panel|test|dev)",
    re.IGNORECASE,
)


def _esc(value: object) -> str:
    """XML-escape one cell, turning a newline into a real line break."""

    text = "" if value is None else str(value)
    return escape(text).replace("\n", "<br/>")


def _value(value: object) -> str:
    """A cell value or ``N/A`` when the run did not observe one."""

    if value is None:
        return "N/A"
    if isinstance(value, str):
        return value if value.strip() else "N/A"
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        items = [str(item) for item in value if str(item).strip()]
        return ", ".join(items) if items else "N/A"
    return str(value)


def _duration(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "N/A"
    total = int(round(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


class _Styles:
    """The document's type scale, built once per report."""

    def __init__(self) -> None:
        self.cover_kicker = ParagraphStyle(
            "cover_kicker",
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=CYAN,
            spaceAfter=6,
        )
        self.cover_title = ParagraphStyle(
            "cover_title",
            fontName="Helvetica-Bold",
            fontSize=28,
            leading=34,
            textColor=WHITE,
            spaceAfter=10,
        )
        self.cover_sub = ParagraphStyle(
            "cover_sub",
            fontName="Helvetica",
            fontSize=13,
            leading=18,
            textColor=colors.HexColor("#CBD5E1"),
        )
        self.cover_label = ParagraphStyle(
            "cover_label",
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=12,
            textColor=CYAN,
        )
        self.cover_value = ParagraphStyle(
            "cover_value",
            fontName="Helvetica",
            fontSize=11,
            leading=15,
            textColor=WHITE,
        )
        self.h1 = ParagraphStyle(
            "h1",
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=NAVY,
            spaceAfter=4,
        )
        self.h2 = ParagraphStyle(
            "h2",
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=NAVY,
            spaceBefore=10,
            spaceAfter=5,
        )
        self.body = ParagraphStyle(
            "body",
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=INK,
            spaceAfter=6,
            alignment=TA_LEFT,
        )
        self.small = ParagraphStyle(
            "small",
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=GREY,
        )
        self.cell = ParagraphStyle(
            "cell",
            fontName="Helvetica",
            fontSize=7.5,
            leading=9.5,
            textColor=INK,
        )
        self.cell_mono = ParagraphStyle(
            "cell_mono",
            fontName="Courier",
            fontSize=6.8,
            leading=8.5,
            textColor=INK,
        )
        self.header = ParagraphStyle(
            "header",
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9.5,
            textColor=WHITE,
        )
        self.metric = ParagraphStyle(
            "metric",
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=NAVY,
            alignment=1,
        )
        self.metric_label = ParagraphStyle(
            "metric_label",
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=GREY,
            alignment=1,
        )


def _paragraph(text: object, style: ParagraphStyle) -> Paragraph:
    return Paragraph(_esc(text), style)


def _cell(text: object, style: ParagraphStyle) -> Paragraph:
    return Paragraph(_esc(_value(text)), style)


def _link(url: str, style: ParagraphStyle) -> Paragraph:
    """A URL cell that is clickable in every conforming PDF reader."""

    shown = url if len(url) <= 110 else url[:107] + "..."
    return Paragraph(
        f'<link href="{escape(url, {chr(34): "&quot;"})}" color="#0B5FFF">{_esc(shown)}</link>',
        style,
    )


def _section(styles: _Styles, title: str) -> list[object]:
    return [
        Paragraph(_esc(title), styles.h1),
        HRFlowable(width="100%", thickness=1.6, color=CYAN, spaceBefore=2, spaceAfter=12),
    ]


def _data_table(
    header: Sequence[str],
    rows: Sequence[Sequence[object]],
    widths: Sequence[float],
    styles: _Styles,
    *,
    font_style: ParagraphStyle | None = None,
) -> Table:
    """A long table with a navy header, alternating rows and repeated headers."""

    body_style = font_style or styles.cell
    data: list[list[object]] = [[Paragraph(_esc(label), styles.header) for label in header]]
    data.extend(
        [
            [cell if isinstance(cell, Paragraph) else _cell(cell, body_style) for cell in row]
            for row in rows
        ]
    )
    table = LongTable(data, colWidths=list(widths), repeatRows=1, splitByRow=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, GRID),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, ROW_ALT]),
    ]
    table.setStyle(TableStyle(style))
    return table


def _kv_table(
    pairs: Sequence[tuple[str, object]], styles: _Styles, *, label_width: float = 115
) -> Table:
    data = [
        [_paragraph(label, styles.h2), _paragraph(_value(value), styles.body)]
        for label, value in pairs
    ]
    table = Table(data, colWidths=[label_width, 523 - label_width])
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LINEBELOW", (0, 0), (-1, -2), 0.3, GRID),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return table


def _metric_cards(styles: _Styles, metrics: Sequence[tuple[str, object]]) -> Table:
    header = [Paragraph(_esc(str(value)), styles.metric) for _, value in metrics]
    labels = [Paragraph(_esc(label.upper()), styles.metric_label) for label, _ in metrics]
    table = Table([header, labels], colWidths=[523 / len(metrics)] * len(metrics))
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), ROW_ALT),
                ("BOX", (0, 0), (-1, -1), 0.5, GRID),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, GRID),
                ("TOPPADDING", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    return table


def _on_page(canv: canvas.Canvas, doc: BaseDocTemplate, *, target: str = "") -> None:
    """Full-bleed cover background and a running header on later pages."""

    width, height = A4
    canv.saveState()
    if doc.page == 1:
        canv.setFillColor(NAVY)
        canv.rect(0, 0, width, height, stroke=0, fill=1)
        canv.setFillColor(NAVY_LIGHT)
        canv.rect(0, 0, width, 34 * mm, stroke=0, fill=1)
        canv.setStrokeColor(CYAN)
        canv.setLineWidth(2)
        canv.line(15 * mm, height - 15 * mm, 30 * mm, height - 15 * mm)
    else:
        canv.setStrokeColor(GRID)
        canv.setLineWidth(0.6)
        canv.line(15 * mm, height - 14 * mm, width - 15 * mm, height - 14 * mm)
        canv.setFillColor(NAVY)
        canv.setFont("Helvetica-Bold", 7.5)
        canv.drawString(15 * mm, height - 11.5 * mm, "RECONKIT")
        canv.setFillColor(GREY)
        canv.setFont("Helvetica", 7.5)
        canv.drawString(15 * mm + 21 * mm, height - 11.5 * mm, "Reconnaissance Assessment Report")
        canv.drawRightString(width - 15 * mm, height - 11.5 * mm, target)
        canv.setStrokeColor(GRID)
        canv.setLineWidth(0.5)
        canv.line(15 * mm, 13 * mm, width - 15 * mm, 13 * mm)
        canv.setFont("Helvetica", 7)
        canv.setFillColor(GREY)
        canv.drawString(15 * mm, 9 * mm, f"Generated by ReconKit · Developed by {DEVELOPERS}")
        canv.drawRightString(width - 15 * mm, 9 * mm, f"Page {doc.page}")
    canv.restoreState()


def _cover(
    styles: _Styles,
    *,
    target: str,
    run_at: datetime,
    mode: str | None,
    status: str,
) -> list[object]:
    info = Table(
        [
            [
                Paragraph("TARGET", styles.cover_label),
                Paragraph("SCAN DATE (UTC)", styles.cover_label),
            ],
            [
                Paragraph(_esc(target), styles.cover_value),
                Paragraph(
                    _esc(run_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")), styles.cover_value
                ),
            ],
            [
                Paragraph("SCAN MODE", styles.cover_label),
                Paragraph("REPORT STATUS", styles.cover_label),
            ],
            [
                Paragraph(_esc((mode or "N/A").upper()), styles.cover_value),
                Paragraph(_esc(status.upper()), styles.cover_value),
            ],
        ],
        colWidths=[250, 250],
    )
    info.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return [
        Spacer(1, 48 * mm),
        Paragraph("RECONKIT", styles.cover_kicker),
        Paragraph("RECONNAISSANCE<br/>ASSESSMENT REPORT", styles.cover_title),
        Paragraph(
            "Authorized security testing · Reconnaissance evidence and inventory", styles.cover_sub
        ),
        Spacer(1, 18 * mm),
        HRFlowable(width="100%", thickness=1, color=CYAN, spaceAfter=10),
        Spacer(1, 7 * mm),
        info,
        Spacer(1, 22 * mm),
        Paragraph(f"Generated by ReconKit · Developed by {DEVELOPERS}", styles.cover_sub),
        Spacer(1, 2 * mm),
        Paragraph(
            "This report contains reconnaissance data only. It is not a vulnerability assessment.",
            styles.small,
        ),
    ]


def _executive(
    styles: _Styles,
    rows: Sequence[HostSnapshot],
    urls: Sequence[UrlSnapshot],
    *,
    target: str,
    run_at: datetime,
    mode: str | None,
    status: str,
    duration_s: float | None,
    scope_mode: str | None,
    scope_limited: bool,
    warnings: Sequence[str],
) -> list[object]:
    counts = Counter(row.state for row in rows)
    in_scope = [item for item in urls if not item.external]
    non_responsive = len(rows) - counts[HostState.ALIVE]
    # A www/non-www duplicate is stored as a host row, so the unique count is
    # the same `www_dedup` fact the text/JSON reports carry (D22).
    unique = sum(1 for row in rows if row.duplicate_of is None)
    story: list[object] = [
        *_section(styles, "1 · Executive Summary"),
        _kv_table(
            [
                ("Target domain", target),
                ("Total subdomains", len(rows)),
                ("Unique subdomains (www-dedup)", unique),
                ("Report generated", run_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")),
                (
                    "Scan mode",
                    (mode or "N/A") + (" (scope-limited passive run)" if scope_limited else ""),
                ),
                ("Scope enforcement", _value(scope_mode)),
                ("Scan status", status),
                ("Scan duration", _duration(duration_s)),
            ],
            styles,
        ),
        Spacer(1, 10),
        _metric_cards(
            styles,
            [
                ("Subdomains", len(rows)),
                ("Live hosts", counts[HostState.ALIVE]),
                ("Non-responsive", non_responsive),
                ("URLs observed", len(in_scope)),
            ],
        ),
        Spacer(1, 12),
        Paragraph("Host state breakdown", styles.h2),
        _kv_table(
            [
                ("ALIVE", counts[HostState.ALIVE]),
                ("DNS_ONLY", counts[HostState.DNS_ONLY]),
                ("SHUT_DOWN", counts[HostState.SHUT_DOWN]),
                ("DEAD", counts[HostState.DEAD]),
                ("UNKNOWN", counts[HostState.UNKNOWN]),
            ],
            styles,
        ),
        Spacer(1, 8),
        Paragraph(
            "The scan collected the evidence above from the tools and stages recorded in "
            "section 3. A host that did not answer is reported as non-responsive; it is not "
            "described as vulnerable.",
            styles.body,
        ),
    ]
    if scope_limited:
        story.append(
            Paragraph(
                _esc(
                    "Scope limitation: the requested active stages were skipped by the scope gate; "
                    "this report covers passive results only."
                ),
                styles.body,
            )
        )
    if warnings:
        story.append(Paragraph("Warnings recorded during the run", styles.h2))
        for warning in warnings:
            story.append(Paragraph(_esc(f"• {warning}"), styles.body))
    return story


def _results(
    styles: _Styles,
    rows: Sequence[HostSnapshot],
    urls: Sequence[UrlSnapshot],
    *,
    max_urls: int,
) -> list[object]:
    story: list[object] = [PageBreak(), *_section(styles, "2 · Reconnaissance Results")]
    if not rows:
        story.append(Paragraph("No hosts were recorded by this scan.", styles.body))
        return story
    host_rows: list[list[object]] = []
    details: list[list[object]] = []
    for row in rows:
        ips = ", ".join(row.ips[:2]) + (f" (+{len(row.ips) - 2})" if len(row.ips) > 2 else "")
        tech = ", ".join(row.tech) if row.tech else "N/A"
        status = "-" if row.status_code is None else row.status_code
        host_rows.append(
            [
                _paragraph(row.fqdn, styles.cell),
                _paragraph(row.state.value, styles.cell),
                _paragraph(status, styles.cell),
                _paragraph(ips or "N/A", styles.cell),
                _paragraph(tech, styles.cell),
                _paragraph(row.title or "N/A", styles.cell),
            ]
        )
        if row.detail:
            details.append(
                [
                    _paragraph(row.fqdn, styles.cell),
                    _paragraph(row.state.value, styles.cell),
                    _paragraph(row.detail, styles.cell),
                ]
            )
    story.append(Paragraph("Discovered hosts", styles.h2))
    story.append(
        _data_table(
            ["Subdomain", "State", "HTTP", "IP address", "Technology / server", "Page title"],
            host_rows,
            [138, 50, 32, 78, 100, 125],
            styles,
        )
    )
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "Response time and web-server banner: N/A unless a tool stored them; reconkit "
            "does not invent a value. Redirect locations and failure reasons are listed "
            "below where recorded.",
            styles.small,
        )
    )
    if details:
        story.append(Paragraph("Redirects and failure reasons", styles.h2))
        story.append(
            _data_table(
                ["Subdomain", "State", "Recorded reason / redirect"],
                details,
                [150, 55, 318],
                styles,
            )
        )
    scoped = [item for item in urls if not item.external]
    if scoped:
        shown = scoped if max_urls <= 0 else scoped[:max_urls]
        story.append(Paragraph("URL evidence", styles.h2))
        url_rows = [
            [
                _link(item.url, styles.cell_mono),
                _paragraph("N/A" if item.status_code is None else item.status_code, styles.cell),
                _paragraph(item.host_state, styles.cell),
            ]
            for item in shown
        ]
        story.append(
            _data_table(
                ["URL", "HTTP", "Host state"],
                url_rows,
                [400, 38, 85],
                styles,
                font_style=styles.cell_mono,
            )
        )
        if len(shown) < len(scoped):
            story.append(
                Paragraph(
                    _esc(
                        f"Showing {len(shown)} of {len(scoped)} stored URLs. The complete "
                        "list is in report.json, report.txt and the per-host urls.txt files."
                    ),
                    styles.small,
                )
            )
    elif not urls:
        story.append(
            Paragraph(
                "No URLs were stored by this run, so there is no URL evidence table.",
                styles.body,
            )
        )
    return story


def _technical(
    styles: _Styles,
    rows: Sequence[HostSnapshot],
    *,
    tool_results: Sequence[ToolResult],
    parameters: Mapping[str, str],
    run_at: datetime,
    started_at: datetime | None,
    status: str,
) -> list[object]:
    story: list[object] = [PageBreak(), *_section(styles, "3 · Technical Details")]
    story.append(Paragraph("Tools used during reconnaissance", styles.h2))
    if tool_results:
        tool_rows = [
            [
                _paragraph(result.tool, styles.cell),
                _paragraph(result.status.value, styles.cell),
                _paragraph(len(result.records), styles.cell),
                _paragraph(f"{result.duration_s:.1f}s", styles.cell),
                _paragraph(result.error or "-", styles.cell),
            ]
            for result in tool_results
        ]
        story.append(
            _data_table(
                ["Tool", "Status", "Items", "Runtime", "Detail"],
                tool_rows,
                [105, 55, 40, 55, 268],
                styles,
            )
        )
    else:
        story.append(
            Paragraph(
                "Tool-run details are N/A: this report was rebuilt from stored rows, "
                "not from a live scan.",
                styles.body,
            )
        )
    story.append(Paragraph("Scan configuration and parameters", styles.h2))
    pairs: list[tuple[str, object]] = [
        ("Report generated (UTC)", run_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")),
        (
            "Scan started (UTC)",
            None
            if started_at is None
            else started_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S"),
        ),
        ("Scan status", status),
        ("Hosts in report", len(rows)),
    ]
    for name, value in parameters.items():
        pairs.append((name, value))
    story.append(_kv_table(pairs, styles, label_width=150))
    story.append(Paragraph("Methodology", styles.h2))
    methodology = (
        "ReconKit orchestrates multiple reconnaissance tools per stage and merges their "
        "output. Host discovery combines subdomain sources; DNS resolution and HTTP probing "
        "decide host state (ALIVE, DNS_ONLY, SHUT_DOWN, DEAD, UNKNOWN); confidence reflects "
        "how many distinct tools agree on a name. URL evidence is collected from archives "
        "and crawlers and, in active runs, probed for an HTTP status. No attack payloads "
        "are sent by the core and opt-in tiers, and vulnerability findings are not persisted "
        "by this build. Every value in this report is a stored observation."
    )
    for sentence in methodology.split(". "):
        if sentence.strip():
            story.append(Paragraph(_esc(f"• {sentence.strip().rstrip('.')}."), styles.body))
    story.append(Paragraph("Technical observations", styles.h2))
    observations = [
        f"{len(rows)} host record(s) in this report.",
        f"{sum(1 for row in rows if row.ips)} host record(s) with at least one stored IP address.",
        f"{sum(1 for row in rows if row.tech)} host record(s) with stored technology evidence.",
        f"{sum(1 for row in rows if row.ports)} host record(s) with stored open ports.",
    ]
    for note in observations:
        story.append(Paragraph(_esc(f"• {note}"), styles.body))
    return story


def _findings(
    styles: _Styles,
    rows: Sequence[HostSnapshot],
    urls: Sequence[UrlSnapshot],
    *,
    target: str,
    mode: str | None,
    scope_limited: bool,
    max_urls: int,
) -> list[object]:
    scoped = [item for item in urls if not item.external]
    counts = Counter(row.state for row in rows)
    codes = Counter(
        "2xx"
        if item.status_code is not None and 200 <= item.status_code < 300
        else "3xx"
        if item.status_code is not None and 300 <= item.status_code < 400
        else "4xx/5xx"
        if item.status_code is not None and item.status_code >= 400
        else "no answer"
        if item.status_code == -1
        else "TLS not verified"
        if item.status_code == -2
        else "not probed"
        for item in scoped
    )
    interesting = [item for item in scoped if _INTERESTING_PATH.search(urlsplit(item.url).path)]
    unusual_ports = sorted({port for row in rows for port in row.ports if port not in (80, 443)})
    tls_notes = [row for row in rows if row.detail and "certificate" in row.detail.lower()]
    story: list[object] = [PageBreak(), *_section(styles, "4 · Findings & Conclusion")]
    story.append(Paragraph("Summary of discovered assets", styles.h2))
    summary_lines = [
        f"{target}: {len(rows)} subdomain record(s), {counts[HostState.ALIVE]} ALIVE, "
        f"{counts[HostState.DNS_ONLY]} DNS_ONLY, {counts[HostState.SHUT_DOWN]} SHUT_DOWN, "
        f"{counts[HostState.DEAD]} DEAD, {counts[HostState.UNKNOWN]} UNKNOWN.",
        f"{len(scoped)} in-scope URL(s) observed; status classes: "
        + ", ".join(f"{name} {value}" for name, value in sorted(codes.items()))
        + ".",
    ]
    if scope_limited:
        summary_lines.append(
            "The run was scope-limited: active stages were skipped by the scope gate, so all "
            "state and URL evidence is passive."
        )
    for line in summary_lines:
        story.append(Paragraph(_esc(f"• {line}"), styles.body))
    story.append(Paragraph("Observations from the collected data", styles.h2))
    observations: list[str] = []
    if counts[HostState.ALIVE]:
        observations.append(
            f"{counts[HostState.ALIVE]} host(s) answered HTTP and are marked ALIVE."
        )
    if interesting:
        names = sorted({urlsplit(item.url).hostname or item.host for item in interesting})
        shown = ", ".join(names[:8]) + (" ..." if len(names) > 8 else "")
        observations.append(
            f"{len(interesting)} URL(s) contain a path associated with administration, "
            f"authentication, APIs, backups or development endpoints, on: {shown}."
        )
    if unusual_ports:
        observations.append(
            "Open ports outside 80/443 were stored: "
            + ", ".join(str(port) for port in unusual_ports)
            + "."
        )
    if tls_notes:
        observations.append(
            f"{len(tls_notes)} host(s) recorded a certificate-related diagnostic; see the "
            "failure reasons table for the stored text."
        )
    if counts[HostState.DEAD] or counts[HostState.DNS_ONLY]:
        observations.append(
            f"{counts[HostState.DEAD] + counts[HostState.DNS_ONLY]} host(s) did not serve HTTP; "
            "this is an availability observation, not a security finding."
        )
    if not observations:
        observations.append("No observations beyond the asset counts above could be derived.")
    for note in observations:
        story.append(Paragraph(_esc(f"• {note}"), styles.body))
    story.append(Paragraph("Potential areas requiring further manual assessment", styles.h2))
    areas = []
    if interesting:
        areas.append(
            "Manually review the admin/login/API/backup URLs listed in section 2; their presence "
            "is not evidence of a vulnerability."
        )
    if unusual_ports:
        areas.append(
            "Confirm the owner and purpose of the non-standard open ports before any "
            "further testing."
        )
    if counts[HostState.ALIVE]:
        areas.append(
            "Review the ALIVE hosts and their detected technologies for patching and configuration "
            "in a separate, authorized assessment."
        )
    if not areas:
        areas.append(
            "No specific area stands out from this data set; treat the inventory as the baseline."
        )
    for note in areas:
        story.append(Paragraph(_esc(f"• {note}"), styles.body))
    story.append(Paragraph("Limitations", styles.h2))
    limitations = [
        "This is a reconnaissance report, not a vulnerability assessment or penetration test.",
        "Results depend on the tools that were installed and on third-party data sources; "
        "a missing result is not proof that an asset does not exist.",
        "Response times and HTTP headers are not uniformly stored by every tool, so they are "
        "reported as N/A where unavailable.",
        f"The URL table shows at most {max_urls} entries." if max_urls > 0 else "",
        "The scan ran in "
        + (mode or "an unknown")
        + " mode; passive evidence cannot confirm services that only answer active probes."
        if mode
        else "",
    ]
    for note in limitations:
        if note:
            story.append(Paragraph(_esc(f"• {note}"), styles.body))
    story.append(Paragraph("Conclusion", styles.h2))
    story.append(
        Paragraph(
            _esc(
                f"The reconnaissance of {target} recorded {len(rows)} subdomain(s) and "
                f"{len(scoped)} in-scope URL(s). The evidence above is limited to what the "
                "selected tools returned during this scan. Any further assessment must be "
                "authorized in writing and performed within the agreed scope."
            ),
            styles.body,
        )
    )
    return story


def write_pdf_report(
    directory: Path,
    target: str,
    rows: Sequence[HostSnapshot],
    urls: Sequence[UrlSnapshot] = (),
    *,
    run_at: datetime,
    mode: str | None = None,
    status: str = "completed",
    scope_mode: str | None = None,
    started_at: datetime | None = None,
    duration_s: float | None = None,
    scope_limited: bool = False,
    warnings: Sequence[str] = (),
    tool_results: Iterable[ToolResult] = (),
    parameters: Mapping[str, str] | None = None,
    max_urls: int = DEFAULT_MAX_URLS,
) -> Path:
    """Write ``report.pdf`` beside the text and JSON reports and return its path.

    Nothing here contacts the network or reads the database: the caller passes
    the same snapshots the text/JSON writer used, so the three artifacts cannot
    disagree. A rendering failure raises, and the caller reports it without
    discarding the text/JSON reports.
    """

    if max_urls < 0:
        raise ValueError("max_urls must be >= 0")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / REPORT_FILENAME
    temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(4)}.tmp")
    styles = _Styles()
    document = BaseDocTemplate(
        str(temporary),
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=22 * mm,
        bottomMargin=20 * mm,
        title=f"Reconnaissance Assessment Report - {target}",
        author=f"ReconKit · {DEVELOPERS}",
        subject="Authorized reconnaissance evidence",
        creator="ReconKit",
    )
    frame = Frame(
        document.leftMargin,
        document.bottomMargin,
        document.width,
        document.height,
        id="body",
        leftPadding=0,
        rightPadding=0,
        topPadding=0,
        bottomPadding=0,
    )
    document.addPageTemplates(
        [
            PageTemplate(
                id="report",
                frames=[frame],
                onPage=partial(_on_page, target=target),
            )
        ]
    )
    tools = list(tool_results)
    story: list[object] = []
    story.extend(_cover(styles, target=target, run_at=run_at, mode=mode, status=status))
    story.append(PageBreak())
    story.extend(
        _executive(
            styles,
            rows,
            urls,
            target=target,
            run_at=run_at,
            mode=mode,
            status=status,
            duration_s=duration_s,
            scope_mode=scope_mode,
            scope_limited=scope_limited,
            warnings=warnings,
        )
    )
    story.extend(_results(styles, rows, urls, max_urls=max_urls))
    story.extend(
        _technical(
            styles,
            rows,
            tool_results=tools,
            parameters=parameters or {},
            run_at=run_at,
            started_at=started_at,
            status=status,
        )
    )
    story.extend(
        _findings(
            styles,
            rows,
            urls,
            target=target,
            mode=mode,
            scope_limited=scope_limited,
            max_urls=max_urls,
        )
    )
    try:
        document.build(story)
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return destination
