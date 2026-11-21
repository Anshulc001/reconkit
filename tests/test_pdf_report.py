"""D107: professional PDF reports (docs/02 section 5)."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from reconkit.engine import HostSnapshot, UrlSnapshot
from reconkit.models import Confidence, HostState
from reconkit.pdf_report import REPORT_FILENAME, write_pdf_report

RUN_AT = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)


def _rows(count: int) -> list[HostSnapshot]:
    return [
        HostSnapshot(
            fqdn=f"host{index:04d}.example.com",
            state=HostState.ALIVE if index % 3 else HostState.DEAD,
            confidence=Confidence.HIGH,
            sources=("crtsh", "subfinder"),
            status_code=200 if index % 3 else None,
            ports=(80, 443) if index % 2 else (),
            ips=(f"10.0.0.{index % 255}",),
            title=f"Service {index}",
            tech=("nginx", "Python"),
            detail=None if index % 3 else "connection refused",
        )
        for index in range(count)
    ]


def _urls(count: int) -> list[UrlSnapshot]:
    return [
        UrlSnapshot(
            url=f"https://host{index % 20:04d}.example.com/admin?utm_source=x&id={index}",
            host=f"host{index % 20:04d}.example.com",
            status_code=200 if index % 2 else -1,
            host_state="ALIVE",
        )
        for index in range(count)
    ]


def test_pdf_is_written_beside_the_other_reports_and_is_private(tmp_path: Path) -> None:
    path = write_pdf_report(
        tmp_path,
        "example.com",
        _rows(4),
        _urls(3),
        run_at=RUN_AT,
        mode="active",
        duration_s=12.5,
    )
    assert path.name == REPORT_FILENAME
    assert path.read_bytes().startswith(b"%PDF")
    assert path.stat().st_mode & 0o777 == 0o600
    # Cover, executive summary, results, technical details and findings.
    assert len(re.findall(rb"/Type /Page\b", path.read_bytes())) >= 5


def test_hundreds_of_hosts_paginate_without_losing_rows(tmp_path: Path) -> None:
    path = write_pdf_report(
        tmp_path,
        "example.com",
        _rows(600),
        _urls(300),
        run_at=RUN_AT,
        mode="full",
        duration_s=3600.0,
    )
    pages = len(re.findall(rb"/Type /Page\b", path.read_bytes()))
    # A single-page table could not hold 600 rows; the LongTable must split.
    assert pages >= 10
    assert path.stat().st_size > 20_000


def test_empty_scan_still_produces_a_complete_report(tmp_path: Path) -> None:
    path = write_pdf_report(tmp_path, "example.com", [], [], run_at=RUN_AT)
    data = path.read_bytes()
    assert data.startswith(b"%PDF")
    assert len(re.findall(rb"/Type /Page\b", data)) >= 4


def test_negative_url_cap_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="max_urls"):
        write_pdf_report(tmp_path, "example.com", [], [], run_at=RUN_AT, max_urls=-1)
