"""D107: per-scan logging (docs/02 section 5)."""

from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest

from reconkit.logs import normalize_level, open_scan_log, scan_log_path


def test_every_level_is_written_with_a_timestamp_and_the_scan_lines(tmp_path) -> None:
    log = open_scan_log(
        tmp_path, "example.com", datetime(2026, 11, 21, 12, 0, tzinfo=UTC), console_enabled=False
    )
    log.info("Starting reconnaissance on example.com")
    log.success("3 subdomains discovered")
    log.warning("one tool was skipped")
    log.error("a failure")
    log.debug("hidden by the configured INFO level")
    log.close()

    text = log.path.read_text(encoding="utf-8")
    assert log.path.parent == tmp_path / "logs" / "example.com"
    assert re.search(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z \[INFO\] Starting", text, re.M)
    assert "[SUCCESS] 3 subdomains discovered" in text
    assert "[WARNING] one tool was skipped" in text
    assert "[ERROR] a failure" in text
    # INFO is the default threshold: DEBUG is dropped, not silently promoted.
    assert "[DEBUG]" not in text


def test_sensitive_values_are_redacted_before_they_reach_the_file(tmp_path) -> None:
    log = open_scan_log(
        tmp_path, "example.com", datetime(2026, 11, 21, tzinfo=UTC), console_enabled=False
    )
    log.error("request failed with Authorization: Bearer super-secret-token")
    log.close()
    text = log.path.read_text(encoding="utf-8")
    assert "super-secret-token" not in text
    assert "***" in text


def test_same_second_logs_never_overwrite_each_other(tmp_path) -> None:
    stamp = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
    first = scan_log_path(tmp_path, "example.com", stamp)
    first.write_text("evidence", encoding="utf-8")
    second = scan_log_path(tmp_path, "example.com", stamp)
    assert second != first
    assert second.name.endswith("-2.log")
    assert first.read_text(encoding="utf-8") == "evidence"


def test_unknown_level_falls_back_to_info_and_bad_target_is_refused(tmp_path) -> None:
    assert normalize_level("success") == "SUCCESS"
    assert normalize_level("loud") == "INFO"
    with pytest.raises(ValueError):
        open_scan_log(tmp_path, "../escape", datetime(2026, 11, 21, tzinfo=UTC))
