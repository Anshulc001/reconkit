"""Machine-checked contribution invariants (AGENTS.md section 0e).

These tests fail when a new tool, adapter, fixture or schema change can silently
drop tools, break the registry, or create duplicate rows. They are part of the
default suite; a change that breaks one of them is not finished.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from reconkit.adapters import ADAPTERS
from reconkit.adapters.base import FIXTURES, ExternalServiceGap, normalize_url
from reconkit.adapters.registry import load_tools
from reconkit.core.runner import validate_host
from reconkit.core.store import Store
from reconkit.errors import ParseError
from reconkit.models import (
    FindingRecord,
    HostStatusRecord,
    PortRecord,
    Stage,
    SubdomainRecord,
    Tier,
    UrlRecord,
)

SPECS = load_tools()
ROOT = Path(__file__).resolve().parents[1]
DOCS_09 = ROOT / "docs" / "09_TOOL_CONTRACTS.md"
PITFALLS = ROOT / "docs" / "PITFALLS.md"
REVIEW_LOG = ROOT / "docs" / "REVIEW_LOG.md"


def _fixture_paths(name: str) -> list[Path]:
    """Every fixture file an adapter can read, in `_read_fixture` order."""
    directory = FIXTURES / name
    paths = (
        sorted(path for path in directory.iterdir() if path.is_file()) if directory.is_dir() else []
    )
    paths += sorted((FIXTURES / "adapters").glob(f"{name}.synthetic.*"))
    return paths


FIXTURE_CASES = [(name, path) for name in sorted(ADAPTERS) for path in _fixture_paths(name)]
FIXTURE_IDS = [f"{name}:{path.name}" for name, path in FIXTURE_CASES]


def test_every_listed_tool_has_an_adapter() -> None:
    """A registry row without an adapter is a silent skip in every scan.

    The only allowed exception is an intrusive phase-3 tool that is selectable
    only through an explicit `--tools` (docs/09 section 4); it has no adapter yet
    by design, and it is never selected automatically.
    """
    missing = sorted(set(SPECS) - set(ADAPTERS))
    for name in missing:
        assert SPECS[name].tier is Tier.INTRUSIVE, f"{name} is selectable but has no adapter"
    assert missing == ["crlfuzz", "dalfox", "sqlmap"]


def test_every_adapter_has_a_registry_row() -> None:
    """An adapter the registry does not know can never run; it is dead code."""
    assert sorted(set(ADAPTERS) - set(SPECS)) == []


@pytest.mark.parametrize("name", sorted(ADAPTERS))
def test_adapter_name_and_stage_match_the_registry(name: str) -> None:
    """A stage mismatch would run the tool in the wrong stage, or skip it."""
    spec, adapter = SPECS[name], ADAPTERS[name]
    assert adapter.name == name
    assert adapter.stage is spec.stage


@pytest.mark.parametrize("name", sorted(ADAPTERS))
def test_every_adapter_has_a_fixture(name: str) -> None:
    """`--mock` is the only network-free way to exercise an adapter."""
    assert _fixture_paths(name), f"{name} has no fixture under tests/fixtures"


@pytest.mark.parametrize("name", sorted(SPECS))
def test_every_registry_stage_is_a_real_stage(name: str) -> None:
    assert SPECS[name].stage.value in {stage.value for stage in Stage}


@pytest.mark.parametrize(("name", "path"), FIXTURE_CASES, ids=FIXTURE_IDS)
def test_every_fixture_parses_canonical_records(name: str, path: Path) -> None:
    """A fixture's records reach unique keys, so they must already be canonical.

    The engine canonicalizes again at persistence (PIT-68/69/70), but a fixture
    that encodes a raw spelling hides the parser's own normalization bug from
    every mock-based test.
    """
    try:
        records = ADAPTERS[name]().parse_output(path.read_text(encoding="utf-8"))
    except (ExternalServiceGap, ParseError) as exc:
        # An error-shape fixture (a quota page, an API error body) is not data:
        # the adapter is supposed to refuse it, and its refusal is covered by
        # that adapter's own parser tests.
        pytest.skip(f"{path.name} is an error fixture: {exc}")
    for record in records:
        if isinstance(record, (SubdomainRecord, HostStatusRecord, PortRecord, FindingRecord)):
            assert record.fqdn == validate_host(record.fqdn), (name, record.fqdn)
        elif isinstance(record, UrlRecord):
            assert record.url == normalize_url(record.url), (name, record.url)


def test_natural_keys_keep_one_row_per_fact(tmp_path: Path) -> None:
    """The schema's uniqueness is the last line against duplicate facts."""
    store = Store(tmp_path / "recon.db")
    try:
        target_id = store.create_target("example.com")
        store.create_target("example.com")
        run_id = store.create_scan_run(target_id, "subs")
        sub_id = store.upsert_subdomain(target_id, "www.example.com", run_id=run_id)
        store.upsert_subdomain(target_id, "www.example.com", run_id=run_id)
        store.upsert_port(sub_id, "1.2.3.4", 53, run_id=run_id, state="open", protocol="tcp")
        store.upsert_port(sub_id, "1.2.3.4", 53, run_id=run_id, state="open", protocol="tcp")
        store.upsert_port(sub_id, "1.2.3.4", 53, run_id=run_id, state="open", protocol="udp")
        store.upsert_url(target_id, "https://www.example.com/", run_id=run_id)
        store.upsert_url(target_id, "https://www.example.com/", run_id=run_id)

        def count(sql: str) -> int:
            row = store._conn.execute(sql).fetchone()
            return int(row["n"])

        assert count("SELECT COUNT(*) AS n FROM targets") == 1
        assert count("SELECT COUNT(*) AS n FROM subdomains") == 1
        assert count("SELECT COUNT(*) AS n FROM ports") == 2
        assert count("SELECT COUNT(*) AS n FROM urls") == 1
    finally:
        store.close()


def _docs_stage_table() -> tuple[list[str], dict[str, set[str]]]:
    """The stage registry table in docs/09 section 4 as (header, stage -> tokens)."""
    text = DOCS_09.read_text(encoding="utf-8")
    section = text.split("## 4. Stage Registry", 1)[1].split("Selection rules", 1)[0]
    rows = [line.strip() for line in section.splitlines() if line.strip().startswith("|")]
    header = [cell.strip() for cell in rows[0].strip("|").split("|")]
    pools: dict[str, set[str]] = {}
    for line in rows[2:]:
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        pools[cells[0]] = set(re.findall(r"[a-z0-9_]+", cells[2]))
    return header, pools


def test_regression_docs_stage_table_describes_the_shipped_build() -> None:
    """docs/09 section 4 must describe this build, not a historical phase.

    Regression: the table carried a `Phase 2 working` column that named only the
    first-build subset (`pyscan, naabu` for ports), so the contract read as if
    nmap, rustscan, smap, tlsx, puredns and the other installed adapters were
    still future work, and the `urls`/`tech`/`vulns`/`shots` stages were marked
    unshipped in docs/01 after they had shipped in v1.0.0.
    """
    header, pools = _docs_stage_table()
    assert "Phase 2" not in " ".join(header)
    assert header[:2] == ["Stage", "Mode"] and header[2].startswith("Pool"), header
    for name, spec in SPECS.items():
        assert name in pools[str(spec.stage)], f"{name} is missing from the {spec.stage} row"
    for stage, tokens in pools.items():
        known = {name for name, spec in SPECS.items() if str(spec.stage) == stage}
        unknown = tokens - known - {"opt_in", "intrusive"}
        assert unknown == set(), f"{stage} row names tools the registry does not list: {unknown}"


# ---------------------------------------------------------------- pitfalls table


def _pitfall_rows(text: str) -> list[tuple[str, list[str]]]:
    """Every live `| PIT-nn |` row as (id, cited guard test names)."""
    rows: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        match = re.match(r"^\| (PIT-\d+) \|", line)
        if match is None:
            continue
        rows.append((match.group(1), re.findall(r"`(test_[A-Za-z0-9_]+)`", line)))
    return rows


def test_every_cited_pitfall_guard_exists() -> None:
    """A row that cites a deleted guard reads as verified and is not.

    Regression: PIT-75. `docs/PITFALLS.md` is the live rule set every session is
    told to trust, but nothing executed it: PIT-02 and PIT-31 cited tests that
    went away with pacing and with `install`/`update`, and PIT-35 cited the names
    its guard had already been renamed away from. The table is checked now, so a
    citation cannot rot silently again.
    """
    rows = _pitfall_rows(PITFALLS.read_text(encoding="utf-8"))
    assert len(rows) >= 60, f"only {len(rows)} live pitfall rows; did the table move?"
    source = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "tests").rglob("*.py"))
    missing = sorted(
        f"{pid} -> {name}" for pid, names in rows for name in names if f"def {name}(" not in source
    )
    assert missing == [], "pitfall rows cite guard tests that do not exist: " + ", ".join(missing)


def test_pitfall_ids_are_unique() -> None:
    """Two rules on one ID make every citation of that ID ambiguous.

    Regression: PIT-75. PIT-37 and PIT-38 were each used twice (the reportlab
    stamp and the httpx `UNKNOWN`; the `awk` setup fix and the empty stage), so
    "see PIT-37" named two different traps.
    """
    ids = [pid for pid, _ in _pitfall_rows(PITFALLS.read_text(encoding="utf-8"))]
    duplicates = sorted({pid for pid in ids if ids.count(pid) > 1})
    assert duplicates == [], f"duplicate pitfall ids: {duplicates}"


def test_the_resume_block_stays_short() -> None:
    """A session boots on RESUME; it must not be a second history file.

    Regression: PIT-76. By 2026-11-25 the block carried 62 status entries in 728
    lines (~24k tokens), more than the whole rule set, so the first thing a new
    session read was history. The three newest entries stay here and the rest
    live under "Earlier statuses" at the end of the same file.
    """
    text = (ROOT / "docs" / "PROGRESS.md").read_text(encoding="utf-8")
    block = text.split("## RESUME HERE", 1)[1].split("\n## ", 1)[0]
    lines = block.splitlines()
    assert len(lines) <= 60, f"RESUME is {len(lines)} lines; move older entries down"
    assert block.count("- Status (") <= 4, "RESUME should carry only the newest status entries"
    assert "Earlier statuses" in block


def test_the_pitfall_table_is_not_duplicated_back_into_the_log() -> None:
    """The log is history; the rule set lives in one short file (D120).

    Regression: PIT-75. While the table stood at the top of a 12,000-line log,
    every session-start read paid for the whole log, and the two files could
    disagree without anything noticing.
    """
    table_header = "| ID | Symptom | Root cause | Rule going forward | Guarding test |"
    pitfalls = PITFALLS.read_text(encoding="utf-8")
    log = REVIEW_LOG.read_text(encoding="utf-8")
    assert table_header in pitfalls
    assert table_header not in log
    assert "The table lives in `docs/PITFALLS.md`" in log
