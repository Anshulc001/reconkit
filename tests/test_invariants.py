"""Machine-checked contribution invariants (AGENTS.md section 0e).

These tests fail when a new tool, adapter, fixture or schema change can silently
drop tools, break the registry, or create duplicate rows. They are part of the
default suite; a change that breaks one of them is not finished.
"""

from __future__ import annotations

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
