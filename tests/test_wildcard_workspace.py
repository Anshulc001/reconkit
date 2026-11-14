"""Part 5: wildcard detection and per-target workspace tests (no network)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import reconkit.core.workspace as workspace_module
from reconkit.adapters.dnspython import DnsOutcome, DnsResult
from reconkit.core.runner import MAX_OUTPUT_BYTES, validate_host
from reconkit.core.wildcard import WildcardDetector, WildcardStatus
from reconkit.core.workspace import STAGES, Workspace

# ------------------------------------------------------------------ wildcard


def resolved(*ips: str, cnames: list[str] | None = None) -> DnsResult:
    return DnsResult(DnsOutcome.RESOLVED, ips=list(ips), cnames=cnames or [])


def nxdomain() -> DnsResult:
    return DnsResult(DnsOutcome.NXDOMAIN)


class CyclingRng:
    """Deterministic stand-in for random.Random; enough to make unique labels."""

    def __init__(self) -> None:
        self.index = 0

    def choice(self, seq: str) -> str:
        value = seq[self.index % len(seq)]
        self.index += 1
        return value


class FakeProbe:
    def __init__(self, *results: DnsResult | BaseException) -> None:
        self.results = list(results)
        self.hosts: list[str] = []

    async def __call__(self, host: str) -> DnsResult:
        self.hosts.append(host)
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


def make_detector(probe: FakeProbe, *, probes: int = 3) -> WildcardDetector:
    return WildcardDetector(probe=probe, rng=CyclingRng(), probes=probes)


async def test_wildcard_present_and_only_wildcard_ips_match() -> None:
    probe = FakeProbe(resolved("1.2.3.4"), resolved("1.2.3.4"), nxdomain())
    result = await make_detector(probe).detect("example.com")
    assert result.status is WildcardStatus.PRESENT
    assert result.ips == frozenset({"1.2.3.4"})
    assert result.probes == 3
    assert result.resolved == 2
    assert result.matches(ips=["1.2.3.4"]) is True
    assert result.matches(ips=["1.2.3.4", "5.6.7.8"]) is False
    assert result.matches(ips=["9.9.9.9"]) is False


async def test_wildcard_none_when_every_probe_is_nxdomain() -> None:
    probe = FakeProbe(nxdomain(), nxdomain(), nxdomain())
    result = await make_detector(probe).detect("example.com")
    assert result.status is WildcardStatus.NONE
    assert result.ips == frozenset()
    assert result.matches(ips=["1.2.3.4"]) is False


@pytest.mark.parametrize(
    "outcome",
    [DnsOutcome.TIMEOUT, DnsOutcome.SERVFAIL, DnsOutcome.NOANSWER, DnsOutcome.ERROR],
)
async def test_wildcard_unknown_is_not_none(outcome: DnsOutcome) -> None:
    """Regression: PIT-21 timeout/SERVFAIL/NOANSWER/ERROR are UNKNOWN, never NONE."""
    probe = FakeProbe(*(DnsResult(outcome) for _ in range(3)))
    result = await make_detector(probe).detect("example.com")
    assert result.status is WildcardStatus.UNKNOWN
    assert result.status is not WildcardStatus.NONE
    assert result.matches(ips=["1.2.3.4"]) is False


async def test_wildcard_timeout_plus_nxdomain_is_unknown() -> None:
    probe = FakeProbe(nxdomain(), DnsResult(DnsOutcome.TIMEOUT), nxdomain())
    result = await make_detector(probe).detect("example.com")
    assert result.status is WildcardStatus.UNKNOWN


async def test_wildcard_cname_answer_matches_cname() -> None:
    probe = FakeProbe(resolved(cnames=["Wild.Example.NET."]), nxdomain(), nxdomain())
    result = await make_detector(probe).detect("example.com")
    assert result.status is WildcardStatus.PRESENT
    assert result.cnames == frozenset({"wild.example.net"})
    assert result.matches(cnames=["WILD.example.net."]) is True
    assert result.matches(ips=["1.2.3.4"]) is False


async def test_wildcard_resolved_beats_a_failed_probe() -> None:
    probe = FakeProbe(resolved("1.2.3.4"), DnsResult(DnsOutcome.TIMEOUT), nxdomain())
    result = await make_detector(probe).detect("example.com")
    assert result.status is WildcardStatus.PRESENT


async def test_wildcard_unexpected_probe_exception_is_unknown() -> None:
    probe = FakeProbe(RuntimeError("boom"), RuntimeError("boom"), RuntimeError("boom"))
    result = await make_detector(probe).detect("example.com")
    assert result.status is WildcardStatus.UNKNOWN


async def test_wildcard_labels_are_unique_valid_and_under_the_target() -> None:
    """Regression: PIT-13 the RNG is injected; labels are deterministic and valid."""
    probe = FakeProbe(nxdomain(), nxdomain(), nxdomain())
    result = await make_detector(probe).detect("Example.COM.")
    assert result.status is WildcardStatus.NONE
    assert len(probe.hosts) == 3
    assert len(set(probe.hosts)) == 3
    for host in probe.hosts:
        assert host.endswith(".example.com")
        label = host[: -len(".example.com")]
        assert len(label) == 12
        assert validate_host(host) == host


async def test_wildcard_rejects_an_invalid_target_before_probing() -> None:
    probe = FakeProbe()
    with pytest.raises(ValueError):
        await make_detector(probe).detect("../evil.example.com")
    assert probe.hosts == []


def test_wildcard_probe_count_must_be_positive() -> None:
    with pytest.raises(ValueError):
        WildcardDetector(probe=FakeProbe(), rng=CyclingRng(), probes=0)


# ----------------------------------------------------------------- workspace


def test_workspace_create_builds_documented_layout(tmp_path: Path) -> None:
    workspace = Workspace.create(tmp_path / "workspaces", "Example.COM.")
    assert workspace.target == "example.com"
    assert workspace.directory == tmp_path / "workspaces" / "example.com"
    for stage in STAGES:
        assert (workspace.directory / stage).is_dir()
    assert sorted(item.name for item in workspace.directory.iterdir()) == sorted(STAGES)
    workspace.ensure()  # idempotent
    assert workspace.path("subs", "subfinder.txt") == (
        workspace.directory / "subs" / "subfinder.txt"
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes are not meaningful on Windows")
def test_workspace_permissions_are_private(tmp_path: Path) -> None:
    workspace = Workspace.create(tmp_path / "workspaces", "example.com")
    assert workspace.directory.stat().st_mode & 0o777 == 0o700
    target = workspace.write("subs", "source.txt", "data")
    assert target.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "filename",
    [
        "../escape.txt",
        "..",
        ".",
        "a/b.txt",
        "a\\b.txt",
        "C:\\evil.txt",
        "\\\\server\\share\\evil.txt",
        "/etc/passwd",
        "CON",
        "con.txt",
        "NUL.json",
        "COM1",
        "LPT9.log",
        "name.",
        "name ",
        ".hidden",
        "",
    ],
)
def test_workspace_rejects_unsafe_filenames(tmp_path: Path, filename: str) -> None:
    """Regression: PIT-11 traversal, absolute/UNC paths and device names are rejected."""
    workspace = Workspace.create(tmp_path / "workspaces", "example.com")
    with pytest.raises(ValueError):
        workspace.write("subs", filename, "data")
    assert not (tmp_path / "workspaces" / "example.com" / "escape.txt").exists()


@pytest.mark.parametrize("stage", ["js", "../subs", "", "META", "subs/.."])
def test_workspace_rejects_unknown_stages(tmp_path: Path, stage: str) -> None:
    workspace = Workspace.create(tmp_path / "workspaces", "example.com")
    with pytest.raises(ValueError):
        workspace.path(stage, "source.txt")


@pytest.mark.parametrize(
    "target",
    ["example", "../evil.example.com", "http://example.com", "con.example.com", ""],
)
def test_workspace_rejects_invalid_targets(tmp_path: Path, target: str) -> None:
    """Regression: PIT-24 Windows-reserved target labels are rejected."""
    with pytest.raises(ValueError):
        Workspace.create(tmp_path / "workspaces", target)


def test_workspace_redacts_two_secrets_and_a_bearer_token(tmp_path: Path) -> None:
    """Regression: PIT-22 output is redacted before the atomic write."""
    secrets = ("sk-live-abc123", "ghp_secretvalue")
    workspace = Workspace.create(tmp_path / "workspaces", "example.com", secrets=secrets)
    path = workspace.write(
        "subs",
        "subfinder.txt",
        "key=sk-live-abc123\n"
        "Authorization: Bearer topsecret\n"
        "cookie: session=ghp_secretvalue\n"
        "plain.example.com\n",
    )
    content = path.read_text(encoding="utf-8")
    assert "sk-live-abc123" not in content
    assert "ghp_secretvalue" not in content
    assert "topsecret" not in content
    assert "plain.example.com" in content
    assert "***" in content


def test_workspace_empty_output_is_written(tmp_path: Path) -> None:
    workspace = Workspace.create(tmp_path / "workspaces", "example.com")
    path = workspace.write("meta", "empty.txt", "")
    assert path.read_text(encoding="utf-8") == ""


def test_workspace_large_output_is_written_up_to_the_cap(tmp_path: Path) -> None:
    """12a: a raw file is capped, never dropped and never written unbounded."""
    workspace = Workspace.create(tmp_path / "workspaces", "example.com")
    payload = "A" * (MAX_OUTPUT_BYTES + 2 * 1024)
    path = workspace.write("urls", "large.txt", payload)
    assert path.stat().st_size == MAX_OUTPUT_BYTES
    assert path.read_text(encoding="utf-8") == payload[:MAX_OUTPUT_BYTES]


def test_workspace_write_honours_an_explicit_byte_cap(tmp_path: Path) -> None:
    workspace = Workspace.create(tmp_path / "workspaces", "example.com")
    assert workspace.write("meta", "exact.txt", "12345", max_bytes=5).read_text() == "12345"
    assert workspace.write("meta", "short.txt", "123456", max_bytes=5).read_text() == "12345"


def test_workspace_cap_never_writes_a_broken_multibyte_character(tmp_path: Path) -> None:
    workspace = Workspace.create(tmp_path / "workspaces", "example.com")
    path = workspace.write("meta", "wide.txt", "\u00e9" * 10, max_bytes=3)
    assert path.read_text(encoding="utf-8") == "\u00e9"
    assert path.stat().st_size == 2


def test_workspace_write_rejects_a_non_positive_cap(tmp_path: Path) -> None:
    workspace = Workspace.create(tmp_path / "workspaces", "example.com")
    with pytest.raises(ValueError, match="max_bytes"):
        workspace.write("meta", "zero.txt", "data", max_bytes=0)


def test_workspace_same_filename_twice_replaces_atomically(tmp_path: Path) -> None:
    workspace = Workspace.create(tmp_path / "workspaces", "example.com")
    first = workspace.write("live", "httpx.txt", "old")
    second = workspace.write("live", "httpx.txt", "new")
    assert first == second
    assert second.read_text(encoding="utf-8") == "new"
    assert [item.name for item in second.parent.iterdir()] == ["httpx.txt"]


def test_workspace_failed_replace_leaves_no_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = Workspace.create(tmp_path / "workspaces", "example.com")
    path = workspace.write("ports", "naabu.txt", "old")

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(workspace_module.os, "replace", fail)
    with pytest.raises(OSError):
        workspace.write("ports", "naabu.txt", "new")

    assert path.read_text(encoding="utf-8") == "old"
    leftovers = [item.name for item in path.parent.iterdir() if item.name != "naabu.txt"]
    assert leftovers == []


def test_workspace_write_creates_directories_without_create(tmp_path: Path) -> None:
    workspace = Workspace(tmp_path / "workspaces", "example.com")
    path = workspace.write("meta", "note.txt", "hi")
    assert path.read_text(encoding="utf-8") == "hi"
