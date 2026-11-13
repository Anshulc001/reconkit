"""Verify tests: checksums and safe extraction, all from local files."""

from __future__ import annotations

import hashlib
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from reconkit.errors import InstallError
from reconkit.installer.verify import (
    checksum_for,
    extract_binary,
    sha256_file,
    verify_checksum,
)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def test_checksum_round_trip_and_mismatch(tmp_path: Path) -> None:
    artifact = tmp_path / "tool_linux_amd64.zip"
    artifact.write_bytes(b"payload")
    expected = sha256_file(artifact)
    verify_checksum(artifact, expected)
    with pytest.raises(InstallError, match="checksum mismatch"):
        verify_checksum(artifact, "0" * 64)


def test_checksum_for_picks_the_named_entry() -> None:
    text = (
        f"{sha('a')}  tool_linux_amd64.zip\n"
        f"{sha('b')} *tool_linux_arm64.zip\n"
        "not-a-checksum  tool_linux_amd64.zip\n"
    )
    assert checksum_for(text, "tool_linux_amd64.zip") == sha("a")
    assert checksum_for(text, "tool_linux_arm64.zip") == sha("b")
    assert checksum_for(text, "missing.zip") is None


def zip_with(tmp_path: Path, members: dict[str, bytes]) -> Path:
    archive = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for name, data in members.items():
            bundle.writestr(name, data)
    return archive


def test_zip_extracts_only_the_expected_binary(tmp_path: Path) -> None:
    archive = zip_with(tmp_path, {"README.md": b"docs", "bin/beta": b"#!/bin/sh\n"})
    dest = tmp_path / "out"
    placed = extract_binary(archive, "beta", dest)
    assert placed == dest / "beta"
    assert placed.read_bytes() == b"#!/bin/sh\n"
    assert placed.stat().st_mode & 0o777 == 0o755
    assert not (dest / "README.md").exists()


def test_zip_without_the_binary_fails(tmp_path: Path) -> None:
    archive = zip_with(tmp_path, {"README.md": b"docs"})
    with pytest.raises(InstallError, match="no beta member"):
        extract_binary(archive, "beta", tmp_path / "out")


def test_zip_slip_is_refused(tmp_path: Path) -> None:
    archive = zip_with(tmp_path, {"../beta": b"evil"})
    with pytest.raises(InstallError, match="unsafe archive path"):
        extract_binary(archive, "beta", tmp_path / "out")
    assert not (tmp_path / "beta").exists()


def test_absolute_member_is_refused(tmp_path: Path) -> None:
    archive = zip_with(tmp_path, {"/evil/beta": b"evil"})
    with pytest.raises(InstallError, match="unsafe archive path"):
        extract_binary(archive, "beta", tmp_path / "out")


def test_archive_and_member_limits(tmp_path: Path) -> None:
    archive = zip_with(tmp_path, {"beta": b"0123456789"})
    with pytest.raises(InstallError, match="archive is"):
        extract_binary(archive, "beta", tmp_path / "out", archive_limit=1)
    with pytest.raises(InstallError, match="exceeds 1 bytes"):
        extract_binary(archive, "beta", tmp_path / "out", member_limit=1)


def test_tar_gz_extracts_the_binary(tmp_path: Path) -> None:
    archive = tmp_path / "bundle.tar.gz"
    payload = b"#!/bin/sh\necho hi\n"
    with tarfile.open(archive, "w:gz") as bundle:
        info = tarfile.TarInfo("release/beta")
        info.size = len(payload)
        info.mode = 0o644
        bundle.addfile(info, io.BytesIO(payload))
    placed = extract_binary(archive, "beta", tmp_path / "out")
    assert placed.read_bytes() == payload
    assert placed.stat().st_mode & 0o777 == 0o755


def test_tar_gz_slip_is_refused(tmp_path: Path) -> None:
    archive = tmp_path / "bundle.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        info = tarfile.TarInfo("../beta")
        info.size = 3
        bundle.addfile(info, io.BytesIO(b"bad"))
    with pytest.raises(InstallError, match="unsafe archive path"):
        extract_binary(archive, "beta", tmp_path / "out")


def test_non_archive_is_refused(tmp_path: Path) -> None:
    archive = tmp_path / "bundle.bin"
    archive.write_bytes(b"not an archive")
    with pytest.raises(InstallError, match="not a zip or tar.gz archive"):
        extract_binary(archive, "beta", tmp_path / "out")
