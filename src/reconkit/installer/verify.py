"""Checksum and archive verification for installs (docs/10_TOOL_INSTALLER.md)."""

from __future__ import annotations

import hashlib
import os
import tarfile
import zipfile
from pathlib import Path

from reconkit.errors import InstallError

ARCHIVE_LIMIT = 200 * 1024 * 1024
MEMBER_LIMIT = 100 * 1024 * 1024
CHUNK = 1024 * 1024


def sha256_file(path: Path) -> str:
    """Return the lowercase SHA-256 of a file, read in chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checksum_for(text: str, filename: str) -> str | None:
    """Find `<sha256>  <filename>` in a checksums file, or return None."""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].lstrip("*") == filename:
            candidate = parts[0].lower()
            if len(candidate) == 64 and all(char in "0123456789abcdef" for char in candidate):
                return candidate
    return None


def verify_checksum(path: Path, expected: str) -> None:
    """Fail closed when the file does not match its published checksum."""
    actual = sha256_file(path)
    if actual != expected.lower():
        raise InstallError(
            f"{path.name}: checksum mismatch (expected {expected.lower()}, got {actual})"
        )


def _normalized(name: str) -> str:
    return name.replace("\\", "/")


def _safe_member(name: str) -> bool:
    """Reject absolute paths, drive letters and any `..` segment (zip-slip)."""
    normalized = _normalized(name)
    if normalized.startswith("/"):
        return False
    if len(normalized) > 1 and normalized[1] == ":":
        return False
    return ".." not in normalized.split("/")


def _matches(name: str, binary: str) -> bool:
    base = _normalized(name).rsplit("/", 1)[-1]
    return base in (binary, f"{binary}.exe")


def _place(data: bytes, dest: Path, member_limit: int) -> Path:
    if len(data) > member_limit:
        raise InstallError(f"{dest.name}: extracted member exceeds {member_limit} bytes")
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = dest.with_name(f"{dest.name}.part")
    try:
        temp.write_bytes(data)
        temp.chmod(0o755)
        os.replace(temp, dest)
    except OSError as exc:
        temp.unlink(missing_ok=True)
        raise InstallError(f"{dest.name}: cannot write the binary: {exc}") from exc
    return dest


def _from_zip(archive: Path, binary: str, dest_dir: Path, member_limit: int) -> Path:
    with zipfile.ZipFile(archive) as bundle:
        for info in bundle.infolist():
            if not _safe_member(info.filename):
                raise InstallError(
                    f"{archive.name}: refusing unsafe archive path {info.filename!r}"
                )
            if info.is_dir() or not _matches(info.filename, binary):
                continue
            if info.file_size > member_limit:
                raise InstallError(
                    f"{archive.name}: {info.filename!r} exceeds {member_limit} bytes"
                )
            return _place(bundle.read(info), dest_dir / Path(info.filename).name, member_limit)
    raise InstallError(f"{archive.name}: no {binary} member in the archive")


def _from_tar(archive: Path, binary: str, dest_dir: Path, member_limit: int) -> Path:
    with tarfile.open(archive, "r:*") as bundle:
        for member in bundle:
            if not _safe_member(member.name):
                raise InstallError(f"{archive.name}: refusing unsafe archive path {member.name!r}")
            if not member.isfile() or not _matches(member.name, binary):
                continue
            if member.size > member_limit:
                raise InstallError(f"{archive.name}: {member.name!r} exceeds {member_limit} bytes")
            handle = bundle.extractfile(member)
            if handle is None:
                raise InstallError(f"{archive.name}: {member.name!r} cannot be read")
            return _place(handle.read(), dest_dir / Path(member.name).name, member_limit)
    raise InstallError(f"{archive.name}: no {binary} member in the archive")


def extract_binary(
    archive: Path,
    binary: str,
    dest_dir: Path,
    *,
    archive_limit: int = ARCHIVE_LIMIT,
    member_limit: int = MEMBER_LIMIT,
) -> Path:
    """Extract only the expected binary from a zip or tar.gz into `dest_dir`."""
    size = archive.stat().st_size
    if size > archive_limit:
        raise InstallError(f"{archive.name}: archive is {size} bytes, over {archive_limit}")
    if zipfile.is_zipfile(archive):
        return _from_zip(archive, binary, dest_dir, member_limit)
    if tarfile.is_tarfile(archive):
        return _from_tar(archive, binary, dest_dir, member_limit)
    raise InstallError(f"{archive.name}: not a zip or tar.gz archive")
