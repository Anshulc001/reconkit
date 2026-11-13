"""github_release tests: MockTransport only, no real network, no real installs."""

from __future__ import annotations

import hashlib
import io
import zipfile
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from reconkit.core.runner import ExecResult
from reconkit.errors import InstallError
from reconkit.installer.github_release import (
    InstallOutcome,
    _fetch_text,
    download,
    exit_code,
    host_arch,
    install_plans,
    install_release,
    release_for,
)
from reconkit.installer.registry import InstallPlan, plan_for

API = "https://api.github.com/repos/projectdiscovery/subfinder/releases/latest"
ASSET = "subfinder_2.6.0_linux_amd64.zip"
CHECKSUMS = "subfinder_2.6.0_checksums.txt"
ASSET_URL = f"https://github.com/projectdiscovery/subfinder/releases/download/v2.6.0/{ASSET}"
CHECKSUMS_URL = (
    f"https://github.com/projectdiscovery/subfinder/releases/download/v2.6.0/{CHECKSUMS}"
)


def archive_bytes(name: str = "subfinder", data: bytes = b"#!/bin/sh\n") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr("README.md", b"docs")
        bundle.writestr(name, data)
    return buffer.getvalue()


def handler(
    *,
    archive: bytes | None = None,
    checksums: str | None = None,
    tag: str = "v2.6.0",
    assets: dict[str, str] | None = None,
) -> Callable[[httpx.Request], httpx.Response]:
    payload = archive if archive is not None else archive_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    documents = assets or {ASSET: ASSET_URL, CHECKSUMS: CHECKSUMS_URL}
    text = checksums if checksums is not None else f"{digest}  {ASSET}\n"

    def respond(request: httpx.Request) -> httpx.Response:
        if str(request.url) == API:
            return httpx.Response(
                200,
                json={
                    "tag_name": tag,
                    "assets": [
                        {"name": key, "browser_download_url": value}
                        for key, value in documents.items()
                    ],
                },
            )
        if str(request.url) == ASSET_URL:
            return httpx.Response(200, content=payload)
        if str(request.url) == CHECKSUMS_URL:
            return httpx.Response(200, text=text)
        return httpx.Response(404)

    return respond


def client(**kwargs: object) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler(**kwargs)))


def fake_runner(returncode: int = 0, timed_out: bool = False):
    calls: list[tuple[list[str], dict[str, str] | None]] = []

    def run(
        argv: list[str], timeout: float | None = None, env: dict[str, str] | None = None
    ) -> ExecResult:
        calls.append((argv, env))
        return ExecResult(
            returncode=returncode,
            stdout="subfinder v2.6.0",
            stderr="",
            timed_out=timed_out,
            truncated=False,
        )

    return run, calls


def subfinder_plan() -> InstallPlan:
    return plan_for("subfinder")


def test_release_resolves_the_asset_and_checksums() -> None:
    with client() as http:
        release = release_for(subfinder_plan(), client=http, arch="amd64")
    assert release.tag == "v2.6.0"
    assert release.asset_name == ASSET
    assert release.asset_url == ASSET_URL
    assert release.checksums_name == CHECKSUMS
    assert release.checksums_url == CHECKSUMS_URL


def test_missing_asset_is_an_install_error() -> None:
    plan = replace(subfinder_plan(), asset_pattern="{name}_nope.zip")
    with client() as http, pytest.raises(InstallError, match="has no asset"):
        release_for(plan, client=http, arch="amd64")


def test_dry_run_lists_steps_and_touches_nothing(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    runner, calls = fake_runner()
    with client() as http:
        outcome = install_release(
            subfinder_plan(),
            client=http,
            bin_dir=bin_dir,
            dry_run=True,
            arch="amd64",
            runner=runner,
        )
    assert outcome.ok is True
    assert outcome.destination is None
    assert outcome.steps == (
        f"subfinder: download {ASSET_URL}",
        f"subfinder: checksum {CHECKSUMS_URL}",
        f"subfinder: install to {bin_dir / 'subfinder'}",
    )
    assert not bin_dir.exists()
    assert calls == []


def test_install_places_the_binary_with_permissions(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    runner, calls = fake_runner()
    with client() as http:
        outcome = install_release(
            subfinder_plan(), client=http, bin_dir=bin_dir, arch="amd64", runner=runner
        )
    binary = bin_dir / "subfinder"
    assert outcome.ok is True
    assert binary.read_bytes() == b"#!/bin/sh\n"
    assert binary.stat().st_mode & 0o777 == 0o755
    assert bin_dir.stat().st_mode & 0o777 == 0o700
    assert calls[0][0] == [str(binary), "-version"]
    assert calls[0][1] == {"HOME": str(Path.home())}
    assert not (bin_dir / "subfinder.prev").exists()


def test_checksum_mismatch_installs_nothing(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    with client(checksums=f"{'0' * 64}  {ASSET}\n") as http:
        with pytest.raises(InstallError, match="checksum mismatch"):
            install_release(subfinder_plan(), client=http, bin_dir=bin_dir, arch="amd64")
    assert not (bin_dir / "subfinder").exists()


def test_checksums_file_without_our_asset_is_an_error(tmp_path: Path) -> None:
    with client(checksums="abc  other.zip\n") as http:
        with pytest.raises(InstallError, match="has no checksum for"):
            install_release(subfinder_plan(), client=http, bin_dir=tmp_path / "bin", arch="amd64")


def test_verify_checksums_without_a_checksums_asset_is_an_error(tmp_path: Path) -> None:
    plan = replace(subfinder_plan(), checksums_pattern=None)
    with client() as http:
        with pytest.raises(InstallError, match="no checksums asset is published"):
            install_release(plan, client=http, bin_dir=tmp_path / "bin", arch="amd64")


def test_plan_checksum_opt_out_allows_a_release_without_checksums(tmp_path: Path) -> None:
    plan = replace(subfinder_plan(), checksums_pattern=None, verify_checksums=False)
    run, calls = fake_runner()
    with client() as http:
        outcome = install_release(
            plan, client=http, bin_dir=tmp_path / "bin", arch="amd64", runner=run
        )
    assert outcome.ok
    assert (tmp_path / "bin" / "subfinder").exists()
    assert len(calls) == 1


def test_member_override_extracts_a_renamed_binary(tmp_path: Path) -> None:
    plan = replace(subfinder_plan(), member="subfinder-linux")
    run, _calls = fake_runner()
    with client(archive=archive_bytes("subfinder-linux")) as http:
        install_release(plan, client=http, bin_dir=tmp_path / "bin", arch="amd64", runner=run)
    installed = tmp_path / "bin" / "subfinder"
    assert installed.exists()
    assert installed.read_bytes() == b"#!/bin/sh\n"


def test_checksums_fetch_is_size_capped() -> None:
    with (
        client(checksums="a" * 200) as http,
        pytest.raises(InstallError, match="checksums file exceeds"),
    ):
        _fetch_text(CHECKSUMS_URL, client=http, max_bytes=64)


def test_http_url_is_refused() -> None:
    with client() as http, pytest.raises(InstallError, match="only HTTPS GitHub hosts"):
        download("http://github.com/x/y.zip", Path("unused.zip"), client=http)


def test_non_github_asset_host_is_refused() -> None:
    plan = subfinder_plan()
    documents = {ASSET: "https://evil.example/x.zip", CHECKSUMS: CHECKSUMS_URL}
    with (
        client(assets=documents) as http,
        pytest.raises(InstallError, match="only HTTPS GitHub hosts"),
    ):
        release_for(plan, client=http, arch="amd64")


def test_download_cap_is_enforced(tmp_path: Path) -> None:
    with client() as http, pytest.raises(InstallError, match="download exceeds"):
        download(ASSET_URL, tmp_path / "a.zip", client=http, max_bytes=1)


def test_failed_version_check_restores_the_previous_binary(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    binary = bin_dir / "subfinder"
    binary.write_bytes(b"old")
    runner, _ = fake_runner(returncode=1)
    with client() as http:
        with pytest.raises(InstallError, match="version check failed"):
            install_release(
                subfinder_plan(), client=http, bin_dir=bin_dir, arch="amd64", runner=runner
            )
    assert binary.read_bytes() == b"old"


def test_plans_are_isolated_and_exit_codes_follow_the_table(tmp_path: Path) -> None:
    good = subfinder_plan()
    bad = replace(good, asset_pattern="{name}_missing.zip")
    runner, _ = fake_runner()
    with client() as http:
        outcomes, code = install_plans(
            [good, bad], client=http, bin_dir=tmp_path / "bin", arch="amd64", runner=runner
        )
    assert [outcome.ok for outcome in outcomes] == [True, False]
    assert code == 5
    failed = [outcome for outcome in outcomes if not outcome.ok]
    assert "has no asset" in (failed[0].error or "")
    assert exit_code([]) == 0
    assert exit_code([InstallOutcome(tool="x", ok=True)]) == 0
    assert exit_code([InstallOutcome(tool="x", ok=False)]) == 6


def test_host_arch_maps_machine_names() -> None:
    assert host_arch("x86_64") == "amd64"
    assert host_arch("aarch64") == "arm64"
    with pytest.raises(InstallError, match="unsupported architecture"):
        host_arch("riscv64")


def test_rustscan_placeholder_cannot_resolve() -> None:
    """The registry still holds a placeholder, so 10c must not install it."""
    plan = plan_for("rustscan")
    assert plan.asset_pattern == "verify-at-implementation"

    def respond(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"tag_name": "2.4.1", "assets": []})

    with httpx.Client(transport=httpx.MockTransport(respond)) as http:
        with pytest.raises(InstallError, match="has no asset"):
            release_for(plan, client=http, arch="amd64")


def test_release_lookup_follows_a_rename_redirect() -> None:
    """Regression: a renamed repo answers the API with 301; follow it."""
    moved = "https://api.github.com/repos/bee-san/RustScan/releases/latest"

    def respond(request: httpx.Request) -> httpx.Response:
        if str(request.url) == API:
            return httpx.Response(301, headers={"Location": moved})
        return httpx.Response(
            200,
            json={
                "tag_name": "v2.6.0",
                "assets": [
                    {"name": ASSET, "browser_download_url": ASSET_URL},
                    {"name": CHECKSUMS, "browser_download_url": CHECKSUMS_URL},
                ],
            },
        )

    with httpx.Client(transport=httpx.MockTransport(respond)) as http:
        release = release_for(subfinder_plan(), client=http, arch="amd64")
    assert release.tag == "v2.6.0"
