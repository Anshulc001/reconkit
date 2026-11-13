"""GitHub release download and install (docs/10 section 4)."""

from __future__ import annotations

import platform
import shutil
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from reconkit.core.runner import ExecResult, run_exec
from reconkit.errors import InstallError
from reconkit.installer.registry import InstallPlan
from reconkit.installer.verify import ARCHIVE_LIMIT, checksum_for, extract_binary, verify_checksum

API_URL = "https://api.github.com"
USER_AGENT = "reconkit/0.1"
TIMEOUT_S = 30.0
BIN_DIR_MODE = 0o700
BINARY_MODE = 0o755
VERSION_TIMEOUT_S = 10.0
ALLOWED_HOSTS = frozenset(
    {
        "api.github.com",
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    }
)
ARCH_NAMES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
Runner = Callable[..., ExecResult]


@dataclass(frozen=True)
class Release:
    """One resolved release: the asset to fetch and its checksums file."""

    tag: str
    asset_name: str
    asset_url: str
    checksums_name: str | None = None
    checksums_url: str | None = None


@dataclass(frozen=True)
class InstallOutcome:
    """What one tool's install attempt did, or would do under --dry-run."""

    tool: str
    ok: bool
    destination: str | None = None
    steps: tuple[str, ...] = ()
    error: str | None = None


def host_arch(machine: str | None = None) -> str:
    """Map the machine string onto the `{arch}` values used in tools.yaml."""
    value = platform.machine() if machine is None else machine
    arch = ARCH_NAMES.get(value.lower())
    if arch is None:
        raise InstallError(f"unsupported architecture {value!r}; expected amd64 or arm64")
    return arch


def render_pattern(pattern: str, *, name: str, version: str, arch: str) -> str:
    """Fill `{name}`, `{version}` and `{arch}` in a release asset pattern."""
    clean = version[1:] if version.startswith("v") else version
    return pattern.replace("{name}", name).replace("{version}", clean).replace("{arch}", arch)


def checked_https(url: str, *, what: str) -> str:
    """Refuse anything that is not HTTPS on a documented GitHub host."""
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise InstallError(f"{what}: refusing {url!r}; only HTTPS GitHub hosts are allowed")
    return url


def _assets(document: object) -> dict[str, str]:
    if not isinstance(document, dict):
        raise InstallError("release response is not a JSON object")
    found: dict[str, str] = {}
    raw = document.get("assets")
    if isinstance(raw, list):
        for asset in raw:
            if not isinstance(asset, dict):
                continue
            name = asset.get("name")
            url = asset.get("browser_download_url")
            if isinstance(name, str) and isinstance(url, str):
                found[name] = url
    return found


def release_for(
    plan: InstallPlan,
    *,
    client: httpx.Client,
    arch: str | None = None,
    timeout: float = TIMEOUT_S,
) -> Release:
    """Resolve the release and the exact asset names this platform needs."""
    if plan.method != "github_release":
        raise InstallError(f"{plan.name}: not a github_release plan ({plan.method!r})")
    if plan.asset_pattern is None:
        raise InstallError(f"{plan.name}: no asset_pattern to resolve a release with")
    architecture = arch if arch is not None else host_arch()
    suffix = "releases/latest" if plan.version == "latest" else f"releases/tags/{plan.version}"
    url = checked_https(f"{API_URL}/repos/{plan.repo}/{suffix}", what=f"{plan.name} release API")
    response = client.get(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT},
        timeout=timeout,
    )
    if response.status_code != 200:
        raise InstallError(f"{plan.name}: release lookup failed with HTTP {response.status_code}")
    document = response.json()
    tag = str(document.get("tag_name", "")) if isinstance(document, dict) else ""
    assets = _assets(document)
    name = plan.asset_name or plan.name
    wanted = render_pattern(
        plan.asset_pattern, name=name, version=tag or plan.version, arch=architecture
    )
    if wanted not in assets:
        raise InstallError(f"{plan.name}: release {tag or plan.version} has no asset {wanted!r}")
    checksums_name: str | None = None
    checksums_url: str | None = None
    if plan.checksums_pattern is not None:
        checksums_name = render_pattern(
            plan.checksums_pattern, name=name, version=tag or plan.version, arch=architecture
        )
        if checksums_name not in assets:
            raise InstallError(
                f"{plan.name}: release {tag or plan.version} has no checksums asset "
                f"{checksums_name!r}"
            )
        checksums_url = checked_https(assets[checksums_name], what=f"{plan.name} checksums")
    return Release(
        tag=tag,
        asset_name=wanted,
        asset_url=checked_https(assets[wanted], what=f"{plan.name} asset"),
        checksums_name=checksums_name,
        checksums_url=checksums_url,
    )


def download(
    url: str,
    dest: Path,
    *,
    client: httpx.Client,
    max_bytes: int = ARCHIVE_LIMIT,
    timeout: float = TIMEOUT_S,
) -> Path:
    """Stream one asset to `dest`, refusing anything over the cap."""
    checked_https(url, what="download")
    with client.stream(
        "GET",
        url,
        headers={"User-Agent": USER_AGENT},
        timeout=timeout,
        follow_redirects=True,
    ) as response:
        if response.status_code != 200:
            raise InstallError(f"download failed with HTTP {response.status_code}: {url}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        total = 0
        with dest.open("wb") as handle:
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise InstallError(f"{dest.name}: download exceeds {max_bytes} bytes")
                handle.write(chunk)
    return dest


def _fetch_text(url: str, *, client: httpx.Client, timeout: float = TIMEOUT_S) -> str:
    checked_https(url, what="checksums")
    response = client.get(
        url, headers={"User-Agent": USER_AGENT}, timeout=timeout, follow_redirects=True
    )
    if response.status_code != 200:
        raise InstallError(f"checksums download failed with HTTP {response.status_code}: {url}")
    return response.text


def _verify_version(destination: Path, plan: InstallPlan, runner: Runner, timeout: float) -> None:
    if not plan.version_args:
        return
    outcome = runner(
        [str(destination), *plan.version_args],
        timeout=timeout,
        env={"HOME": str(Path.home())},
    )
    if outcome.timed_out or outcome.returncode != 0:
        raise InstallError(f"{plan.name}: version check failed after install")


def install_release(
    plan: InstallPlan,
    *,
    client: httpx.Client,
    bin_dir: Path,
    dry_run: bool = False,
    arch: str | None = None,
    verify_checksums: bool = True,
    runner: Runner = run_exec,
    version_timeout: float = VERSION_TIMEOUT_S,
) -> InstallOutcome:
    """Install one github_release tool, or describe the steps under --dry-run."""
    release = release_for(plan, client=client, arch=arch)
    destination = bin_dir / plan.binary
    steps = (
        f"{plan.name}: download {release.asset_url}",
        f"{plan.name}: checksum {release.checksums_url or 'not published'}",
        f"{plan.name}: install to {destination}",
    )
    if dry_run:
        return InstallOutcome(tool=plan.name, ok=True, steps=steps)
    if verify_checksums and release.checksums_url is None:
        raise InstallError(
            f"{plan.name}: verify_checksums is on but no checksums asset is published"
        )
    bin_dir.mkdir(parents=True, exist_ok=True)
    bin_dir.chmod(BIN_DIR_MODE)
    with tempfile.TemporaryDirectory(prefix="reconkit-install-") as temp:
        work = Path(temp)
        archive = download(release.asset_url, work / release.asset_name, client=client)
        if verify_checksums and release.checksums_url is not None:
            expected = checksum_for(
                _fetch_text(release.checksums_url, client=client), release.asset_name
            )
            if expected is None:
                raise InstallError(
                    f"{plan.name}: {release.checksums_name} has no checksum for "
                    f"{release.asset_name}"
                )
            verify_checksum(archive, expected)
        extracted = extract_binary(archive, plan.binary, work / "bin")
        previous = destination.with_name(f"{destination.name}.prev")
        if destination.exists():
            shutil.copy2(destination, previous)
        shutil.copy2(extracted, destination)
        destination.chmod(BINARY_MODE)
        try:
            _verify_version(destination, plan, runner, version_timeout)
        except InstallError:
            destination.unlink(missing_ok=True)
            if previous.exists():
                shutil.copy2(previous, destination)
                destination.chmod(BINARY_MODE)
            raise
        previous.unlink(missing_ok=True)
    return InstallOutcome(tool=plan.name, ok=True, destination=str(destination), steps=steps)


def exit_code(outcomes: Iterable[InstallOutcome]) -> int:
    """0 when every tool succeeded, 5 for a partial install, 6 when nothing installed."""
    results = list(outcomes)
    if not results:
        return 0
    ok = sum(1 for result in results if result.ok)
    if ok == len(results):
        return 0
    return 5 if ok else 6


def install_plans(
    plans: Iterable[InstallPlan],
    *,
    client: httpx.Client,
    bin_dir: Path,
    dry_run: bool = False,
    arch: str | None = None,
    verify_checksums: bool = True,
    runner: Runner = run_exec,
) -> tuple[list[InstallOutcome], int]:
    """Install each plan, isolating failures so one tool cannot stop the rest."""
    outcomes: list[InstallOutcome] = []
    for plan in plans:
        try:
            outcomes.append(
                install_release(
                    plan,
                    client=client,
                    bin_dir=bin_dir,
                    dry_run=dry_run,
                    arch=arch,
                    verify_checksums=verify_checksums,
                    runner=runner,
                )
            )
        except InstallError as exc:
            outcomes.append(InstallOutcome(tool=plan.name, ok=False, error=str(exc)))
    return outcomes, exit_code(outcomes)
