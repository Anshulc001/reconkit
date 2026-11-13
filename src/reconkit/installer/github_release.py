"""GitHub release download and install (docs/10 section 4)."""

from __future__ import annotations

import os
import platform
import shutil
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from reconkit.core.runner import ExecResult, run_exec
from reconkit.errors import ConfigError, InstallError, InstallSkipped
from reconkit.installer import apt, go_install, pipx
from reconkit.installer.registry import InstallPlan
from reconkit.installer.verify import (
    ARCHIVE_LIMIT,
    check_version,
    checksum_for,
    extract_binary,
    verify_checksum,
)

API_URL = "https://api.github.com"
USER_AGENT = "reconkit/0.1"
TIMEOUT_S = 30.0
BIN_DIR_MODE = 0o700
BINARY_MODE = 0o755
VERSION_TIMEOUT_S = 10.0
CHECKSUMS_LIMIT = 64 * 1024
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
Confirm = Callable[[str], bool]


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
    skipped: bool = False
    up_to_date: bool = False
    method: str = ""


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


def _fetch_text(
    url: str,
    *,
    client: httpx.Client,
    max_bytes: int = CHECKSUMS_LIMIT,
    timeout: float = TIMEOUT_S,
) -> str:
    """Fetch a small text file (checksums), refusing anything over the cap."""
    checked_https(url, what="checksums")
    with client.stream(
        "GET", url, headers={"User-Agent": USER_AGENT}, timeout=timeout, follow_redirects=True
    ) as response:
        if response.status_code != 200:
            raise InstallError(f"checksums download failed with HTTP {response.status_code}: {url}")
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > max_bytes:
                raise InstallError(f"checksums file exceeds {max_bytes} bytes: {url}")
            chunks.append(chunk)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InstallError(f"checksums file is not UTF-8: {url}") from exc


def _verify_version(destination: Path, plan: InstallPlan, runner: Runner, timeout: float) -> None:
    check_version(destination, plan.version_args, name=plan.name, runner=runner, timeout=timeout)


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
        return InstallOutcome(tool=plan.name, ok=True, steps=steps, method=plan.method)
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
    return InstallOutcome(
        tool=plan.name, ok=True, destination=str(destination), steps=steps, method=plan.method
    )


def exit_code(outcomes: Iterable[InstallOutcome]) -> int:
    """0 when every tool succeeded, 5 for a partial install, 6 when nothing installed."""
    results = list(outcomes)
    if not results:
        return 0
    ok = sum(1 for result in results if result.ok)
    if ok == len(results):
        return 0
    return 5 if ok else 6


def _require_confirm(confirm: Confirm | None, plan: InstallPlan) -> Confirm:
    """A sudo-bearing plan must have a caller-owned confirmation handler."""
    if confirm is None:
        raise ConfigError(f"{plan.name}: {plan.method} install needs a confirmation handler")
    return confirm


def _install_one(
    plan: InstallPlan,
    *,
    bin_dir: Path,
    client: httpx.Client | None,
    dry_run: bool,
    arch: str | None,
    verify_checksums: bool,
    confirm: Confirm | None,
    runner: Runner,
    has_pipx: bool | None,
) -> InstallOutcome:
    """Dispatch one plan to its backend (docs/10 section 3)."""
    if plan.method == "github_release":
        if client is None:
            raise InstallError(f"{plan.name}: a client is required for github_release plans")
        return install_release(
            plan,
            client=client,
            bin_dir=bin_dir,
            dry_run=dry_run,
            arch=arch,
            verify_checksums=verify_checksums,
            runner=runner,
        )
    if plan.method == "apt":
        steps = apt.install_apt(
            plan,
            confirm=_require_confirm(confirm, plan),
            runner=runner,
            dry_run=dry_run,
        )
        return InstallOutcome(tool=plan.name, ok=True, steps=steps, method=plan.method)
    if plan.method == "go_install":
        steps = go_install.install_go(plan, bin_dir=bin_dir, runner=runner, dry_run=dry_run)
        return InstallOutcome(tool=plan.name, ok=True, steps=steps, method=plan.method)
    if plan.method == "pipx":
        steps = pipx.install_pipx_tool(
            plan,
            bin_dir=bin_dir,
            confirm=_require_confirm(confirm, plan),
            runner=runner,
            dry_run=dry_run,
            has_pipx=has_pipx,
        )
        return InstallOutcome(tool=plan.name, ok=True, steps=steps, method=plan.method)
    if plan.method == "none":
        return InstallOutcome(
            tool=plan.name,
            ok=True,
            steps=(f"{plan.name}: nothing to install",),
            method=plan.method,
        )
    raise InstallError(f"{plan.name}: unknown install method {plan.method!r}")


def install_plans(
    plans: Iterable[InstallPlan],
    *,
    bin_dir: Path,
    client: httpx.Client | None = None,
    dry_run: bool = False,
    arch: str | None = None,
    verify_checksums: bool = True,
    confirm: Confirm | None = None,
    runner: Runner = run_exec,
    has_pipx: bool | None = None,
) -> tuple[list[InstallOutcome], int]:
    """Install each plan, isolating failures so one tool cannot stop the rest."""
    outcomes: list[InstallOutcome] = []
    for plan in plans:
        try:
            outcomes.append(
                _install_one(
                    plan,
                    bin_dir=bin_dir,
                    client=client,
                    dry_run=dry_run,
                    arch=arch,
                    verify_checksums=verify_checksums,
                    confirm=confirm,
                    runner=runner,
                    has_pipx=has_pipx,
                )
            )
        except InstallSkipped as exc:
            outcomes.append(
                InstallOutcome(
                    tool=plan.name, ok=False, skipped=True, error=str(exc), method=plan.method
                )
            )
        except InstallError as exc:
            outcomes.append(
                InstallOutcome(tool=plan.name, ok=False, error=str(exc), method=plan.method)
            )
    return outcomes, exit_code(outcomes)


def installed_copy(plan: InstallPlan, bin_dir: Path) -> Path | None:
    """The managed copy, else a copy on PATH, else None (docs/10 section 5)."""
    candidate = bin_dir / plan.binary
    if candidate.exists():
        return candidate
    found = shutil.which(plan.binary)
    return Path(found) if found else None


def installed_version(
    plan: InstallPlan,
    bin_dir: Path,
    *,
    runner: Runner = run_exec,
    timeout: float = VERSION_TIMEOUT_S,
) -> str | None:
    """Return the installed version line, or None when the tool is not usable."""
    copy = installed_copy(plan, bin_dir)
    if copy is None:
        return None
    if not plan.version_args:
        return str(copy)
    outcome = runner(
        [str(copy), *plan.version_args],
        timeout=timeout,
        env={"HOME": str(Path.home())},
    )
    if outcome.timed_out or outcome.returncode != 0:
        return None
    text = (outcome.stdout or outcome.stderr).strip()
    return text.splitlines()[0] if text else str(copy)


def _same_version(desired: str, installed: str) -> bool:
    """Loose compare: the release tag appears in the version output."""
    clean = desired[1:] if desired.startswith("v") else desired
    return bool(clean) and clean.lower() in installed.lower()


def desired_version(
    plan: InstallPlan, *, client: httpx.Client | None, arch: str | None = None
) -> str | None:
    """The version we would install, when it can be known without installing."""
    if plan.method == "github_release" and client is not None:
        try:
            return release_for(plan, client=client, arch=arch).tag
        except InstallError:
            return None
    if plan.method == "go_install" and plan.package and "@" in plan.package:
        version = plan.package.rsplit("@", 1)[1]
        return None if version in {"", "latest"} else version
    return None


def _refresh_templates(plan: InstallPlan, *, runner: Runner) -> str | None:
    """`nuclei -ut` after a nuclei change; the flag is in its real --help.

    `HOME` is required (PIT-30: nuclei writes its config under `$HOME/.config`)
    and `PATH` is passed because the binary lives wherever the user installed Go
    tooling, exactly like the go_install/pipx exception in docs/10 section 3d.
    """
    if plan.name != "nuclei":
        return None
    env = {"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "")}
    outcome = runner(["nuclei", "-ut"], timeout=120.0, env=env)
    if outcome.timed_out or outcome.returncode != 0:
        return "templates not refreshed"
    return "templates refreshed"


def install_selected(
    plans: Iterable[InstallPlan],
    *,
    bin_dir: Path,
    update: bool = False,
    dry_run: bool = False,
    client: httpx.Client | None = None,
    arch: str | None = None,
    verify_checksums: bool = True,
    confirm: Confirm | None = None,
    runner: Runner = run_exec,
    has_pipx: bool | None = None,
) -> tuple[list[InstallOutcome], int]:
    """Install or update a selection, skipping what is already current."""
    outcomes: list[InstallOutcome] = []
    for plan in plans:
        state = None if dry_run else installed_version(plan, bin_dir, runner=runner)
        if not dry_run and update:
            desired = desired_version(plan, client=client, arch=arch)
            if state is not None and desired is not None and _same_version(desired, state):
                outcomes.append(
                    InstallOutcome(
                        tool=plan.name,
                        ok=True,
                        up_to_date=True,
                        method=plan.method,
                        steps=(f"{plan.name}: {state} is current",),
                    )
                )
                continue
        elif not dry_run and state is not None:
            outcomes.append(
                InstallOutcome(
                    tool=plan.name,
                    ok=True,
                    up_to_date=True,
                    method=plan.method,
                    steps=(f"{plan.name}: already installed ({state})",),
                )
            )
            continue
        try:
            outcome = _install_one(
                plan,
                bin_dir=bin_dir,
                client=client,
                dry_run=dry_run,
                arch=arch,
                verify_checksums=verify_checksums,
                confirm=confirm,
                runner=runner,
                has_pipx=has_pipx,
            )
            note = None if dry_run else _refresh_templates(plan, runner=runner)
            if note is not None:
                outcome = replace(outcome, steps=(*outcome.steps, f"{plan.name}: {note}"))
            outcomes.append(outcome)
        except InstallSkipped as exc:
            outcomes.append(
                InstallOutcome(
                    tool=plan.name, ok=False, skipped=True, error=str(exc), method=plan.method
                )
            )
        except InstallError as exc:
            outcomes.append(
                InstallOutcome(tool=plan.name, ok=False, error=str(exc), method=plan.method)
            )
    return outcomes, exit_code(outcomes)
