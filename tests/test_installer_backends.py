"""apt, go_install and pipx backends: fake runner only, no real installs."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from reconkit.core.runner import ExecResult
from reconkit.errors import ConfigError, InstallError, InstallSkipped
from reconkit.installer import apt, go_install, pipx
from reconkit.installer.github_release import install_plans
from reconkit.installer.registry import InstallPlan, plan_for

APT_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "DEBIAN_FRONTEND": "noninteractive",
    "LC_ALL": "C",
}


def fake_runner(
    *,
    returncode: int = 0,
    timed_out: bool = False,
    stderr: str = "",
    create: Path | None = None,
):
    calls: list[tuple[list[str], dict[str, str] | None]] = []

    def run(
        argv: list[str], timeout: float | None = None, env: dict[str, str] | None = None
    ) -> ExecResult:
        calls.append((argv, env))
        if create is not None and argv[0] in {"go", "pipx"}:
            create.parent.mkdir(parents=True, exist_ok=True)
            create.write_bytes(b"#!/bin/sh\n")
        return ExecResult(
            returncode=returncode,
            stdout="",
            stderr=stderr,
            timed_out=timed_out,
            truncated=False,
        )

    return run, calls


def always(message: str) -> bool:
    return True


# ---------------------------------------------------------------- apt


def test_apt_runs_sudo_non_interactively_with_the_documented_env(monkeypatch) -> None:
    monkeypatch.setattr(apt.shutil, "which", lambda name: f"/usr/bin/{name}")
    runner, calls = fake_runner()
    steps = apt.install_apt(plan_for("nmap"), confirm=always, runner=runner)
    assert steps == ("nmap: sudo apt-get install -y nmap (sudo required)",)
    assert calls[0][0] == ["sudo", "-n", "apt-get", "install", "-y", "nmap"]
    assert calls[0][1] == APT_ENV
    assert "HOME" not in calls[0][1]
    assert calls[1][0] == ["nmap", "--version"]
    assert calls[1][1] == APT_ENV


def test_apt_declined_starts_no_process_at_all() -> None:
    runner, calls = fake_runner()
    prompts: list[str] = []

    def decline(message: str) -> bool:
        prompts.append(message)
        return False

    with pytest.raises(InstallSkipped, match="declined"):
        apt.install_apt(plan_for("nmap"), confirm=decline, runner=runner)
    assert prompts == ["nmap: sudo apt-get install -y nmap (sudo required)"]
    assert calls == []


def test_apt_without_a_sudo_password_is_skipped_with_a_hint() -> None:
    runner, calls = fake_runner(returncode=1, stderr="sudo: a password is required\n")
    with pytest.raises(InstallSkipped, match="sudo -v"):
        apt.install_apt(plan_for("nmap"), confirm=always, runner=runner)
    assert len(calls) == 1


def test_apt_failure_is_an_install_error() -> None:
    runner, _ = fake_runner(returncode=100, stderr="E: Unable to locate package\n")
    with pytest.raises(InstallError, match="apt-get failed"):
        apt.install_apt(plan_for("nmap"), confirm=always, runner=runner)


def test_apt_timeout_is_an_install_error() -> None:
    runner, _ = fake_runner(timed_out=True)
    with pytest.raises(InstallError, match="timed out"):
        apt.install_apt(plan_for("nmap"), confirm=always, runner=runner)


def test_apt_package_names_are_validated() -> None:
    plan = replace(plan_for("nmap"), package="../evil")
    runner, calls = fake_runner()
    with pytest.raises(ConfigError, match="invalid apt package name"):
        apt.install_apt(plan, confirm=always, runner=runner)
    assert calls == []
    with pytest.raises(ConfigError, match="invalid apt package name"):
        apt.apt_argv("-o Acquire::http::Proxy=http://evil")


def test_apt_dry_run_prompts_nothing_and_runs_nothing() -> None:
    runner, calls = fake_runner()
    steps = apt.install_apt(plan_for("nmap"), confirm=always, runner=runner, dry_run=True)
    assert steps == ("nmap: sudo apt-get install -y nmap (sudo required)",)
    assert calls == []


# ---------------------------------------------------------------- go_install


def test_go_env_is_home_gobin_and_path_only(tmp_path: Path) -> None:
    env = go_install.go_env(tmp_path, home=tmp_path / "home", path="/usr/bin:/bin")
    assert env == {
        "HOME": str(tmp_path / "home"),
        "GOBIN": str(tmp_path),
        "PATH": "/usr/bin:/bin",
    }


def test_go_install_runs_go_install_and_checks_the_version(tmp_path: Path) -> None:
    binary = tmp_path / "assetfinder"
    runner, calls = fake_runner(create=binary)
    steps = go_install.install_go(plan_for("assetfinder"), bin_dir=tmp_path, runner=runner)
    assert steps == (
        f"assetfinder: go install github.com/tomnomnom/assetfinder@latest -> {binary}",
    )
    assert calls[0][0] == ["go", "install", "github.com/tomnomnom/assetfinder@latest"]
    assert calls[0][1] == go_install.go_env(tmp_path)
    assert calls[1][0] == [str(binary), "-h"]
    assert calls[1][1] == calls[0][1]


def test_go_install_failure_is_an_install_error(tmp_path: Path) -> None:
    runner, calls = fake_runner(returncode=1)
    with pytest.raises(InstallError, match="go install failed"):
        go_install.install_go(plan_for("assetfinder"), bin_dir=tmp_path, runner=runner)
    assert len(calls) == 1


def test_go_install_without_the_expected_binary_fails(tmp_path: Path) -> None:
    runner, _ = fake_runner()
    with pytest.raises(InstallError, match="was not created"):
        go_install.install_go(plan_for("assetfinder"), bin_dir=tmp_path, runner=runner)


def test_go_specs_are_validated(tmp_path: Path) -> None:
    plan = replace(plan_for("assetfinder"), package="github.com/x/y@latest; rm -rf /")
    with pytest.raises(ConfigError, match="invalid go package"):
        go_install.install_go(plan, bin_dir=tmp_path, runner=fake_runner()[0])


def test_go_dry_run_runs_nothing(tmp_path: Path) -> None:
    runner, calls = fake_runner()
    steps = go_install.install_go(
        plan_for("assetfinder"), bin_dir=tmp_path, runner=runner, dry_run=True
    )
    assert steps[0].startswith("assetfinder: go install ")
    assert calls == []


# ---------------------------------------------------------------- pipx


def test_pipx_env_points_at_the_managed_bin_dir(tmp_path: Path) -> None:
    env = pipx.pipx_env(tmp_path, home=tmp_path / "home", path="/usr/bin:/bin")
    assert env == {
        "HOME": str(tmp_path / "home"),
        "PATH": "/usr/bin:/bin",
        "PIPX_BIN_DIR": str(tmp_path),
        "PIPX_HOME": str(tmp_path / "home" / ".local" / "pipx"),
    }


def test_pipx_missing_apt_prompts_twice_and_keeps_them_distinct(tmp_path: Path) -> None:
    binary = tmp_path / "wafw00f"
    runner, calls = fake_runner(create=binary)
    prompts: list[str] = []

    def confirm(message: str) -> bool:
        prompts.append(message)
        return True

    steps = pipx.install_pipx_tool(
        plan_for("wafw00f"),
        bin_dir=tmp_path,
        confirm=confirm,
        runner=runner,
        has_pipx=False,
    )
    assert prompts == [
        "pipx is required for wafw00f: sudo apt-get install -y pipx (sudo required)",
        f"wafw00f: pipx install wafw00f -> {binary}",
    ]
    assert prompts[0] != prompts[1]
    assert steps == tuple(prompts)
    assert calls[0][0] == ["sudo", "-n", "apt-get", "install", "-y", "pipx"]
    assert calls[1][0] == ["pipx", "install", "wafw00f"]
    assert calls[2][0] == [str(binary), "--version"]


def test_declined_pipx_prerequisite_installs_nothing(tmp_path: Path) -> None:
    runner, calls = fake_runner()
    prompts: list[str] = []

    def decline(message: str) -> bool:
        prompts.append(message)
        return False

    with pytest.raises(InstallSkipped, match="declined"):
        pipx.install_pipx_tool(
            plan_for("wafw00f"),
            bin_dir=tmp_path,
            confirm=decline,
            runner=runner,
            has_pipx=False,
        )
    assert len(prompts) == 1
    assert "sudo apt-get install -y pipx" in prompts[0]
    assert calls == []


def test_declining_the_tool_after_the_prerequisite_stops_before_pipx(tmp_path: Path) -> None:
    runner, calls = fake_runner(create=tmp_path / "wafw00f")
    answers = iter([True, False])

    def confirm(_message: str) -> bool:
        return next(answers)

    with pytest.raises(InstallSkipped, match="pipx install declined"):
        pipx.install_pipx_tool(
            plan_for("wafw00f"),
            bin_dir=tmp_path,
            confirm=confirm,
            runner=runner,
            has_pipx=False,
        )
    assert [call[0][:3] for call in calls] == [["sudo", "-n", "apt-get"]]


def test_pipx_already_installed_needs_one_prompt(tmp_path: Path) -> None:
    binary = tmp_path / "wafw00f"
    runner, calls = fake_runner(create=binary)
    prompts: list[str] = []

    def confirm(message: str) -> bool:
        prompts.append(message)
        return True

    pipx.install_pipx_tool(
        plan_for("wafw00f"),
        bin_dir=tmp_path,
        confirm=confirm,
        runner=runner,
        has_pipx=True,
    )
    assert prompts == [f"wafw00f: pipx install wafw00f -> {binary}"]
    assert calls[0][0] == ["pipx", "install", "wafw00f"]


def test_pipx_git_spec_is_allowed_and_other_specs_are_rejected(tmp_path: Path) -> None:
    assert pipx.pipx_spec(plan_for("dnsreaper")) == "git+https://github.com/punk-security/dnsReaper"
    plan = replace(plan_for("wafw00f"), package="wafw00f; rm -rf /")
    with pytest.raises(ConfigError, match="invalid pipx package"):
        pipx.install_pipx_tool(
            plan, bin_dir=tmp_path, confirm=always, runner=fake_runner()[0], has_pipx=True
        )


# ---------------------------------------------------------------- dispatch


def test_dispatch_uses_each_backend_and_isolates_failures(tmp_path: Path) -> None:
    good_go = plan_for("assetfinder")
    runner, calls = fake_runner(create=tmp_path / "assetfinder")
    with_go_and_apt: list[InstallPlan] = [
        plan_for("nmap"),
        good_go,
        plan_for("pyprobe"),
    ]
    outcomes, code = install_plans(
        with_go_and_apt,
        bin_dir=tmp_path,
        confirm=always,
        runner=runner,
        has_pipx=True,
    )
    assert [outcome.tool for outcome in outcomes] == ["nmap", "assetfinder", "pyprobe"]
    assert all(outcome.ok for outcome in outcomes)
    assert code == 0
    assert outcomes[2].steps == ("pyprobe: nothing to install",)
    assert calls[0][0][:5] == ["sudo", "-n", "apt-get", "install", "-y"]
    assert calls[2][0] == ["go", "install", "github.com/tomnomnom/assetfinder@latest"]


def test_dispatch_marks_a_declined_apt_plan_skipped_and_exits_5(tmp_path: Path) -> None:
    runner, calls = fake_runner(create=tmp_path / "assetfinder")
    outcomes, code = install_plans(
        [plan_for("nmap"), plan_for("assetfinder")],
        bin_dir=tmp_path,
        confirm=lambda _message: False,
        runner=runner,
    )
    assert [outcome.ok for outcome in outcomes] == [False, True]
    assert outcomes[0].skipped is True
    assert "declined" in (outcomes[0].error or "")
    assert all(call[0][0] != "sudo" for call in calls)
    assert calls[0][0][0] == "go"


def test_dispatch_without_a_confirm_handler_refuses_sudo_plans(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="needs a confirmation handler"):
        install_plans([plan_for("nmap")], bin_dir=tmp_path, runner=fake_runner()[0])


def test_dispatch_dry_run_prompts_and_runs_nothing(tmp_path: Path) -> None:
    runner, calls = fake_runner()
    prompts: list[str] = []

    def confirm(message: str) -> bool:
        prompts.append(message)
        return True

    outcomes, code = install_plans(
        [plan_for("nmap"), plan_for("wafw00f")],
        bin_dir=tmp_path,
        dry_run=True,
        confirm=confirm,
        runner=runner,
        has_pipx=False,
    )
    assert code == 0
    assert prompts == []
    assert calls == []
    assert "sudo required" in outcomes[0].steps[0]
    assert "pipx is required for wafw00f" in outcomes[1].steps[0]


def test_dispatch_every_tool_failing_exits_6(tmp_path: Path) -> None:
    outcomes, code = install_plans(
        [plan_for("nmap"), plan_for("assetfinder")],
        bin_dir=tmp_path,
        confirm=lambda _message: False,
        runner=fake_runner()[0],
    )
    assert all(not outcome.ok for outcome in outcomes)
    assert code == 6
