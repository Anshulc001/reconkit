"""Part 10e: install/update orchestration, idempotency and exit codes."""

from __future__ import annotations

import io
import shutil
from dataclasses import replace
from pathlib import Path

import yaml
from typer.testing import CliRunner

from reconkit import cli
from reconkit.cli import app
from reconkit.core.runner import ExecResult, run_exec
from reconkit.doctor import key_checks
from reconkit.installer import github_release
from reconkit.installer.github_release import install_selected
from reconkit.installer.registry import bin_dir, load_plans, plan_for
from reconkit.ui import make_console, render_keys

REPO = Path(__file__).resolve().parents[1]


def fake_runner(*, version_text: str = "tool v1.0.0", create: Path | None = None):
    calls: list[tuple[list[str], dict[str, str] | None]] = []

    def run(
        argv: list[str], timeout: float | None = None, env: dict[str, str] | None = None
    ) -> ExecResult:
        calls.append((argv, env))
        if create is not None and argv[0] in {"go", "pipx"}:
            create.parent.mkdir(parents=True, exist_ok=True)
            create.write_bytes(b"#!/bin/sh\n")
        return ExecResult(
            returncode=0,
            stdout=version_text,
            stderr="",
            timed_out=False,
            truncated=False,
        )

    return run, calls


def test_bin_dir_defaults_to_the_home_directory(tmp_path: Path) -> None:
    assert bin_dir() == Path.home() / ".reconkit" / "bin"
    assert bin_dir(tmp_path) == tmp_path / ".reconkit" / "bin"


def test_installed_version_uses_the_managed_copy_first(tmp_path: Path) -> None:
    binary = bin_dir(tmp_path) / "assetfinder"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"#!/bin/sh\n")
    runner, calls = fake_runner(version_text="assetfinder 1.2.3")
    state = github_release.installed_version(
        plan_for("assetfinder"), bin_dir(tmp_path), runner=runner
    )
    assert state == "assetfinder 1.2.3"
    assert calls[0][0] == [str(binary), "-h"]


def test_install_skips_a_tool_that_is_already_usable(tmp_path: Path) -> None:
    binary = bin_dir(tmp_path) / "assetfinder"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"#!/bin/sh\n")
    runner, calls = fake_runner(version_text="assetfinder 1.2.3")
    outcomes, code = install_selected(
        [plan_for("assetfinder")], bin_dir=bin_dir(tmp_path), runner=runner
    )
    assert [outcome.up_to_date for outcome in outcomes] == [True]
    assert outcomes[0].steps == ("assetfinder: already installed (assetfinder 1.2.3)",)
    assert [call[0][0] for call in calls] == [str(binary)]
    assert code == 0


def test_update_skips_when_the_pin_is_already_installed(tmp_path: Path) -> None:
    plan = replace(
        plan_for("assetfinder"),
        package="github.com/tomnomnom/assetfinder@2.0.0",
    )
    binary = bin_dir(tmp_path) / "assetfinder"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"#!/bin/sh\n")
    runner, calls = fake_runner(version_text="assetfinder 2.0.0")
    outcomes, code = install_selected([plan], bin_dir=bin_dir(tmp_path), update=True, runner=runner)
    assert outcomes[0].up_to_date is True
    assert outcomes[0].steps == ("assetfinder: assetfinder 2.0.0 is current",)
    assert [call[0][0] for call in calls] == [str(binary)]
    assert code == 0


def test_update_installs_when_the_installed_version_is_older(tmp_path: Path) -> None:
    plan = replace(plan_for("assetfinder"), package="github.com/tomnomnom/assetfinder@2.0.0")
    binary = bin_dir(tmp_path) / "assetfinder"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"#!/bin/sh\n")
    runner, calls = fake_runner(version_text="assetfinder 1.0.0")

    def create(argv: list[str], timeout: float | None = None, env=None) -> ExecResult:
        calls.append((argv, env))
        if argv[0] == "go":
            binary.write_bytes(b"#!/bin/sh\n")
        return ExecResult(returncode=0, stdout="assetfinder 1.0.0", stderr="", truncated=False)

    outcomes, code = install_selected([plan], bin_dir=bin_dir(tmp_path), update=True, runner=create)
    assert outcomes[0].ok is True
    assert outcomes[0].up_to_date is False
    assert ["go", "install", "github.com/tomnomnom/assetfinder@2.0.0"] in [c[0] for c in calls]
    assert code == 0


def test_exit_code_is_aggregated_over_every_selected_tool(tmp_path: Path) -> None:
    good = plan_for("assetfinder")
    bad = replace(good, name="broken", binary="broken")
    runner, _ = fake_runner(create=bin_dir(tmp_path) / "assetfinder")
    outcomes, code = install_selected([good, bad], bin_dir=bin_dir(tmp_path), runner=runner)
    assert [outcome.ok for outcome in outcomes] == [True, False]
    assert code == 5

    only_bad, code = install_selected([bad], bin_dir=bin_dir(tmp_path), runner=runner)
    assert only_bad[0].ok is False
    assert code == 6


def test_nuclei_templates_are_refreshed_after_a_change(tmp_path: Path) -> None:
    """Regression: PIT-31 - the refresh env carries HOME and PATH, not HOME alone."""
    plan = replace(
        plan_for("assetfinder"),
        name="nuclei",
        binary="nuclei",
        package="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    )
    runner, calls = fake_runner(create=bin_dir(tmp_path) / "nuclei")
    outcomes, code = install_selected([plan], bin_dir=bin_dir(tmp_path), update=True, runner=runner)
    assert code == 0
    assert outcomes[0].steps[-1] == "nuclei: templates refreshed"
    refresh = next(call for call in calls if call[0] == ["nuclei", "-ut"])
    assert refresh[1] is not None
    assert set(refresh[1]) == {"HOME", "PATH"}
    assert refresh[1]["HOME"] == str(Path.home())


def test_cli_install_without_a_selection_is_a_usage_error() -> None:
    result = CliRunner().invoke(app, ["install"])
    assert result.exit_code == 2
    assert "name at least one tool or pass --all" in result.output


def test_cli_install_rejects_an_unknown_tool() -> None:
    result = CliRunner().invoke(app, ["install", "nope", "--dry-run"])
    assert result.exit_code == 2
    assert "unknown tool 'nope'" in result.output


def test_cli_install_refuses_non_linux(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "platform", "win32")
    result = CliRunner().invoke(app, ["install", "--all", "--dry-run"])
    assert result.exit_code == 1
    assert "Use WSL2 Kali" in result.output


def test_cli_install_wires_tool_versions_and_core_selection(tmp_path: Path, monkeypatch) -> None:
    config = yaml.safe_load((REPO / "config.yaml").read_text(encoding="utf-8"))
    config["tool_versions"] = {"subfinder": "9.9.9"}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_install_selected(plans, **kwargs):
        captured["plans"] = list(plans)
        captured["kwargs"] = kwargs
        return [], 0

    monkeypatch.setattr(cli, "install_selected", fake_install_selected)
    monkeypatch.setattr(cli, "bin_dir", lambda: tmp_path / "bin")
    result = CliRunner().invoke(app, ["install", "--all", "--dry-run", "--config", str(path)])
    assert result.exit_code == 0
    plans = captured["plans"]
    assert plans, "no plans selected"
    assert all(plan.tier == "core" and plan.method != "none" for plan in plans)
    subfinder = next(plan for plan in plans if plan.name == "subfinder")
    assert subfinder.version == "9.9.9"
    kwargs = captured["kwargs"]
    assert kwargs["dry_run"] is True
    assert kwargs["update"] is False


def test_cli_update_passes_update_true(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_install_selected(plans, **kwargs):
        captured["kwargs"] = kwargs
        return [], 0

    monkeypatch.setattr(cli, "install_selected", fake_install_selected)
    monkeypatch.setattr(cli, "bin_dir", lambda: tmp_path / "bin")
    result = CliRunner().invoke(app, ["update", "nmap", "--dry-run"])
    assert result.exit_code == 0
    assert captured["kwargs"]["update"] is True


def test_doctor_fix_now_runs_the_installer(monkeypatch) -> None:
    called: dict[str, object] = {}

    def fake_install_selected(plans, **kwargs):
        called["plans"] = list(plans)
        return [], 0

    monkeypatch.setattr(cli, "install_selected", fake_install_selected)
    monkeypatch.setattr(cli, "bin_dir", lambda: REPO / "workspaces" / "bin")
    result = CliRunner().invoke(app, ["doctor", "--fix", "--config", str(REPO / "config.yaml")])
    assert result.exit_code == 0
    assert "--fix is not available yet" not in result.output
    assert called["plans"], "doctor --fix did not select any plans"


def test_no_env_file_is_written_without_a_tty(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    shutil.copy2(REPO / ".env.example", tmp_path / ".env.example")
    monkeypatch.setattr(cli, "install_selected", lambda plans, **kwargs: ([], 0))
    result = CliRunner().invoke(app, ["install", "nmap", "--config", str(REPO / "config.yaml")])
    assert result.exit_code == 0
    assert not (tmp_path / ".env").exists()


def test_plans_carry_the_tier_from_tools_yaml() -> None:
    plans = load_plans()
    assert plans["nmap"].tier == "core"
    assert plans["nikto"].tier == "opt_in"


def test_managed_bin_dir_has_one_source_of_truth() -> None:
    from reconkit.adapters.base import managed_bin_dir
    from reconkit.installer.registry import bin_dir as installer_bin_dir

    assert managed_bin_dir() == installer_bin_dir()
    assert managed_bin_dir() == Path.home() / ".reconkit" / "bin"


def test_choosing_keys_writes_a_private_env_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    shutil.copy2(REPO / ".env.example", tmp_path / ".env.example")
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    cli._maybe_ask_keys(no_color=True)
    env = tmp_path / ".env"
    assert env.exists()
    assert env.stat().st_mode & 0o777 == 0o600
    assert env.read_text(encoding="utf-8") == (REPO / ".env.example").read_text(encoding="utf-8")


def test_keys_table_lists_names_and_states() -> None:
    buffer = io.StringIO()
    render_keys(key_checks(), console=make_console(stream=buffer, no_color=True))
    out = buffer.getvalue()
    assert "CERTSPOTTER_API" in out
    assert "missing" in out
    assert "tool" in out


def test_keys_table_is_printed_by_the_prompt(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    shutil.copy2(REPO / ".env.example", tmp_path / ".env.example")
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    buffer = io.StringIO()
    monkeypatch.setattr(
        cli,
        "make_console",
        lambda no_color=False: make_console(stream=buffer, no_color=no_color),
    )
    cli._maybe_ask_keys(no_color=True)
    out = buffer.getvalue()
    assert "wrote" in out
    assert "CERTSPOTTER_API" in out
    assert "missing" in out


def test_declining_keys_prints_nothing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: False)
    buffer = io.StringIO()
    monkeypatch.setattr(
        cli,
        "make_console",
        lambda no_color=False: make_console(stream=buffer, no_color=no_color),
    )
    cli._maybe_ask_keys(no_color=True)
    assert buffer.getvalue() == ""
    assert not (tmp_path / ".env").exists()


def test_regression_custom_env_without_path_cannot_resolve_binary(tmp_path: Path) -> None:
    """Regression: PIT-31 - a custom env without PATH cannot resolve a bare name."""
    probe = tmp_path / "reconkit-probe"
    probe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    probe.chmod(0o700)
    found = run_exec(["reconkit-probe"], timeout=5.0, env={"PATH": str(tmp_path)})
    assert found.returncode == 0
    missing = run_exec(["reconkit-probe"], timeout=5.0, env={"HOME": str(tmp_path)})
    assert missing.returncode is None
