"""Part 8: Typer CLI flags, wiring, exit codes and mock end-to-end tests."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
import yaml
from typer.main import get_command
from typer.testing import CliRunner

from reconkit.cli import app

REPO = Path(__file__).resolve().parents[1]
CLI = REPO / "src" / "reconkit" / "cli.py"
DOCUMENTED_OPTIONS = {
    "--help",
    "-d",
    "--domain",
    "-l",
    "--list",
    "--json",
    "--silent",
    "-q",
    "--min-sources",
    "--tools",
    "--exclude",
    "--include-noisy",
    "--phase-timeout",
    "--mock",
    "--speed",
    "--delay",
    "--active",
    "--no-keys",
    "--resume",
    "--no-color",
    "-v",
    "--verbose",
    "--config",
    "--scope",
    "--db",
}
SCAN_COMMANDS = (
    "subs",
    "dns",
    "live",
    "ports",
    "tech",
    "urls",
    "vulns",
    "passive",
    "lite",
    "run",
)


def make_config(tmp_path: Path) -> Path:
    raw = yaml.safe_load((REPO / "config.yaml").read_text(encoding="utf-8"))
    raw["workspace_dir"] = str(tmp_path / "workspaces")
    raw["db_path"] = str(tmp_path / "recon.db")
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return path


def scan_args(config: Path, command: str = "passive", *extra: str) -> list[str]:
    return [
        command,
        "-d",
        "example.com",
        "--mock",
        "--speed",
        "fast",
        "--config",
        str(config),
        *extra,
    ]


def test_cli_imports_only_the_allowed_layers() -> None:
    tree = ast.parse(CLI.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)

    assert "reconkit.engine" in imported
    assert "reconkit.ui" in imported
    assert "reconkit.config" in imported
    assert "reconkit.core.scope" in imported
    assert not any(name == "reconkit.core.store" for name in imported)
    assert not any(name.startswith("reconkit.adapters") for name in imported)


def test_cli_never_reads_environment_keys() -> None:
    source = CLI.read_text(encoding="utf-8")
    assert "os.environ" not in source
    assert "getenv" not in source


def test_every_documented_scan_flag_is_registered() -> None:
    result = CliRunner().invoke(app, ["passive", "--help"])
    assert result.exit_code == 0
    for option in DOCUMENTED_OPTIONS:
        assert option in result.stdout


def test_scan_has_no_undocumented_options() -> None:
    passive = get_command(app).commands["passive"]
    actual: set[str] = {"--help"}
    for param in passive.params:
        actual.update(getattr(param, "opts", ()))
        actual.update(getattr(param, "secondary_opts", ()))
    assert actual == DOCUMENTED_OPTIONS


@pytest.mark.parametrize("command", SCAN_COMMANDS)
def test_every_scan_command_has_help(command: str) -> None:
    result = CliRunner().invoke(app, [command, "--help"])
    assert result.exit_code == 0
    assert command in result.stdout


@pytest.mark.parametrize(
    "args",
    [
        ["scope", "--help"],
        ["scope", "check", "--help"],
        ["scope", "import", "--help"],
        ["diff", "--help"],
        ["status", "--help"],
        ["doctor", "--help"],
        ["install", "--help"],
        ["update", "--help"],
        ["db", "--help"],
        ["db", "list", "--help"],
        ["db", "export", "--help"],
        ["export", "--help"],
    ],
)
def test_every_non_scan_command_has_help(args: list[str]) -> None:
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0


def test_mock_json_is_one_valid_document_and_exit_zero(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    result = CliRunner().invoke(app, scan_args(config, "passive", "--json"))
    assert result.exit_code == 0
    assert result.stderr == ""
    assert result.stdout.count("\n") == 1
    document = json.loads(result.stdout)
    assert document["type"] == "summary"
    assert document["target"] == "example.com"
    assert document["exit_code"] == 0
    assert document["hosts"]
    assert {"fqdn", "state", "confidence", "sources"} <= set(document["hosts"][0])


def test_mock_human_output_uses_rich_tables_on_stderr(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    result = CliRunner().invoke(app, scan_args(config, "passive"))
    assert result.exit_code == 0
    assert result.stdout == ""
    assert "Results" in result.stderr
    assert "Tools" in result.stderr
    assert "UNKNOWN" in result.stderr or "ALIVE" in result.stderr


def test_mock_scope_denial_returns_three(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    missing_scope = tmp_path / "missing.yaml"
    result = CliRunner().invoke(
        app,
        scan_args(
            config,
            "run",
            "--active",
            "--scope",
            str(missing_scope),
            "--json",
        ),
    )
    assert result.exit_code == 3
    assert result.stderr == ""
    document = json.loads(result.stdout)
    assert document["scope_denied"] is True
    assert document["exit_code"] == 3


def test_silent_json_through_the_real_cli_has_no_stderr(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    result = CliRunner().invoke(app, scan_args(config, "passive", "--silent", "--json"))
    assert result.exit_code == 0
    assert result.stderr == ""
    assert result.stdout.count("\n") == 1
    assert json.loads(result.stdout)["type"] == "summary"


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        (("--speed", "turbo"), "invalid speed"),
        (("--delay", "10-5"), "invalid delay"),
        (("--delay", "-1-5"), "invalid delay"),
        (("--delay", "abc"), "invalid delay"),
        (("--tools", "not-a-tool"), "unknown tool"),
    ],
)
def test_bad_flags_exit_two_without_a_traceback(
    tmp_path: Path, extra: tuple[str, ...], expected: str
) -> None:
    config = make_config(tmp_path)
    result = CliRunner().invoke(app, scan_args(config, "passive", *extra))
    assert result.exit_code == 2
    assert expected in result.stderr
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr


def test_bare_command_rejects_active_instead_of_running_lite(tmp_path: Path) -> None:
    """Regression: 11d-findings-f, bare `--active` was silently a no-op.

    `reconkit -d X --active` is the `lite` shorthand (docs/02 section 2) and ran
    subs+dns only, with no warning that the requested active stages never ran.
    """
    config = make_config(tmp_path)
    result = CliRunner().invoke(
        app, ["-d", "example.com", "--active", "--mock", "--config", str(config)]
    )
    assert result.exit_code == 2
    message = " ".join(result.stderr.split())
    assert "passive-only" in message
    assert "reconkit run -d X --active" in message
    # The remedy must survive the 80-column console without a mid-command break.
    assert "reconkit run -d X --active" in result.stderr
    assert "Traceback" not in result.stderr
    # A scan that would have run is not started at all.
    assert not (tmp_path / "recon.db").exists()


@pytest.mark.parametrize("command", ["lite", "passive", "subs", "dns"])
def test_passive_only_commands_reject_active(tmp_path: Path, command: str) -> None:
    config = make_config(tmp_path)
    result = CliRunner().invoke(app, scan_args(config, command, "--active"))
    assert result.exit_code == 2
    assert "--active" in result.stderr
    assert "passive-only" in result.stderr


def test_a_stage_with_no_adapter_reports_its_skips(tmp_path: Path) -> None:
    """Regression: 11d-findings-f, `tools_skipped: 0` for a stage that built nothing."""
    config = make_config(tmp_path)
    result = CliRunner().invoke(app, scan_args(config, "tech", "--active", "--json"))
    assert result.exit_code == 4  # no usable tool for the stage, unchanged
    document = json.loads(result.stdout)
    (stage,) = document["stages"]
    assert stage["stage"] == "tech"
    assert stage["results"] == []
    assert stage["skipped"], "a stage with no adapter must list what it skipped"
    assert all("no adapter yet" in skip["reason"] for skip in stage["skipped"])
    assert document["summary"]["tools_skipped"] == len(stage["skipped"])


def test_active_commands_require_active_flag(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    result = CliRunner().invoke(app, scan_args(config, "live"))
    assert result.exit_code == 2
    assert "--active" in result.stderr
    assert "Traceback" not in result.stderr


def test_fast_active_requires_typed_confirmation(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "live",
            "-d",
            "example.com",
            "--active",
            "--speed",
            "fast",
            "--config",
            str(config),
        ],
        input="no\n",
    )
    assert result.exit_code == 2
    assert "cancelled" in result.stderr


def test_resume_flag_reaches_the_engine_resume_path(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    runner = CliRunner()
    first = runner.invoke(app, scan_args(config, "passive"))
    assert first.exit_code == 0

    second = runner.invoke(app, scan_args(config, "passive", "--resume", "--json"))
    assert second.exit_code == 0
    document = json.loads(second.stdout)
    assert document["resumed"] is True
    assert all(stage["resumed"] for stage in document["stages"])


def test_target_list_accepts_comments_and_deduplicates(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    target_file = tmp_path / "targets.txt"
    target_file.write_text(
        "# authorized targets\n\nExample.COM.\nexample.com\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        app,
        [
            "passive",
            "-l",
            str(target_file),
            "--mock",
            "--speed",
            "fast",
            "--config",
            str(config),
            "--json",
        ],
    )
    assert result.exit_code == 0
    assert json.loads(result.stdout)["target"] == "example.com"


def test_scope_check_command_reports_allowed_and_blocked(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "\n".join(
            [
                'authorization: "test"',
                "expires: 2099-01-01",
                "in_scope:",
                "  - example.com",
                "out_of_scope:",
                "  - admin.example.com",
                "allow_active: true",
                "max_speed: fast",
            ]
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    allowed = runner.invoke(app, ["scope", "check", "-d", "example.com", "--scope", str(scope)])
    assert allowed.exit_code == 0
    assert "ALLOWED" in allowed.stderr
    blocked = runner.invoke(
        app, ["scope", "check", "-d", "admin.example.com", "--scope", str(scope)]
    )
    assert blocked.exit_code == 3
    assert "BLOCKED" in blocked.stderr


def test_root_invocation_without_a_command_runs_the_passive_pipeline(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "-d",
            "example.com",
            "--mock",
            "--speed",
            "fast",
            "--config",
            str(config),
            "--json",
        ],
    )
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert [stage["stage"] for stage in document["stages"]] == ["subs", "dns"]


def test_diff_and_status_after_two_mock_runs(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    runner = CliRunner()
    assert runner.invoke(app, scan_args(config, "passive")).exit_code == 0
    assert runner.invoke(app, scan_args(config, "passive")).exit_code == 0
    diff = runner.invoke(
        app,
        ["diff", "-d", "example.com", "--config", str(config), "--json"],
    )
    assert diff.exit_code == 0
    document = json.loads(diff.stdout)
    assert document["type"] == "diff"
    assert document["previous_run_id"] != document["latest_run_id"]
    status = runner.invoke(app, ["status", "--config", str(config), "--json"])
    assert status.exit_code == 0
    payload = json.loads(status.stdout)
    assert payload["type"] == "status"
    assert payload["runs"]
