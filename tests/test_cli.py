"""Part 8: Typer CLI flags, wiring, exit codes and mock end-to-end tests."""

from __future__ import annotations

import ast
import json
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from typer.main import get_command
from typer.testing import CliRunner

from reconkit.cli import app
from reconkit.core.store import configure_redaction
from reconkit.engine import Engine, HostSnapshot
from reconkit.models import Confidence, HostState

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
    assert not any(name.startswith("reconkit.adapters") for name in imported)

    # 12f: the CLI imports the shared redaction helpers from core/store.py and
    # nothing else from the persistence layer (docs/03 section 9). This is more
    # precise than the old "no store import at all" rule, not weaker: `Store`
    # and sqlite3 stay banned from the CLI.
    store_names = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "reconkit.core.store"
        for alias in node.names
    }
    assert store_names == {"configure_redaction", "redact"}
    source = CLI.read_text(encoding="utf-8")
    assert "Store(" not in source
    assert "sqlite3" not in source


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
    # Part 13: `--json` now reports progress on stderr (docs/02 section 5). The
    # stdout contract is unchanged and still asserted below: exactly one JSON
    # document and nothing else.
    assert "subs: running" in result.stderr
    assert result.stdout.count("\n") == 1
    document = json.loads(result.stdout)
    assert document["type"] == "summary"
    assert document["target"] == "example.com"
    assert document["exit_code"] == 0
    assert document["hosts"]
    assert {"fqdn", "state", "confidence", "sources"} <= set(document["hosts"][0])


def test_json_run_exposes_the_stored_host_detail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """12d: the CLI maps the stored detail into the documented `--json` field."""
    config = make_config(tmp_path)
    snapshot = HostSnapshot(
        fqdn="mystery.example.com",
        state=HostState.UNKNOWN,
        confidence=Confidence.LOW,
        sources=("pyprobe",),
        status_code=None,
        ports=(),
        detail="tls: certificate has expired",
    )
    monkeypatch.setattr(Engine, "host_rows", lambda _self, _target_id: [snapshot])
    result = CliRunner().invoke(app, scan_args(config, "passive", "--json"))
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["hosts"][0]["detail"] == "tls: certificate has expired"


def test_mock_human_output_uses_rich_tables_on_stderr(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    result = CliRunner().invoke(app, scan_args(config, "passive"))
    assert result.exit_code == 0
    assert result.stdout == ""
    assert "Results" in result.stderr
    assert "Tools" in result.stderr
    assert "UNKNOWN" in result.stderr or "ALIVE" in result.stderr


def test_mock_run_without_a_scope_file_is_unrestricted(tmp_path: Path) -> None:
    """Regression: 2026-11-17 - a missing scope file is not a refusal.

    Changed from `test_mock_scope_denial_returns_three`, which asserted exit 3 for
    an absent scope file. That behaviour was replaced by the owner request: no
    scope file means unrestricted active scanning of the operator's target. The
    exit-3 path is still covered, against a real scope file, by
    `test_mock_scope_file_denial_returns_three` below.
    """
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
    assert result.exit_code != 3
    assert "subs: running" in result.stderr
    document = json.loads(result.stdout)
    assert document["scope_denied"] is False
    assert document["exit_code"] != 3


def test_mock_scope_file_denial_returns_three(tmp_path: Path) -> None:
    """A scope file that *is* present keeps the unchanged gate (docs/05 rule 2)."""
    config = make_config(tmp_path)
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "authorization: engagement\nin_scope:\n  - example.com\nallow_active: false\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        app,
        scan_args(config, "run", "--active", "--scope", str(scope), "--json"),
    )
    assert result.exit_code == 3
    assert "subs: running" in result.stderr
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


def test_speed_and_delay_flags_are_gone(tmp_path: Path) -> None:
    """2026-11-17: the flags were removed, so Typer rejects them as unknown."""
    config = make_config(tmp_path)
    for args in (["--speed", "fast"], ["--delay", "5-20"]):
        result = CliRunner().invoke(app, scan_args(config, "passive", *args))
        assert result.exit_code == 2
        assert "No such option" in result.stderr


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
    # docs/02: GONE needs two consecutive misses, so two runs confirm nothing.
    assert document["baseline_run_id"] is None
    assert document["gone"] == []
    assert document["pending_gone"] == []
    human = runner.invoke(app, ["diff", "-d", "example.com", "--config", str(config)])
    assert human.exit_code == 0
    assert "GONE needs three discovery runs" in human.stderr
    status = runner.invoke(app, ["status", "--config", str(config), "--json"])
    assert status.exit_code == 0
    payload = json.loads(status.stdout)
    assert payload["type"] == "status"
    assert payload["runs"]


# ------------------------------------------------------- 12f console redaction

LEAK_VALUE = "sk-live-abc123"


def _raise_unexpected(message: str):
    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(message)

    return boom


def _raise_chained(secret: str):
    """The secret is only in the nested exception (`__cause__`)."""

    def boom(*_args: object, **_kwargs: object) -> None:
        try:
            raise ValueError(f"inner {secret}")
        except ValueError as exc:
            raise RuntimeError("outer wrapper") from exc

    return boom


@pytest.fixture()
def dotenv_secret(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Feed the CLI a fake `.env`, never the developer's real one."""
    monkeypatch.setattr("reconkit.cli.dotenv_values", lambda: {"PROVIDER_API_KEY": LEAK_VALUE})
    yield
    configure_redaction(())


def test_report_error_redacts_a_secret_in_the_message(
    dotenv_secret: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: PIT-42 - the last-resort handler redacts the message (12f, C-1)."""
    config = make_config(tmp_path)
    monkeypatch.setattr(Engine, "open", _raise_unexpected(f"boom {LEAK_VALUE}"))
    result = CliRunner().invoke(app, scan_args(config))
    assert result.exit_code == 1
    assert LEAK_VALUE not in result.stderr
    assert LEAK_VALUE not in result.stdout
    assert "unexpected error: RuntimeError: boom ***" in result.stderr


def test_verbose_traceback_redacts_the_same_secret(
    dotenv_secret: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The `-v` branch is a second code path: a traceback, not one line."""
    config = make_config(tmp_path)
    monkeypatch.setattr(Engine, "open", _raise_unexpected(f"boom {LEAK_VALUE}"))
    result = CliRunner().invoke(app, [*scan_args(config), "-v"])
    assert result.exit_code == 1
    assert LEAK_VALUE not in result.stderr
    assert LEAK_VALUE not in result.stdout
    assert "Traceback (most recent call last)" in result.stderr
    assert "boom ***" in result.stderr


def test_report_error_leaves_a_message_without_a_secret_unchanged(
    dotenv_secret: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    monkeypatch.setattr(Engine, "open", _raise_unexpected("boom without a key"))
    result = CliRunner().invoke(app, scan_args(config))
    assert result.exit_code == 1
    assert "unexpected error: RuntimeError: boom without a key" in result.stderr
    assert "***" not in result.stderr


def test_verbose_traceback_redacts_a_secret_in_a_chained_exception(
    dotenv_secret: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tracebacks print `__cause__` chains; the nested message is masked too."""
    config = make_config(tmp_path)
    monkeypatch.setattr(Engine, "open", _raise_chained(LEAK_VALUE))
    result = CliRunner().invoke(app, [*scan_args(config), "-v"])
    assert result.exit_code == 1
    assert LEAK_VALUE not in result.stderr
    assert "inner ***" in result.stderr
    assert "ValueError: inner" in result.stderr


def test_json_error_path_keeps_stdout_clean_and_redacts_stderr(
    dotenv_secret: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    monkeypatch.setattr(Engine, "open", _raise_unexpected(f"boom {LEAK_VALUE}"))
    result = CliRunner().invoke(app, [*scan_args(config, "passive", "--json")])
    assert result.exit_code == 1
    assert result.stdout == ""
    assert LEAK_VALUE not in result.stderr
    assert "***" in result.stderr


def test_console_redaction_uses_the_shared_patterns_without_a_dotenv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `key=value` shape is masked by the pattern list alone (no configured key)."""
    config = make_config(tmp_path)
    monkeypatch.setattr("reconkit.cli.dotenv_values", lambda: {})
    monkeypatch.setattr(Engine, "open", _raise_unexpected("api_key=abcd1234efgh"))
    result = CliRunner().invoke(app, scan_args(config))
    assert result.exit_code == 1
    assert "api_key=***" in result.stderr
    assert "abcd1234efgh" not in result.stderr


def test_an_unreadable_dotenv_does_not_break_the_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode() -> dict[str, str]:
        raise OSError(".env is a directory")

    config = make_config(tmp_path)
    monkeypatch.setattr("reconkit.cli.dotenv_values", explode)
    result = CliRunner().invoke(app, scan_args(config))
    assert result.exit_code == 0, result.stderr
