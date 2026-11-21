"""Part 8: Typer CLI flags, wiring, exit codes and mock end-to-end tests."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from typer.main import get_command
from typer.testing import CliRunner, Result

from reconkit import ui
from reconkit.cli import app
from reconkit.core.store import SCHEMA_VERSION, Store, configure_redaction
from reconkit.engine import MODE_STAGES, Engine, HostSnapshot, ScanOptions, ScanSummary
from reconkit.errors import ConfigError, ScopeError
from reconkit.models import Confidence, HostState, Tier

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
    "--include",
    "--include-noisy",
    "--phase-timeout",
    "--mock",
    "--active",
    "--full",
    "--no-scope",
    "--only-alive",
    "--only-states",
    "--ports",
    "--status-codes",
    "--header",
    "--user-agent",
    "--redact-headers",
    "--show-headers",
    "--ffuf-wordlist",
    "--resolvers",
    "--skip-url-probe",
    "--reprobe-urls",
    "--no-keys",
    "--resume",
    "--no-color",
    "-v",
    "--verbose",
    "--config",
    "--scope",
    "--db",
}
# D88/D92: on GitHub Actions Typer sets FORCE_TERMINAL (typer/rich_utils.py),
# so Rich styles the help even though CliRunner captures it to a pipe. The
# option highlighter then splits a name across escape runs
# (`\x1b[1m-\x1b[0m\x1b[1m-only\x1b[0m`), so a plain substring check misses it.
# Strip the styling before asserting; COLUMNS keeps the render wide enough that
# no option is truncated (`terminal_width` is ignored by Rich's help console).
HELP_ENV = {"COLUMNS": "120", "LINES": "60"}
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def help_text(result: Result) -> str:
    """Help output with ANSI styling removed, so option names stay contiguous."""
    return ANSI_ESCAPE.sub("", result.stdout)


SCAN_COMMANDS = (
    "subs",
    "dns",
    "live",
    "ports",
    "tech",
    "urls",
    "vulns",
    "passive",
    "active",
    "full",
    "run",
)


def make_config(tmp_path: Path) -> Path:
    raw = yaml.safe_load((REPO / "config.yaml").read_text(encoding="utf-8"))
    raw["workspace_dir"] = str(tmp_path / "workspaces")
    raw["db_path"] = str(tmp_path / "recon.db")
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    # D82: an active run now needs a scope file. Give every test that asks for
    # one a permissive local scope; tests that exercise a missing or denying
    # scope pass --scope explicitly or chdir to a scope-free directory.
    (tmp_path / "scope.yaml").write_text(
        "authorization: test engagement\nin_scope:\n  - example.com\n"
        '  - "*.example.com"\n  - testfire.net\n  - "*.testfire.net"\n'
        "allow_active: true\n",
        encoding="utf-8",
    )
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


def test_cli_version_flag_prints_current_version() -> None:
    """D84: the root CLI can say which version it is."""
    from reconkit import __version__

    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0, result.stderr
    assert result.stdout.strip() == f"reconkit v{__version__}"


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
    result = CliRunner().invoke(app, ["passive", "--help"], env=HELP_ENV)
    assert result.exit_code == 0
    rendered = help_text(result)
    for option in DOCUMENTED_OPTIONS:
        assert option in rendered


def test_scan_has_no_undocumented_options() -> None:
    passive = get_command(app).commands["passive"]
    actual: set[str] = {"--help"}
    for param in passive.params:
        actual.update(getattr(param, "opts", ()))
        actual.update(getattr(param, "secondary_opts", ()))
    assert actual == DOCUMENTED_OPTIONS


@pytest.mark.parametrize("command", SCAN_COMMANDS)
def test_every_scan_command_has_help(command: str) -> None:
    result = CliRunner().invoke(app, [command, "--help"], env=HELP_ENV)
    assert result.exit_code == 0
    assert command in help_text(result)


@pytest.mark.parametrize(
    "args",
    [
        ["scope", "--help"],
        ["scope", "check", "--help"],
        ["scope", "import", "--help"],
        ["diff", "--help"],
        ["status", "--help"],
        ["doctor", "--help"],
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


def test_flagged_run_writes_the_report_files_too(tmp_path: Path) -> None:
    """2026-11-18: a `-d` run used to leave no artifact; it writes both files now.

    Found on a real scan of testfire.net: the tables went to the terminal and
    nothing was saved, because the writer was gated on the interactive plan.
    """
    config = make_config(tmp_path)
    raw = yaml.safe_load(config.read_text(encoding="utf-8"))
    raw["results_dir"] = str(tmp_path / "results")
    config.write_text(yaml.safe_dump(raw), encoding="utf-8")
    result = CliRunner().invoke(app, scan_args(config, "passive"))
    assert result.exit_code == 0
    assert "report:" in result.stderr
    folders = sorted((tmp_path / "results" / "mock" / "example.com").iterdir())
    assert len(folders) == 1
    assert (folders[0] / "report.txt").is_file()
    document = json.loads((folders[0] / "report.json").read_text(encoding="utf-8"))
    assert document["type"] == "report"
    assert document["target"] == "example.com"
    # No question was asked, so the report carries every stored field.
    assert document["fields"] == [field.key for field in ui.REPORT_FIELDS]
    # No filter was given, so nothing was narrowed and nothing is claimed.
    assert document["selection"] is None


def test_a_filtered_run_writes_only_what_it_showed_and_says_so(tmp_path: Path) -> None:
    """2026-11-18: the report follows --only-alive, and records the selection.

    A saved artifact that silently dropped the DEAD hosts would look like a
    complete scan, so the count of the whole run travels with it.
    """
    config = make_config(tmp_path)
    raw = yaml.safe_load(config.read_text(encoding="utf-8"))
    raw["results_dir"] = str(tmp_path / "results")
    config.write_text(yaml.safe_dump(raw), encoding="utf-8")
    result = CliRunner().invoke(
        app, scan_args(config, "run", "--active", "--no-scope", "--only-alive")
    )
    assert result.exit_code == 0, result.stderr
    folder = sorted((tmp_path / "results" / "mock" / "example.com").iterdir())[0]
    document = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    selection = document["selection"]
    assert selection["filter"] == "ALIVE"
    assert selection["matched"] == len(document["hosts"])
    assert selection["total"] >= selection["matched"]
    assert {host["state"] for host in document["hosts"]} == {"ALIVE"}
    text = (folder / "report.txt").read_text(encoding="utf-8")
    assert f"selection: {selection['matched']} of {selection['total']} hosts (ALIVE)" in text
    assert "UNKNOWN" in result.stderr or "ALIVE" in result.stderr


def test_mock_run_with_an_explicit_missing_scope_file_is_refused(tmp_path: Path) -> None:
    """D82: `--scope PATH` pointing at a missing file also fails closed."""
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
    assert "No scope.yaml found" in " ".join(result.stderr.split())
    assert result.stdout == ""


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


def test_bare_command_rejects_active_instead_of_running_passive(tmp_path: Path) -> None:
    """Regression: 11d-findings-f, bare `--active` was silently a no-op.

    `reconkit -d X --active` is the bare passive form (docs/02 section 2) and ran
    subs+dns only, with no warning that the requested active stages never ran.
    """
    config = make_config(tmp_path)
    result = CliRunner().invoke(
        app, ["-d", "example.com", "--active", "--mock", "--config", str(config)]
    )
    assert result.exit_code == 2
    message = " ".join(result.stderr.split())
    assert "passive-only" in message
    # 2026-11-21: the remedy names the `active` command first, `run --active` second.
    assert "reconkit active -d X" in message
    assert "run -d X --active" in message
    assert "Traceback" not in result.stderr
    # A scan that would have run is not started at all.
    assert not (tmp_path / "recon.db").exists()


@pytest.mark.parametrize("command", ["passive", "subs", "dns"])
def test_passive_only_commands_reject_active(tmp_path: Path, command: str) -> None:
    config = make_config(tmp_path)
    result = CliRunner().invoke(app, scan_args(config, command, "--active"))
    assert result.exit_code == 2
    assert "--active" in result.stderr
    assert "passive-only" in result.stderr


def test_a_stage_with_no_adapter_reports_its_skips(tmp_path: Path) -> None:
    """Regression: 11d-findings-f, `tools_skipped: 0` for a stage that built nothing.

    Changed 2026-11-20 (D100): `dnsreaper` gained an adapter, so the example is
    now `sqlmap` - an intrusive tool that needs `--tools` and still has no
    adapter. `--full` lifts the intrusive tier; the explicit name is what
    overrides `exploitation: true`.
    """
    config = make_config(tmp_path)
    result = CliRunner().invoke(
        app,
        scan_args(config, "vulns", "--full", "--no-scope", "--json", "--tools", "sqlmap"),
    )
    assert result.exit_code == 4  # no usable tool for the stage, unchanged
    document = json.loads(result.stdout)
    (stage,) = document["stages"]
    assert stage["stage"] == "vulns"
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
    # D10 (2026-11-17): the passive pipeline now ends with the urls stage.
    assert [stage["stage"] for stage in document["stages"]] == ["subs", "dns", "urls"]


def test_mock_run_creates_no_rows_under_the_real_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D30: the default mock run writes to its own DB, never the real one."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    config = make_config(tmp_path)
    raw = yaml.safe_load(config.read_text(encoding="utf-8"))
    raw["db_path"] = "recon.db"  # the shipped default, so D30's branch applies
    config.write_text(yaml.safe_dump(raw), encoding="utf-8")

    result = CliRunner().invoke(app, scan_args(config))
    assert result.exit_code == 0, result.stderr

    assert not (tmp_path / "recon.db").exists(), "the real DB must stay untouched"
    mock_db = tmp_path / ".reconkit" / "mock.db"
    assert mock_db.exists()
    conn = sqlite3.connect(mock_db)
    try:
        target_id = conn.execute("SELECT id FROM targets WHERE domain = 'example.com'").fetchone()[
            0
        ]
        stored = conn.execute(
            "SELECT COUNT(*) FROM subdomains WHERE target_id = ?", (target_id,)
        ).fetchone()[0]
    finally:
        conn.close()
    assert stored > 0


def test_mock_run_does_not_overwrite_a_real_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D30: a mock run reports under results/mock/ and leaves a real report alone."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    config = make_config(tmp_path)
    sentinel = "real testfire.net output - do not overwrite"
    real_report = tmp_path / "results" / "testfire.net" / "report.txt"
    real_report.parent.mkdir(parents=True)
    real_report.write_text(sentinel, encoding="utf-8")

    # The scan target is example.com (it has fixtures for every passive tool);
    # the sentinel sits where a real testfire.net run would have written.
    result = CliRunner().invoke(app, scan_args(config))
    assert result.exit_code == 0, result.stderr

    assert real_report.read_text(encoding="utf-8") == sentinel
    (run_dir,) = (tmp_path / "results" / "mock" / "example.com").iterdir()
    assert (run_dir / "report.txt").exists()
    assert (run_dir / "report.json").exists()


def test_mock_db_default_is_separate_unless_db_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D30: `--db` wins; without it the mock DB is separate from the real one."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    config = make_config(tmp_path)
    raw = yaml.safe_load(config.read_text(encoding="utf-8"))
    raw["db_path"] = "recon.db"
    config.write_text(yaml.safe_dump(raw), encoding="utf-8")

    assert CliRunner().invoke(app, scan_args(config)).exit_code == 0
    mock_db = tmp_path / ".reconkit" / "mock.db"
    assert mock_db.exists()
    assert not (tmp_path / "recon.db").exists()
    before = mock_db.read_bytes()

    explicit = tmp_path / "chosen.db"
    assert (
        CliRunner().invoke(app, scan_args(config, "passive", "--db", str(explicit))).exit_code == 0
    )
    assert explicit.exists()
    # `--db` wins and the default mock DB is not touched at all.
    assert mock_db.read_bytes() == before


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


# ---------------------------------------------------------------- scan modes (2026-11-17)

DENYING_SCOPE_TEXT = """\
authorization: "engagement 2026-11"
in_scope:
  - other.example
allow_active: true
"""


def mode_args(config: Path, *extra: str) -> list[str]:
    """`run` on a target, with --mock and the new flags appended."""
    return ["run", "-d", "example.com", "--mock", "--config", str(config), *extra]


def captured_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]
) -> list[ScanOptions]:
    calls: list[ScanOptions] = []

    async def fake_run(
        self: Engine, target: str, options: ScanOptions | None = None
    ) -> ScanSummary:
        calls.append(options or ScanOptions())
        return ScanSummary(target=target, target_id=1)

    monkeypatch.setattr(Engine, "run", fake_run)
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.stderr
    return calls


def test_cli_passive_runs_only_passive_stages_and_passive_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (options,) = captured_options(tmp_path, monkeypatch, mode_args(make_config(tmp_path)))
    assert options.stages == MODE_STAGES["passive"]
    assert options.active is False
    assert options.full is False
    assert options.include_noisy is False


def test_cli_active_runs_subs_dns_live_stages_and_passive_active_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (options,) = captured_options(
        tmp_path, monkeypatch, mode_args(make_config(tmp_path), "--active", "--no-scope")
    )
    assert options.stages == MODE_STAGES["active"]
    assert options.active is True
    assert options.full is False


def test_cli_active_does_not_run_intrusive_tier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (options,) = captured_options(
        tmp_path, monkeypatch, mode_args(make_config(tmp_path), "--active", "--no-scope")
    )
    assert Tier.INTRUSIVE not in options_tiers(options)


def options_tiers(options: ScanOptions) -> frozenset[str]:
    from reconkit.engine import allowed_tiers

    return frozenset(tier.value for tier in allowed_tiers(options.mode, include_noisy=False))


def test_cli_full_runs_all_stages_tool_modes_and_tiers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (options,) = captured_options(
        tmp_path, monkeypatch, mode_args(make_config(tmp_path), "--full", "--no-scope")
    )
    assert options.stages == MODE_STAGES["full"]
    assert options.mode == "full"
    assert options_tiers(options) == {"core", "opt_in", "intrusive"}


def test_full_implies_active(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (options,) = captured_options(
        tmp_path, monkeypatch, mode_args(make_config(tmp_path), "--full", "--no-scope")
    )
    assert options.active is True


def test_full_implies_include_noisy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (options,) = captured_options(
        tmp_path, monkeypatch, mode_args(make_config(tmp_path), "--full", "--no-scope")
    )
    assert options.include_noisy is True


@pytest.mark.parametrize(
    ("command", "flag", "mode"),
    [("passive", [], "passive"), ("active", ["--active"], "active"), ("full", ["--full"], "full")],
)
def test_mode_commands_are_the_same_run_as_the_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    flag: list[str],
    mode: str,
) -> None:
    """docs/02 section 2: `active -d X` is `run -d X --active` (2026-11-21).

    The three modes now have three commands; each must select the same stages,
    mode, permission gate and tier set as the flag form, not a near copy.
    """
    config = make_config(tmp_path)
    (by_name,) = captured_options(tmp_path, monkeypatch, scan_args(config, command, "--no-scope"))
    (by_flag,) = captured_options(tmp_path, monkeypatch, mode_args(config, *flag, "--no-scope"))
    assert by_name.stages == by_flag.stages == MODE_STAGES[mode]
    assert by_name.mode == by_flag.mode == mode
    assert by_name.active is by_flag.active
    assert by_name.include_noisy is by_flag.include_noisy


def test_lite_is_no_longer_a_command() -> None:
    """`lite` was a duplicate spelling of `passive`; removed 2026-11-21."""
    result = CliRunner().invoke(app, ["lite", "-d", "example.com"])
    assert result.exit_code == 2
    assert "No such command" in result.stderr


def _stage(document: dict[str, object], name: str) -> dict[str, object]:
    stages = document["stages"]
    assert isinstance(stages, list)
    return next(stage for stage in stages if stage["stage"] == name)


def test_gowitness_runs_in_full_with_include_noisy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D19: the orphaned `shots` stage now executes gowitness in a full run."""
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        mode_args(
            config,
            "--full",
            "--no-scope",
            "--include-noisy",
            "--json",
            "--tools",
            "pyprobe,httpx,tlsx,gowitness",
        ),
    )
    assert result.exit_code == 0, result.stderr
    shots = _stage(json.loads(result.stdout), "shots")
    assert [(item["tool"], item["status"], len(item["records"])) for item in shots["results"]] == [
        ("gowitness", "ok", 2)
    ]


def test_gowitness_runs_when_explicitly_named_via_tools_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tier gating is bypassed by an explicit name; the mode gate still holds.

    `--tools` bypasses the tier rule (docs/02 section 3), so naming gowitness is
    enough even without `--include-noisy`; the shots stage is still only in the
    full mode table, which is what a `--active` run below proves.
    """
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app, mode_args(config, "--full", "--no-scope", "--json", "--tools", "gowitness")
    )
    assert result.exit_code == 0, result.stderr
    shots = _stage(json.loads(result.stdout), "shots")
    assert [item["tool"] for item in shots["results"]] == ["gowitness"]


def test_full_runs_gowitness_without_the_noisy_flag_because_full_implies_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Documented deviation from the batch text: there is no full-mode tier skip.

    `--full` sets `include_noisy = True` in the CLI (cli.py, docs/02 section 2),
    and `--tools` bypasses the tier gate anyway, so `opt_in` is never the reason
    gowitness does not run. The difference is pinned here rather than asserted
    away: a `--full` run without `--include-noisy` still runs gowitness.
    """
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        mode_args(
            config, "--full", "--no-scope", "--json", "--tools", "pyprobe,httpx,tlsx,gowitness"
        ),
    )
    assert result.exit_code == 0, result.stderr
    shots = _stage(json.loads(result.stdout), "shots")
    assert [item["status"] for item in shots["results"]] == ["ok"]


def test_active_mode_never_runs_the_shots_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D19: `shots` is full-only; `--active` does not even request the stage."""
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, mode_args(config, "--active", "--no-scope", "--json"))
    assert result.exit_code == 0, result.stderr
    document = json.loads(result.stdout)
    assert all(stage["stage"] != "shots" for stage in document["stages"])


def test_run_help_describes_stages_tool_modes_and_tiers() -> None:
    """The help strings state stages + tool modes + tiers, generated from the table.

    Asserted on the module constants because CliRunner renders at 80 columns and
    truncates the description column; the rendered help still has to carry both
    flags.
    """
    from reconkit.cli import _ACTIVE_HELP, _FULL_HELP, _NO_SCOPE_HELP

    assert "Run active stages: subs, dns, live, tech, urls, url_probe." in _ACTIVE_HELP
    assert "Uses passive and active tools" in _ACTIVE_HELP
    assert "no intrusive/aggressive tools" in _ACTIVE_HELP
    assert (
        "Run a full scan: all stages (subs, dns, live, ports, tech, urls, url_probe,"
        " shots, vulns)." in _FULL_HELP
    )
    assert "passive, active, and intrusive-tier tools" in _FULL_HELP
    assert "Implies --active and --include-noisy" in _FULL_HELP
    assert "scope_mode = unrestricted_flag" in _NO_SCOPE_HELP

    result = CliRunner().invoke(app, ["run", "--help"], env=HELP_ENV)
    assert result.exit_code == 0
    rendered = help_text(result)
    for flag in ("--active", "--full", "--no-scope", "--only-alive", "--header"):
        assert flag in rendered


def test_run_help_renders_flags_without_requiring_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D88: help is handled by Typer before the scan execution function."""
    monkeypatch.chdir(tmp_path)  # deliberately no scope.yaml here
    result = CliRunner().invoke(app, ["run", "--help"], env=HELP_ENV)
    assert result.exit_code == 0, result.stderr
    rendered = help_text(result)
    for flag in ("--active", "--reprobe-urls", "--full", "--no-scope"):
        assert flag in rendered
    assert "No scope.yaml found" not in result.stdout + result.stderr


def test_skip_url_probe_drops_the_stage_from_an_active_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D23: the flag narrows the run; the stage is simply not requested."""
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "run",
            "-d",
            "example.com",
            "--active",
            "--mock",
            "--json",
            "--config",
            str(config),
            "--skip-url-probe",
        ],
    )
    assert result.exit_code == 0, result.stderr
    stages = [stage["stage"] for stage in json.loads(result.stdout)["stages"]]
    assert "url_probe" not in stages
    assert "urls" in stages


def test_reprobe_urls_reaches_the_engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """D24: `--reprobe-urls` is accepted on a run and recorded on the probe run."""
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            *scan_args(config, "run", "--active", "--json"),
            "--reprobe-urls",
        ],
    )
    assert result.exit_code == 0, result.stderr
    document = json.loads(result.stdout)
    assert "url_probe" in [stage["stage"] for stage in document["stages"]]


def test_reprobe_urls_with_skip_url_probe_warns_instead_of_contradicting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both flags together: the stage stays out and stderr says why (D24)."""
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        [*scan_args(config, "run", "--active", "--json"), "--reprobe-urls", "--skip-url-probe"],
    )
    assert result.exit_code == 0, result.stderr
    assert "url_probe" not in [stage["stage"] for stage in json.loads(result.stdout)["stages"]]
    assert "--reprobe-urls has no effect with --skip-url-probe" in result.stderr


def test_active_run_requests_the_url_probe_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default: an active run includes the probe, and mock mode says it skipped."""
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app, ["run", "-d", "example.com", "--active", "--mock", "--json", "--config", str(config)]
    )
    assert result.exit_code == 0, result.stderr
    document = json.loads(result.stdout)
    assert "url_probe" in [stage["stage"] for stage in document["stages"]]
    assert any("url_probe: skipped in --mock" in note for note in document["warnings"])


def test_full_json_skips_exploitation_tools_and_does_not_tier_skip_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real registry: full never auto-fires sqlmap/dalfox/crlfuzz."""
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, mode_args(config, "--full", "--json"))
    # Changed 2026-11-17 from `in (0, 5)`: a stage that had no runnable tool is
    # a completion gap, not a partial run, so full exits 0 (docs/02 section 6).
    assert result.exit_code == 0, result.stderr
    document = json.loads(result.stdout)
    skipped = {
        item["tool"]: item["reason"] for stage in document["stages"] for item in stage["skipped"]
    }
    for name in ("sqlmap", "dalfox", "crlfuzz"):
        assert skipped[name] == "exploitation tool requires explicit --tools"
    # opt_in is enabled by --full: masscan is no longer tier-skipped.
    assert skipped["masscan"] != "tier not included in full mode"
    assert [stage["stage"] for stage in document["stages"]] == [
        "subs",
        "dns",
        "live",
        "ports",
        "tech",
        "urls",
        # D23: engine-owned, so it adds a stage with no tool results.
        "url_probe",
        "shots",
        "vulns",
    ]


def test_a_full_run_skips_masscan_with_the_root_reason_when_not_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`needs_root` in tools.yaml is a selection skip, so the run still exits 0."""
    from reconkit import engine as engine_module

    monkeypatch.setattr(engine_module, "running_as_root", lambda: False)
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, mode_args(config, "--full", "--json"))
    assert result.exit_code == 0, result.stderr
    document = json.loads(result.stdout)
    ports = next(stage for stage in document["stages"] if stage["stage"] == "ports")
    assert {"tool": "masscan", "reason": "requires root / sudo"} in ports["skipped"]
    assert [item["tool"] for item in ports["results"]] == [
        "smap",
        "pyscan",
        "naabu",
        "nmap",
        "rustscan",
    ]
    assert document["completion"] == {"status": "complete", "gaps": []}


def test_a_full_run_has_no_gaps_when_every_mode_stage_has_a_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Changed 2026-11-17 (wave 5): every mode stage can now run something.

    The gap rule itself (exit 0 plus a `completion.gaps` entry) is still guarded
    by `test_engine.py::test_a_stage_that_executed_no_tools_is_a_gap` and the
    block rendering by `test_ui.py`; what this test pins is the consequence of
    the vulns adapters - a `--full` run is no longer `complete_with_gaps`.
    """
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, mode_args(config, "--full", "--json"))

    assert result.exit_code == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["completion"] == {"status": "complete", "gaps": []}
    # The human block is stderr-only and prints nothing without gaps.
    assert result.stdout.count("\n") == 1
    assert "completed with gaps" not in result.stderr
    vulns = next(stage for stage in document["stages"] if stage["stage"] == "vulns")
    assert [item["tool"] for item in vulns["results"]] == [
        "nuclei",
        "subzy",
        "dnsreaper",
        "nikto",
        "ffuf",
    ]


def test_a_partial_stage_still_exits_five(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Added 2026-11-17: a stage that had tools but one failed keeps exit 5.

    The gap ruling only covers stages with no runnable tool; a real failure is
    still a partial run (docs/02 section 6).
    """
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    engine_run = Engine.run
    calls = {"n": 0}

    async def flaky(self: Engine, target: str, options: ScanOptions | None = None) -> ScanSummary:
        summary = await engine_run(self, target, options)
        calls["n"] += 1
        return summary

    def broken(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("pyscan fixture is unreadable")

    monkeypatch.setattr(Engine, "run", flaky)
    # pyscan is a ports-stage tool, so the stage only exists under --full.
    monkeypatch.setattr("reconkit.adapters.pyscan.PyscanAdapter.run", broken)
    result = CliRunner().invoke(app, mode_args(config, "--full"))

    assert calls["n"] == 1
    assert result.exit_code == 5, result.stderr


def test_only_alive_and_only_states_filter_the_json_hosts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, mode_args(config, "--active", "--only-alive", "--json"))
    assert result.exit_code == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["filter"]["only_states"] == ["ALIVE"]
    assert document["filter"]["matched"] == len(document["hosts"])
    assert document["filter"]["total"] >= document["filter"]["matched"]
    assert all(host["state"] == "ALIVE" for host in document["hosts"])

    result = CliRunner().invoke(
        app, mode_args(config, "--active", "--only-states", "ALIVE,DNS_ONLY", "--json")
    )
    document = json.loads(result.stdout)
    assert document["filter"]["only_states"] == ["ALIVE", "DNS_ONLY"]
    assert all(host["state"] in {"ALIVE", "DNS_ONLY"} for host in document["hosts"])


def test_status_codes_filter_the_json_hosts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app, mode_args(config, "--active", "--status-codes", "200", "--json")
    )
    assert result.exit_code == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["filter"]["status_codes"] == [200]
    assert all(host["status_code"] == 200 for host in document["hosts"])


def test_injections_are_reported_and_headers_are_redacted_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        mode_args(
            config,
            "--active",
            "--ports",
            "80,443",
            "--status-codes",
            "200,301",
            "--header",
            "X-Test: abc",
            "--user-agent",
            "reconkit-test",
            "--json",
        ),
    )
    assert result.exit_code == 0, result.stderr
    injections = json.loads(result.stdout)["injections"]
    assert injections["ports"] == [80, 443]
    assert injections["status_codes"] == [200, 301]
    assert injections["headers"] == {"X-Test": "***"}
    assert injections["user_agent"] == "reconkit-test"

    result = CliRunner().invoke(
        app,
        mode_args(config, "--active", "--header", "X-Test: abc", "--show-headers", "--json"),
    )
    assert json.loads(result.stdout)["injections"]["headers"] == {"X-Test": "abc"}


def test_ports_injection_reaches_the_port_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, mode_args(config, "--full", "--ports", "80,443", "--json"))
    # Changed 2026-11-17 from `in (0, 5)`: zero-adapter stages are gaps, not 5.
    assert result.exit_code == 0, result.stderr
    # pyscan runs in mock and must see exactly the injected ports; its mock
    # fixture output is parsed unchanged, so the proof is the run params.
    document = json.loads(result.stdout)
    assert document["injections"]["ports"] == [80, 443]


def test_active_scan_still_fails_closed_without_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D82: a missing scope file is not an implicit unrestricted run."""
    config = make_config(tmp_path)
    no_scope_dir = tmp_path / "no-scope"
    no_scope_dir.mkdir()
    monkeypatch.chdir(no_scope_dir)
    result = CliRunner().invoke(app, mode_args(config, "--active"))
    assert result.exit_code == 3, result.stderr
    message = " ".join(result.stderr.split())
    assert (
        "Error: No scope.yaml found. Active scanning requires a scope file. "
        "If you intend to scan without scope restrictions, you must explicitly "
        "pass --no-scope."
    ) in message
    assert "Traceback" not in result.stderr


def test_active_scan_succeeds_with_no_scope_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D82: --no-scope remains the explicit opt-out when no scope file exists."""
    config = make_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, mode_args(config, "--active", "--no-scope", "--json"))
    assert result.exit_code == 0, result.stderr
    assert "--no-scope given" in result.stderr
    document = json.loads(result.stdout)
    assert document["scope_mode"] == "unrestricted_flag"
    assert document["scope_denied"] is False


def test_passive_scan_still_works_without_scope_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D82 narrows active scans only; passive discovery needs no scope file."""
    config = make_config(tmp_path)
    no_scope_dir = tmp_path / "no-scope"
    no_scope_dir.mkdir()
    monkeypatch.chdir(no_scope_dir)
    result = CliRunner().invoke(app, scan_args(config, "passive"))
    assert result.exit_code == 0, result.stderr


def test_no_scope_flag_overrides_a_scope_path_and_records_the_flag(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    scope = tmp_path / "denying.yaml"
    scope.write_text(DENYING_SCOPE_TEXT, encoding="utf-8")
    result = CliRunner().invoke(
        app,
        mode_args(config, "--active", "--no-scope", "--scope", str(scope), "--json"),
    )
    assert result.exit_code == 0, result.stderr
    assert f"--scope {scope} ignored because --no-scope was given" in " ".join(
        result.stderr.split()
    )
    document = json.loads(result.stdout)
    assert document["scope_mode"] == "unrestricted_flag"
    assert document["scope_denied"] is False


def test_no_scope_in_passive_mode_warns_and_continues(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    result = CliRunner().invoke(app, mode_args(config, "--no-scope"))
    assert result.exit_code == 0, result.stderr
    assert "no effect on a passive run" in result.stderr


def test_out_of_scope_non_interactive_warns_and_exits_three(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    scope = tmp_path / "denying.yaml"
    scope.write_text(DENYING_SCOPE_TEXT, encoding="utf-8")
    result = CliRunner().invoke(app, mode_args(config, "--active", "--scope", str(scope)))
    assert result.exit_code == 3, result.stderr
    assert "⚠ scope gate would block active stages for: example.com" in result.stderr
    assert "other.example" in result.stderr
    assert "pass --no-scope" in result.stderr
    messages = " ".join(result.stderr.split())
    assert (
        "active scan refused: example.com not in scope.yaml. "
        "Re-run with --no-scope or add example.com to scope.yaml."
    ) in messages


# ---------------------------------- D32 render_error sites route through redact()

AUTHORIZATION_SECRET = "Authorization: Bearer " + "abc123"


def _assert_redacted(result) -> None:
    assert "abc123" not in result.stderr, result.stderr
    assert "abc123" not in result.stdout, result.stdout
    assert "***" in result.stderr


def test_scope_check_error_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    """D32: the `scope check` render_error site masks a header value."""

    def boom(*_args: object, **_kwargs: object) -> None:
        raise ScopeError(f"scope said no: {AUTHORIZATION_SECRET}")

    monkeypatch.setattr("reconkit.cli.check_target", boom)
    result = CliRunner().invoke(app, ["scope", "check", "-d", "example.com"])
    assert result.exit_code == 3
    _assert_redacted(result)


def test_diff_error_is_redacted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """D32: the `diff` render_error site masks a header value."""
    config = make_config(tmp_path)

    def boom(*_args: object, **_kwargs: object) -> None:
        raise ConfigError(f"cannot diff: {AUTHORIZATION_SECRET}")

    monkeypatch.setattr(Engine, "diff", boom)
    result = CliRunner().invoke(app, ["diff", "-d", "example.com", "--config", str(config)])
    assert result.exit_code == 2
    _assert_redacted(result)


def test_status_error_is_redacted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """D32: the `status` render_error site masks a header value."""
    config = make_config(tmp_path)

    def boom(*_args: object, **_kwargs: object) -> None:
        raise ConfigError(f"cannot list runs: {AUTHORIZATION_SECRET}")

    monkeypatch.setattr(Engine, "recent_runs", boom)
    result = CliRunner().invoke(app, ["status", "--config", str(config)])
    assert result.exit_code == 2
    _assert_redacted(result)


def test_doctor_error_is_redacted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """D32: the `doctor` render_error site masks a header value."""
    config = make_config(tmp_path)

    def boom(**_kwargs: object) -> None:
        raise ConfigError(f"cannot inspect tools: {AUTHORIZATION_SECRET}")

    monkeypatch.setattr("reconkit.cli.collect_report", boom)
    result = CliRunner().invoke(app, ["doctor", "--config", str(config)])
    assert result.exit_code == 1
    _assert_redacted(result)


def test_active_mock_run_stores_hosts_alive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D31 (withdrawn) pinned as a regression: mock `--active` reaches ALIVE.

    The batch that named this test assumed a mock active run stored every host
    `UNKNOWN`; it does not (see REVIEW_LOG "Part G"). This test keeps it that
    way, using the statuses the pyprobe/httpx fixtures already carry.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    config = make_config(tmp_path)

    result = CliRunner().invoke(app, scan_args(config, "run", "--active", "--json"))
    assert result.exit_code == 0, result.stderr
    summary = json.loads(result.stdout.strip().splitlines()[-1])
    states = {host["fqdn"]: host for host in summary["hosts"]}

    assert states["www.example.com"]["state"] == "ALIVE"
    assert states["www.example.com"]["status_code"] == 200
    assert states["api.example.com"]["state"] == "ALIVE"
    assert states["api.example.com"]["status_code"] == 401


def test_mock_active_reports_status_200_from_the_live_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D33: a host reached only via httprobe/tlsx gets its status from pyprobe.

    Regression: the generic httprobe/tlsx fixtures name testfire.net hosts but
    carry no HTTP status, so those hosts were ALIVE with `status_code` NULL
    (R6's remainder). The per-target pyprobe fixture supplies the status; no
    parser or verdict rule changed.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    config = make_config(tmp_path)

    args = ["run", "-d", "testfire.net", "--active", "--mock", "--config", str(config), "--json"]
    result = CliRunner().invoke(app, args)
    summary = json.loads(result.stdout.strip().splitlines()[-1])
    hosts = {host["fqdn"]: host for host in summary["hosts"]}

    assert hosts["www.testfire.net"]["state"] == "ALIVE"
    assert hosts["www.testfire.net"]["status_code"] == 200
    assert hosts["testfire.net"]["status_code"] == 200


def test_ctrl_c_in_a_stage_kills_the_child_and_exits_130(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D44: the engine runs tools in threads, so the CLI handler must kill them.

    `Engine.run` is replaced by a coroutine that starts a real long child the way
    an adapter would (`run_exec` in a worker thread) and then raises
    KeyboardInterrupt, which is what a terminal Ctrl+C produces in the main
    thread. Before D44 the handler only printed the message: the child survived.
    """
    import subprocess
    import sys
    import threading
    import time

    from reconkit.core import runner as runner_module

    config = make_config(tmp_path)
    spawned: list[subprocess.Popen[bytes]] = []
    real_popen = subprocess.Popen

    def tracking_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        spawned.append(process)
        return process

    async def fake_run(self: Engine, target: str, opts: ScanOptions) -> ScanSummary:
        def worker() -> None:
            runner_module.run_exec(
                [sys.executable, "-c", "import time; time.sleep(60)"], timeout=30.0
            )

        threading.Thread(target=worker, daemon=True).start()
        deadline = time.monotonic() + 5.0
        while not spawned and time.monotonic() < deadline:
            time.sleep(0.01)
        if not spawned:  # pragma: no cover - only if the worker never started
            raise AssertionError("the fake adapter never spawned a child")
        raise KeyboardInterrupt

    monkeypatch.setattr(subprocess, "Popen", tracking_popen)
    monkeypatch.setattr(Engine, "run", fake_run)

    started = time.monotonic()
    result = CliRunner().invoke(app, scan_args(config))
    elapsed = time.monotonic() - started

    assert result.exit_code == 130
    assert "interrupted; state is saved and the run is resumable" in result.stderr
    assert spawned and all(process.poll() is not None for process in spawned)
    assert elapsed < 10.0
    # The abandoned worker unregisters the child once its pipes close; the pid is
    # already dead above, the registry is bookkeeping.
    deadline = time.monotonic() + 2.0
    while runner_module.live_processes() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert runner_module.live_processes() == ()


# ---------------------- (D63) --exclude namespaces and --include forcing


def _isolated_config(tmp_path: Path) -> Path:
    """A config whose reports land under tmp_path, not the repo's results/."""
    config = make_config(tmp_path)
    raw = yaml.safe_load(config.read_text(encoding="utf-8"))
    raw["results_dir"] = str(tmp_path / "results")
    config.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return config


def _reports(tmp_path: Path, target: str = "example.com") -> list[Path]:
    return sorted((tmp_path / "results" / "mock" / target).glob("*"))


def test_exclude_stage_skips_it_and_hides_its_section(tmp_path: Path) -> None:
    """D63: `--exclude urls` skips the stage and hides its report section."""
    config = _isolated_config(tmp_path)
    db = str(tmp_path / "recon.db")
    first = CliRunner().invoke(app, scan_args(config, "run", "--active", "--no-scope", "--db", db))
    assert first.exit_code == 0, first.stderr
    assert "urls: running" in first.stderr
    # D76: the mock URL fixtures name testfire.net, so they are external to
    # example.com. Seed one in-scope URL so this test still proves that a
    # hidden section is a display choice, not missing data.
    conn = sqlite3.connect(db)
    try:
        target_id = conn.execute("SELECT id FROM targets WHERE domain = 'example.com'").fetchone()[
            0
        ]
        run_id = conn.execute(
            "SELECT id FROM scan_runs WHERE target_id = ? ORDER BY id DESC LIMIT 1",
            (target_id,),
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO urls (target_id, url, first_seen_run, last_seen_run)"
            " VALUES (?, 'https://www.example.com/admin', ?, ?)",
            (target_id, run_id, run_id),
        )
        conn.commit()
    finally:
        conn.close()
    second = CliRunner().invoke(
        app, scan_args(config, "run", "--active", "--no-scope", "--db", db, "--exclude", "urls")
    )
    assert second.exit_code == 0, second.stderr
    assert "urls: running" not in second.stderr
    assert "--exclude urls: stage skipped, report section hidden" in second.stderr
    # The URLs are still stored from the first run, so their absence from the
    # report is the section being hidden, not the data being empty.
    document = json.loads((_reports(tmp_path)[-1] / "report.json").read_text(encoding="utf-8"))
    # D76: the mock URL fixtures name testfire.net while the target is
    # example.com, so every stored URL is third-party and counted apart.
    assert document["urls_total"] > 0
    assert document["external_urls_total"] > 0
    assert "urls_by_host" not in document
    text = (_reports(tmp_path)[-1] / "report.txt").read_text(encoding="utf-8")
    assert "=== URLs by host ===" not in text
    assert "=== Domains ===" in text


def test_exclude_adapter_still_works(tmp_path: Path) -> None:
    """D63: an adapter name keeps its old meaning."""
    config = _isolated_config(tmp_path)
    result = CliRunner().invoke(
        app, scan_args(config, "run", "--active", "--no-scope", "--exclude", "pyprobe")
    )
    assert result.exit_code == 0, result.stderr
    assert "pyprobe" not in result.stdout
    assert "--exclude pyprobe: adapter skipped" in result.stderr


def test_exclude_unknown_value_warns_but_runs(tmp_path: Path) -> None:
    """A typo is a warning, never an aborted scan (D63)."""
    config = _isolated_config(tmp_path)
    result = CliRunner().invoke(
        app, scan_args(config, "run", "--active", "--no-scope", "--exclude", "nonsense")
    )
    assert result.exit_code == 0, result.stderr
    assert "unknown name 'nonsense'" in result.stderr
    assert "--exclude nonsense:" not in result.stderr


def test_include_stage_runs_it_in_a_mode_that_would_skip_it(tmp_path: Path) -> None:
    """D63: `--active --include ports` runs the ports stage active mode omits."""
    config = _isolated_config(tmp_path)
    plain = CliRunner().invoke(app, scan_args(config, "run", "--active", "--no-scope"))
    assert plain.exit_code == 0, plain.stderr
    assert "ports: running" not in plain.stderr
    forced = CliRunner().invoke(
        app, scan_args(config, "run", "--active", "--no-scope", "--include", "ports")
    )
    assert forced.exit_code == 0, forced.stderr
    assert "ports: running" in forced.stderr
    assert "--include ports: stage added" in forced.stderr
    assert "⚠ --include ports forces target contact; this is no longer an active scan." in (
        forced.stderr
    )


def test_include_live_under_passive_prints_banner_and_relabels_mode(tmp_path: Path) -> None:
    """D63: a passive run forced to contact the target says so, in both artifacts."""
    config = _isolated_config(tmp_path)
    result = CliRunner().invoke(
        app, scan_args(config, "passive", "--no-scope", "--include", "live")
    )
    assert result.exit_code == 0, result.stderr
    assert "live: running" in result.stderr
    assert "⚠ --include live forces target contact; this is no longer a passive scan." in (
        result.stderr
    )
    report = _reports(tmp_path)[-1]
    document = json.loads((report / "report.json").read_text(encoding="utf-8"))
    assert document["mode"] == "active (forced by --include)"
    text = (report / "report.txt").read_text(encoding="utf-8")
    assert "mode: active (forced by --include)" in text


def test_include_and_exclude_same_value_is_an_error(tmp_path: Path) -> None:
    """D63: naming one thing on both sides is a contradiction, not a guess."""
    config = _isolated_config(tmp_path)
    result = CliRunner().invoke(
        app,
        scan_args(
            config, "run", "--active", "--no-scope", "--include", "urls", "--exclude", "urls"
        ),
    )
    assert result.exit_code == 2
    assert "contradictory: --include and --exclude both name urls" in result.stderr


# ------------------------------------ (D64) a scope-limited run says so


def _denying_scope(tmp_path: Path) -> Path:
    """A valid scope file whose `in_scope` does not contain example.com."""
    path = tmp_path / "scope.yaml"
    path.write_text(DENYING_SCOPE_TEXT, encoding="utf-8")
    return path


def test_scope_limited_run_marks_the_report(tmp_path: Path) -> None:
    """D64: passive results from a refused active run are labelled, not implied.

    The exit code stays 3: docs/05 rule 2 and docs/02 section 6 make a scope
    refusal code 3, and this run did refuse the active stages it was asked for.
    """
    config = _isolated_config(tmp_path)
    scope = _denying_scope(tmp_path)
    result = CliRunner().invoke(app, scan_args(config, "run", "--active", "--scope", str(scope)))
    assert result.exit_code == 3, result.stderr
    report = _reports(tmp_path)[-1]
    document = json.loads((report / "report.json").read_text(encoding="utf-8"))
    assert document["scope_limited"] is True
    assert document["scope_limited_reason"] == "active stages skipped by scope gate"
    text = (report / "report.txt").read_text(encoding="utf-8")
    assert "⚠ ACTIVE STAGES SKIPPED BY SCOPE — this run is passive-only; the report says so." in (
        text
    )


def test_scope_limited_banner_prints_once(tmp_path: Path) -> None:
    """D64: the end-of-run banner is one line, and only when scope denied."""
    config = _isolated_config(tmp_path)
    scope = _denying_scope(tmp_path)
    result = CliRunner().invoke(app, scan_args(config, "run", "--active", "--scope", str(scope)))
    assert result.stderr.count("ACTIVE STAGES SKIPPED BY SCOPE") == 1
    # The pre-flight block still explains what will be skipped, so the two
    # lines cannot be confused for each other.
    assert "active stages will be SKIPPED" in result.stderr
    # No scope file is not the control: a bare `run` still reads ./scope.yaml.
    permitting = tmp_path / "allowing.yaml"
    permitting.write_text(
        'authorization: "engagement"\nin_scope:\n  - example.com\nallow_active: true\n',
        encoding="utf-8",
    )
    allowed = CliRunner().invoke(
        app, scan_args(config, "run", "--active", "--scope", str(permitting))
    )
    assert allowed.exit_code == 0, allowed.stderr
    assert "ACTIVE STAGES SKIPPED BY SCOPE" not in allowed.stderr


# --------------------------------------- (D65) report from a stored database


def _scan_for_report(tmp_path: Path) -> Path:
    """One small mock scan so the tests have a real DB and a real report."""
    config = _isolated_config(tmp_path)
    result = CliRunner().invoke(app, scan_args(config, "run", "--active", "--no-scope"))
    assert result.exit_code == 0, result.stderr
    return config


def test_report_from_db_writes_both_files(tmp_path: Path) -> None:
    """D65: a stored DB is enough to rebuild the report, no scan involved."""
    config = _scan_for_report(tmp_path)
    out = tmp_path / "rebuilt"
    result = CliRunner().invoke(
        app,
        [
            "report",
            "--db",
            str(tmp_path / "recon.db"),
            "--target",
            "example.com",
            "--out",
            str(out),
            "--config",
            str(config),
            "--no-color",
        ],
    )
    assert result.exit_code == 0, result.stderr
    assert (out / "report.txt").is_file()
    document = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert len(document["hosts"]) > 0
    # D76: the stored mock URLs name testfire.net, so they are external to
    # example.com and live in external_urls.txt instead of the URL block.
    assert document["urls_total"] == 0
    assert document["external_urls_total"] > 0
    assert "testfire.net" in (out / "external_urls.txt").read_text(encoding="utf-8")
    # Informational lines are stderr in this CLI; stdout stays data-only.
    assert "hosts," in result.stderr and "URLs (" in result.stderr


def test_report_from_db_latest_is_default(tmp_path: Path) -> None:
    """No --run and no --out: the latest run's folder, without overwriting it."""
    config = _scan_for_report(tmp_path)
    original = _reports(tmp_path)[-1]
    before = (original / "report.json").read_bytes()
    result = CliRunner().invoke(
        app,
        [
            "report",
            "--db",
            str(tmp_path / "recon.db"),
            "--target",
            "example.com",
            "--config",
            str(config),
            "--no-color",
        ],
    )
    assert result.exit_code == 0, result.stderr
    # The run's start stamp is not the moment the scan wrote its report, so the
    # default lands beside that folder rather than inside it.
    default_root = tmp_path / "results" / "example.com"
    written = sorted(default_root.glob("*/report.json"))
    assert written, result.stderr
    assert written[-1].parent != original
    # The report the scan wrote is evidence of that run and stays untouched.
    assert (original / "report.json").read_bytes() == before


def test_report_from_db_nonexistent_run_errors_cleanly(tmp_path: Path) -> None:
    """A run id that is not this target's is a usage error, and writes nothing."""
    config = _scan_for_report(tmp_path)
    out = tmp_path / "never"
    result = CliRunner().invoke(
        app,
        [
            "report",
            "--db",
            str(tmp_path / "recon.db"),
            "--target",
            "example.com",
            "--run",
            "999999",
            "--out",
            str(out),
            "--config",
            str(config),
            "--no-color",
        ],
    )
    assert result.exit_code == 2
    assert "run 999999 does not belong to example.com" in result.stderr
    assert not out.exists()


def _seed_target(tmp_path: Path, domain: str = "example.com") -> Path:
    """One target with a run, source, status, port and URL, for D81."""
    database = tmp_path / "recon.db"
    with Store(database) as store:
        target_id = store.create_target(domain)
        run_id = store.create_scan_run(target_id, "subs")
        store.record_tool_run(run_id, "crtsh", "ok", item_count=1)
        subdomain_id = store.upsert_subdomain(target_id, f"www.{domain}", run_id=run_id)
        store.add_subdomain_source(subdomain_id, run_id, "crtsh")
        store.append_host_status(subdomain_id, run_id, "ALIVE", status_code=200)
        port_id = store.upsert_port(subdomain_id, "203.0.113.7", 443, run_id=run_id, state="open")
        store.add_port_source(port_id, run_id, "pyscan", "open")
        store.upsert_url(target_id, f"https://www.{domain}/admin", run_id=run_id)
    return database


def _db_config(tmp_path: Path) -> Path:
    config = make_config(tmp_path)
    raw = yaml.safe_load(config.read_text(encoding="utf-8"))
    raw["results_dir"] = str(tmp_path / "results")
    config.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return config


def test_db_delete_removes_target_and_cascades(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    database = _seed_target(tmp_path)
    folder = tmp_path / "results" / "example.com" / "20260101T000000Z"
    folder.mkdir(parents=True)
    (folder / "report.txt").write_text("x", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["--config", str(config), "db", "delete", "--target", "example.com", "--yes"]
    )

    assert result.exit_code == 0, result.stderr
    assert "Deleted 1 target, 1 subdomain, 1 URL, 1 tool run, 1 stage run." in result.output
    assert "Removed " in result.output
    assert not folder.exists()
    conn = sqlite3.connect(database)
    try:
        counts = {
            "targets": "SELECT COUNT(*) FROM targets",
            "scan_runs": "SELECT COUNT(*) FROM scan_runs",
            "tool_runs": "SELECT COUNT(*) FROM tool_runs",
            "subdomains": "SELECT COUNT(*) FROM subdomains",
            "subdomain_sources": "SELECT COUNT(*) FROM subdomain_sources",
            "host_status_history": "SELECT COUNT(*) FROM host_status_history",
            "ports": "SELECT COUNT(*) FROM ports",
            "port_sources": "SELECT COUNT(*) FROM port_sources",
            "urls": "SELECT COUNT(*) FROM urls",
        }
        for table, sql in counts.items():
            assert conn.execute(sql).fetchone()[0] == 0, table
    finally:
        conn.close()


def test_db_delete_requires_yes_when_interactive(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    database = _seed_target(tmp_path)

    declined = CliRunner().invoke(
        app, ["--config", str(config), "db", "delete", "--target", "example.com"], input="n\n"
    )

    assert declined.exit_code == 2
    assert "Are you sure" not in declined.output
    assert "cancelled; nothing was deleted." in declined.output
    with Store(database) as store:
        assert store.get_target("example.com") is not None

    accepted = CliRunner().invoke(
        app, ["--config", str(config), "db", "delete", "--target", "example.com"], input="y\n"
    )
    assert accepted.exit_code == 0, accepted.stderr
    with Store(database) as store:
        assert store.get_target("example.com") is None


def test_db_delete_defaults_to_no(tmp_path: Path) -> None:
    """D85: Enter on the destructive prompt must cancel, not delete."""
    config = _db_config(tmp_path)
    database = _seed_target(tmp_path)

    result = CliRunner().invoke(
        app, ["--config", str(config), "db", "delete", "--target", "example.com"], input="\n"
    )

    assert result.exit_code == 2
    assert "[y/N]" in result.output
    assert "cancelled; nothing was deleted." in result.output
    with Store(database) as store:
        assert store.get_target("example.com") is not None


def test_db_delete_handles_locked_database_cleanly(tmp_path: Path) -> None:
    """D85: a write lock becomes one clean error, not a traceback."""
    config = _db_config(tmp_path)
    database = _seed_target(tmp_path)
    lock = sqlite3.connect(database)
    lock.execute("BEGIN IMMEDIATE")
    try:
        result = CliRunner().invoke(
            app,
            ["--config", str(config), "db", "delete", "--target", "example.com", "--yes"],
        )
    finally:
        lock.rollback()
        lock.close()

    assert result.exit_code == 1
    assert "Error: Database is locked. Is a scan running?" in result.stderr
    assert "Traceback" not in result.stderr
    with Store(database) as store:
        assert store.get_target("example.com") is not None


def test_db_wipe_handles_locked_database_cleanly(tmp_path: Path) -> None:
    """D85: wipe reports the same locked-database error and leaves the schema."""
    config = _db_config(tmp_path)
    database = _seed_target(tmp_path)
    lock = sqlite3.connect(database)
    lock.execute("BEGIN IMMEDIATE")
    try:
        result = CliRunner().invoke(app, ["--config", str(config), "db", "wipe", "--yes"])
    finally:
        lock.rollback()
        lock.close()

    assert result.exit_code == 1
    assert "Error: Database is locked. Is a scan running?" in result.stderr
    assert "Traceback" not in result.stderr
    with Store(database) as store:
        assert store.get_target("example.com") is not None


def test_db_delete_warns_if_results_folder_cannot_be_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D85: the rows are gone, so the folder failure is a warning and exit 0."""
    config = _db_config(tmp_path)
    database = _seed_target(tmp_path)
    folder = tmp_path / "results" / "example.com"
    folder.mkdir(parents=True)

    def boom(_path: str) -> None:
        raise OSError("permission denied")

    monkeypatch.setattr("shutil.rmtree", boom)
    result = CliRunner().invoke(
        app, ["--config", str(config), "db", "delete", "--target", "example.com", "--yes"]
    )

    assert result.exit_code == 0, result.stderr
    assert "warning: database rows for example.com were deleted" in result.output
    assert "could not be removed" in result.output
    with Store(database) as store:
        assert store.get_target("example.com") is None


def test_db_delete_nonexistent_target_errors_cleanly(tmp_path: Path) -> None:
    config = _db_config(tmp_path)

    result = CliRunner().invoke(
        app, ["--config", str(config), "db", "delete", "--target", "missing.com", "--yes"]
    )

    assert result.exit_code == 2
    assert "target missing.com is not in" in result.stderr
    assert "Traceback" not in result.stderr


def test_db_wipe_removes_all_data_and_recreates_schema(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    database = _seed_target(tmp_path, "example.com")
    with Store(database) as store:
        other = store.create_target("other.com")
        store.create_scan_run(other, "dns")
    folder = tmp_path / "results" / "example.com"
    folder.mkdir(parents=True)

    result = CliRunner().invoke(app, ["--config", str(config), "db", "wipe", "--yes"])

    assert result.exit_code == 0, result.stderr
    assert database.is_file()
    assert "Wiped " in result.output
    assert "results/ folders are untouched" in result.output
    assert folder.is_dir()
    with Store(database) as store:
        assert store.schema_version == SCHEMA_VERSION
        assert store.get_target("example.com") is None
        assert store.get_target("other.com") is None
        assert all(count == 0 for count in store.database_counts().values())


def test_db_wipe_requires_yes_when_interactive(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    database = _seed_target(tmp_path)

    declined = CliRunner().invoke(app, ["--config", str(config), "db", "wipe"], input="n\n")

    assert declined.exit_code == 2
    assert "This will delete ALL targets and data" in declined.output
    assert "cancelled; nothing was deleted." in declined.output
    with Store(database) as store:
        assert store.get_target("example.com") is not None

    accepted = CliRunner().invoke(app, ["--config", str(config), "db", "wipe"], input="y\n")
    assert accepted.exit_code == 0, accepted.stderr
    with Store(database) as store:
        assert store.get_target("example.com") is None


def test_report_from_db_is_read_only(tmp_path: Path) -> None:
    """The connection cannot write: a read-only file still produces a report."""
    config = _scan_for_report(tmp_path)
    database = tmp_path / "recon.db"
    digest = hashlib.sha256(database.read_bytes()).hexdigest()
    database.chmod(0o444)
    try:
        out = tmp_path / "readonly"
        result = CliRunner().invoke(
            app,
            [
                "report",
                "--db",
                str(database),
                "--target",
                "example.com",
                "--out",
                str(out),
                "--config",
                str(config),
                "--no-color",
            ],
        )
        assert result.exit_code == 0, result.stderr
        assert (out / "report.json").is_file()
    finally:
        database.chmod(0o644)
    assert hashlib.sha256(database.read_bytes()).hexdigest() == digest
