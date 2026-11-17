"""Interactive scan mode, Part 13 (docs/02 section 2b, docs/03 sections 5 and 8b).

Two things must stay true for ever:

1. A scan command with `-d` or `-l` never prompts. The whole automated suite is
   in that branch, and every script that calls reconkit is too.
2. Without a target *and* without a terminal, the old error and exit code stay.

The interactive branch is driven here by monkeypatching `cli._stdin_is_tty`,
which is the single place the terminal is inspected.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

import reconkit.cli as cli
from reconkit import ui
from reconkit.cli import app
from reconkit.engine import Engine, HostSnapshot, ScanOptions, ScanSummary
from reconkit.models import Confidence, HostState, Stage

REPO = Path(__file__).resolve().parent.parent

# The five answers, in order: target, scope file?, [scope path], mode, fields,
# aggressive?. `n` on the scope question means "no scope file".
PASSIVE_ANSWERS = "example.com\nn\npassive\nall\nn\n"


def make_config(tmp_path: Path) -> Path:
    """A config with every path inside tmp_path, plus a results dir there."""
    raw = yaml.safe_load((REPO / "config.yaml").read_text(encoding="utf-8"))
    raw["workspace_dir"] = str(tmp_path / "workspaces")
    raw["db_path"] = str(tmp_path / "recon.db")
    raw["results_dir"] = str(tmp_path / "results")
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return path


def interactive_args(config: Path, command: str = "passive", *extra: str) -> list[str]:
    """A scan command with **no** -d and no -l: the interactive trigger."""
    return [command, "--mock", "--speed", "fast", "--config", str(config), *extra]


def as_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)


# ---------------------------------------------------------------- (a) no prompts


def test_a_flagged_run_never_asks_a_question(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(a) With -d present the interactive branch is never entered.

    The terminal probe is forced to True, so the only thing that can keep the
    questions away is the target flag itself. `typer.prompt` and `typer.confirm`
    are turned into hard failures, which proves they are never called rather
    than merely that their text is absent.
    """
    config = make_config(tmp_path)
    as_tty(monkeypatch)

    def explode(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("a flagged run must not prompt")

    monkeypatch.setattr(cli.typer, "prompt", explode)
    monkeypatch.setattr(cli.typer, "confirm", explode)
    result = CliRunner().invoke(
        app, ["passive", "-d", "example.com", "--mock", "--speed", "fast", "--config", str(config)]
    )
    assert result.exit_code == 0
    assert "Domain, or path to a file of domains" not in result.stderr
    assert "Scan mode:" not in result.stderr


def test_a_listed_run_never_asks_a_question(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(a) The same guarantee for -l, which is the multi-domain path."""
    config = make_config(tmp_path)
    targets = tmp_path / "targets.txt"
    targets.write_text("example.com\n", encoding="utf-8")
    as_tty(monkeypatch)
    monkeypatch.setattr(
        cli.typer,
        "prompt",
        lambda *_a, **_k: pytest.fail("a listed run must not prompt"),
    )
    result = CliRunner().invoke(
        app,
        ["passive", "-l", str(targets), "--mock", "--speed", "fast", "--config", str(config)],
    )
    assert result.exit_code == 0
    assert "Domain, or path to a file of domains" not in result.stderr


def test_no_target_and_no_terminal_keeps_the_old_error(tmp_path: Path) -> None:
    """Without a TTY the command must not block on input that cannot arrive."""
    config = make_config(tmp_path)
    result = CliRunner().invoke(
        app, ["passive", "--mock", "--speed", "fast", "--config", str(config)]
    )
    assert result.exit_code == 2
    assert "provide a target with -d/--domain or -l/--list" in result.stderr


def test_a_prompt_that_hits_end_of_input_is_cancelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    as_tty(monkeypatch)
    result = CliRunner().invoke(
        app, interactive_args(config), input=""
    )  # immediate EOF at question 1
    assert result.exit_code == 2
    assert "interactive scan cancelled" in result.stderr
    assert "Traceback" not in result.stderr


# ------------------------------------------------------------ the five questions


def test_interactive_passive_writes_one_folder_per_domain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole flow, the report files, and their folder layout."""
    config = make_config(tmp_path)
    as_tty(monkeypatch)
    result = CliRunner().invoke(app, interactive_args(config), input=PASSIVE_ANSWERS)
    assert result.exit_code == 0, result.stderr
    assert "plan: example.com; stages subs, dns; active no" in result.stderr

    (domain_dir,) = (tmp_path / "results").iterdir()
    assert domain_dir.name == "example.com"
    (run_dir,) = domain_dir.iterdir()
    assert (run_dir / "report.txt").is_file()
    assert (run_dir / "report.json").is_file()

    document = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    assert document["type"] == "report"
    assert document["target"] == "example.com"
    assert document["fields"] == [field.key for field in ui.REPORT_FIELDS]
    assert {host["hostname"] for host in document["hosts"]} >= {"www.example.com"}
    text = (run_dir / "report.txt").read_text(encoding="utf-8")
    assert "reconkit report" in text
    assert "target: example.com" in text


def test_the_field_menu_is_the_real_stored_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Question 4 offers every real field, numbered, with its gate spelled out."""
    config = make_config(tmp_path)
    as_tty(monkeypatch)
    result = CliRunner().invoke(app, interactive_args(config), input=PASSIVE_ANSWERS)
    assert result.exit_code == 0
    assert "1. Hostname" in result.stderr
    assert "12. Reason (UNKNOWN only)" in result.stderr
    assert "[alive hosts only]" in result.stderr
    assert "[unknown hosts only]" in result.stderr


def test_a_numeric_selection_keeps_menu_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    as_tty(monkeypatch)
    result = CliRunner().invoke(
        app, interactive_args(config), input="example.com\nn\npassive\n3,1,1\nn\n"
    )
    assert result.exit_code == 0, result.stderr
    (run_dir,) = list((tmp_path / "results" / "example.com").iterdir())
    document = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    assert document["fields"] == ["hostname", "confidence"]


@pytest.mark.parametrize(
    ("answers", "message"),
    [
        ("example.com\nn\nsideways\nall\nn\n", "invalid scan mode"),
        ("example.com\nn\npassive\n99\nn\n", "out of range"),
        ("example.com\nn\npassive\nabc\nn\n", "expected a number or 'all'"),
        ("example.com\nn\npassive\n,\nn\n", "no report fields selected"),
    ],
)
def test_a_bad_answer_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answers: str, message: str
) -> None:
    config = make_config(tmp_path)
    as_tty(monkeypatch)
    result = CliRunner().invoke(app, interactive_args(config), input=answers)
    assert result.exit_code == 2
    assert message in result.stderr
    assert "Traceback" not in result.stderr


def test_a_missing_scope_file_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Answering 'yes' to the scope question must name a file that exists."""
    config = make_config(tmp_path)
    as_tty(monkeypatch)
    result = CliRunner().invoke(
        app,
        interactive_args(config),
        input=f"example.com\ny\n{tmp_path / 'nope.yaml'}\npassive\nall\nn\n",
    )
    assert result.exit_code == 2
    # Rich wraps at the console width; compare on collapsed whitespace.
    assert "does not exist" in " ".join(result.stderr.split())


def test_a_scope_file_is_used_exactly_like_the_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The chosen scope file reaches the engine unchanged."""
    config = make_config(tmp_path)
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "program: test\nauthorization: 'test scope'\n"
        "in_scope: ['example.com']\nallow_active: true\nmax_speed: fast\n",
        "utf-8",
    )
    captured: list[Path | None] = []
    original = cli.Engine.open

    def spy(config_obj: Any, **kwargs: Any) -> Engine:
        captured.append(kwargs.get("scope_path"))
        return original(config_obj, **kwargs)

    monkeypatch.setattr(cli.Engine, "open", spy)
    as_tty(monkeypatch)
    result = CliRunner().invoke(
        app,
        interactive_args(config),
        input=f"example.com\ny\n{scope}\npassive\nall\nn\n",
    )
    assert result.exit_code == 0, result.stderr
    assert captured == [scope]


def test_a_multi_domain_file_scans_each_domain_separately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(d) A file of domains dispatches once per domain, not one joined target.

    `reconkit` has no multi-domain tool input of its own: the engine runs once
    per target, so every tool receives exactly one domain and each domain gets
    its own report folder. The per-tool list-flag survey in
    `docs/tool_manuals/README.md` is what a future adapter would use; today the
    engine is the mechanism and this test pins that.
    """
    config = make_config(tmp_path)
    targets = tmp_path / "domains.txt"
    targets.write_text("# two domains\nexample.com\ntestfire.net\n", encoding="utf-8")
    calls: list[tuple[str, ScanOptions]] = []

    async def fake_run(
        self: Engine, target: str, options: ScanOptions | None = None
    ) -> ScanSummary:
        calls.append((target, options or ScanOptions()))
        return ScanSummary(target=target, target_id=1)

    monkeypatch.setattr(Engine, "run", fake_run)
    as_tty(monkeypatch)
    result = CliRunner().invoke(
        app,
        interactive_args(config),
        input=f"{targets}\nn\npassive\nall\nn\n",
    )
    assert result.exit_code == 0, result.stderr
    assert [target for target, _ in calls] == ["example.com", "testfire.net"]
    assert all(isinstance(target, str) and "," not in target for target, _ in calls)
    assert all(options.stages == (Stage.SUBS, Stage.DNS) for _, options in calls)
    folders = sorted(path.name for path in (tmp_path / "results").iterdir())
    assert folders == ["example.com", "testfire.net"]


def test_aggressive_yes_adds_the_ports_stages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Question 5 is separate from question 3 and adds live+ports."""
    config = make_config(tmp_path)
    calls: list[ScanOptions] = []

    async def fake_run(
        self: Engine, target: str, options: ScanOptions | None = None
    ) -> ScanSummary:
        calls.append(options or ScanOptions())
        return ScanSummary(target=target, target_id=1)

    monkeypatch.setattr(Engine, "run", fake_run)
    as_tty(monkeypatch)
    result = CliRunner().invoke(
        app,
        interactive_args(
            config,
        ),  # speed fast would need the typed confirmation
        input="example.com\nn\npassive\nall\ny\n",
    )
    assert result.exit_code == 0, result.stderr
    # 2026-11-17: the message now names both port adapters and the scope-mode
    # branch for naabu (docs/05 rule 6); the deferred-version-detection notice
    # is unchanged.
    assert "aggressive: TCP connect scanning by pyscan" in result.stderr
    assert "naabu runs only on IPs reconkit resolved and verified" in result.stderr
    assert "service/version detection is not wired" in result.stderr
    (options,) = calls
    assert options.stages == (Stage.SUBS, Stage.DNS, Stage.LIVE, Stage.PORTS)
    assert options.active is True


def present_scope_that_denies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A real scope file at the default `./scope.yaml` that does not allow the target.

    2026-11-17: an *absent* scope file no longer refuses anything, so these two
    tests must provide a present file to exercise the gate. `chdir` makes the
    default `./scope.yaml` deterministic instead of depending on whatever the
    checkout's git-ignored file happens to contain.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "scope.yaml").write_text(
        "authorization: engagement\nin_scope:\n  - other.example\nallow_active: true\n",
        encoding="utf-8",
    )


def test_aggressive_no_leaves_the_plan_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Answering `no` adds nothing, so `active` stays subs+dns+live.

    A scope file *is* present at the default location and does not list the
    target, so the unchanged gate refuses the active stage and the run exits 3.
    (An absent file would now be unrestricted - docs/05 rule 2, 2026-11-17.)
    """
    config = make_config(tmp_path)
    present_scope_that_denies(tmp_path, monkeypatch)
    as_tty(monkeypatch)
    result = CliRunner().invoke(
        app, interactive_args(config), input="example.com\nn\nactive\nall\nn\n"
    )
    assert "plan: example.com; stages subs, dns, live; active yes" in result.stderr
    plan_line = result.stderr.split("plan:")[1].splitlines()[0]
    assert Stage.PORTS.value not in plan_line
    assert result.exit_code == 3
    assert "scope" in " ".join(result.stderr.split()).lower()


def test_a_present_scope_file_blocks_an_out_of_scope_interactive_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Renamed from `test_no_scope_file_never_lets_an_active_tool_run`.

    That test asserted that answering `no` could never let an active tool run.
    As of 2026-11-17 an absent scope file means unrestricted active scanning, so
    the only thing that can still block is a *present* file. This proves it does.
    """
    config = make_config(tmp_path)
    present_scope_that_denies(tmp_path, monkeypatch)
    as_tty(monkeypatch)
    result = CliRunner().invoke(
        app,
        interactive_args(config),
        input="example.com\nn\nfull\nall\ny\n",
    )
    assert result.exit_code == 3
    messages = " ".join(result.stderr.split()).lower()
    assert "scope" in messages
    # No report is lost: passive results are still written for the domain.
    assert list((tmp_path / "results" / "example.com").iterdir())


def test_full_mode_does_not_request_the_deferred_vulns_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    calls: list[ScanOptions] = []

    async def fake_run(
        self: Engine, target: str, options: ScanOptions | None = None
    ) -> ScanSummary:
        calls.append(options or ScanOptions())
        return ScanSummary(target=target, target_id=1)

    monkeypatch.setattr(Engine, "run", fake_run)
    as_tty(monkeypatch)
    result = CliRunner().invoke(
        app, ["passive", "--mock", "--config", str(config)], input="example.com\nn\nfull\nall\nn\n"
    )
    assert result.exit_code == 0, result.stderr
    (options,) = calls
    assert Stage.VULNS not in options.stages
    assert options.stages == (
        Stage.SUBS,
        Stage.DNS,
        Stage.LIVE,
        Stage.PORTS,
        Stage.TECH,
        Stage.URLS,
    )


def test_interactive_on_an_active_command_with_passive_chosen_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`live` with the passive answer is a usage error, not a silent no-op."""
    config = make_config(tmp_path)
    as_tty(monkeypatch)
    result = CliRunner().invoke(
        app, interactive_args(config, "live"), input="example.com\nn\npassive\nall\nn\n"
    )
    assert result.exit_code == 2
    assert "requires --active" in result.stderr


# ------------------------------------------------- (b) alive-only report fields


def test_alive_only_fields_are_not_applicable_for_non_alive_hosts() -> None:
    """(b) A gated field never carries a value for a host that is not ALIVE."""
    dead = HostSnapshot(
        fqdn="gone.example.com",
        state=HostState.DEAD,
        confidence=Confidence.LOW,
        sources=(),
        status_code=None,
        ports=(),
        title=None,
        location=None,
        tech=(),
    )
    alive = HostSnapshot(
        fqdn="www.example.com",
        state=HostState.ALIVE,
        confidence=Confidence.HIGH,
        sources=("crtsh", "subfinder", "pyprobe"),
        status_code=200,
        ports=(80, 443),
        title="Example Domain",
        location="https://example.com/",
        tech=("nginx",),
        ips=("203.0.113.5",),
        source_count=3,
    )
    for field in ui.REPORT_FIELDS:
        if field.gate != "alive":
            continue
        assert ui.field_value(dead, field) is None
        assert ui.format_field_value(dead, field) == "not applicable"
        assert ui.field_value(alive, field) is not None
        assert ui.format_field_value(alive, field) != "not applicable"
    # The never-gated fields stay populated for both.
    assert ui.format_field_value(dead, ui.REPORT_FIELDS[0]) == "gone.example.com"
    assert ui.format_field_value(alive, ui.REPORT_FIELDS[0]) == "www.example.com"


def test_the_unknown_reason_is_only_for_unknown_hosts() -> None:
    unknown = HostSnapshot(
        fqdn="mystery.example.com",
        state=HostState.UNKNOWN,
        confidence=Confidence.LOW,
        sources=("pyprobe",),
        status_code=None,
        ports=(),
        detail="tls: untrusted CA",
    )
    alive = HostSnapshot(
        fqdn="www.example.com",
        state=HostState.ALIVE,
        confidence=Confidence.HIGH,
        sources=(),
        status_code=200,
        ports=(),
        detail="stale text that must never be shown",
    )
    reason = next(field for field in ui.REPORT_FIELDS if field.key == "detail")
    assert ui.format_field_value(unknown, reason) == "tls: untrusted CA"
    assert ui.format_field_value(alive, reason) == "not applicable"


def test_a_real_mock_run_reports_alive_fields_only_for_alive_hosts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(b) End to end: the stored DEAD host's gated fields are not applicable.

    A `passive` mock run is enough for this: `gone.example.com` is `DEAD` from
    the DNS fixture, so every alive-gated column must be empty for it while the
    ungated ones still carry values. (A mock `--active` run never produces an
    `ALIVE` host in this build - the flag-based `run --active --mock` behaves the
    same - so the ALIVE side is pinned by the unit test above instead of relying
    on a state the mock pipeline does not reach.)
    """
    config = make_config(tmp_path)
    as_tty(monkeypatch)
    result = CliRunner().invoke(app, interactive_args(config), input=PASSIVE_ANSWERS)
    assert result.exit_code == 0, result.stderr
    (run_dir,) = list((tmp_path / "results" / "example.com").iterdir())
    document = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    hosts = {host["hostname"]: host for host in document["hosts"]}
    assert hosts["gone.example.com"]["state"] == "DEAD"
    for key in ("status_code", "title", "location", "ports", "tech"):
        assert hosts["gone.example.com"][key] is None, key
    assert hosts["gone.example.com"]["hostname"] == "gone.example.com"
    assert hosts["gone.example.com"]["confidence"]
    text = (run_dir / "report.txt").read_text(encoding="utf-8")
    dead_line = next(line for line in text.splitlines() if line.startswith("gone.example.com"))
    assert "not applicable" in dead_line


# -------------------------------------------------- (c) folders never collide


def test_two_runs_of_one_domain_never_share_a_folder(tmp_path: Path) -> None:
    """(c) Same clock second, same domain: two folders, neither overwritten."""
    root = tmp_path / "results"
    stamp = datetime(2026, 11, 16, 12, 0, 0, tzinfo=UTC)
    first = ui.report_directory(root, "example.com", stamp)
    row = HostSnapshot(
        fqdn="www.example.com",
        state=HostState.ALIVE,
        confidence=Confidence.HIGH,
        sources=("crtsh",),
        status_code=200,
        ports=(),
    )
    ui.write_field_report(first, "example.com", [row], ui.REPORT_FIELDS[:1], run_at=stamp)
    second = ui.report_directory(root, "example.com", stamp)
    assert first != second
    assert first.is_dir() and second.is_dir()
    assert (first / "report.json").is_file()
    assert not (second / "report.json").exists()
    ui.write_field_report(second, "example.com", [], ui.REPORT_FIELDS[:1], run_at=stamp)
    # The first run's content is untouched by the second write.
    assert "www.example.com" in (first / "report.json").read_text(encoding="utf-8")
    assert "www.example.com" not in (second / "report.json").read_text(encoding="utf-8")


def test_a_prior_run_folder_survives_a_second_cli_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(c) Through the CLI: two interactive runs, two folders, both readable."""
    config = make_config(tmp_path)
    as_tty(monkeypatch)
    runner = CliRunner()
    assert runner.invoke(app, interactive_args(config), input=PASSIVE_ANSWERS).exit_code == 0
    assert runner.invoke(app, interactive_args(config), input=PASSIVE_ANSWERS).exit_code == 0
    run_dirs = sorted((tmp_path / "results" / "example.com").iterdir())
    assert len(run_dirs) == 2
    for run_dir in run_dirs:
        assert (run_dir / "report.txt").is_file()
        assert (run_dir / "report.json").is_file()


def test_report_directory_refuses_a_traversing_target(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        ui.report_directory(tmp_path, "../escape", datetime.now(UTC))


# --------------------------------------------------- progress on stderr, always


def test_json_progress_goes_to_stderr_and_stdout_stays_one_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The `--json` stdout contract is untouched; progress lands on stderr."""
    config = make_config(tmp_path)
    as_tty(monkeypatch)
    result = CliRunner().invoke(app, interactive_args(config, "--json"), input=PASSIVE_ANSWERS)
    assert result.exit_code == 0, result.stderr
    # Click's test harness echoes the typed answers to stdout; a real terminal
    # echoes them in the terminal itself. The document is the whole last line and
    # no progress or prompt text ever reaches stdout.
    document = json.loads(result.stdout.splitlines()[-1])
    assert document["type"] == "summary"
    assert "subs: running" in result.stderr
    assert "dns: running" in result.stderr
    assert "subs:" not in result.stdout
    assert "plan:" not in result.stdout


def test_silent_still_suppresses_progress(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = make_config(tmp_path)
    as_tty(monkeypatch)
    result = CliRunner().invoke(
        app, interactive_args(config, "--json", "--silent"), input=PASSIVE_ANSWERS
    )
    assert result.exit_code == 0
    # The prompts themselves stay (the user must be able to answer them); only
    # progress and the report line are suppressed.
    assert "subs: running" not in result.stderr
    assert "report:" not in result.stderr
    assert json.loads(result.stdout.splitlines()[-1])["type"] == "summary"


def test_a_flagged_json_run_now_shows_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The documented open risk is closed: --json is no longer silent for minutes."""
    config = make_config(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "passive",
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
    assert "subs: crtsh ok" in result.stderr
    assert json.loads(result.stdout)["type"] == "summary"


# ------------------------------------------------------------ extra adversarial


def test_an_empty_domain_file_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    targets = tmp_path / "empty.txt"
    targets.write_text("# nothing here\n\n", encoding="utf-8")
    as_tty(monkeypatch)
    result = CliRunner().invoke(
        app, interactive_args(config), input=f"{targets}\nn\npassive\nall\nn\n"
    )
    assert result.exit_code == 2
    assert "contains no domains" in " ".join(result.stderr.split())


def test_a_directory_instead_of_a_domain_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    as_tty(monkeypatch)
    result = CliRunner().invoke(
        app, interactive_args(config), input=f"{tmp_path}\nn\npassive\nall\nn\n"
    )
    assert result.exit_code == 2
    assert "Traceback" not in result.stderr


def test_a_flagged_run_writes_no_report_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The interactive file layout must not appear on the flag-based path."""
    config = make_config(tmp_path)
    as_tty(monkeypatch)
    result = CliRunner().invoke(
        app, ["passive", "-d", "example.com", "--mock", "--speed", "fast", "--config", str(config)]
    )
    assert result.exit_code == 0
    assert not (tmp_path / "results").exists()


def test_field_zero_is_out_of_range(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = make_config(tmp_path)
    as_tty(monkeypatch)
    result = CliRunner().invoke(
        app, interactive_args(config), input="example.com\nn\npassive\n0\nn\n"
    )
    assert result.exit_code == 2
    assert "out of range" in result.stderr
