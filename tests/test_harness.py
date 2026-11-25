"""Tests for `scripts/harness.py`, the self-checking gate loop (AGENTS.md 0b).

The harness exists so a red check produces a cause and a question, never a blind
retry. These tests drive it with fake checks, so they never run the real suite.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HARNESS = REPO / "scripts" / "harness.py"


def _run(
    state: Path, *args: str, goal: str = "test the harness", reasons: bool = True
) -> subprocess.CompletedProcess[str]:
    argv = [sys.executable, str(HARNESS)]
    if goal:
        argv += ["--goal", goal]
    if reasons:
        argv += ["--reason", "the loop must prove itself before it is trusted"]
    argv += ["--state", str(state), "--json", *args]
    return subprocess.run(argv, cwd=REPO, capture_output=True, text=True, check=False)


def _payload(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    assert result.stdout.strip(), result.stderr
    return json.loads(result.stdout)


def test_a_green_run_passes_and_records_what_it_ran(tmp_path: Path) -> None:
    result = _run(tmp_path / "state.json", "--check", "ok=/bin/true")
    assert result.returncode == 0, result.stdout + result.stderr
    payload = _payload(result)
    assert payload["status"] == "pass"
    checks = payload["checks"]
    assert [check["name"] for check in checks] == ["ok"]
    assert checks[0]["exit_code"] == 0
    assert payload["goal"] == "test the harness"
    assert payload["reasons"]


def test_a_red_run_exits_one_and_names_the_failing_check(tmp_path: Path) -> None:
    result = _run(tmp_path / "state.json", "--check", "ok=/bin/true", "--check", "bad=/bin/false")
    assert result.returncode == 1, result.stdout + result.stderr
    payload = _payload(result)
    assert payload["status"] == "fail"
    failed = [check for check in payload["checks"] if check["exit_code"] != 0]
    assert [check["name"] for check in failed] == ["bad"]


def test_it_captures_the_first_assertion_line_as_the_cause(tmp_path: Path) -> None:
    command = (
        "/bin/sh -c 'printf "
        '"FAILED tests/x.py::test_y - AssertionError\\nE   AssertionError: boom\\n"'
        "; exit 1'"
    )
    result = _run(tmp_path / "state.json", "--check", f"bad={command}")
    assert result.returncode == 1, result.stdout + result.stderr
    payload = _payload(result)
    check = payload["checks"][0]
    assert "AssertionError: boom" in check["cause"]
    assert check["failures"] == ["tests/x.py::test_y"]


def test_it_refuses_a_goal_without_a_reason(tmp_path: Path) -> None:
    result = _run(tmp_path / "state.json", "--check", "ok=/bin/true", reasons=False)
    assert result.returncode == 2
    assert "--reason" in result.stderr


def test_it_refuses_a_run_without_a_goal(tmp_path: Path) -> None:
    result = _run(tmp_path / "state.json", "--check", "ok=/bin/true", goal="")
    assert result.returncode == 2
    assert "--goal" in result.stderr


def test_it_refuses_to_retest_an_unchanged_tree_with_the_same_failures(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    first = _run(state, "--check", "bad=/bin/false")
    assert first.returncode == 1, first.stdout + first.stderr
    second = _run(state, "--check", "bad=/bin/false")
    assert second.returncode == 2, second.stdout + second.stderr
    assert "unchanged" in second.stderr.lower()
    assert "ask the owner" in second.stderr.lower()


def test_it_stops_with_a_question_when_the_iteration_budget_is_spent(tmp_path: Path) -> None:
    result = _run(tmp_path / "state.json", "--check", "bad=/bin/false", "--loop", "1")
    assert result.returncode == 2, result.stdout + result.stderr
    assert "ask the owner" in result.stderr.lower()
    assert "--loop" in result.stderr


def test_the_state_file_records_the_iteration_and_the_evidence(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    _run(state, "--check", "bad=/bin/false")
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert saved["iteration"] == 1
    assert saved["checks"][0]["command"] == ["/bin/false"]
