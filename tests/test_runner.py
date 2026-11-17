"""Tests for core.runner (no network, no installed tools)."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from reconkit.core.runner import (
    ExecResult,
    _kill_tree,
    run_exec,
    validate_host,
    validate_target,
)

FAKEBIN = Path(__file__).parent / "fakebin"


def run_script(
    name: str,
    *args: str,
    timeout: float = 5.0,
    env: dict[str, str] | None = None,
    max_output_bytes: int = 1_000_000,
) -> ExecResult:
    return run_exec(
        [sys.executable, str(FAKEBIN / name), *args],
        timeout=timeout,
        env=env,
        max_output_bytes=max_output_bytes,
    )


def test_success() -> None:
    result = run_script("success.py")
    assert result.returncode == 0
    assert result.stdout.strip() == "ok"
    assert result.stderr == ""
    assert result.timed_out is False
    assert result.truncated is False


def test_non_zero_exit() -> None:
    result = run_script("fail.py")
    assert result.returncode == 3
    assert "boom" in result.stderr
    assert result.timed_out is False


def test_timeout_keeps_partial_output() -> None:
    """Regression: PIT-05 assert a lower bound only; no tight upper bound on Windows."""
    result = run_script("timeout.py", timeout=0.3)
    assert result.timed_out is True
    assert result.returncode is not None
    assert "started" in result.stdout
    assert result.duration_s >= 0.25


def test_output_limit_truncates() -> None:
    result = run_script("huge.py", max_output_bytes=1000)
    assert result.truncated is True
    assert len(result.stdout.encode()) <= 1000


def test_minimal_env_and_redaction() -> None:
    result = run_script("echo_env.py", env={"API_TOKEN": "super-secret-value"})
    assert "API_TOKEN=" in result.stdout
    assert "super-secret-value" not in result.stdout
    assert "***" in result.stdout
    assert "PATH=" not in result.stdout


def test_argv_validation() -> None:
    with pytest.raises(TypeError):
        run_exec("echo", timeout=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        run_exec([], timeout=1)
    with pytest.raises(TypeError):
        run_exec([sys.executable, 1], timeout=1)  # type: ignore[list-item]
    with pytest.raises(ValueError):
        run_exec([""], timeout=1)


def test_rejects_non_positive_limits() -> None:
    with pytest.raises(ValueError):
        run_exec([sys.executable], timeout=0)
    with pytest.raises(ValueError):
        run_exec([sys.executable], timeout=1, max_output_bytes=0)


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX-only")
def _wait_for_pid(pid_file: Path, timeout: float = 10.0) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pid_file.exists():
            text = pid_file.read_text(encoding="utf-8").strip()
            if text:
                return int(text)
        time.sleep(0.02)
    pytest.fail("child did not report its pid")


@pytest.mark.skipif(os.name != "posix", reason="sessions and process groups are POSIX-only")
def test_regression_child_shares_parent_session_but_not_pgid(tmp_path: Path) -> None:
    """Regression: PIT-32 tty-scoped sudo tickets are per session.

    A child must stay in the parent's session, or sudo cannot see a ticket
    cached against the parent's controlling terminal. It must still lead its
    own process group so a timeout kill cannot reach the parent.
    """
    pid_file = tmp_path / "session-child.pid"
    outcome: dict[str, ExecResult] = {}

    def run() -> None:
        outcome["result"] = run_script("session_child.py", str(pid_file), timeout=20)

    worker = threading.Thread(target=run)
    worker.start()
    pid = _wait_for_pid(pid_file)
    try:
        child_sid = os.getsid(pid)
        child_pgid = os.getpgid(pid)
        parent_sid = os.getsid(0)
        parent_pgid = os.getpgid(0)
        report = (
            f"child sid={child_sid} parent sid={parent_sid}; "
            f"child pgid={child_pgid} parent pgid={parent_pgid}"
        )
        assert child_sid == parent_sid, report
        assert child_pgid != parent_pgid, report
        assert child_pgid == pid, report
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        worker.join(timeout=10)
    assert not worker.is_alive()
    assert outcome["result"].returncode == -signal.SIGKILL


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX-only")
def test_timeout_kills_child(tmp_path: Path) -> None:
    """Regression: PIT-06 POSIX-only killpg path; skipped and UNTESTED on Windows."""
    pid_file = tmp_path / "child.pid"
    result = run_script("spawn_child.py", str(pid_file), timeout=0.5)
    assert result.timed_out is True
    pid = int(pid_file.read_text(encoding="utf-8").strip())
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    pytest.fail("child process survived the timeout kill")


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX-only")
def test_regression_kill_tree_kills_only_the_child_group() -> None:
    """Regression: PIT-32 process_group=0 must keep killpg out of our group."""
    parent_pgid = os.getpgid(0)
    sleeper = [sys.executable, "-c", "import time; time.sleep(60)"]
    sibling = subprocess.Popen(
        sleeper,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    child = subprocess.Popen(
        sleeper,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=False,
        process_group=0,
    )
    try:
        deadline = time.monotonic() + 5.0
        while os.getpgid(child.pid) != child.pid and time.monotonic() < deadline:
            time.sleep(0.01)
        assert os.getpgid(child.pid) == child.pid
        assert os.getpgid(child.pid) != parent_pgid

        _kill_tree(child)

        assert child.wait(timeout=5) == -signal.SIGKILL
        assert sibling.poll() is None, "a process in the parent's group was killed"
        assert os.getpgid(0) == parent_pgid
        os.kill(os.getpid(), 0)
    finally:
        sibling.kill()
        sibling.wait(timeout=5)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("API.Example.COM.", "api.example.com"),
        ("a-b.example.co.uk", "a-b.example.co.uk"),
    ],
)
def test_validate_target_accepts(raw: str, expected: str) -> None:
    assert validate_target(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "localhost",
        "-bad.example.com",
        "bad-.example.com",
        "bad..example.com",
        "exa mple.com",
        "example.com;rm -rf /",
        "example.com/evil",
        f"{'a' * 64}.example.com",
    ],
)
def test_validate_target_rejects(raw: str) -> None:
    with pytest.raises(ValueError):
        validate_target(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("dev_api.example.com", "dev_api.example.com"),
        ("*.example.com", "example.com"),
        ("API.Example.COM.", "api.example.com"),
        ("_dmarc.example.com", "_dmarc.example.com"),
    ],
)
def test_validate_host_accepts(raw: str, expected: str) -> None:
    assert validate_host(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "-x.example.com",
        "a b.example.com",
        "bad-.example.com",
        "example.com;id",
        "a.*.example.com",
        "exa|mple.com",
        f"{'a' * 64}.example.com",
    ],
)
def test_validate_host_rejects(raw: str) -> None:
    with pytest.raises(ValueError):
        validate_host(raw)


def test_stdin_text_reaches_the_child_and_none_keeps_stdin_closed() -> None:
    """D11/PIT-50: a tool that reads its input list on stdin gets it without a shell."""
    fed = run_exec(
        [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read().upper())"],
        timeout=10.0,
        stdin_text="testfire.net\nwww.testfire.net\n",
    )
    assert fed.returncode == 0
    assert fed.stdout == "TESTFIRE.NET\nWWW.TESTFIRE.NET\n"

    # The default is still EOF: `cat` exits immediately instead of hanging.
    empty = run_exec(
        [sys.executable, "-c", "import sys; print(len(sys.stdin.read()))"], timeout=10.0
    )
    assert empty.returncode == 0
    assert empty.stdout.strip() == "0"


def test_stdin_text_survives_a_child_that_never_reads_it() -> None:
    """A child that exits without reading gets a broken pipe, not a hang."""
    result = run_exec(
        [sys.executable, "-c", "print('done')"],
        timeout=10.0,
        stdin_text="x" * 200_000,
    )
    assert result.returncode == 0
    assert "done" in result.stdout
