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

from reconkit.core import runner as runner_module
from reconkit.core.runner import (
    ExecResult,
    _kill_tree,
    run_exec,
    terminate_tree,
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
    idle_timeout: float | None = None,
    min_runtime: float = 0.0,
) -> ExecResult:
    return run_exec(
        [sys.executable, str(FAKEBIN / name), *args],
        timeout=timeout,
        env=env,
        max_output_bytes=max_output_bytes,
        idle_timeout=idle_timeout,
        min_runtime=min_runtime,
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
    """Regression: PIT-05 assert a lower bound only; no tight upper bound."""
    result = run_script("timeout.py", timeout=0.3)
    assert result.timed_out is True
    assert result.returncode is not None
    assert "started" in result.stdout
    assert result.duration_s >= 0.25


def test_idle_timeout_kills_a_child_that_went_silent() -> None:
    """2026-11-18 (2.3): stdout silence is a kill signal, partial output is kept."""
    result = run_script("silent_after_output.py", timeout=30.0, idle_timeout=0.4, min_runtime=0.1)
    assert result.timed_out is True
    assert result.idle_killed is True
    assert "url 0" in result.stdout
    # Killed by the clock, not by the 30 s total timeout.
    assert result.duration_s < 10


def test_the_floor_protects_a_slow_start_before_the_idle_clock() -> None:
    """`min_runtime` wins: a child inside its floor is never killed for silence."""
    result = run_script("silent_after_output.py", timeout=0.6, idle_timeout=0.1, min_runtime=10.0)
    assert result.timed_out is True
    # The total timeout fired while the floor still protected the child.
    assert result.idle_killed is False
    assert "url 0" in result.stdout


def test_a_finished_child_is_never_flagged_idle() -> None:
    result = run_script("success.py", idle_timeout=0.1, min_runtime=0.0)
    assert result.returncode == 0
    assert result.timed_out is False
    assert result.idle_killed is False


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
    """Regression: PIT-06 the timeout kill must reach the whole child group."""
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


def test_terminate_tree_kills_a_real_child_and_reaps_it() -> None:
    """Regression: PIT-06 / D37 - a Ctrl+C or timeout must leave no orphan.

    A real `sleep 60` child, in its own process group exactly like run_exec's
    children, must be dead and reaped well inside two seconds.
    """
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=False,
        process_group=0,
    )
    started = time.monotonic()
    terminate_tree(process)
    assert process.poll() is not None, "the child is still running"
    assert time.monotonic() - started < 2.0


def test_ctrl_c_during_a_run_kills_the_child_and_reraises(monkeypatch: pytest.MonkeyPatch) -> None:
    """D37: KeyboardInterrupt inside run_exec kills the group, then propagates.

    The interrupt has to arrive in the thread that is waiting, so the real
    class's `wait` raises it on its first call; that is the frame a real SIGINT
    unwinds through. Later calls (the reap inside `terminate_tree`) behave.
    """
    real_popen = subprocess.Popen
    real_wait = real_popen.wait
    spawned: list[subprocess.Popen[bytes]] = []
    state = {"raised": False}

    def tracking_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        spawned.append(process)
        return process

    def ctrl_c_wait(self: subprocess.Popen[bytes], *args: object, **kwargs: object) -> int:
        if not state["raised"]:
            state["raised"] = True
            raise KeyboardInterrupt
        return real_wait(self, *args, **kwargs)

    kills: list[int] = []

    real_kill = runner_module._kill_tree

    def recording_kill(process: subprocess.Popen[bytes]) -> None:
        kills.append(process.pid)
        real_kill(process)

    monkeypatch.setattr(real_popen, "wait", ctrl_c_wait)
    monkeypatch.setattr(subprocess, "Popen", tracking_popen)
    monkeypatch.setattr(runner_module, "_kill_tree", recording_kill)

    try:
        with pytest.raises(KeyboardInterrupt):
            run_exec([sys.executable, "-c", "import time; time.sleep(60)"], timeout=30.0)
        assert len(spawned) == 1
        assert kills == [spawned[0].pid]
        # terminate_tree's reap still ran, so the child is dead, not a zombie.
        assert spawned[0].poll() is not None
    finally:
        for process in spawned:
            if process.poll() is None:  # pragma: no cover - only on a failure
                real_kill(process)


def test_a_real_sigint_reaches_run_exec_and_leaves_no_orphan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D37 integration: a genuine SIGINT kills the real child within 2 s.

    SIGINT is delivered to this process from another thread, which is what a
    terminal Ctrl+C does; the handler raises KeyboardInterrupt in the main
    thread, exactly where `run_exec` is waiting.
    """
    real_popen = subprocess.Popen
    spawned: list[subprocess.Popen[bytes]] = []

    def tracking_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        spawned.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", tracking_popen)

    def poke() -> None:
        time.sleep(0.3)
        os.kill(os.getpid(), signal.SIGINT)

    threading.Thread(target=poke, daemon=True).start()
    started = time.monotonic()
    try:
        with pytest.raises(KeyboardInterrupt):
            run_exec([sys.executable, "-c", "import time; time.sleep(60)"], timeout=30.0)
        assert time.monotonic() - started < 5.0
        assert spawned, "no child was spawned"
        assert spawned[0].poll() is not None, "the child survived the interrupt"
    finally:
        for process in spawned:
            if process.poll() is None:  # pragma: no cover - only on a failure
                process.kill()


def test_terminate_all_live_kills_a_child_owned_by_another_thread() -> None:
    """D44: the engine's pattern - `run_exec` in a worker, the interrupt in main.

    `asyncio.to_thread` puts the child in another thread, so `run_exec`'s own
    KeyboardInterrupt handler never sees a terminal Ctrl+C. The registry is what
    the CLI's handler uses instead.
    """
    child: list[subprocess.Popen[bytes]] = []
    real_popen = subprocess.Popen

    def tracking_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        child.append(process)
        return process

    errors: list[BaseException] = []

    def worker() -> None:
        try:
            run_exec([sys.executable, "-c", "import time; time.sleep(60)"], timeout=30.0)
        except BaseException as exc:  # pragma: no cover - the child is killed
            errors.append(exc)

    original = subprocess.Popen
    subprocess.Popen = tracking_popen  # type: ignore[assignment]
    try:
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        deadline = time.monotonic() + 5.0
        while not child and time.monotonic() < deadline:
            time.sleep(0.01)
        assert child, "the worker never spawned a child"
        assert runner_module.live_processes() == (child[0],)

        started = time.monotonic()
        assert runner_module.terminate_all_live() == 1
        thread.join(timeout=5.0)
        assert time.monotonic() - started < 2.0
        assert not thread.is_alive()
        assert child[0].poll() is not None
        assert runner_module.live_processes() == ()
        assert errors == []
    finally:
        subprocess.Popen = original  # type: ignore[assignment]
        for process in child:
            if process.poll() is None:  # pragma: no cover - only on a failure
                process.kill()


def test_a_finished_child_leaves_the_registry() -> None:
    """D44: a reaped pid is never kept, so a reused pid cannot be killed later."""
    result = run_exec([sys.executable, "-c", "print('done')"], timeout=30.0)
    assert result.returncode == 0
    assert runner_module.live_processes() == ()
