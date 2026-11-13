"""Tests for core.runner (no network, no installed tools)."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from reconkit.core.runner import ExecResult, run_exec, validate_host, validate_target

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
    result = run_script("timeout.py", timeout=0.3)
    assert result.timed_out is True
    assert result.returncode is not None
    assert "started" in result.stdout
    assert result.duration_s >= 0.3


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
def test_timeout_kills_child(tmp_path: Path) -> None:
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
