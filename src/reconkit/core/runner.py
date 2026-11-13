"""The only subprocess entry point: argv lists, timeouts, process groups."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import threading
import time
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import IO

from pydantic import BaseModel

REDACTED = "***"
_READ_CHUNK = 8192
_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_FORBIDDEN_CHARS = frozenset(" \t\r\n;|&`$<>(){}[]*?!~'\"\\")


class ExecResult(BaseModel):
    """Outcome of one external process."""

    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False
    duration_s: float = 0.0


def validate_target(target: str) -> str:
    """Return the normalized target or raise ValueError (docs/05 section 4)."""
    if not isinstance(target, str):
        raise TypeError("target must be a string")
    host = target.strip().lower().rstrip(".")
    if not host:
        raise ValueError("target is empty")
    if len(host) > 253:
        raise ValueError("target is longer than 253 characters")
    if any(char.isspace() for char in host) or any(char in _FORBIDDEN_CHARS for char in host):
        raise ValueError("target contains whitespace or shell metacharacters")
    labels = host.split(".")
    if len(labels) < 2:
        raise ValueError("target must be a fully qualified domain name")
    for label in labels:
        if not label or not _LABEL_RE.match(label):
            raise ValueError(f"invalid domain label: {label!r}")
    return host


def run_exec(
    argv: list[str],
    *,
    timeout: float,
    env: Mapping[str, str] | None = None,
    max_output_bytes: int = 1_000_000,
    cwd: Path | str | None = None,
) -> ExecResult:
    """Run one program without a shell and return its captured output.

    The child receives only the environment keys passed in `env`. On timeout
    the whole process group is killed; whatever was already read is kept.
    """
    _validate_argv(argv)
    if timeout <= 0:
        raise ValueError("timeout must be > 0")
    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be > 0")

    child_env = dict(env or {})
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_env,
            cwd=None if cwd is None else str(cwd),
            shell=False,
            start_new_session=True,
        )
    except OSError as exc:
        return ExecResult(
            returncode=None,
            stdout="",
            stderr=_redact(str(exc), child_env.values()),
            duration_s=time.monotonic() - started,
        )

    stdout_pipe = process.stdout
    stderr_pipe = process.stderr
    if stdout_pipe is None or stderr_pipe is None:
        process.kill()
        raise RuntimeError("subprocess pipes were not created")
    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    truncated = False
    trunc_lock = threading.Lock()

    def drain(stream: IO[bytes], chunks: list[bytes]) -> None:
        nonlocal truncated
        kept = 0
        while True:
            chunk = stream.read(_READ_CHUNK)
            if not chunk:
                break
            room = max_output_bytes - kept
            if room > 0:
                chunks.append(chunk[:room])
                kept += min(len(chunk), room)
            if len(chunk) > room:
                with trunc_lock:
                    truncated = True

    out_thread = threading.Thread(target=drain, args=(stdout_pipe, out_chunks), daemon=True)
    err_thread = threading.Thread(target=drain, args=(stderr_pipe, err_chunks), daemon=True)
    out_thread.start()
    err_thread.start()

    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(process)
        process.wait()

    out_thread.join()
    err_thread.join()

    secrets = tuple(child_env.values())
    return ExecResult(
        returncode=process.returncode,
        stdout=_redact(b"".join(out_chunks).decode("utf-8", "replace"), secrets),
        stderr=_redact(b"".join(err_chunks).decode("utf-8", "replace"), secrets),
        timed_out=timed_out,
        truncated=truncated,
        duration_s=time.monotonic() - started,
    )


def _validate_argv(argv: list[str]) -> None:
    if not isinstance(argv, list):
        raise TypeError("argv must be a list of strings")
    if not argv:
        raise ValueError("argv must not be empty")
    if not all(isinstance(arg, str) for arg in argv):
        raise TypeError("argv must contain only strings")
    if not argv[0]:
        raise ValueError("argv[0] must not be empty")


def _kill_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        return
    process.kill()


def _redact(text: str, secrets: Iterable[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    return text
