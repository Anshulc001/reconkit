"""The only subprocess entry point: argv lists, timeouts, process groups."""

from __future__ import annotations

import contextlib
import os
import re
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import IO

from pydantic import BaseModel

REDACTED = "***"
# One cap for a child's output and for the raw-output file the engine writes
# (docs/03 section 5); the workspace imports this instead of inventing a second
# limit or a config key.
MAX_OUTPUT_BYTES = 1_000_000
_READ_CHUNK = 8192
# How often the wait loop re-checks the inactivity clock; the total timeout is
# still exact, this only bounds the idle check's resolution.
_POLL_INTERVAL = 0.25
_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
# Discovered hosts may contain underscores (real subdomains like dev_api do).
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
_FORBIDDEN_CHARS = frozenset(" \t\r\n;|&`$<>(){}[]*?!~'\"\\")


class ExecResult(BaseModel):
    """Outcome of one external process."""

    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False
    duration_s: float = 0.0
    # True when the kill came from the inactivity clock, not the total timeout;
    # an adapter reports the two differently in its detail line (docs/09 4a2b).
    idle_killed: bool = False
    # D52: seconds since stdout last grew when the child was stopped. A tool that
    # was killed on the stage budget reports this; a clean exit is 0.
    last_output_s: float = 0.0


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


def validate_host(host: str) -> str:
    """Return a normalized discovered host or raise ValueError (docs/05 section 4).

    Looser than validate_target: underscores are allowed and a leading `*.`
    (added by sources such as crt.sh) is stripped. Option injection, whitespace,
    shell metacharacters and label/length limits still apply.
    """
    if not isinstance(host, str):
        raise TypeError("host must be a string")
    name = host.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if not name:
        raise ValueError("host is empty")
    if len(name) > 253:
        raise ValueError("host is longer than 253 characters")
    if any(char.isspace() for char in name) or any(char in _FORBIDDEN_CHARS for char in name):
        raise ValueError("host contains whitespace or shell metacharacters")
    for label in name.split("."):
        if not label or not _HOST_LABEL_RE.match(label):
            raise ValueError(f"invalid host label: {label!r}")
    return name


def run_exec(
    argv: list[str],
    *,
    timeout: float,
    env: Mapping[str, str] | None = None,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
    cwd: Path | str | None = None,
    stdin_text: str | None = None,
    idle_timeout: float | None = None,
    min_runtime: float = 0.0,
    stop_event: threading.Event | None = None,
    on_output: Callable[[], None] | None = None,
) -> ExecResult:
    """Run one program without a shell and return its captured output.

    The child receives only the environment keys passed in `env`; callers must
    add `HOME` for tools that read their config from it. On timeout the whole
    process group is killed; whatever was already read is kept.

    `stdin_text` feeds a tool that takes its input list on stdin (httprobe,
    waybackurls); `None` (the default) keeps stdin closed, so a program that
    reads it sees EOF instead of hanging forever.

    `idle_timeout` adds a second clock: the process is killed once its **stdout**
    has been silent that long, but never before `min_runtime` seconds have
    elapsed. That is how a source that has stopped answering is told apart from
    one that is still working (docs/09 section 4a2b).

    `stop_event` is the engine's own kill switch (D52): when it is set the child
    is stopped the same way an idle kill stops it, so the adapter still parses
    the partial output it produced. `on_output` is called on every stdout chunk,
    so the engine's idle watchdog sees activity rather than mere liveness.
    """
    _validate_argv(argv)
    if timeout <= 0:
        raise ValueError("timeout must be > 0")
    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be > 0")
    if idle_timeout is not None and idle_timeout <= 0:
        raise ValueError("idle_timeout must be > 0")

    child_env = dict(env or {})
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_env,
            cwd=None if cwd is None else str(cwd),
            shell=False,
            # Stay in the parent's session so a sudo ticket cached by
            # tty_tickets stays visible (PIT-32), but lead a new process group
            # so a timeout kill cannot reach reconkit.
            start_new_session=False,
            process_group=0,
        )
    except OSError as exc:
        return ExecResult(
            returncode=None,
            stdout="",
            stderr=_redact(str(exc), child_env.values()),
            duration_s=time.monotonic() - started,
        )

    with _LIVE_LOCK:
        _LIVE_PROCESSES.add(process)
    try:
        return _collect(
            process,
            argv=argv,
            child_env=child_env,
            started=started,
            stdin_text=stdin_text,
            timeout=timeout,
            max_output_bytes=max_output_bytes,
            idle_timeout=idle_timeout,
            min_runtime=min_runtime,
            stop_event=stop_event,
            on_output=on_output,
        )
    finally:
        # Registered only while the child can still run, so an interrupt cannot
        # kill a pid that has been reaped and reused (D44).
        with _LIVE_LOCK:
            _LIVE_PROCESSES.discard(process)


def _collect(
    process: subprocess.Popen[bytes],
    *,
    argv: list[str],
    child_env: dict[str, str],
    started: float,
    stdin_text: str | None,
    timeout: float,
    max_output_bytes: int,
    idle_timeout: float | None,
    min_runtime: float,
    stop_event: threading.Event | None = None,
    on_output: Callable[[], None] | None = None,
) -> ExecResult:
    """Drain the child's pipes and wait for it (the body of `run_exec`)."""
    stdout_pipe = process.stdout
    stderr_pipe = process.stderr
    if stdout_pipe is None or stderr_pipe is None:
        process.kill()
        raise RuntimeError("subprocess pipes were not created")
    if stdin_text is not None and process.stdin is not None:
        # Fed from its own thread so a child that reads lazily can never block
        # the timeout clock; a child that exits early gets a broken pipe, which
        # is not an error (PIT-50).
        def feed(stream: IO[bytes]) -> None:
            try:
                stream.write(stdin_text.encode("utf-8"))
            except (BrokenPipeError, OSError):
                return
            finally:
                with contextlib.suppress(BrokenPipeError, OSError):
                    stream.close()

        threading.Thread(target=feed, args=(process.stdin,), daemon=True).start()
    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    truncated = False
    trunc_lock = threading.Lock()
    # The inactivity clock reads stdout only: stderr chatter is not progress.
    activity_lock = threading.Lock()
    last_activity = [started]

    def drain(stream: IO[bytes], chunks: list[bytes], *, watch: bool = False) -> None:
        nonlocal truncated
        kept = 0
        while True:
            chunk = stream.read(_READ_CHUNK)
            if not chunk:
                break
            if watch:
                with activity_lock:
                    last_activity[0] = time.monotonic()
                if on_output is not None:
                    on_output()
            room = max_output_bytes - kept
            if room > 0:
                chunks.append(chunk[:room])
                kept += min(len(chunk), room)
            if len(chunk) > room:
                with trunc_lock:
                    truncated = True

    out_thread = threading.Thread(
        target=drain, args=(stdout_pipe, out_chunks), kwargs={"watch": True}, daemon=True
    )
    err_thread = threading.Thread(target=drain, args=(stderr_pipe, err_chunks), daemon=True)
    out_thread.start()
    err_thread.start()

    timed_out = False
    idle_killed = False
    deadline = started + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                terminate_tree(process)
                break
            if stop_event is not None and stop_event.is_set():
                # D52: the engine asked this tool to stop (its idle window passed).
                timed_out = True
                idle_killed = True
                terminate_tree(process)
                break
            try:
                process.wait(timeout=min(remaining, _POLL_INTERVAL))
                break
            except subprocess.TimeoutExpired:
                pass
            if idle_timeout is None or time.monotonic() - started < min_runtime:
                continue
            with activity_lock:
                silent_for = time.monotonic() - last_activity[0]
            if silent_for >= idle_timeout:
                timed_out = True
                idle_killed = True
                terminate_tree(process)
                break
    except KeyboardInterrupt:
        # D37: the child leads its own process group (so a timeout kill cannot
        # reach reconkit), which also means the terminal's Ctrl+C reaches only
        # this process - without this the tool keeps running as an orphan.
        terminate_tree(process)
        raise

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
        idle_killed=idle_killed,
        last_output_s=time.monotonic() - last_activity[0],
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


# D44 (2026-11-19): every child alive right now, so an interrupt that lands in
# another thread can still reach it. The engine runs adapters through
# `asyncio.to_thread`, so a terminal Ctrl+C raises KeyboardInterrupt in the main
# thread while `run_exec` sits in a worker; without this set the child survived.
_LIVE_PROCESSES: set[subprocess.Popen[bytes]] = set()
_LIVE_LOCK = threading.Lock()


def live_processes() -> tuple[subprocess.Popen[bytes], ...]:
    """A snapshot of the children currently running (D44)."""
    with _LIVE_LOCK:
        return tuple(_LIVE_PROCESSES)


def terminate_all_live(*, wait_timeout: float = 5.0) -> int:
    """Kill every registered child group; returns how many were running.

    Called from the CLI's `KeyboardInterrupt` handler before it reports 130. The
    worker thread that owns the child is not interrupted by this (it is waiting
    on a pipe that closes), so the child is gone even though its thread is
    abandoned by the interrupted run.
    """
    processes = live_processes()
    for process in processes:
        terminate_tree(process, wait_timeout=wait_timeout)
    return len(processes)


def _kill_tree(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except ProcessLookupError:
        pass


def terminate_tree(process: subprocess.Popen[bytes], *, wait_timeout: float = 5.0) -> None:
    """Kill the child's whole process group and reap it (D37).

    One helper for the timeout path and the Ctrl+C path, so both kill the same
    set of processes: the child and anything it spawned.
    """
    _kill_tree(process)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=wait_timeout)


def _redact(text: str, secrets: Iterable[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    return text
