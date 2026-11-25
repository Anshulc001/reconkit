#!/usr/bin/env python3
"""Run the repository gate as a bounded, evidence-producing loop (AGENTS.md 0b).

Why this exists: a red check is not an instruction to try again. It is an
instruction to find a cause. This harness refuses to re-run the same checks
against an unchanged tree, records why it ran and what it saw, and stops with one
specific question instead of a fourth guess when the budget is spent.

It is not a second gate: the pre-commit hook and CI still enforce the checks on
every commit. This is the loop around them - goal, reasons, cause, next action.

Usage:
    python3 scripts/harness.py --goal "wire the urls stage" \\
        --reason "docs/09 lists vibes as a urls adapter" [--loop 3]

Exit codes:
    0  every check passed
    1  a check failed and the loop may continue (after a change)
    2  blocked: missing goal/reason, unchanged tree, spent budget, bad input
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE = ROOT / "results" / "harness" / "state.json"
DEFAULT_LOOP = 3
MAX_LOOP = 5
MAX_LISTED_FAILURES = 20
MAX_CAUSE_CHARS = 400

PASS = 0
RED = 1
BLOCKED = 2


@dataclass(frozen=True)
class Check:
    """One gate command: the argv, plus any env the mode needs."""

    name: str
    command: list[str]
    env: dict[str, str] = field(default_factory=dict)


def gate_checks() -> list[Check]:
    """The gate from AGENTS.md section 6, in the order a fix should satisfy it."""
    return [
        Check("suite", ["pytest", "-q"]),
        Check("suite-styled", ["pytest", "-q"], env={"FORCE_TERMINAL": "1"}),
        Check("invariants", ["pytest", "-q", "tests/test_invariants.py"]),
        Check("lint", ["ruff", "check", "."]),
        Check("format", ["ruff", "format", "--check", "."]),
        Check("types", ["mypy", "src/reconkit"]),
    ]


def _last_line(text: str) -> str:
    for line in reversed(text.splitlines()):
        if line.strip():
            return line.strip()[:200]
    return ""


def _parse_failures(text: str) -> tuple[list[str], str]:
    """Pull the failing node ids and the first assertion line out of the output."""
    failures: list[str] = []
    cause = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("FAILED ", "ERROR ")) and "::" in stripped:
            node = stripped.split(" - ", 1)[0].split(None, 1)[1]
            if node not in failures:
                failures.append(node)
        elif not cause and stripped.startswith("E ") and len(stripped) > 2:
            cause = stripped[1:].strip()[:MAX_CAUSE_CHARS]
    return failures[:MAX_LISTED_FAILURES], cause


def run_check(check: Check, timeout: int) -> dict[str, object]:
    """Run one command and return its evidence; never raise for a red check."""
    started = time.monotonic()
    env = {**os.environ, **check.env} if check.env else None
    try:
        proc = subprocess.run(
            check.command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return {
            "name": check.name,
            "command": check.command,
            "exit_code": 127,
            "duration_s": round(time.monotonic() - started, 2),
            "summary": f"command not found: {check.command[0]}",
            "failures": [],
            "cause": f"{check.command[0]} is not installed; run ./scripts/setup.sh",
        }
    except subprocess.TimeoutExpired:
        return {
            "name": check.name,
            "command": check.command,
            "exit_code": 124,
            "duration_s": round(time.monotonic() - started, 2),
            "summary": f"timed out after {timeout}s",
            "failures": [],
            "cause": f"{check.name} did not finish in {timeout}s",
        }

    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    failures, cause = _parse_failures(output)
    return {
        "name": check.name,
        "command": check.command,
        "exit_code": proc.returncode,
        "duration_s": round(time.monotonic() - started, 2),
        "summary": _last_line(proc.stdout or "") or _last_line(proc.stderr or ""),
        "failures": failures,
        "cause": cause,
    }


def _git(*args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return "<no-git>"
    return proc.stdout if proc.returncode == 0 else "<no-git>"


def tree_signature() -> str:
    """What the checks see: the working tree and the commit it sits on."""
    return _git("status", "--porcelain") + _git("rev-parse", "HEAD")


def failure_signature(checks: list[dict[str, object]]) -> str:
    red = [f"{c['name']}:{c['exit_code']}" for c in checks if c["exit_code"] != 0]
    return "|".join(sorted(red))


def load_state(path: Path) -> dict[str, object]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def save_state(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_checks(values: list[str]) -> list[Check]:
    """`--check name=command` for tests and for one-off checks (argv, no shell)."""
    checks: list[Check] = []
    for value in values:
        name, sep, command = value.partition("=")
        if not sep or not name.strip() or not command.strip():
            raise SystemExit(f"--check expects name=command, got {value!r}")
        checks.append(Check(name.strip(), shlex.split(command)))
    return checks


def _blocked(message: str) -> int:
    print(message, file=sys.stderr)
    return BLOCKED


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the gate as a bounded, evidence-producing loop."
    )
    parser.add_argument("--goal", help="what this change is meant to achieve (required)")
    parser.add_argument(
        "--reason",
        action="append",
        default=[],
        help="why this is the right change, once per reason",
    )
    parser.add_argument(
        "--loop", type=int, default=DEFAULT_LOOP, help=f"iteration budget (max {MAX_LOOP})"
    )
    parser.add_argument(
        "--iteration", type=int, help="iteration number; defaults to the state file"
    )
    parser.add_argument(
        "--check", action="append", default=[], help="override a check: name=command"
    )
    parser.add_argument("--only", action="append", default=[], help="run only these check names")
    parser.add_argument(
        "--state", type=Path, default=DEFAULT_STATE, help="where the evidence is kept"
    )
    parser.add_argument("--timeout", type=int, default=900, help="per-check timeout in seconds")
    parser.add_argument(
        "--force", action="store_true", help="re-run even though the tree is unchanged"
    )
    parser.add_argument("--json", action="store_true", help="print the evidence as JSON")
    args = parser.parse_args(argv)

    goal = (args.goal or "").strip()
    if not goal:
        return _blocked("harness: --goal is required. State what the change must achieve.")
    if not args.reason:
        return _blocked(
            "harness: --reason is required. Every check run must name its justification."
        )
    reasons = [reason.strip() for reason in args.reason if reason.strip()]
    if not reasons:
        return _blocked(
            "harness: --reason is required. Every check run must name its justification."
        )

    checks = parse_checks(args.check) or gate_checks()
    if args.only:
        wanted = set(args.only)
        checks = [check for check in checks if check.name in wanted]
        if not checks:
            return _blocked(f"harness: --only {sorted(wanted)} matches no check")

    budget = max(1, min(args.loop, MAX_LOOP))
    state_path: Path = args.state
    previous = load_state(state_path)
    previous_red = previous.get("status") == "fail"
    iteration = args.iteration or (int(previous.get("iteration", 0)) + 1 if previous_red else 1)
    if iteration > budget:
        return _blocked(
            f"harness: the --loop budget of {budget} is spent. Ask the owner one specific question "
            f"(the failing check and the two causes you cannot separate); do not guess again."
        )

    signature = tree_signature()
    if not args.force and previous_red and previous.get("tree_signature") == signature:
        last_red = previous.get("failure_signature") or "unknown checks"
        return _blocked(
            "harness: refuse to re-run - the tree is unchanged since the last red run "
            f"({last_red}). No fix was attempted, so a retest cannot teach us anything. "
            "Ask the owner, or pass --force if you suspect a flake."
        )

    results = [run_check(check, args.timeout) for check in checks]
    red = [result for result in results if result["exit_code"] != 0]
    payload: dict[str, object] = {
        "goal": goal,
        "reasons": reasons,
        "iteration": iteration,
        "loop": budget,
        "status": "fail" if red else "pass",
        "tree_signature": signature,
        "failure_signature": failure_signature(results),
        "checks": results,
        "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    save_state(state_path, payload)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"goal: {goal}")
        for result in results:
            mark = "ok  " if result["exit_code"] == 0 else "FAIL"
            print(f"  {mark} {result['name']:<14} {result['duration_s']:>6}s  {result['summary']}")
        if red:
            print("\nfailing checks:")
            for result in red:
                print(f"  {result['name']}: exit {result['exit_code']}")
                for node in result["failures"]:
                    print(f"    {node}")
                if result["cause"]:
                    print(f"    cause: {result['cause']}")

    if not red:
        return PASS
    if iteration >= budget:
        return _blocked(
            f"harness: iteration {iteration} of the --loop budget ({budget}) is still red. Ask the "
            f"owner one specific question with this cause: {red[0]['cause'] or red[0]['summary']}. "
            "Do not guess a fix."
        )
    print(
        f"\nharness: iteration {iteration} of {budget} is red. Fix the cause above, then re-run; "
        "an unchanged tree will be refused.",
        file=sys.stderr,
    )
    return RED


if __name__ == "__main__":
    raise SystemExit(main())
