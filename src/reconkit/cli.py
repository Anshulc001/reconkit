"""Typer command wiring for reconkit (docs/02_CLI_UX.md)."""

from __future__ import annotations

import asyncio
import re
import sys
import traceback
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from dotenv import dotenv_values

from reconkit.config import AppConfig, load_config
from reconkit.core.runner import validate_target
from reconkit.core.scope import (
    check_target,
    preflight_warning,
    scope_present,
)
from reconkit.core.scope import (
    scope_path as resolve_scope_path,
)
from reconkit.core.store import configure_redaction, redact
from reconkit.doctor import collect_report
from reconkit.engine import MODE_STAGES, STAGE_ORDER, Engine, ExitCode, ScanOptions
from reconkit.errors import ConfigError, ScopeError
from reconkit.models import HostState, Stage
from reconkit.ui import (
    REPORT_FIELDS,
    HostRow,
    ReportField,
    make_console,
    render,
    render_diff,
    render_doctor,
    render_error,
    render_message,
    render_progress,
    render_status,
    report_directory,
    report_fields,
    write_field_report,
)

app = typer.Typer(
    name="reconkit",
    help="Reconnaissance orchestrator for authorized security testing.",
    add_completion=False,
    no_args_is_help=True,
)
scope_app = typer.Typer(help="Inspect or import scope.yaml.", no_args_is_help=True)
db_app = typer.Typer(help="Query stored assets.", no_args_is_help=True)
app.add_typer(scope_app, name="scope")
app.add_typer(db_app, name="db")

_SCAN_COMMANDS = (
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
_ACTIVE_ONLY = frozenset({"live", "ports", "tech", "urls", "vulns"})
# The passive-only stage tuple is the mode table's entry, never a copy.
_PASSIVE_STAGES = MODE_STAGES["passive"]
# Commands that run no active stage at all, so `--active` promises nothing.
# `urls` is deliberately absent: its active tools need `--active`, and its
# passive tools run without it since the 2026-11-17 mode expansion.
_PASSIVE_ONLY_COMMANDS = frozenset({"subs", "dns", "passive", "lite"})


def _stage_list(mode: str) -> str:
    """The comma-separated stage list for one mode, straight from the table."""
    return ", ".join(stage.value for stage in MODE_STAGES[mode])


# docs/02 section 2. Each help string states the mode's stages, tool modes and
# tiers, and is generated from MODE_STAGES so it cannot drift from the engine.
_ACTIVE_HELP = (
    f"Run active stages: {_stage_list('active')}. The passive stages "
    "still run. Uses passive and active tools; no intrusive/aggressive tools. "
    "A scope.yaml, when present, is enforced; with no scope file, active "
    "scanning is unrestricted."
)
_FULL_HELP = (
    f"Run a full scan: all stages ({_stage_list('full')}). Uses passive, active, "
    "and intrusive-tier tools (exploitation-class tools still require an "
    "explicit --tools). Implies --active and --include-noisy."
)
_NO_SCOPE_HELP = (
    "Ignore any scope file and behave as if none existed. Active stages run "
    "unrestricted; a loud warning is printed and the run records "
    "scope_mode = unrestricted_flag. scope.yaml is never modified."
)
_ONLY_ALIVE_HELP = (
    'Print only hosts whose state is ALIVE. If none match, print "no ALIVE hosts (N scanned)".'
)
_ONLY_STATES_HELP = (
    "Print only hosts matching one of these comma-separated states: "
    "ALIVE, DNS_ONLY, SHUT_DOWN, DEAD, UNKNOWN."
)
_PORTS_HELP = "Override the default port list for naabu and pyscan. Format: 80,443,8000-8100."
_STATUS_CODES_HELP = (
    "Only keep hosts that respond with one of these HTTP status codes. Format: 200,301,302."
)
_HEADER_HELP = (
    "Add an HTTP header to every request made by httpx and pyprobe. Repeatable. "
    'Format: "Name: Value".'
)
_USER_AGENT_HELP = "Override the default User-Agent for httpx and pyprobe."
_REDACT_HELP = "Hide header values in JSON and UI output (default on)."
_SHOW_HEADERS_HELP = "Reveal header values in JSON output (overrides --redact-headers)."
_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
# The adapters that can carry --header/--user-agent today (docs/09 section 4).
_HEADER_TOOLS = frozenset({"httpx", "pyprobe"})


def _targets(domain: str | None, list_file: Path | None) -> list[str]:
    """Normalize one target or a comment-tolerant target file."""
    if domain is not None and list_file is not None:
        raise ConfigError("use either -d/--domain or -l/--list, not both")
    if domain is not None:
        return [validate_target(domain)]
    if list_file is None:
        raise ConfigError("provide a target with -d/--domain or -l/--list")
    try:
        text = list_file.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read target file {list_file}: {exc}") from exc
    targets: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        target = validate_target(value)
        if target not in seen:
            seen.add(target)
            targets.append(target)
    if not targets:
        raise ConfigError(f"target file {list_file} contains no domains")
    return targets


def _csv(value: str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _stages(command: str, active: bool, full: bool = False) -> tuple[Stage, ...]:
    if command == "subs":
        return (Stage.SUBS,)
    if command == "dns":
        return (Stage.DNS,)
    if command in {"passive", "lite"}:
        return _PASSIVE_STAGES
    if command == "live":
        return (Stage.LIVE,)
    if command == "ports":
        return (Stage.PORTS,)
    if command == "tech":
        return (Stage.TECH,)
    if command == "urls":
        return (Stage.URLS,)
    if command == "vulns":
        return (Stage.VULNS,)
    if command == "run":
        # The only place `run` decides stages is the mode table (docs/02).
        mode = "full" if full else ("active" if active else "passive")
        return MODE_STAGES[mode]
    raise ConfigError(f"unknown command {command!r}")


def _ports(value: str | None) -> tuple[int, ...]:
    """Parse `80,443,8000-8100` into the port tuple `ScanOptions` carries."""
    if value is None:
        return ()
    ports: list[int] = []
    seen: set[int] = set()
    for part in value.split(","):
        item = part.strip()
        if not item:
            continue
        if "-" in item:
            start_text, _, end_text = item.partition("-")
            if not start_text.strip().isdigit() or not end_text.strip().isdigit():
                raise ConfigError(f"invalid port range {item!r}; expected START-END")
            start, end = int(start_text), int(end_text)
            if not 1 <= start <= end <= 65535:
                raise ConfigError(f"port range {item!r} must be within 1-65535")
            for port in range(start, end + 1):
                if port not in seen:
                    seen.add(port)
                    ports.append(port)
            continue
        if not item.isdigit():
            raise ConfigError(f"invalid port {item!r}")
        port = int(item)
        if not 1 <= port <= 65535:
            raise ConfigError(f"port {port} must be within 1-65535")
        if port not in seen:
            seen.add(port)
            ports.append(port)
    return tuple(ports)


def _states(value: str | None) -> tuple[str, ...]:
    """Parse `--only-states ALIVE,DNS_ONLY` into validated state names."""
    if value is None:
        return ()
    states: list[str] = []
    for part in value.split(","):
        item = part.strip().upper()
        if not item:
            continue
        try:
            states.append(HostState(item).value)
        except ValueError:
            allowed = ", ".join(state.value for state in HostState)
            raise ConfigError(f"invalid host state {part!r}; expected one of {allowed}") from None
    return tuple(states)


def _status_codes(value: str | None) -> tuple[int, ...]:
    """Parse `200,301,302`; anything outside 100-599 is a usage error."""
    if value is None:
        return ()
    codes: list[int] = []
    seen: set[int] = set()
    for part in value.split(","):
        item = part.strip()
        if not item:
            continue
        if not item.isdigit():
            raise ConfigError(f"invalid HTTP status code {item!r}")
        code = int(item)
        if not 100 <= code <= 599:
            raise ConfigError(f"HTTP status code {code} must be within 100-599")
        if code not in seen:
            seen.add(code)
            codes.append(code)
    return tuple(codes)


def _headers(values: list[str] | None) -> tuple[tuple[str, str], ...]:
    """Parse repeated `--header 'Name: Value'` strings."""
    pairs: list[tuple[str, str]] = []
    for raw in values or []:
        name, sep, value = raw.partition(":")
        name = name.strip()
        value = value.strip()
        if not sep or not _HEADER_NAME.fullmatch(name) or not value:
            raise ConfigError(f"invalid --header {raw!r}; expected 'Name: Value'")
        if any(lower == name.lower() for lower, _ in pairs):
            raise ConfigError(f"duplicate --header {name!r}")
        pairs.append((name, value))
    return tuple(pairs)


def _configure_redaction() -> None:
    """Seed the shared redactor from `.env` before any command body runs (12f).

    `Engine.open` loads the same file, but only inside the command, which is too
    late for `_targets()`, `load_config()` and the usage refusals. Calling
    `dotenv_values()` from this module resolves the same checkout-level `.env`
    it resolves from `engine.py`, because python-dotenv searches from the calling
    file and both modules live in `src/reconkit`; this is not a second source and
    no process environment is read directly. An unreadable `.env` is ignored
    here - the engine reports it properly when it loads it.
    """
    try:
        values = dotenv_values()
    except OSError:
        return
    configure_redaction(value for value in values.values() if value is not None)


@dataclass(frozen=True)
class _InteractivePlan:
    """The answers, already resolved into the ordinary scan inputs."""

    domain: str | None
    list_file: Path | None
    scope_path: Path | None
    stages: tuple[Stage, ...]
    active: bool
    fields: tuple[ReportField, ...]
    full: bool = False
    no_scope: bool = False
    ports: tuple[int, ...] = ()
    status_codes: tuple[int, ...] = ()
    only_states: tuple[str, ...] = ()
    headers: tuple[tuple[str, str], ...] = ()
    user_agent: str | None = None


def _tools_label(mode: str) -> str:
    if mode == "full":
        return "passive+active+intrusive"
    if mode == "active":
        return "passive+active"
    return "passive only"


def _mode_legend() -> str:
    """The interactive legend, generated from `MODE_STAGES` (docs/02 section 2b).

    Same words as the "Scan modes (source of truth)" table: the stage list is
    `_stage_list()` and the tool modes come from `_tools_label()`, so the prompt
    cannot drift from the engine.
    """
    lines = ["Scan mode:"]
    for mode in ("passive", "active", "full"):
        stages = _stage_list(mode)
        if mode == "full":
            lines.append(f"  {mode:<8} — all stages ({stages}); {_tools_label(mode)}")
        else:
            lines.append(f"  {mode:<8} — {stages} stages; {_tools_label(mode)} tools")
    return "\n".join(lines)


def _stdin_is_tty() -> bool:
    """True only when a real terminal is on stdin (docs/02 section 2b).

    Without a terminal the interactive questions would block on input that can
    never arrive, so the command keeps the documented "provide a target" error.
    Tests drive the interactive path by monkeypatching this function.
    """
    try:
        return bool(sys.stdin.isatty())
    except (AttributeError, ValueError):
        return False


def _ask_target() -> tuple[str | None, Path | None]:
    """Question 1: one domain, or a path to a file of domains."""
    answer = ""
    while not answer:
        answer = str(
            typer.prompt("Domain, or path to a file of domains (one per line)", err=True)
        ).strip()
    candidate = Path(answer).expanduser()
    if candidate.is_file():
        return None, candidate
    return answer, None


def _ask_scope() -> Path | None:
    """Question 2: an optional scope file, used exactly like `--scope`."""
    if not typer.confirm("Do you have a scope file?", default=True, err=True):
        return None
    raw = str(typer.prompt("Scope file path", err=True)).strip()
    path = Path(raw).expanduser()
    if not path.is_file():
        raise ConfigError(f"scope file {path} does not exist")
    return path


def _ask_mode(*, no_color: bool) -> tuple[tuple[Stage, ...], bool, str]:
    """Question 3: passive, active or full (docs/02 section 2b).

    The legend is generated from `MODE_STAGES`/`MODE_TOOLS`, so the prompt says
    exactly what the CLI help and docs/02 say. There is no default and no
    assumed mode; the prompt repeats until one of the three words is typed.
    """
    while True:
        render_message(_mode_legend(), no_color=no_color)
        answer = str(typer.prompt("Choice [passive/active/full]", err=True))
        mode = answer.strip().lower()
        if mode in MODE_STAGES:
            return MODE_STAGES[mode], mode != "passive", mode
        render_error(
            f"invalid scan mode {answer!r}; expected passive, active or full",
            no_color=no_color,
        )


def _ask_no_scope(*, no_color: bool) -> bool:
    """Ask whether to ignore a scope file, with the loud warning and a confirm (y/N)."""
    if not typer.confirm("Ignore scope file and run unrestricted?", default=False, err=True):
        return False
    render_message(
        "--no-scope: active stages will run WITHOUT scope enforcement; no scope "
        "file is read, checked, or enforced. The run records "
        "scope_mode = unrestricted_flag.",
        no_color=no_color,
    )
    return bool(
        typer.confirm("This disables scope enforcement. Continue?", default=False, err=True)
    )


def _ask_ports() -> tuple[int, ...]:
    answer = str(
        typer.prompt("Ports to scan (comma or ranges, blank = default)", default="", err=True)
    )
    return _ports(answer.strip() or None)


def _ask_only_states(*, no_color: bool) -> tuple[str, ...]:
    answer = (
        str(
            typer.prompt(
                "Only show ALIVE, all, or custom states? [alive/all/custom]",
                default="all",
                err=True,
            )
        )
        .strip()
        .lower()
    )
    if answer in {"all", ""}:
        return ()
    if answer == "alive":
        return (HostState.ALIVE.value,)
    raw = str(typer.prompt("States (comma list)", default="ALIVE", err=True))
    states: list[str] = []
    for part in raw.split(","):
        value = part.strip().upper()
        if not value:
            continue
        try:
            states.append(HostState(value).value)
        except ValueError:
            render_error(f"invalid host state {part!r}", no_color=no_color)
    return tuple(states)


def _ask_headers() -> tuple[tuple[str, str], ...]:
    if not typer.confirm("Extra HTTP headers?", default=False, err=True):
        return ()
    pairs: list[tuple[str, str]] = []
    while True:
        raw = str(typer.prompt("Header", default="", err=True)).strip()
        if not raw:
            break
        name, sep, value = raw.partition(":")
        if not sep or not _HEADER_NAME.fullmatch(name.strip()) or not value.strip():
            raise ConfigError(f"invalid header {raw!r}; expected 'Name: Value'")
        pairs.append((name.strip(), value.strip()))
    return tuple(pairs)


def _ask_user_agent() -> str | None:
    if not typer.confirm("Custom User-Agent?", default=False, err=True):
        return None
    value = str(typer.prompt("User-Agent", default="", err=True)).strip()
    return value or None


def _ask_fields(*, no_color: bool) -> tuple[ReportField, ...]:
    """Question 4: which stored fields the saved report should contain."""
    lines = ["Report fields (numbers like 1,3,5, or 'all'):"]
    for number, field in enumerate(REPORT_FIELDS, start=1):
        gate = "" if field.gate == "always" else f"  [{field.gate} hosts only]"
        lines.append(f"  {number}. {field.label}{gate}")
    render_message("\n".join(lines), no_color=no_color)
    answer = str(typer.prompt("Fields", default="all", err=True)).strip().lower()
    if answer in {"all", "*"}:
        return REPORT_FIELDS
    numbers: list[int] = []
    for part in answer.replace(" ", "").split(","):
        if not part:
            continue
        if not part.isdigit():
            raise ConfigError(f"invalid report field {part!r}; expected a number or 'all'")
        number = int(part)
        if not 1 <= number <= len(REPORT_FIELDS):
            raise ConfigError(f"report field {number} is out of range (1-{len(REPORT_FIELDS)})")
        numbers.append(number)
    if not numbers:
        raise ConfigError("no report fields selected")
    return report_fields(numbers)


def _ask_aggressive(*, no_color: bool) -> bool:
    """Question 5: port scan + version detection, whatever the mode was."""
    answer = typer.confirm(
        "Also run aggressive scanning (port scan + version detection)?",
        default=False,
        err=True,
    )
    if answer:
        # docs/02 section 2b: state the real capability, never a guess.
        render_message(
            "aggressive: TCP connect scanning by pyscan, plus naabu when installed "
            "(with a scope file, naabu runs only on IPs reconkit resolved and "
            "verified against in_scope_cidrs); service/version detection is not "
            "wired in this build (nmap -sV has no adapter).",
            no_color=no_color,
        )
    return answer


def _interactive_plan(*, no_color: bool) -> _InteractivePlan:
    """Ask the questions and resolve them into ordinary scan inputs (docs/02 2b)."""
    domain, list_file = _ask_target()
    scope_path = _ask_scope()
    stages, active, mode = _ask_mode(no_color=no_color)
    fields = _ask_fields(no_color=no_color)
    no_scope = active and _ask_no_scope(no_color=no_color)
    ports: tuple[int, ...] = ()
    status_codes: tuple[int, ...] = ()
    only_states: tuple[str, ...] = ()
    headers: tuple[tuple[str, str], ...] = ()
    user_agent: str | None = None
    if active:
        ports = _ask_ports()
        only_states = _ask_only_states(no_color=no_color)
        status_codes = _status_codes(
            str(
                typer.prompt(
                    "Only keep HTTP status codes? (comma, blank = all)", default="", err=True
                )
            )
            or None
        )
        headers = _ask_headers()
        user_agent = _ask_user_agent()
    aggressive = False
    if mode != "full":
        aggressive = _ask_aggressive(no_color=no_color)
    if aggressive:
        wanted = set(stages) | {Stage.LIVE, Stage.PORTS}
        stages = tuple(stage for stage in STAGE_ORDER if stage in wanted)
        active = True
    label = domain if domain is not None else str(list_file)
    if no_scope:
        scope_label = "unrestricted (--no-scope)"
    elif scope_present(scope_path):
        scope_label = "enforced (scope file)"
    else:
        scope_label = "no scope file"
    render_message(
        f"plan: {label}; mode {mode}; scope {scope_label}; "
        f"stages {', '.join(stage.value for stage in stages)}; "
        f"tools {_tools_label(mode)}; fields {len(fields)}",
        no_color=no_color,
    )
    inject: list[str] = []
    if ports:
        inject.append("ports " + ",".join(str(port) for port in ports))
    if status_codes:
        inject.append("status_codes " + ",".join(str(code) for code in status_codes))
    if only_states:
        inject.append("states " + ",".join(only_states))
    if headers:
        inject.append(f"headers {len(headers)}")
    if user_agent:
        inject.append("user_agent custom")
    if inject:
        render_message("inject: " + "; ".join(inject), no_color=no_color)
    return _InteractivePlan(
        domain,
        list_file,
        scope_path,
        stages,
        active,
        fields,
        full=mode == "full",
        no_scope=no_scope,
        ports=ports,
        status_codes=status_codes,
        only_states=only_states,
        headers=headers,
        user_agent=user_agent,
    )


def _report_error(message: str, code: int, *, no_color: bool, verbose: bool = False) -> int:
    if verbose:
        # A chained exception (`__cause__`/`__context__`) is rendered into this
        # string before redaction, so a key in a nested message is masked too.
        message = traceback.format_exc()
    render_error(redact(message), no_color=no_color)
    return code


def _no_scope_warning(targets: list[str]) -> str:
    """The loud block for an active run with `--no-scope` (docs/05 section 3)."""
    return "\n".join(
        [
            "⚠ --no-scope given: active stages will run WITHOUT scope enforcement.",
            f"  target(s): {', '.join(targets)}",
            "  no scope file is being read, checked, or enforced.",
            '  a scan_runs record will be written with scope_mode = "unrestricted_flag".',
        ]
    )


def _append_scope_entry(path: Path, target: str) -> None:
    """Add `target` under `in_scope:` without rewriting the file's other text.

    Line-based on purpose: a YAML round-trip would drop the `authorization`
    comment block and reorder keys (F2 is frozen). Only reached from the
    interactive `[a]` path, and only after an explicit `y`.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from None
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip().split("#", 1)[0].strip() != "in_scope:":
            continue
        insert_at = index + 1
        while insert_at < len(lines) and lines[insert_at].lstrip().startswith("- "):
            insert_at += 1
        lines.insert(insert_at, f"  - {target}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return
    raise ConfigError(f"{path} has no 'in_scope:' list to append to")


def _ask_out_of_scope(target: str, scope_path: Path, *, no_color: bool) -> tuple[str, str | None]:
    """The four interactive choices for a target a present scope file blocks."""
    render_message(
        f"{target} is not in scope.yaml. Options:\n"
        f"  [a] add {target} to scope.yaml (modifies scope.yaml)\n"
        "  [b] ignore scope and run unrestricted (--no-scope)\n"
        "  [c] scan an in-scope target instead\n"
        "  [d] abort",
        no_color=no_color,
    )
    answer = str(typer.prompt("Choice [a/b/c/d]", default="d", err=True)).strip().lower()
    if answer.startswith("a"):
        if not typer.confirm("This will modify scope.yaml. Proceed?", default=False, err=True):
            return "abort", None
        _append_scope_entry(scope_path, target)
        render_message(f"added {target} to {scope_path}", no_color=no_color)
        return "proceed", None
    if answer.startswith("b"):
        render_message(_no_scope_warning([target]), no_color=no_color)
        if not typer.confirm("This disables scope enforcement. Continue?", default=False, err=True):
            return "abort", None
        return "noscope", None
    if answer.startswith("c"):
        replacement = str(typer.prompt("In-scope domain", default="", err=True)).strip()
        if not replacement:
            return "abort", None
        return "retarget", validate_target(replacement)
    return "abort", None


def _run_scan(
    command: str,
    *,
    domain: str | None,
    list_file: Path | None,
    json_output: bool,
    silent: bool,
    min_sources: int,
    tools: str | None,
    exclude: str | None,
    include_noisy: bool,
    phase_timeout: float | None,
    mock: bool,
    active: bool,
    no_keys: bool,
    resume: bool,
    no_color: bool,
    verbose: bool,
    config_path: Path | None,
    scope_path: Path | None,
    db_path: Path | None,
    full: bool = False,
    no_scope: bool = False,
    only_alive: bool = False,
    only_states: tuple[str, ...] = (),
    ports: tuple[int, ...] = (),
    status_codes: tuple[int, ...] = (),
    headers: tuple[tuple[str, str], ...] = (),
    user_agent: str | None = None,
    redact_headers: bool = True,
) -> int:
    engine: Engine | None = None
    try:
        # docs/02 section 2b: the questions are asked only when a scan command got
        # neither -d nor -l and a terminal is on stdin. Any target flag keeps the
        # flag-based path byte-identical, which is what every script relies on.
        plan: _InteractivePlan | None = None
        if domain is None and list_file is None and command in _SCAN_COMMANDS and _stdin_is_tty():
            try:
                plan = _interactive_plan(no_color=no_color)
            except (EOFError, typer.Abort):
                raise ConfigError("interactive scan cancelled") from None
            domain, list_file = plan.domain, plan.list_file
            scope_path = plan.scope_path
            full = plan.full or full
            no_scope = plan.no_scope or no_scope
            only_states = plan.only_states or only_states
            ports = plan.ports or ports
            status_codes = plan.status_codes or status_codes
            headers = plan.headers or headers
            user_agent = plan.user_agent or user_agent
        if full:
            # docs/02 section 2: full implies both, in that order.
            active = True
            include_noisy = True
        targets = _targets(domain, list_file)
        config: AppConfig = load_config(config_path)
        is_active = active if plan is None else (plan.active or active)
        if command in _ACTIVE_ONLY and not is_active:
            raise ConfigError(f"{command} requires --active")
        # Only the flag path: an interactive run decides its own mode (and may
        # legitimately choose active from the bare command).
        if plan is None and command in _PASSIVE_ONLY_COMMANDS and is_active:
            raise ConfigError(
                f"{command!r} is passive-only; --active needs: reconkit run -d X --active"
            )
        # docs/02 section 2: the passive-only commands run no active stage, so
        # accepting --active would promise work the command cannot do.
        stages = plan.stages if plan is not None else _stages(command, is_active, full)
        progress_console = make_console(no_color=no_color)
        if no_scope and not is_active:
            render_message(
                "warning: --no-scope has no effect on a passive run; continuing",
                console=progress_console,
                no_color=no_color,
            )
        elif no_scope and scope_path is not None:
            render_message(
                f"warning: --scope {scope_path} ignored because --no-scope was given",
                console=progress_console,
                no_color=no_color,
            )
        if no_scope and is_active:
            render_message(_no_scope_warning(targets), console=progress_console, no_color=no_color)
        # Item 7: an interactive run that a present scope file blocks asks what
        # to do instead of just refusing. Never runs for the flag path.
        if plan is not None and len(targets) == 1 and is_active and not no_scope:
            if preflight_warning(targets[0], path=scope_path) is not None:
                try:
                    action, replacement = _ask_out_of_scope(
                        targets[0], resolve_scope_path(scope_path), no_color=no_color
                    )
                except (EOFError, typer.Abort):
                    raise ConfigError("interactive scan cancelled") from None
                if action == "abort":
                    return int(ExitCode.USAGE)
                if action == "noscope":
                    no_scope = True
                elif action == "retarget" and replacement is not None:
                    targets = [replacement]
        if json_output and len(targets) > 1:
            raise ConfigError("--json accepts one target per invocation; use -d")
        # Progress goes to stderr for every scan, --json included; only --silent
        # suppresses it (docs/02 section 5).
        progress = (
            None if silent else (lambda message: render_progress(message, console=progress_console))
        )
        engine = Engine.open(config, db_path=db_path, scope_path=scope_path, progress=progress)
        exit_code = int(ExitCode.SUCCESS)
        for target in targets:
            # Item 2: loud pre-flight block, stderr only, and the run never stops.
            if is_active and not no_scope:
                block = preflight_warning(target, path=scope_path)
                if block is not None:
                    render_message(block, console=progress_console, no_color=no_color)
            summary = asyncio.run(
                engine.run(
                    target,
                    ScanOptions(
                        stages=stages,
                        tools=_csv(tools),
                        exclude=frozenset(_csv(exclude)),
                        include_noisy=include_noisy,
                        active=is_active,
                        full=full,
                        no_scope=no_scope,
                        no_keys=no_keys,
                        mock=mock,
                        phase_timeout=phase_timeout,
                        min_sources=min_sources,
                        resume=resume,
                        ports=ports,
                        status_codes=status_codes,
                        headers=headers,
                        user_agent=user_agent,
                        redact_headers=redact_headers,
                    ),
                )
            )
            snapshots = engine.host_rows(summary.target_id)
            rows = [
                HostRow(
                    fqdn=item.fqdn,
                    state=item.state,
                    confidence=item.confidence,
                    sources=item.sources,
                    status_code=item.status_code,
                    ports=item.ports,
                    detail=item.detail,
                )
                for item in snapshots
            ]
            # docs/02 section 3: filters change what is printed, never what is
            # stored; the JSON document carries the counts.
            states = {HostState.ALIVE.value} if only_alive else set(only_states)
            shown = rows
            if states:
                shown = [row for row in shown if row.state.value in states]
            if status_codes:
                shown = [row for row in shown if row.status_code in status_codes]
            filter_info: dict[str, object] | None = None
            if only_alive or only_states or status_codes:
                filter_info = {
                    "only_states": sorted(states),
                    "matched": len(shown),
                    "total": len(rows),
                }
                if status_codes:
                    filter_info["status_codes"] = list(status_codes)
            injections: dict[str, object] | None = None
            if ports or status_codes or headers or user_agent:
                injections = {
                    "ports": list(ports),
                    "status_codes": list(status_codes),
                    "headers": {
                        name: ("***" if redact_headers else value) for name, value in headers
                    },
                    "user_agent": user_agent,
                }
            for name in sorted({result.tool for result in summary.results}):
                if headers and name not in _HEADER_TOOLS:
                    render_message(
                        f"warning: --header not applied to {name} (no -H support)",
                        console=progress_console,
                        no_color=no_color,
                    )
            exit_code = render(
                summary,
                shown,
                json_output=json_output,
                silent=silent,
                no_color=no_color,
                filter_info=filter_info,
                injections=injections,
            )
            if plan is not None:
                run_at = datetime.now(UTC)
                directory = report_directory(config.results_dir, target, run_at)
                report_text_path, report_json_path = write_field_report(
                    directory, target, snapshots, plan.fields, run_at=run_at
                )
                render_progress(
                    f"report: {report_text_path} and {report_json_path}",
                    console=progress_console,
                    silent=silent,
                )
        return exit_code
    except ConfigError as exc:
        return _report_error(str(exc), exc.exit_code, no_color=no_color)
    except ScopeError as exc:
        return _report_error(str(exc), exc.exit_code, no_color=no_color)
    except ValueError as exc:
        return _report_error(str(exc), int(ExitCode.USAGE), no_color=no_color)
    except KeyboardInterrupt:
        return _report_error(
            "interrupted; state is saved and the run is resumable", 130, no_color=no_color
        )
    except Exception as exc:
        message = f"unexpected error: {type(exc).__name__}: {exc}"
        return _report_error(message, int(ExitCode.ERROR), no_color=no_color, verbose=verbose)
    finally:
        if engine is not None:
            engine.close()


def _scan_command(
    ctx: typer.Context,
    domain: Annotated[
        str | None, typer.Option("-d", "--domain", help="Root domain to scan.")
    ] = None,
    list_file: Annotated[
        Path | None, typer.Option("-l", "--list", help="File with one root domain per line.")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Write one JSON document to stdout.")
    ] = False,
    silent: Annotated[
        bool, typer.Option("--silent", "-q", help="Suppress tables and progress.")
    ] = False,
    min_sources: Annotated[
        int, typer.Option("--min-sources", min=1, help="Hide results below this many sources.")
    ] = 1,
    tools: Annotated[
        str | None, typer.Option("--tools", help="Comma-separated adapters to run.")
    ] = None,
    exclude: Annotated[
        str | None, typer.Option("--exclude", help="Comma-separated adapters to skip.")
    ] = None,
    include_noisy: Annotated[
        bool, typer.Option("--include-noisy", help="Allow opt_in tier tools.")
    ] = False,
    phase_timeout: Annotated[
        float | None, typer.Option("--phase-timeout", help="Stage time limit in seconds.")
    ] = None,
    mock: Annotated[
        bool, typer.Option("--mock", help="Use fixtures; no network or external processes.")
    ] = False,
    active: Annotated[
        bool,
        typer.Option("--active", help=_ACTIVE_HELP),
    ] = False,
    full: Annotated[bool, typer.Option("--full", help=_FULL_HELP)] = False,
    no_scope: Annotated[bool, typer.Option("--no-scope", help=_NO_SCOPE_HELP)] = False,
    only_alive: Annotated[bool, typer.Option("--only-alive", help=_ONLY_ALIVE_HELP)] = False,
    only_states: Annotated[
        str | None, typer.Option("--only-states", help=_ONLY_STATES_HELP)
    ] = None,
    ports: Annotated[str | None, typer.Option("--ports", help=_PORTS_HELP)] = None,
    status_codes: Annotated[
        str | None, typer.Option("--status-codes", help=_STATUS_CODES_HELP)
    ] = None,
    header: Annotated[list[str] | None, typer.Option("--header", help=_HEADER_HELP)] = None,
    user_agent: Annotated[str | None, typer.Option("--user-agent", help=_USER_AGENT_HELP)] = None,
    redact_headers: Annotated[
        bool,
        typer.Option("--redact-headers/--show-headers", help=_REDACT_HELP),
    ] = True,
    no_keys: Annotated[bool, typer.Option("--no-keys", help="Force free mode.")] = False,
    resume: Annotated[
        bool, typer.Option("--resume", help="Continue the latest unfinished run.")
    ] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colors.")] = False,
    verbose: Annotated[
        bool, typer.Option("-v", "--verbose", help="Show a traceback for unexpected errors.")
    ] = False,
    config_path: Annotated[Path | None, typer.Option("--config", help="Config file path.")] = None,
    scope_path: Annotated[Path | None, typer.Option("--scope", help="Scope file path.")] = None,
    db_path: Annotated[Path | None, typer.Option("--db", help="SQLite database path.")] = None,
) -> None:
    name = ctx.info_name or "lite"
    raise typer.Exit(
        code=_run_scan(
            name,
            domain=domain,
            list_file=list_file,
            json_output=json_output,
            silent=silent,
            min_sources=min_sources,
            tools=tools,
            exclude=exclude,
            include_noisy=include_noisy,
            phase_timeout=phase_timeout,
            mock=mock,
            active=active,
            full=full,
            no_scope=no_scope,
            only_alive=only_alive,
            only_states=_states(only_states),
            ports=_ports(ports),
            status_codes=_status_codes(status_codes),
            headers=_headers(header),
            user_agent=user_agent,
            redact_headers=redact_headers,
            no_keys=no_keys,
            resume=resume,
            no_color=no_color,
            verbose=verbose,
            config_path=config_path,
            scope_path=scope_path,
            db_path=db_path,
        )
    )


for _name in _SCAN_COMMANDS:
    app.command(_name)(_scan_command)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    domain: Annotated[
        str | None, typer.Option("-d", "--domain", help="Root domain to scan.")
    ] = None,
    list_file: Annotated[
        Path | None, typer.Option("-l", "--list", help="File with one root domain per line.")
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Write one JSON document to stdout.")
    ] = False,
    silent: Annotated[
        bool, typer.Option("--silent", "-q", help="Suppress tables and progress.")
    ] = False,
    min_sources: Annotated[
        int, typer.Option("--min-sources", min=1, help="Hide results below this many sources.")
    ] = 1,
    tools: Annotated[
        str | None, typer.Option("--tools", help="Comma-separated adapters to run.")
    ] = None,
    exclude: Annotated[
        str | None, typer.Option("--exclude", help="Comma-separated adapters to skip.")
    ] = None,
    include_noisy: Annotated[
        bool, typer.Option("--include-noisy", help="Allow opt_in tier tools.")
    ] = False,
    phase_timeout: Annotated[
        float | None, typer.Option("--phase-timeout", help="Stage time limit in seconds.")
    ] = None,
    mock: Annotated[
        bool, typer.Option("--mock", help="Use fixtures; no network or external processes.")
    ] = False,
    active: Annotated[
        bool,
        typer.Option("--active", help=_ACTIVE_HELP),
    ] = False,
    full: Annotated[bool, typer.Option("--full", help=_FULL_HELP)] = False,
    no_scope: Annotated[bool, typer.Option("--no-scope", help=_NO_SCOPE_HELP)] = False,
    only_alive: Annotated[bool, typer.Option("--only-alive", help=_ONLY_ALIVE_HELP)] = False,
    only_states: Annotated[
        str | None, typer.Option("--only-states", help=_ONLY_STATES_HELP)
    ] = None,
    ports: Annotated[str | None, typer.Option("--ports", help=_PORTS_HELP)] = None,
    status_codes: Annotated[
        str | None, typer.Option("--status-codes", help=_STATUS_CODES_HELP)
    ] = None,
    header: Annotated[list[str] | None, typer.Option("--header", help=_HEADER_HELP)] = None,
    user_agent: Annotated[str | None, typer.Option("--user-agent", help=_USER_AGENT_HELP)] = None,
    redact_headers: Annotated[
        bool,
        typer.Option("--redact-headers/--show-headers", help=_REDACT_HELP),
    ] = True,
    no_keys: Annotated[bool, typer.Option("--no-keys", help="Force free mode.")] = False,
    resume: Annotated[
        bool, typer.Option("--resume", help="Continue the latest unfinished run.")
    ] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colors.")] = False,
    verbose: Annotated[
        bool, typer.Option("-v", "--verbose", help="Show a traceback for unexpected errors.")
    ] = False,
    config_path: Annotated[Path | None, typer.Option("--config", help="Config file path.")] = None,
    scope_path: Annotated[Path | None, typer.Option("--scope", help="Scope file path.")] = None,
    db_path: Annotated[Path | None, typer.Option("--db", help="SQLite database path.")] = None,
) -> None:
    # 12f: before any command body, because Engine.open loads `.env` too late
    # for errors raised by _targets()/load_config()/the usage refusals.
    _configure_redaction()
    if ctx.invoked_subcommand is not None:
        return
    raise typer.Exit(
        code=_run_scan(
            "lite",
            domain=domain,
            list_file=list_file,
            json_output=json_output,
            silent=silent,
            min_sources=min_sources,
            tools=tools,
            exclude=exclude,
            include_noisy=include_noisy,
            phase_timeout=phase_timeout,
            mock=mock,
            active=active,
            full=full,
            no_scope=no_scope,
            only_alive=only_alive,
            only_states=_states(only_states),
            ports=_ports(ports),
            status_codes=_status_codes(status_codes),
            headers=_headers(header),
            user_agent=user_agent,
            redact_headers=redact_headers,
            no_keys=no_keys,
            resume=resume,
            no_color=no_color,
            verbose=verbose,
            config_path=config_path,
            scope_path=scope_path,
            db_path=db_path,
        )
    )


@scope_app.command("check")
def scope_check(
    domain: Annotated[str, typer.Option("-d", "--domain", help="Domain to check.")],
    scope_path: Annotated[Path | None, typer.Option("--scope", help="Scope file path.")] = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colors.")] = False,
) -> None:
    try:
        decision = check_target(domain, path=scope_path)
    except ValueError as exc:
        render_error(str(exc), no_color=no_color)
        raise typer.Exit(code=int(ExitCode.USAGE)) from None
    except (ConfigError, ScopeError) as exc:
        render_error(str(exc), no_color=no_color)
        raise typer.Exit(code=exc.exit_code) from None
    render_message(decision, no_color=no_color)
    raise typer.Exit(code=0 if decision.startswith("ALLOWED") else int(ExitCode.SCOPE))


@scope_app.command("import")
def scope_import() -> None:
    render_error("scope import is Phase 3 and is not available in this build.")
    raise typer.Exit(code=int(ExitCode.ERROR))


@app.command("diff")
def diff_command(
    domain: Annotated[str, typer.Option("-d", "--domain", help="Domain to compare.")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Write one JSON document to stdout.")
    ] = False,
    silent: Annotated[bool, typer.Option("--silent", "-q", help="Suppress tables.")] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colors.")] = False,
    config_path: Annotated[Path | None, typer.Option("--config", help="Config file path.")] = None,
    db_path: Annotated[Path | None, typer.Option("--db", help="SQLite database path.")] = None,
) -> None:
    engine: Engine | None = None
    try:
        config = load_config(config_path)
        engine = Engine.open(config, db_path=db_path)
        raise typer.Exit(
            code=render_diff(
                engine.diff(domain),
                json_output=json_output,
                silent=silent,
                no_color=no_color,
            )
        )
    except (ConfigError, ScopeError, ValueError) as exc:
        render_error(str(exc), no_color=no_color)
        raise typer.Exit(
            code=exc.exit_code if hasattr(exc, "exit_code") else int(ExitCode.USAGE)
        ) from None
    finally:
        if engine is not None:
            engine.close()


@app.command("status")
def status_command(
    json_output: Annotated[
        bool, typer.Option("--json", help="Write one JSON document to stdout.")
    ] = False,
    silent: Annotated[bool, typer.Option("--silent", "-q", help="Suppress tables.")] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colors.")] = False,
    config_path: Annotated[Path | None, typer.Option("--config", help="Config file path.")] = None,
    db_path: Annotated[Path | None, typer.Option("--db", help="SQLite database path.")] = None,
) -> None:
    engine: Engine | None = None
    try:
        config = load_config(config_path)
        engine = Engine.open(config, db_path=db_path)
        raise typer.Exit(
            code=render_status(
                engine.recent_runs(),
                json_output=json_output,
                silent=silent,
                no_color=no_color,
            )
        )
    except (ConfigError, ScopeError, ValueError) as exc:
        render_error(str(exc), no_color=no_color)
        raise typer.Exit(
            code=exc.exit_code if hasattr(exc, "exit_code") else int(ExitCode.USAGE)
        ) from None
    finally:
        if engine is not None:
            engine.close()


@app.command("doctor")
def doctor_command(
    json_output: Annotated[
        bool, typer.Option("--json", help="Write one JSON document to stdout.")
    ] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colors.")] = False,
    config_path: Annotated[Path | None, typer.Option("--config", help="Config file path.")] = None,
) -> None:
    try:
        config = load_config(config_path)
        report = collect_report(config=config, config_path=config_path)
    except (ConfigError, ValueError) as exc:
        render_error(str(exc), no_color=no_color)
        raise typer.Exit(code=int(ExitCode.ERROR)) from None
    code = render_doctor(report, json_output=json_output, no_color=no_color)
    if not report.python_ok:
        render_error(
            f"python {report.python_version} is too old; reconkit needs 3.11 or newer",
            no_color=no_color,
        )
        raise typer.Exit(code=int(ExitCode.ERROR))
    raise typer.Exit(code=code)


@db_app.command("list")
def db_list(
    domain: Annotated[str, typer.Option("-d", "--domain", help="Target to list.")],
) -> None:
    del domain
    render_error("db list is not wired in Part 8; no data was read.")
    raise typer.Exit(code=int(ExitCode.ERROR))


@db_app.command("export")
def db_export(
    domain: Annotated[str, typer.Option("-d", "--domain", help="Target to export.")],
    new_only: Annotated[
        bool, typer.Option("--new-only", help="Only items new since the previous run.")
    ] = False,
) -> None:
    del domain, new_only
    render_error("db export is not wired in Part 8; no data was written.")
    raise typer.Exit(code=int(ExitCode.ERROR))


@app.command("export")
def export_command(
    domain: Annotated[str, typer.Option("-d", "--domain", help="Target to export.")],
    output_format: Annotated[
        str, typer.Option("--format", help="Report format: json, md or html.")
    ] = "json",
) -> None:
    del domain, output_format
    render_error("export is not wired in Part 8; no report was written.")
    raise typer.Exit(code=int(ExitCode.ERROR))
