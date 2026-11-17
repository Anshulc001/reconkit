"""Typer command wiring for reconkit (docs/02_CLI_UX.md)."""

from __future__ import annotations

import asyncio
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
from reconkit.core.scope import check_target
from reconkit.core.store import configure_redaction, redact
from reconkit.doctor import collect_report
from reconkit.engine import STAGE_ORDER, Engine, ExitCode, ScanOptions
from reconkit.errors import ConfigError, ScopeError
from reconkit.models import Stage
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
_PASSIVE_STAGES = (Stage.SUBS, Stage.DNS)
# The --active rule in one sentence (docs/05 rule 2, docs/02 section 3). Kept here
# so the two scan-command call sites and docs/02 quote the same words.
_ACTIVE_HELP = (
    "Allow active stages. A scope.yaml, when present, is enforced; "
    "with no scope file, active scanning is unrestricted."
)


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


def _stages(command: str, active: bool) -> tuple[Stage, ...]:
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
        return (
            (Stage.SUBS, Stage.DNS, Stage.LIVE, Stage.PORTS, Stage.TECH, Stage.URLS, Stage.VULNS)
            if active
            else _PASSIVE_STAGES
        )
    raise ConfigError(f"unknown command {command!r}")


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


# The interactive mode's three scan modes (docs/02 section 2b). `vulns` is never
# requested: this build is recon-only, so a `vulns` adapter does not exist.
_MODE_STAGES: dict[str, tuple[Stage, ...]] = {
    "passive": (Stage.SUBS, Stage.DNS),
    "active": (Stage.SUBS, Stage.DNS, Stage.LIVE),
    "full": (Stage.SUBS, Stage.DNS, Stage.LIVE, Stage.PORTS, Stage.TECH, Stage.URLS),
}


@dataclass(frozen=True)
class _InteractivePlan:
    """The five answers, already resolved into the ordinary scan inputs."""

    domain: str | None
    list_file: Path | None
    scope_path: Path | None
    stages: tuple[Stage, ...]
    active: bool
    fields: tuple[ReportField, ...]


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


def _ask_mode(*, no_color: bool) -> tuple[tuple[Stage, ...], bool]:
    """Question 3: passive, active or full.

    2026-11-17 (owner request): there is no default and no assumed mode. The
    prompt repeats until one of the three words is typed, so a run can never
    start on an empty answer with an implicitly chosen mode.
    """
    while True:
        answer = str(typer.prompt("Scan mode: passive, active or full", err=True))
        mode = answer.strip().lower()
        if mode in _MODE_STAGES:
            return _MODE_STAGES[mode], mode != "passive"
        render_error(
            f"invalid scan mode {answer!r}; expected passive, active or full",
            no_color=no_color,
        )


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
    """Ask the five questions and resolve them into ordinary scan inputs."""
    domain, list_file = _ask_target()
    scope_path = _ask_scope()
    stages, active = _ask_mode(no_color=no_color)
    fields = _ask_fields(no_color=no_color)
    aggressive = _ask_aggressive(no_color=no_color)
    if aggressive:
        wanted = set(stages) | {Stage.LIVE, Stage.PORTS}
        stages = tuple(stage for stage in STAGE_ORDER if stage in wanted)
        active = True
    label = domain if domain is not None else str(list_file)
    render_message(
        f"plan: {label}; stages {', '.join(stage.value for stage in stages)}; "
        f"active {'yes' if active else 'no'}; fields {len(fields)}",
        no_color=no_color,
    )
    return _InteractivePlan(domain, list_file, scope_path, stages, active, fields)


def _report_error(message: str, code: int, *, no_color: bool, verbose: bool = False) -> int:
    if verbose:
        # A chained exception (`__cause__`/`__context__`) is rendered into this
        # string before redaction, so a key in a nested message is masked too.
        message = traceback.format_exc()
    render_error(redact(message), no_color=no_color)
    return code


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
        targets = _targets(domain, list_file)
        config: AppConfig = load_config(config_path)
        is_active = active if plan is None else (plan.active or active)
        if command in _ACTIVE_ONLY and not is_active:
            raise ConfigError(f"{command} requires --active")
        # docs/02 section 2: the passive-only commands run no active stage, so
        # accepting --active would promise work the command cannot do.
        stages = plan.stages if plan is not None else _stages(command, is_active)
        if is_active and all(stage in _PASSIVE_STAGES for stage in stages):
            raise ConfigError(
                f"{command!r} is passive-only; --active needs: reconkit run -d X --active"
            )
        if json_output and len(targets) > 1:
            raise ConfigError("--json accepts one target per invocation; use -d")
        # Progress goes to stderr for every scan, --json included; only --silent
        # suppresses it (docs/02 section 5).
        progress_console = make_console(no_color=no_color)
        progress = (
            None if silent else (lambda message: render_progress(message, console=progress_console))
        )
        engine = Engine.open(config, db_path=db_path, scope_path=scope_path, progress=progress)
        exit_code = int(ExitCode.SUCCESS)
        for target in targets:
            summary = asyncio.run(
                engine.run(
                    target,
                    ScanOptions(
                        stages=stages,
                        tools=_csv(tools),
                        exclude=frozenset(_csv(exclude)),
                        include_noisy=include_noisy,
                        active=is_active,
                        no_keys=no_keys,
                        mock=mock,
                        phase_timeout=phase_timeout,
                        min_sources=min_sources,
                        resume=resume,
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
            exit_code = render(
                summary,
                rows,
                json_output=json_output,
                silent=silent,
                no_color=no_color,
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
