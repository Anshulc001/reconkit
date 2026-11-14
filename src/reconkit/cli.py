"""Typer command wiring for reconkit (docs/02_CLI_UX.md)."""

from __future__ import annotations

import asyncio
import shutil
import sys
import traceback
from contextlib import nullcontext
from pathlib import Path
from typing import Annotated

import httpx
import typer

from reconkit.config import AppConfig, load_config
from reconkit.core.runner import validate_target
from reconkit.core.scope import check_target
from reconkit.doctor import collect_report, key_checks
from reconkit.engine import Engine, ExitCode, ScanOptions
from reconkit.errors import ConfigError, ScopeError
from reconkit.installer.github_release import install_selected
from reconkit.installer.registry import InstallPlan, bin_dir, load_plans
from reconkit.models import Stage
from reconkit.ui import (
    HostRow,
    make_console,
    render,
    render_diff,
    render_doctor,
    render_error,
    render_install,
    render_keys,
    render_message,
    render_status,
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


def _report_error(message: str, code: int, *, no_color: bool, verbose: bool = False) -> int:
    if verbose:
        message = traceback.format_exc()
    render_error(message, no_color=no_color)
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
    speed: str | None,
    delay: str | None,
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
        targets = _targets(domain, list_file)
        config: AppConfig = load_config(config_path, speed=speed, delay=delay)
        if command in _ACTIVE_ONLY and not active:
            raise ConfigError(f"{command} requires --active and a matching scope.yaml")
        # docs/02 section 2: the passive-only commands run no active stage, so
        # accepting --active would promise work the command cannot do.
        stages = _stages(command, active)
        if active and all(stage in _PASSIVE_STAGES for stage in stages):
            raise ConfigError(
                f"{command!r} is passive-only; --active needs: reconkit run -d X --active"
            )
        if active and config.default_speed == "fast" and not mock:
            render_message(
                "warning: active fast mode can be noisy; typed confirmation is required.",
                no_color=no_color,
            )
            answer = typer.prompt(
                "Type I AM AUTHORIZED to continue",
                default="",
                show_default=False,
            )
            if answer != "I AM AUTHORIZED":
                raise ConfigError("fast active scan cancelled")
        if json_output and len(targets) > 1:
            raise ConfigError("--json accepts one target per invocation; use -d")
        engine = Engine.open(config, db_path=db_path, scope_path=scope_path)
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
                        active=active,
                        no_keys=no_keys,
                        mock=mock,
                        speed=config.default_speed,
                        phase_timeout=phase_timeout,
                        min_sources=min_sources,
                        resume=resume,
                    ),
                )
            )
            rows = [
                HostRow(
                    fqdn=item.fqdn,
                    state=item.state,
                    confidence=item.confidence,
                    sources=item.sources,
                    status_code=item.status_code,
                    ports=item.ports,
                )
                for item in engine.host_rows(summary.target_id)
            ]
            exit_code = render(
                summary,
                rows,
                json_output=json_output,
                silent=silent,
                no_color=no_color,
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
    speed: Annotated[
        str | None, typer.Option("--speed", help="slow, normal or fast (default: slow).")
    ] = None,
    delay: Annotated[
        str | None, typer.Option("--delay", help="Random pause MIN-MAX seconds.")
    ] = None,
    active: Annotated[
        bool, typer.Option("--active", help="Allow active stages inside scope.")
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
            speed=speed,
            delay=delay,
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
    speed: Annotated[
        str | None, typer.Option("--speed", help="slow, normal or fast (default: slow).")
    ] = None,
    delay: Annotated[
        str | None, typer.Option("--delay", help="Random pause MIN-MAX seconds.")
    ] = None,
    active: Annotated[
        bool, typer.Option("--active", help="Allow active stages inside scope.")
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
            speed=speed,
            delay=delay,
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
    fix: Annotated[bool, typer.Option("--fix", help="Offer to install missing tools.")] = False,
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
    if fix:
        _run_install(
            None,
            True,
            dry_run=False,
            update=False,
            config_path=config_path,
            no_color=no_color,
        )
    raise typer.Exit(code=code)


def _install_confirm(message: str) -> bool:
    """The only confirmation prompt for sudo; the installer never prompts.

    Without a TTY there is nobody to answer (CI, `ssh host reconkit install`,
    a pipe). `typer.confirm` would abort the whole run there; a refusal only
    skips that one sudo tool, which is what docs/10 section 3d promises.
    """
    if not sys.stdin.isatty():
        return False
    return typer.confirm(message, default=False)


def _install_selection(
    tools: list[str] | None, all_tools: bool, *, config: AppConfig
) -> list[InstallPlan]:
    """`--all` means every core tool with something to install; else the names."""
    plans = load_plans(versions=config.tool_versions)
    if all_tools:
        return [plan for plan in plans.values() if plan.tier == "core" and plan.method != "none"]
    selected = []
    for name in tools or []:
        plan = plans.get(name)
        if plan is None:
            raise ConfigError(f"unknown tool {name!r}; see tools.yaml")
        selected.append(plan)
    return selected


def _maybe_ask_keys(*, no_color: bool) -> None:
    """docs/05 section 6.1: ask once on a TTY, never with no TTY or --dry-run."""
    console = make_console(no_color=no_color)
    if not sys.stdin.isatty() or not typer.confirm("Free only, or add keys?", default=False):
        return
    env_path = Path.cwd() / ".env"
    example = Path.cwd() / ".env.example"
    if env_path.exists():
        render_message(f"keeping existing {env_path}", console=console)
    elif not example.exists():
        render_message(".env.example not found; nothing copied", console=console)
        return
    else:
        shutil.copy2(example, env_path)
        env_path.chmod(0o600)
        render_message(f"wrote {env_path}; add your keys there", console=console)
    render_keys(key_checks(), console=console)


def _run_install(
    tools: list[str] | None,
    all_tools: bool,
    *,
    dry_run: bool,
    update: bool,
    config_path: Path | None,
    no_color: bool,
) -> None:
    """Shared body of `install` and `update` (docs/10 section 1)."""
    if sys.platform != "linux":
        message = (
            "Use WSL2 Kali (see SETUP.md)"
            if sys.platform == "win32"
            else "Linux is required (see SETUP.md)"
        )
        render_error(message, no_color=no_color)
        raise typer.Exit(code=int(ExitCode.ERROR))
    if not tools and not all_tools:
        render_error("name at least one tool or pass --all", no_color=no_color)
        raise typer.Exit(code=int(ExitCode.USAGE))
    try:
        config = load_config(config_path)
        selected = _install_selection(tools, all_tools, config=config)
    except (ConfigError, ValueError) as exc:
        render_error(str(exc), no_color=no_color)
        raise typer.Exit(code=int(ExitCode.USAGE)) from None
    if selected and not update and not dry_run:
        _maybe_ask_keys(no_color=no_color)
    client = httpx.Client() if any(plan.method == "github_release" for plan in selected) else None
    try:
        try:
            with client if client is not None else nullcontext():
                outcomes, code = install_selected(
                    selected,
                    bin_dir=bin_dir(),
                    update=update,
                    dry_run=dry_run,
                    client=client,
                    confirm=_install_confirm,
                )
        except KeyboardInterrupt:
            render_message(
                "interrupted; tools already installed are kept",
                no_color=no_color,
            )
            raise typer.Exit(code=int(ExitCode.INTERRUPTED)) from None
    finally:
        if client is not None:
            client.close()
    if outcomes:
        render_install(outcomes, dry_run=dry_run, console=make_console(no_color=no_color))
    for outcome in outcomes:
        if not outcome.ok and outcome.error:
            render_message(
                f"{outcome.tool}: {outcome.error}", console=make_console(no_color=no_color)
            )
    raise typer.Exit(code=code)


@app.command("install")
def install_command(
    tools: Annotated[list[str] | None, typer.Argument(help="Tools to install.")] = None,
    all_tools: Annotated[bool, typer.Option("--all", help="Install every core tool.")] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show actions without changing anything.")
    ] = False,
    config_path: Annotated[Path | None, typer.Option("--config", help="Config file path.")] = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colors.")] = False,
) -> None:
    _run_install(
        tools,
        all_tools,
        dry_run=dry_run,
        update=False,
        config_path=config_path,
        no_color=no_color,
    )


@app.command("update")
def update_command(
    tools: Annotated[list[str] | None, typer.Argument(help="Tools to update.")] = None,
    all_tools: Annotated[bool, typer.Option("--all", help="Update every installed tool.")] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show actions without changing anything.")
    ] = False,
    config_path: Annotated[Path | None, typer.Option("--config", help="Config file path.")] = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colors.")] = False,
) -> None:
    _run_install(
        tools,
        all_tools,
        dry_run=dry_run,
        update=True,
        config_path=config_path,
        no_color=no_color,
    )


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
