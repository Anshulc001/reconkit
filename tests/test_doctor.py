"""Doctor tests: readiness is reported without executing or installing anything."""

from __future__ import annotations

import io
import json
from collections.abc import Mapping
from pathlib import Path

from typer.testing import CliRunner

from reconkit import doctor
from reconkit.cli import app
from reconkit.config import load_config
from reconkit.doctor import (
    MISSING,
    NO_BINARY,
    WRONG_PROGRAM,
    DoctorReport,
    collect_report,
)
from reconkit.models import InstallStatus
from reconkit.ui import render_doctor

REPO = Path(__file__).resolve().parents[1]
CONFIG = load_config(REPO / "config.yaml")

TOOLS_YAML = """\
version: 1
system_packages: [jq, libpcap-dev]
tools:
  alpha: {stage: subs, kind: http, tier: core, mode: passive, phase: 2, install: {method: none}}
  beta: {stage: subs, kind: binary, tier: core, mode: passive, phase: 2, binary: beta,
         install: {method: apt, package: beta}, requires_apt: [libpcap-dev]}
  gamma: {stage: dns, kind: binary, tier: core, mode: passive, phase: 2, binary: gamma,
          install: {method: apt, package: gamma}}
  delta: {stage: dns, kind: http, tier: core, mode: passive, phase: 2, install: {method: none},
          keys: [{env: DELTA_KEY, url: "https://example.com/keys", adds: "higher limits"}]}
"""


def write_tools(tmp_path: Path) -> Path:
    path = tmp_path / "tools.yaml"
    path.write_text(TOOLS_YAML, encoding="utf-8")
    return path


def report_for(
    tmp_path: Path,
    *,
    statuses: Mapping[str, InstallStatus] | None = None,
    env: Mapping[str, str] | None = None,
) -> DoctorReport:
    mapping = statuses or {}
    return collect_report(
        config=CONFIG,
        tools_path=write_tools(tmp_path),
        env=env if env is not None else {},
        scope_path=tmp_path / "scope.yaml",
        dpkg_status=tmp_path / "dpkg-status",
        status_of=lambda spec: mapping.get(spec.name, InstallStatus(installed=False)),
    )


def test_every_tool_present_reports_no_missing_tools(tmp_path: Path) -> None:
    report = report_for(
        tmp_path,
        statuses={
            "beta": InstallStatus(installed=True, version="1.2.3", path=tmp_path / "beta"),
            "gamma": InstallStatus(installed=True, version="4.5.6", path=tmp_path / "gamma"),
        },
    )
    assert report.missing == 0
    assert report.warnings == ()
    coverage = {item.stage.name: (item.ready, item.total) for item in report.stages}
    assert coverage["SUBS"] == (2, 2)
    assert coverage["DNS"] == (2, 2)


def test_missing_binaries_are_counted_and_http_tools_need_nothing(tmp_path: Path) -> None:
    report = report_for(tmp_path)
    assert report.missing == 2
    row = {check.name: check for check in report.tools}
    assert row["alpha"].installed == "yes"
    assert row["alpha"].path == NO_BINARY
    assert row["beta"].installed == MISSING
    assert row["beta"].path == "-"
    coverage = {item.stage.name: (item.ready, item.total) for item in report.stages}
    assert coverage["SUBS"] == (1, 2)
    assert coverage["DNS"] == (1, 2)


def test_wrong_program_is_a_warning_not_a_missing_binary(tmp_path: Path) -> None:
    clash = tmp_path / "bin" / "beta"
    report = report_for(
        tmp_path,
        statuses={"beta": InstallStatus(installed=False, path=clash)},
    )
    row = {check.name: check for check in report.tools}
    assert row["beta"].installed == WRONG_PROGRAM
    assert row["beta"].path == str(clash)
    assert row["beta"].identity == "failed"
    assert report.missing == 2
    assert len(report.warnings) == 1
    assert str(clash) in report.warnings[0]
    assert "beta" in report.warnings[0]


def test_a_doctor_row_and_its_json_object_carry_no_version(tmp_path: Path) -> None:
    """2026-11-17 (D6): the probe's string decides identity, it is never shown."""
    report = report_for(
        tmp_path,
        statuses={"beta": InstallStatus(installed=True, version="1.2.3", path=tmp_path / "beta")},
    )
    row = {check.name: check for check in report.tools}
    assert row["beta"].installed == "yes"
    assert not hasattr(row["beta"], "version")
    stream = io.StringIO()
    render_doctor(report, json_output=True, stdout=stream)
    document = json.loads(stream.getvalue())
    first = document["tools"][0]
    assert first["tool"] == "alpha"
    assert set(first) == {"tool", "stage", "tier", "kind", "installed", "path", "identity"}
    assert "version" not in stream.getvalue()


def test_a_tool_without_an_adapter_is_probed_through_its_install_plan(
    monkeypatch, tmp_path: Path
) -> None:
    resolved = tmp_path / "bin" / "beta"
    monkeypatch.setattr(doctor, "installed_copy", lambda plan, directory: resolved)
    monkeypatch.setattr(doctor, "installed_version", lambda plan, directory: "beta 1.2")
    report = collect_report(
        config=CONFIG,
        tools_path=write_tools(tmp_path),
        env={},
        scope_path=tmp_path / "scope.yaml",
        dpkg_status=tmp_path / "dpkg-status",
    )
    beta = next(check for check in report.tools if check.name == "beta")
    assert beta.installed == "yes"
    assert beta.path == str(resolved)
    # The probe's string is the identity signal only; the row has no version field.
    assert not hasattr(beta, "version")


def test_a_failed_plan_probe_is_a_wrong_program_warning(monkeypatch, tmp_path: Path) -> None:
    resolved = tmp_path / "bin" / "beta"
    monkeypatch.setattr(doctor, "installed_copy", lambda plan, directory: resolved)
    monkeypatch.setattr(doctor, "installed_version", lambda plan, directory: None)
    report = collect_report(
        config=CONFIG,
        tools_path=write_tools(tmp_path),
        env={},
        scope_path=tmp_path / "scope.yaml",
        dpkg_status=tmp_path / "dpkg-status",
    )
    beta = next(check for check in report.tools if check.name == "beta")
    assert beta.installed == WRONG_PROGRAM
    assert any("not the expected program" in warning for warning in report.warnings)


def test_system_packages_come_from_the_registry_and_dpkg(tmp_path: Path) -> None:
    dpkg = tmp_path / "dpkg-status"
    dpkg.write_text(
        "Package: jq\nStatus: install ok installed\n\n"
        "Package: curl\nStatus: deinstall ok config-files\n",
        encoding="utf-8",
    )
    report = collect_report(
        config=CONFIG,
        tools_path=write_tools(tmp_path),
        env={},
        scope_path=tmp_path / "scope.yaml",
        dpkg_status=dpkg,
        status_of=lambda spec: InstallStatus(installed=False),
    )
    states = {item.package: item.state for item in report.packages}
    assert states == {"jq": "installed", "libpcap-dev": "missing"}


def test_system_packages_are_unknown_without_a_dpkg_database(tmp_path: Path) -> None:
    report = report_for(tmp_path)
    assert {item.state for item in report.packages} == {"unknown"}


def test_json_document_has_the_documented_shape(tmp_path: Path) -> None:
    report = report_for(
        tmp_path,
        env={"DELTA_KEY": "placeholder-value"},
        statuses={"beta": InstallStatus(installed=True, version="1.2.3", path=tmp_path / "beta")},
    )
    stream = io.StringIO()
    code = render_doctor(report, json_output=True, stdout=stream)
    assert code == 0
    document = json.loads(stream.getvalue())
    assert document["type"] == "doctor"
    assert document["exit_code"] == 0
    assert [tool["tool"] for tool in document["tools"]] == ["alpha", "beta", "delta", "gamma"]
    assert {stage["stage"] for stage in document["stages"]} == {"subs", "dns"}
    assert document["keys"] == [
        {
            "tool": "delta",
            "env": "DELTA_KEY",
            "set": True,
            "url": "https://example.com/keys",
            "adds": "higher limits",
        }
    ]
    assert "placeholder-value" not in stream.getvalue()


def test_missing_tools_keep_exit_code_zero(tmp_path: Path) -> None:
    report = report_for(tmp_path)
    stream = io.StringIO()
    assert render_doctor(report, stderr=stream) == 0
    text = stream.getvalue()
    assert (
        "Missing tools: 2. Scans will use the tools that are installed and skip the rest." in text
    )
    assert "Per-tool provenance: docs/10_TOOL_SOURCES.md." in text
    assert "Install them yourself" not in text
    assert "reconkit install --all" not in stream.getvalue()


def test_python_too_old_exits_one(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(doctor, "MIN_PYTHON", (9, 9))
    monkeypatch.setattr(doctor, "ADAPTERS", {})
    result = CliRunner().invoke(app, ["doctor", "--config", str(REPO / "config.yaml")])
    assert result.exit_code == 1
    assert "too old" in result.output


def test_unreadable_config_exits_one(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["doctor", "--config", str(tmp_path / "missing.yaml")])
    assert result.exit_code == 1
    assert "cannot read config file" in result.output


def test_doctor_json_writes_one_document(monkeypatch) -> None:
    monkeypatch.setattr(doctor, "ADAPTERS", {})
    result = CliRunner().invoke(app, ["doctor", "--json", "--config", str(REPO / "config.yaml")])
    assert result.exit_code == 0
    document = json.loads(result.output)
    assert document["type"] == "doctor"
    assert document["missing"] == sum(1 for tool in document["tools"] if tool["installed"] != "yes")


def test_chromium_row_reports_missing_when_no_browser_is_installed(
    tmp_path: Path, monkeypatch
) -> None:
    """D35: an absent browser is its own doctor row, not a silent 0 screenshots."""
    monkeypatch.setattr(doctor, "browser_state", lambda **_kwargs: MISSING)
    report = report_for(tmp_path)
    assert report.chromium == MISSING
    buffer = io.StringIO()
    render_doctor(report, stderr=buffer)
    assert "chromium" in buffer.getvalue()
    assert "shots will produce 0 screenshots" in buffer.getvalue()


def test_chromium_row_reports_installed_when_a_browser_exists(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(doctor, "browser_state", lambda **_kwargs: "yes")
    report = report_for(tmp_path)
    buffer = io.StringIO()
    render_doctor(report, stderr=buffer)
    assert "chromium" in buffer.getvalue()
    assert "shots will produce 0 screenshots" not in buffer.getvalue()


def test_browser_state_finds_only_the_browsers_gowitness_launches() -> None:
    """D35: gowitness execs google-chrome, so chromium alone must read missing.

    Measured on this box: /usr/bin/chromium exists and gowitness still reports
    `failed to initialize chrome context`. A row that said `yes` there would be
    a lie, so the check asks for the names gowitness actually launches.
    """
    assert doctor.browser_state(which=lambda name: None) == MISSING
    assert (
        doctor.browser_state(which=lambda name: "/usr/bin/x" if name == "chromium" else None)
        == MISSING
    )
    assert (
        doctor.browser_state(which=lambda name: "/usr/bin/x" if name == "google-chrome" else None)
        == "yes"
    )
    assert (
        doctor.browser_state(which=lambda name: "/usr/bin/x" if name == "chrome" else None) == "yes"
    )
