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
    assert row["alpha"].version == NO_BINARY
    assert row["alpha"].path == NO_BINARY
    assert row["beta"].installed == MISSING
    assert row["beta"].version == "-"
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


def test_unparsable_version_is_reported_as_unknown(tmp_path: Path) -> None:
    report = report_for(
        tmp_path,
        statuses={"beta": InstallStatus(installed=True, version=None, path=tmp_path / "beta")},
    )
    row = {check.name: check for check in report.tools}
    assert row["beta"].version == "unknown"


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
    assert beta.version == "beta 1.2"
    assert beta.path == str(resolved)


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
    assert "Missing tools: 2. Run: reconkit install --all" in stream.getvalue()


def test_python_too_old_exits_one(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(doctor, "MIN_PYTHON", (9, 9))
    monkeypatch.setattr(doctor, "ADAPTERS", {})
    result = CliRunner().invoke(app, ["doctor", "--config", str(REPO / "config.yaml")])
    assert result.exit_code == 1
    assert "too old" in result.output


def test_fix_runs_the_installer(monkeypatch) -> None:
    calls: list[object] = []

    def fake_install_selected(plans, **kwargs):
        calls.append((list(plans), kwargs))
        return [], 0

    monkeypatch.setattr(doctor, "ADAPTERS", {})
    monkeypatch.setattr("reconkit.cli.install_selected", fake_install_selected)
    result = CliRunner().invoke(app, ["doctor", "--fix", "--config", str(REPO / "config.yaml")])
    assert result.exit_code == 0
    assert "--fix is not available yet" not in result.output
    assert calls, "--fix did not call the installer"


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
