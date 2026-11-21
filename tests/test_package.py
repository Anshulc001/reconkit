"""Package smoke test."""

import shutil
import subprocess
import sys
from pathlib import Path

from reconkit import __version__

REPO = Path(__file__).resolve().parents[1]


def test_version_is_set() -> None:
    assert __version__ == "1.1.0"


def test_package_version_matches_pyproject() -> None:
    import tomllib

    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert __version__ == project["version"]


def _checkout(tmp_path: Path) -> Path:
    """A throwaway checkout with the real setup.sh and an empty registry."""
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(REPO / "scripts" / "setup.sh", root / "scripts")
    (root / "pyproject.toml").write_text("[project]\nname = 'reconkit'\n", encoding="utf-8")
    (root / "tools.yaml").write_text(
        'tools:\n  alpha: {kind: binary, binary: alpha, source: "apt: alpha"}\n',
        encoding="utf-8",
    )
    return root


def _stamp(root: Path) -> str:
    import hashlib

    return hashlib.sha256((root / "pyproject.toml").read_bytes()).hexdigest()


def _fake_python(root: Path, *, cli_import_ok: bool = True, pip_ok: bool = True) -> Path:
    """A python that logs every call, fakes pip, and delegates the rest.

    `setup.sh` must not reach the network in a test, but the registry plan is
    real Python (PyYAML), so only `pip install` and the CLI-import probe are
    answered locally; every other call runs the test interpreter.
    """
    log = root / "calls.log"
    script = root / "fake-python"
    script.write_text(
        "#!/bin/sh\n"
        f'echo "python $*" >> "{log}"\n'
        'case "$*" in\n'
        f'  *"-c import reconkit.cli"*) exit {0 if cli_import_ok else 1} ;;\n'
        f'  *"-m pip install"*) exit {0 if pip_ok else 1} ;;\n'
        "esac\n"
        f'exec "{sys.executable}" "$@"\n',
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _fake_venv(
    root: Path,
    *,
    stamp: str | None,
    cli_import_ok: bool = True,
    pip_ok: bool = True,
    reconkit_script: str | None = None,
) -> None:
    """A venv whose `python` is the logging wrapper.

    `.venv/bin/activate` prepends the fake bin directory, which is what the
    real activate script does; without it the bootstrap would reach the host
    python and install for real.
    """
    bin_dir = root / ".venv" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "activate").write_text(f'export PATH="{bin_dir}:$PATH"\n', encoding="utf-8")
    wrapper = _fake_python(root, cli_import_ok=cli_import_ok, pip_ok=pip_ok)
    shutil.copy(wrapper, bin_dir / "python")
    entry = bin_dir / "reconkit"
    entry.write_text(reconkit_script or "#!/bin/sh\nexit 0\n", encoding="utf-8")
    entry.chmod(0o755)
    if stamp is not None:
        (root / ".venv" / ".reconkit-deps").write_text(stamp, encoding="utf-8")


def _calls(root: Path) -> list[str]:
    log = root / "calls.log"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def _run_setup(root: Path, *args: str, extra_path: Path | None = None):
    path = [str(extra_path)] if extra_path else []
    path += [str(Path(sys.executable).parent), "/usr/bin", "/bin"]
    return subprocess.run(
        ["bash", str(root / "scripts" / "setup.sh"), *args],
        cwd=root,
        capture_output=True,
        text=True,
        env={"PATH": ":".join(path), "HOME": str(root)},
        check=False,
    )


def test_install_plan_checks_each_tool_by_its_own_name(tmp_path: Path) -> None:
    """A plan row must carry its own registry name, not the loop's last one.

    2026-11-20: the planner printed the final `name` for every row, so the
    script asked doctor about one tool (alphabetically last) for all of them.
    On a machine where that tool was installed, every row printed `have`,
    nothing was installed, and doctor then reported 23 missing.
    """
    root = _checkout(tmp_path)
    (root / "tools.yaml").write_text(
        "tools:\n"
        "  alpha: {kind: binary, binary: alpha, "
        'source: "go install github.com/example/alpha@latest"}\n'
        '  zulu: {kind: binary, binary: zulu, source: "apt: zulu"}\n',
        encoding="utf-8",
    )
    doctor = (
        "#!" + sys.executable + "\n"
        "import json\n"
        "print(json.dumps({'tools': [\n"
        "    {'tool': 'alpha', 'kind': 'binary', 'installed': 'missing'},\n"
        "    {'tool': 'zulu', 'kind': 'binary', 'installed': 'yes'},\n"
        "]}))\n"
    )
    _fake_venv(root, stamp=_stamp(root), reconkit_script=doctor)
    result = _run_setup(root, "--check")
    assert result.returncode == 0, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    assert any(line.startswith("have") and "zulu" in line for line in lines), lines
    assert any(line.startswith("go") and "alpha" in line for line in lines), lines


def test_setup_bootstraps_a_fresh_checkout(tmp_path: Path) -> None:
    root = _checkout(tmp_path)
    fakebin = root / "fakebin"
    fakebin.mkdir()
    log = root / "calls.log"
    wrapper = _fake_python(root)
    python3 = fakebin / "python3"
    python3.write_text(
        "#!/bin/sh\n"
        f'echo "python3 $*" >> "{log}"\n'
        'if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then\n'
        '  mkdir -p "$3/bin"\n'
        f'  cp "{wrapper}" "$3/bin/python"\n'
        '  chmod +x "$3/bin/python"\n'
        '  printf \'export PATH="%s/bin:$PATH"\\n\' "$3" > "$3/bin/activate"\n'
        "  printf '#!/bin/sh\\nexit 0\\n' > \"$3/bin/reconkit\"\n"
        '  chmod +x "$3/bin/reconkit"\n'
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    python3.chmod(0o755)
    result = _run_setup(root, "--check", extra_path=fakebin)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "== environment: venv + reconkit ==" in result.stdout
    assert (root / ".venv" / ".reconkit-deps").read_text(encoding="utf-8").strip() == _stamp(root)
    assert "check only" in result.stdout


def test_setup_skips_environment_when_the_venv_matches_pyproject(tmp_path: Path) -> None:
    root = _checkout(tmp_path)
    _fake_venv(root, stamp=_stamp(root))
    result = _run_setup(root, "--check")
    assert result.returncode == 0, result.stdout + result.stderr
    assert not [line for line in _calls(root) if "pip install" in line], _calls(root)
    assert "check only" in result.stdout


def test_regression_setup_rebootstraps_a_venv_without_a_stamp(tmp_path: Path) -> None:
    """D108: an existing venv must be re-synced after a pull adds a dependency.

    `setup.sh` used to bootstrap only when `.venv/bin/reconkit` was missing, so
    the `reportlab` dependency added in D107 never reached an existing venv and
    `reconkit doctor` died with ModuleNotFoundError. A venv with no install
    stamp (every venv created before this fix) is stale by definition.
    """
    root = _checkout(tmp_path)
    _fake_venv(root, stamp=None)
    result = _run_setup(root, "--check")
    assert result.returncode == 0, result.stdout + result.stderr
    assert any("pip install -e" in line for line in _calls(root)), _calls(root)
    assert (root / ".venv" / ".reconkit-deps").read_text(encoding="utf-8").strip() == _stamp(root)


def test_regression_setup_rebootstraps_when_pyproject_changes(tmp_path: Path) -> None:
    root = _checkout(tmp_path)
    _fake_venv(root, stamp="0" * 64)
    result = _run_setup(root, "--check")
    assert result.returncode == 0, result.stdout + result.stderr
    assert any("pip install -e" in line for line in _calls(root)), _calls(root)


def test_regression_setup_rebootstraps_when_the_cli_import_fails(tmp_path: Path) -> None:
    """A matching stamp does not prove the install finished: repair and fail loudly."""
    root = _checkout(tmp_path)
    _fake_venv(root, stamp=_stamp(root), cli_import_ok=False, pip_ok=False)
    result = _run_setup(root, "--check")
    assert result.returncode == 1
    assert "environment setup failed" in result.stderr
    assert any("pip install" in line for line in _calls(root)), _calls(root)


def test_regression_setup_does_not_use_awk() -> None:
    """Minimal Kali/Debian images do not ship `awk` (PIT-38).

    The old bootstrap ended with `python --version | awk '{print $2}'`, so a
    complete install exited 1 in a container with no `awk`. The setup script
    may rely only on utilities a minimal image has, or install them itself.
    """
    import re

    lines = (REPO / "scripts" / "setup.sh").read_text(encoding="utf-8").splitlines()
    code = [line for line in lines if not line.lstrip().startswith("#")]
    offenders = [line for line in code if re.search(r"\bawk\b", line)]
    assert not offenders, offenders


def test_documented_scripts_are_executable() -> None:
    """A fresh clone must be able to run the script the README names.

    Git stores the mode, not the checkout's filesystem: a script committed as
    100644 fails with Permission denied for every new user, and
    `core.fileMode=false` (this repo's setting) silently records a new file as
    100644 even when it is +x on disk. Check the index git will hand a fresh
    clone.
    """
    import stat

    scripts = REPO / "scripts"
    names = ("setup.sh",)
    for name in names:
        mode = (scripts / name).stat().st_mode
        assert mode & stat.S_IXUSR, f"{name} is not executable in the checkout"
    if (REPO / ".git").exists() and shutil.which("git"):
        listed = subprocess.run(
            ["git", "ls-files", "-s", *[f"scripts/{name}" for name in names]],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        recorded = {
            line.split("\t", 1)[1]: line.split("\t", 1)[0].split()[0]
            for line in listed.splitlines()
            if "\t" in line
        }
        for name in names:
            assert recorded.get(f"scripts/{name}") == "100755", (
                f"scripts/{name} is {recorded.get(f'scripts/{name}')} in the git index; "
                "run `git update-index --chmod=+x scripts/%s`" % name
            )
