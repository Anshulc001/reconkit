"""Package smoke test."""

from reconkit import __version__


def test_version_is_set() -> None:
    assert __version__ == "1.0.0"


def test_package_version_matches_pyproject() -> None:
    import tomllib
    from pathlib import Path

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    project = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]
    assert __version__ == project["version"]


def test_install_plan_checks_each_tool_by_its_own_name(tmp_path) -> None:
    """A plan row must carry its own registry name, not the loop's last one.

    2026-11-20: the planner printed the final `name` for every row, so
    install-tools.sh asked doctor about one tool (alphabetically last) for all
    of them. On a machine where that tool was installed, every row printed
    `have`, nothing was installed, and doctor then reported 23 missing.
    """
    import shutil
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    (tmp_path / "scripts").mkdir()
    shutil.copy(root / "scripts" / "install-tools.sh", tmp_path / "scripts")
    (tmp_path / "tools.yaml").write_text(
        "tools:\n"
        "  alpha: {kind: binary, binary: alpha, "
        'source: "go install github.com/example/alpha@latest"}\n'
        '  zulu: {kind: binary, binary: zulu, source: "apt: zulu"}\n',
        encoding="utf-8",
    )
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    reconkit = fakebin / "reconkit"
    reconkit.write_text(
        "#!" + sys.executable + "\n"
        "import json\n"
        "print(json.dumps({'tools': [\n"
        "    {'tool': 'alpha', 'kind': 'binary', 'installed': 'missing'},\n"
        "    {'tool': 'zulu', 'kind': 'binary', 'installed': 'yes'},\n"
        "]}))\n",
        encoding="utf-8",
    )
    reconkit.chmod(0o755)
    env = {
        "PATH": f"{fakebin}:{Path(sys.executable).parent}:/usr/bin:/bin",
        "HOME": str(tmp_path),
    }
    result = subprocess.run(
        ["bash", str(tmp_path / "scripts" / "install-tools.sh"), "--check"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    lines = result.stdout.splitlines()
    assert any(line.startswith("have") and "zulu" in line for line in lines), lines
    assert any(line.startswith("go") and "alpha" in line for line in lines), lines


def test_documented_scripts_are_executable() -> None:
    """A fresh clone must be able to run the scripts the README names.

    Git stores the mode, not the checkout's filesystem: `install-tools.sh` was
    committed as 100644 while `bootstrap.sh` was 100755, so `./scripts/
    install-tools.sh` failed with Permission denied for every new user.
    """
    import shutil
    import stat
    import subprocess
    from pathlib import Path

    scripts = Path(__file__).resolve().parents[1] / "scripts"
    names = ("bootstrap.sh", "install-tools.sh", "setup.sh")
    for name in names:
        mode = (scripts / name).stat().st_mode
        assert mode & stat.S_IXUSR, f"{name} is not executable in the checkout"
    # The checkout mode is not enough: `core.fileMode=false` (this repo's
    # setting) silently records a new file as 100644 even when it is +x on
    # disk, which is how `setup.sh` first landed. Check the index git will hand
    # a fresh clone.
    root = scripts.parent
    if (root / ".git").exists() and shutil.which("git"):
        listed = subprocess.run(
            ["git", "ls-files", "-s", *[f"scripts/{name}" for name in names]],
            cwd=root,
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
