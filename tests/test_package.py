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
