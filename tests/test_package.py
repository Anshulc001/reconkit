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
    import stat
    from pathlib import Path

    scripts = Path(__file__).resolve().parents[1] / "scripts"
    for name in ("bootstrap.sh", "install-tools.sh"):
        mode = (scripts / name).stat().st_mode
        assert mode & stat.S_IXUSR, f"{name} is not executable in the checkout"
