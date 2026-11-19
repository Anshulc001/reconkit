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
