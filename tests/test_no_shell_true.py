"""Static guards for subprocess safety (docs/05 section 4)."""

from __future__ import annotations

from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "reconkit"


def test_no_shell_true_or_os_system() -> None:
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "shell=True" not in text, path
        assert "os.system" not in text, path


def test_subprocess_imports_only_in_runner() -> None:
    for path in SRC.rglob("*.py"):
        if path.name == "runner.py":
            continue
        text = path.read_text(encoding="utf-8")
        assert "import subprocess" not in text, path
