"""D107/D124: terminal branding (docs/02 section 1)."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

from rich.console import Console

from reconkit import __version__
from reconkit.branding import (
    BANNER_ART,
    DEVELOPERS,
    TAGLINE,
    banner_text,
    render_banner,
    separator_text,
)

# The contributor the project no longer credits. Split so the guard that keeps
# the name out of the tree does not smuggle it back in itself.
_REMOVED_NAME = "Pri" + "tam"
_SCAN_SUFFIXES = {".py", ".md", ".yaml", ".toml", ".sh"}


def test_banner_shows_the_wordmark_tagline_credit_and_live_version() -> None:
    text = banner_text().plain
    assert BANNER_ART.splitlines()[0] in text
    assert TAGLINE in text
    assert DEVELOPERS == "Anshul"
    assert f"by {DEVELOPERS}" in text
    # The banner must follow the package version, not a hard-coded string.
    assert f"v{__version__}" in text


def test_banner_wordmark_is_five_lines_within_the_width_budget() -> None:
    lines = BANNER_ART.splitlines()
    assert len(lines) == 5
    assert max(len(line) for line in lines) <= 50


def test_separator_is_a_rule_not_a_table() -> None:
    assert set(separator_text().plain) == {"─"}


def test_render_banner_writes_to_the_given_console() -> None:
    stream = StringIO()
    console = Console(file=stream, force_terminal=False, width=100)
    render_banner(console)
    written = stream.getvalue()
    assert TAGLINE in written
    assert __version__ in written
    assert "─" in written


def _scanned_files(root: Path) -> list[Path]:
    """The hand-written text of the project, without fixtures or the venv."""

    candidates = [
        root / name
        for name in (
            "README.md",
            "AGENTS.md",
            "COMMANDS.md",
            "SETUP.md",
            "pyproject.toml",
            "config.yaml",
            "tools.yaml",
        )
    ]
    for directory in ("docs", "src", "tests", "scripts"):
        candidates.extend((root / directory).rglob("*"))
    return [path for path in candidates if path.is_file() and path.suffix in _SCAN_SUFFIXES]


def test_the_removed_contributor_is_not_named_anywhere() -> None:
    """D124: the credit is the owner's alone, in banner, docs and reports."""

    root = Path(__file__).resolve().parents[1]
    offenders = [
        str(path.relative_to(root))
        for path in _scanned_files(root)
        if _REMOVED_NAME.lower() in path.read_text(encoding="utf-8", errors="ignore").lower()
    ]
    assert offenders == []
