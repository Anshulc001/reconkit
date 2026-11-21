"""D107: terminal branding (docs/02 section 1)."""

from __future__ import annotations

from io import StringIO

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


def test_banner_names_the_tool_credits_and_live_version() -> None:
    text = banner_text().plain
    assert BANNER_ART.splitlines()[0] in text
    assert "RECONKIT" in text
    assert TAGLINE in text
    assert "Pritam & Anshul" == DEVELOPERS
    assert DEVELOPERS in text
    # The banner must follow the package version, not a hard-coded string.
    assert f"Version: {__version__}" in text


def test_separator_is_a_rule_not_a_table() -> None:
    assert set(separator_text().plain) == {"─"}


def test_render_banner_writes_to_the_given_console() -> None:
    stream = StringIO()
    console = Console(file=stream, force_terminal=False, width=100)
    render_banner(console)
    written = stream.getvalue()
    assert "RECONKIT" in written
    assert __version__ in written
    assert "─" in written
