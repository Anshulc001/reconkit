"""Terminal branding for reconkit (docs/02_CLI_UX.md section 1).

The banner is printed once per human scan invocation, never from adapters or
child processes, and never when stdout/stderr must stay machine-readable
(``--json``/``--silent``). The version comes from ``reconkit.__version__``, the
same value ``reconkit --version`` prints.
"""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from reconkit import __version__
from reconkit.ui import make_console

DEVELOPERS = "Anshul"
TAGLINE = "Advanced Reconnaissance Framework"

# The wordmark is figlet's "slant" face: five lines, a 50-column budget. The
# width is fixed - the banner is branding, not a responsive table, and a
# half-drawn logo reads as broken output.
BANNER_ART = r"""    ____  ________________  _   ____ __ __________
   / __ \/ ____/ ____/ __ \/ | / / //_//  _/_  __/
  / /_/ / __/ / /   / / / /  |/ / ,<   / /  / /
 / _, _/ /___/ /___/ /_/ / /|  / /| |_/ /  / /
/_/ |_/_____/\____/\____/_/ |_/_/ |_/___/ /_/"""

# One colour stop per art line (cyan -> violet), so the wordmark reads as one
# gradient instead of five unrelated colours. --no-color keeps the art and
# drops only this.
_ART_COLORS = ("#22d3ee", "#38bdf8", "#60a5fa", "#818cf8", "#a78bfa")

_SEPARATOR_WIDTH = 72


def banner_text() -> Text:
    """The banner as styled Rich text: wordmark, tagline, credit, version."""

    text = Text()
    for line, color in zip(BANNER_ART.splitlines(), _ART_COLORS, strict=True):
        text.append(line, style=f"bold {color}")
        text.append("\n")
    text.append("\n")
    text.append(TAGLINE, style="bold grey70")
    text.append("\n")
    text.append(f"v{__version__}", style="bold white")
    text.append("  ·  ", style="grey37")
    text.append(f"made by {DEVELOPERS}", style="grey62")
    return text


def separator_text() -> Text:
    """A dim rule that closes the banner and separates it from scan output."""

    return Text("─" * _SEPARATOR_WIDTH, style="grey37")


def render_banner(console: Console | None = None, *, no_color: bool = False) -> None:
    """Print the banner and its separator to stderr.

    Stderr is deliberate: the banner must never become part of the ``--json``
    document or of a redirected result file on stdout (docs/02 section 5).
    """

    target = console if console is not None else make_console(no_color=no_color)
    target.print(banner_text())
    target.print(separator_text())
