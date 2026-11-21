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

DEVELOPERS = "Pritam & Anshul"
TAGLINE = "Advanced Reconnaissance Framework"

# The width is fixed: the banner is branding, not a responsive table, and a
# half-drawn logo reads as broken output.
BANNER_ART = r"""██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗██╗████████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║ ██╔╝██║╚══██╔══╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╔╝ ██║   ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔═██╗ ██║   ██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██╗██║   ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝   ╚═╝"""

_SEPARATOR_WIDTH = 72


def banner_text() -> Text:
    """The banner as styled Rich text: art, wordmark, credits, version."""

    text = Text()
    text.append(BANNER_ART, style="bold cyan")
    text.append("\n\n")
    text.append("RECONKIT", style="bold white")
    text.append("   ")
    text.append(TAGLINE, style="italic grey70")
    text.append("\n")
    text.append(f"Made with ♥ by {DEVELOPERS}", style="green")
    text.append("\n")
    text.append(f"Version: {__version__}", style="yellow")
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
