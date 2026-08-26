"""plexavo/interactive.py — interactive terminal experience.

Launched when `plexavo` is run with no subcommand in a real terminal.
This is additive: `plexavo scan --profile ... --report-html ...` (the
scripting/CI path documented in the README) never touches this module
and keeps working exactly as before.

Built in slices — see plexavo-journal.md for what's live so far.
Slice 1: splash screen only.
"""

from __future__ import annotations

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from plexavo import __version__

WEBSITE = "https://plexavo.com"

TIPS = [
    "Run without --profile to scan your default AWS credentials.",
    "Nothing you scan ever leaves this machine — no server in between.",
    "--explain adds plain-English narration; optional, a few cents per scan.",
]


def _splash_panel() -> Panel:
    header = Text()
    header.append("PLEXAVO", style="bold white")
    header.append("  ")
    header.append(f"v{__version__}", style="grey62")

    body = Text()
    body.append_text(header)
    body.append("\n")
    body.append("AWS Security Reimagined", style="italic grey74")
    body.append("\n")
    body.append(WEBSITE, style="underline grey62")
    body.append("\n\n")
    body.append("TIPS\n", style="bold grey74")
    for i, tip in enumerate(TIPS):
        body.append(f"  · {tip}", style="grey66")
        if i != len(TIPS) - 1:
            body.append("\n")

    return Panel(
        Align.center(body),
        border_style="grey50",
        box=box.ROUNDED,
        padding=(1, 4),
    )


def show_splash(console: Console) -> None:
    console.print()
    console.print(_splash_panel())
    console.print()


def run_interactive() -> None:
    """Entry point for bare `plexavo` in a real terminal.

    Slice 1 only: shows the splash screen. Profile selection, report
    options, and the scan flow itself land in later slices.
    """
    console = Console()
    show_splash(console)
