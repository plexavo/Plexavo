"""plexavo/interactive.py — interactive terminal experience.

Launched when `plexavo` is run with no subcommand in a real terminal.
This is additive: `plexavo scan --profile ... --report-html ...` (the
scripting/CI path documented in the README) never touches this module
and keeps working exactly as before.

Built in slices — see plexavo-journal.md for what's live so far.
Slice 1: splash screen. Slice 2: profile picker + live status check.
Slice 3: new-profile write flow.
"""

from __future__ import annotations

import boto3
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.text import Text

from plexavo import __version__
from plexavo.auth import get_local_session
from plexavo.aws_profile_setup import write_profile

WEBSITE = "https://plexavo.com"
NEW_PROFILE_CHOICE = "+ Configure new profile"

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


def _prompt_profile_menu(console: Console) -> str | None:
    """Numbered profile menu — plain line-buffered input (type a number,
    press Enter), not a live arrow-key redraw. Deliberate choice: the
    prompt_toolkit-based arrow-key menu this replaced was unreliable
    across Windows terminal hosts (desyncs, missed keys, sometimes never
    registering) — this is immune to that whole class of bug."""
    profiles = sorted(boto3.Session().available_profiles)
    if not profiles:
        console.print("[grey62]No AWS profiles found in ~/.aws/credentials or ~/.aws/config.[/grey62]\n")

    options = list(profiles) + [NEW_PROFILE_CHOICE]

    console.print("[bold]Select an AWS profile to scan:[/bold]\n")
    for i, name in enumerate(options, start=1):
        console.print(f"  [bold green]{i}[/bold green]  {name}")
    console.print()

    try:
        choice = IntPrompt.ask(
            "Enter a number",
            choices=[str(i) for i in range(1, len(options) + 1)],
            show_choices=False,
            console=console,
        )
    except (KeyboardInterrupt, EOFError):
        return None

    return options[choice - 1]


def _prompt_new_profile(console: Console) -> str | None:
    """Collects Access Key ID / Secret Access Key (masked) / region /
    profile name, writes them to ~/.aws/credentials + ~/.aws/config
    (plexavo.aws_profile_setup.write_profile — same layout `aws
    configure` itself produces), and returns the new profile's name for
    the caller to auto-select. Returns None on cancel (Ctrl+C/EOF) or
    if either key field is left empty.
    """
    console.print("\n[bold]Configure a new AWS profile[/bold]\n")
    existing = set(boto3.Session().available_profiles)

    try:
        while True:
            name = Prompt.ask("Profile name", console=console).strip()
            if not name:
                console.print("[red]Profile name can't be empty.[/red]")
                continue
            if name in existing and not Confirm.ask(
                f"Profile '{name}' already exists — overwrite it?",
                console=console, default=False,
            ):
                continue
            break

        access_key = Prompt.ask("AWS Access Key ID", console=console).strip()
        secret_key = Prompt.ask("AWS Secret Access Key", password=True, console=console).strip()
        region = Prompt.ask("Default region", default="us-east-1", console=console).strip()
    except (KeyboardInterrupt, EOFError):
        return None

    if not access_key or not secret_key:
        console.print("[red]Access key and secret key are both required — cancelled.[/red]")
        return None

    write_profile(name, access_key, secret_key, region)
    console.print(f"\n[green]Saved profile '{name}' to ~/.aws/credentials and ~/.aws/config.[/green]")
    return name


def _check_profile(console: Console, profile_name: str) -> boto3.Session | None:
    """Live sts get_caller_identity status check.

    Returns the validated session on success, None on failure — reuses
    auth.get_local_session so this is the exact same validation the real
    scan uses, just surfaced here instead of discovered mid-scan.
    """
    with console.status(f"[grey62]Checking '{profile_name}'...[/grey62]"):
        try:
            session = get_local_session(profile_name=profile_name)
        except RuntimeError as e:
            error = str(e)
        else:
            error = None

    if error is not None:
        console.print(Panel(
            f"[bold red]✗ Failed[/bold red]\n\n{error}",
            border_style="red", box=box.ROUNDED,
        ))
        return None

    identity = session.client("sts").get_caller_identity()
    console.print(Panel(
        f"[bold green]✓ Active[/bold green]\n\n"
        f"Account: {identity['Account']}\n"
        f"ARN: {identity['Arn']}\n"
        f"Region: {session.region_name}",
        border_style="green", box=box.ROUNDED,
    ))
    return session


def run_interactive() -> None:
    """Entry point for bare `plexavo` in a real terminal.

    Slice 1: splash screen. Slice 2: profile picker + live status check.
    Slice 3: new-profile write flow. Report options and the scan flow
    itself land in later slices.
    """
    console = Console()
    show_splash(console)

    while True:
        choice = _prompt_profile_menu(console)
        if choice is None:
            console.print("[dim]Cancelled.[/dim]")
            return

        if choice == NEW_PROFILE_CHOICE:
            choice = _prompt_new_profile(console)
            if choice is None:
                continue

        console.print()
        session = _check_profile(console, choice)
        if session is None:
            continue

        console.print("[dim]Profile confirmed. Report options and the scan "
                       "flow itself land in the next slices.[/dim]")
        return
