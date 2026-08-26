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

import os

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

REPORT_FORMATS = [
    ("HTML report", "html"),
    ("PDF report", "pdf"),
    ("Both HTML and PDF", "both"),
    ("Console output only (no file)", "none"),
]

FEATURES = [
    "AI-powered remediation guidance for every finding",
    "IAM privilege escalation path mapping",
    "100% local scanning — your AWS credentials never leave this machine",
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
    body.append("FEATURES\n", style="bold grey74")
    for i, feature in enumerate(FEATURES):
        body.append(f"  · {feature}", style="grey66")
        if i != len(FEATURES) - 1:
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


def _check_profile(console: Console, profile_name: str) -> tuple[boto3.Session, dict] | None:
    """Live sts get_caller_identity status check.

    Returns (session, identity) on success, None on failure — reuses
    auth.get_local_session so this is the exact same validation the real
    scan uses, just surfaced here instead of discovered mid-scan. The
    identity dict is handed back so callers (the confirm+run summary)
    don't need a second sts call for the same information.
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
    return session, identity


def _prompt_report_options(console: Console) -> dict | None:
    """Report format + AI-narration choices. Returns None on cancel."""
    console.print("\n[bold]Report format:[/bold]\n")
    for i, (label, _) in enumerate(REPORT_FORMATS, start=1):
        console.print(f"  [bold green]{i}[/bold green]  {label}")
    console.print()

    try:
        idx = IntPrompt.ask(
            "Enter a number",
            choices=[str(i) for i in range(1, len(REPORT_FORMATS) + 1)],
            show_choices=False,
            console=console,
        )
        fmt = REPORT_FORMATS[idx - 1][1]

        report_html = None
        report_pdf = None
        if fmt != "none":
            console.print(
                "\n[grey62]Files save in the folder you launched plexavo from, unless "
                "you type a full path.[/grey62]"
            )
        if fmt in ("html", "both"):
            report_html = Prompt.ask("Name the HTML file", default="report.html", console=console).strip()
        if fmt in ("pdf", "both"):
            report_pdf = Prompt.ask("Name the PDF file", default="report.pdf", console=console).strip()

        console.print()
        key_present = bool(os.environ.get("ANTHROPIC_API_KEY"))
        if key_present:
            console.print("[bold green]✓ ANTHROPIC_API_KEY detected[/bold green] — full AI narration available.")
        else:
            console.print("[bold red]✗ ANTHROPIC_API_KEY not set[/bold red] — you'll still get free template "
                           "remediation for common findings; live AI narration needs a key.")
        explain = Confirm.ask(
            "Enable full AI narration for every finding? (off still includes free template remediation)",
            console=console, default=key_present,
        )
    except (KeyboardInterrupt, EOFError):
        return None

    return {"report_html": report_html, "report_pdf": report_pdf, "explain": explain}


def _confirm_and_run(console: Console, profile: str, identity: dict, session: boto3.Session, options: dict) -> bool:
    html_line = os.path.abspath(options["report_html"]) if options["report_html"] else "(skipped)"
    pdf_line = os.path.abspath(options["report_pdf"]) if options["report_pdf"] else "(skipped)"
    summary = (
        f"Profile: {profile}\n"
        f"Account: {identity['Account']}\n"
        f"Region: {session.region_name}\n"
        f"HTML report: {html_line}\n"
        f"PDF report: {pdf_line}\n"
        f"AI narration: {'on' if options['explain'] else 'off'}"
    )
    console.print()
    console.print(Panel(summary, title="Ready to scan", border_style="grey50", box=box.ROUNDED))

    try:
        return Confirm.ask("Run scan now?", console=console, default=True)
    except (KeyboardInterrupt, EOFError):
        return False


def run_interactive() -> None:
    """Entry point for bare `plexavo` in a real terminal.

    Slice 1: splash screen. Slice 2: profile picker + live status check.
    Slice 3: new-profile write flow. Slice 4: report options + confirm,
    wired into the existing cli._run_scan (no duplicated scan logic —
    interactive mode drives the exact same code path `plexavo scan`
    does, just fed answers gathered via prompts instead of flags).
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
        result = _check_profile(console, choice)
        if result is None:
            continue

        session, identity = result
        break

    profile = choice
    while True:
        options = _prompt_report_options(console)
        if options is None:
            console.print("[dim]Cancelled.[/dim]")
            return

        if _confirm_and_run(console, profile, identity, session, options):
            break
        # Declined — loop back and let them re-pick report options.

    console.print()
    from plexavo.cli import _run_scan  # lazy: avoids a top-level circular import with cli.py
    import argparse

    _run_scan(argparse.Namespace(
        profile=profile,
        region=None,
        explain=options["explain"],
        explain_limit=25,
        report_html=options["report_html"],
        report_pdf=options["report_pdf"],
    ))
