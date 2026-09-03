#!/usr/bin/env python3
"""plexavo/cli.py — entry point for the installed `plexavo` command.

Usage:
    plexavo scan --profile my-aws-profile
    plexavo scan --profile my-aws-profile --explain --report-html out.html

No --profile → uses your default AWS credentials (same resolution order
as the AWS CLI: env vars, then the [default] profile). Nothing is ever
handed to anyone else — this runs entirely with your own local
credentials, the same way `aws s3 ls` does.
"""

import argparse
import os
import random
import sys
import time
from contextlib import nullcontext

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from plexavo import __version__
from plexavo.auth import get_local_session, get_account_id
from plexavo.principals import list_all_principals
from plexavo.checks import iam as iam_checks
from plexavo.checks import iam_hygiene
from plexavo.checks import network as network_checks
from plexavo.checks import storage as storage_checks
from plexavo.checks import encryption as encryption_checks
from plexavo.checks import logging as logging_checks
from plexavo.checks import usage as usage_checks
from plexavo.scoring import calculate_score
from plexavo.report.ai_narration import explain_finding, COMMON_CHECK_TEMPLATES
from plexavo.report.html_report import build_report_data, generate_html
from plexavo.report.pdf import generate_pdf

console = Console()

# Cloud-security-themed flavor words shown next to the spinner during a
# scan (real terminals only — see _run_scan's is_terminal branch). Each
# scan shuffles a fresh order so back-to-back runs don't feel identical.
FLAVOR_WORDS = [
    "Pondering privilege escalation paths",
    "Sweeping exposed security groups",
    "Auditing encryption at rest",
    "Cross-referencing CloudTrail history",
    "Hunting dormant credentials",
    "Tracing IAM trust relationships",
    "Probing public S3 exposure",
    "Checking GuardDuty coverage",
    "Weighing blast radius",
    "Chasing unused permissions",
    "Untangling trust policies",
    "Mapping the attack surface",
    "Interrogating access keys",
    "Scrutinizing bucket policies",
]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="plexavo",
        description="Plexavo — open-source AWS misconfiguration scanner. "
                     "Runs with your own local AWS credentials; nothing is sent to anyone else.",
    )
    parser.add_argument("--version", action="version", version=f"plexavo {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=False)
    scan = subparsers.add_parser("scan", help="Run a scan against one AWS account")

    scan.add_argument("--profile", default=None,
                       help="Named AWS profile to use (default: your default profile / env vars, "
                            "same resolution order as the AWS CLI)")
    scan.add_argument("--region", default=None,
                       help="AWS region to scan (default: your configured region)")
    scan.add_argument("--explain", action="store_true",
                       help="Generate a live AI narrative (WHAT'S WRONG / WHAT AN ATTACKER DOES / HOW TO FIX) for "
                            "every finding via the Anthropic API, using YOUR OWN ANTHROPIC_API_KEY and your own "
                            "account's credits (typically a few cents for a full scan) — never a project-owned "
                            "key. No key set, or a call fails for any reason? That finding falls back to raw "
                            "detail automatically, the scan never stops because of it. Off by default — without "
                            "it, findings still get free, no-API-key-needed remediation text wherever a template "
                            "exists (11 common check types); --explain always uses live AI instead, for every "
                            "finding, not just the non-templated ones.")
    scan.add_argument("--explain-limit", type=int, default=25,
                       help="Safety cap on how many findings get a live AI call when --explain is passed, in "
                            "case a scan turns up more than expected (default: 25). Doesn't affect the free "
                            "template remediation, which always applies to every eligible finding.")
    scan.add_argument("--report-html", metavar="PATH", default=None,
                       help="Write a self-contained, offline HTML report to PATH — no external requests, opens "
                            "anywhere. Includes free template remediation where available even without --explain; "
                            "--explain replaces that with a full AI narrative for every finding instead.")
    scan.add_argument("--report-pdf", metavar="PATH", default=None,
                       help="Write a PDF report to PATH. Same --explain behavior as --report-html.")
    return parser


def _run_scan(args) -> None:
    console.print(f"[bold]Using AWS profile:[/bold] {args.profile or '(default)'}")
    try:
        session = get_local_session(profile_name=args.profile, region=args.region)
    except RuntimeError as e:
        console.print(f"[bold red]Auth failed:[/bold red] {e}")
        sys.exit(1)

    account_id = get_account_id(session)
    console.print(f"[bold]Scanning account:[/bold] {account_id}")
    console.print(f"[bold]Region:[/bold] {session.region_name}\n")

    # Real terminal: a live spinner + rotating flavor word + running
    # stats, restyled each stage. Piped/non-terminal (CI, log capture):
    # console.status() produces ZERO output when console.is_terminal is
    # False (confirmed — Rich only renders it in real terminals), so
    # scripting users get the exact same plain progress lines as before,
    # not silence. This is a deliberate branch, not an oversight.
    is_tty = console.is_terminal
    findings = []
    principals = []
    stage_num = 0
    total_stages = 8
    start_time = time.monotonic()
    flavor_pool = FLAVOR_WORDS.copy()
    random.shuffle(flavor_pool)

    status = console.status("Starting scan...") if is_tty else None

    def stage(technical_label: str) -> None:
        nonlocal stage_num
        stage_num += 1
        if is_tty:
            elapsed = time.monotonic() - start_time
            word = flavor_pool[(stage_num - 1) % len(flavor_pool)]
            stats = (f"[grey50]{technical_label} · Stage {stage_num}/{total_stages} · "
                      f"Principals: {len(principals)} · Findings so far: {len(findings)} · "
                      f"Elapsed: {elapsed:0.0f}s[/grey50]")
            status.update(f"[grey74]{word}...[/grey74]\n{stats}")
        else:
            console.print(f"{technical_label}...")

    with status if is_tty else nullcontext():
        stage("Enumerating IAM principals")
        principals = list_all_principals(session)
        console.print(f"Found {len(principals)} principals ({sum(p.type == 'user' for p in principals)} users, "
                      f"{sum(p.type == 'role' for p in principals)} roles)\n")

        stage("Running checks IAM-01 through IAM-06")
        findings = iam_checks.run_all(session, principals)

        stage("Running checks IAM-07 through IAM-14 (hygiene)")
        findings += iam_hygiene.run_all(session, principals, account_id)

        stage("Running checks NET-01 through NET-04")
        findings += network_checks.run_all(session)

        stage("Running checks STOR-19 through STOR-21")
        findings += storage_checks.run_all(session)

        stage("Running checks ENC-29 through ENC-31")
        findings += encryption_checks.run_all(session)

        stage("Running checks LOG-22 through LOG-25")
        findings += logging_checks.run_all(session)

        stage("Running checks USE-26, USE-27 (usage analysis)")
        findings += usage_checks.run_all(session, principals)

    result = calculate_score(findings)
    rating_color = {"Excellent": "green", "Good": "green", "Fair": "yellow", "Poor": "orange3", "Critical": "red"}
    console.print(f"\n[bold {rating_color[result.rating]}]{result.summary_line()}[/bold {rating_color[result.rating]}]")
    if result.counts_by_category:
        breakdown = ", ".join(f"{cat}: {n}" for cat, n in sorted(result.counts_by_category.items()))
        console.print(f"By category — {breakdown}\n")
    else:
        console.print()

    if not findings:
        console.print("[green]No findings.[/green]")
        return

    table = Table(title=f"Findings ({len(findings)})")
    table.add_column("Check")
    table.add_column("Severity")
    table.add_column("Resource")
    table.add_column("Detail", overflow="fold")

    severity_color = {"Critical": "red", "High": "orange3", "Medium": "yellow", "Low": "white"}
    for f in findings:
        table.add_row(
            f.check_id,
            f"[{severity_color[f.severity.value]}]{f.severity.value}[/{severity_color[f.severity.value]}]",
            f.resource_arn.split("/")[-1],
            f.raw_detail,
        )
    console.print(table)

    # Built once, reused for both the console panels below and report
    # generation (if --report-html/--report-pdf) — explaining a finding
    # twice would mean two real API calls for the same finding, doubling
    # cost for no reason.
    explanations = [None] * len(findings)

    if args.explain:
        # AI on: every finding (up to --explain-limit) gets a live API
        # call, bypassing the free templates entirely — "AI narration on"
        # always means fully AI-written content, never a mix.
        to_explain = findings[:args.explain_limit]
        skipped = len(findings) - len(to_explain)
        console.print(f"\n[bold]Generating AI explanations for {len(to_explain)} finding(s)...[/bold]")
        if skipped:
            console.print(f"[yellow]{skipped} additional finding(s) skipped — raise --explain-limit to include them.[/yellow]")
        console.print("[dim]Uses your own ANTHROPIC_API_KEY, if set, and costs a few cents per finding "
                       "in your own account.[/dim]\n")
        for i, f in enumerate(to_explain):
            explanations[i] = explain_finding(f, use_ai=True)
    else:
        # AI off (default): free templates only, for every finding, no
        # network call, no key needed, no limit — this used to require
        # --explain just to see, at zero actual AI cost.
        console.print(f"\n[dim]Adding free remediation guidance where a template is available "
                       f"({len(COMMON_CHECK_TEMPLATES)} check types) — pass --explain for full AI-written "
                       f"explanations on every finding instead.[/dim]")
        for i, f in enumerate(findings):
            explanations[i] = explain_finding(f, use_ai=False)

    source_counts = {}
    for f, explanation in zip(findings, explanations):
        if explanation is None:
            continue
        source_counts[explanation.source] = source_counts.get(explanation.source, 0) + 1

        if explanation.source == "fallback":
            # Same clean content the report shows — no raw exception
            # text at the console either. This is what "no AI" looks
            # like whether that's because no key was set, the key
            # was invalid, or the call failed for any other reason.
            body = (f"[bold]{f.check_id}[/bold] — {f.resource_arn.split('/')[-1]}\n\n"
                    f"{explanation.impact}\n\n"
                    f"[dim]No AI narration for this finding — set ANTHROPIC_API_KEY for "
                    f"plain-English explanations, or see the raw detail above.[/dim]")
        else:
            confidence_style = "yellow" if explanation.confidence != "Confirmed" else "dim"
            body = (f"[bold]{f.check_id}[/bold] — {f.resource_arn.split('/')[-1]}\n\n"
                    f"[bold]IMPACT:[/bold] {explanation.impact}\n\n"
                    f"[{confidence_style}]CONFIDENCE: {explanation.confidence}[/{confidence_style}]\n\n")
            if explanation.evidence:
                body += f"[bold]EVIDENCE:[/bold] {explanation.evidence}\n\n"
            body += (f"[bold green]NEXT STEP:[/bold green] {explanation.next_step}\n\n"
                     f"[bold]FULL FIX DETAIL:[/bold] {explanation.how_to_fix}")

        console.print(Panel(
            body,
            border_style=severity_color.get(f.severity.value, "white"),
            title=f"[dim]source: {explanation.source}[/dim]",
        ))

    if source_counts:
        summary = ", ".join(f"{v} {k}" for k, v in source_counts.items())
        console.print(f"\n[dim]{summary}[/dim]")
        if source_counts.get("fallback"):
            console.print(
                "[dim]Some findings fell back to raw detail — this happens with no ANTHROPIC_API_KEY set, "
                "an invalid key, rate limiting, or a network issue. The scan and report are unaffected either way.[/dim]"
            )

    if args.report_html or args.report_pdf:
        if not args.explain:
            console.print("\n[yellow]Report includes free template remediation where available, raw technical "
                           "detail otherwise — pass --explain for full AI-written explanations on every "
                           "finding instead.[/yellow]")
        report_data = build_report_data(findings, result, account_id, explanations)

        if args.report_html:
            html = generate_html(report_data)
            with open(args.report_html, "w", encoding="utf-8") as f:
                f.write(html)
            # Absolute path, not the raw --report-html value — a bare name
            # like "report.html" is easy to lose track of otherwise; this
            # always says exactly where it landed.
            console.print(f"[green]HTML report written to {os.path.abspath(args.report_html)}[/green]")

        if args.report_pdf:
            generate_pdf(report_data, args.report_pdf)
            console.print(f"[green]PDF report written to {os.path.abspath(args.report_pdf)}[/green]")


def main():
    parser = _build_parser()
    args = parser.parse_args()
    if args.command == "scan":
        _run_scan(args)
    elif args.command is None:
        if sys.stdout.isatty():
            from plexavo.interactive import run_interactive
            run_interactive()
        else:
            parser.print_help()


if __name__ == "__main__":
    main()
