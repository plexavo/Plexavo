"""report/html_report.py — Assembles findings + score into a single shared
data structure (build_report_data), then renders it as HTML via Jinja2
(generate_html). pdf.py consumes the SAME build_report_data output, so
the HTML and PDF outputs are driven from one consistent source rather
than two separate implementations that could silently drift apart.
"""

import os
import re
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup, escape

_TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def _markdown_inline(text: str) -> Markup:
    """Convert the two inline markdown forms Claude's output actually
    uses (**bold** and `inline code`) into real HTML, safely.

    Jinja2's plain {{ text }} output leaves ** and backticks as literal
    characters — they aren't HTML syntax, so nothing converts them.
    This escapes the raw text FIRST (protecting against any genuine
    <, >, & in the AI's output), then inserts the **only** HTML this
    function ever produces (<strong>/<code> tags it creates itself),
    and marks the result safe so Jinja2 doesn't re-escape those tags.

    A final pass strips any remaining, genuinely UNPAIRED ** or ` that
    survive the paired substitution above — confirmed against real
    output that Claude's markdown isn't always symmetrically paired
    (a stray closing ** with no matching open). Whatever survives the
    paired conversion by definition wasn't part of a matched pair, so
    it's noise, not content, and gets removed rather than left literal.

    Triple-backtick code fences are stripped first, separately — same
    reason as the PDF path: they share the backtick character with
    single-backtick inline code, and running the inline-code regex
    directly against fenced content partially matches inside the fence
    markers themselves."""
    escaped = str(escape(text))
    escaped = re.sub(r"```[a-zA-Z]*\n?", "", escaped)
    escaped = escaped.replace("```", "")
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)
    escaped = re.sub(r"`(.+?)`", r"<code>\1</code>", escaped)
    escaped = escaped.replace("**", "").replace("`", "")
    return Markup(escaped)


def build_report_data(findings, score_result, account_id, explanations=None):
    """Assemble the shared data structure both HTML and PDF generation
    read from.

    `explanations`, if given, must be a list the same length as
    `findings` (parallel, matched by index) — use None for any finding
    that wasn't explained (--explain wasn't passed, or --explain-limit
    cut it off before reaching that finding). Those fall back to the
    finding's raw technical detail instead of silently vanishing from
    the report.
    """
    if explanations is None:
        explanations = [None] * len(findings)
    if len(explanations) != len(findings):
        raise ValueError(
            f"explanations must be the same length as findings ({len(findings)}), "
            f"got {len(explanations)} — pass None for any unexplained finding, not a shorter list"
        )

    findings_by_severity = {sev: [] for sev in SEVERITY_ORDER}
    for f, exp in zip(findings, explanations):
        # Confidence/evidence are Finding-level facts, set by the check's
        # own detection logic — they exist whether or not this finding
        # ever got AI/template narration, so they're read from `f`
        # directly, not from `exp`. `exp` only ever supplies prose.
        confidence, evidence = f.confidence, f.evidence

        if exp is not None:
            impact, how_to_fix, next_step = exp.impact, exp.how_to_fix, exp.next_step
            # Derived from actual content, not from exp.source: a
            # "fallback" or "api-unparsed" Explanation carries the same
            # empty how_to_fix/next_step shape as "never attempted," so
            # it renders through the same clean single-paragraph branch
            # below rather than a layout with empty sections. This keeps
            # the report-rendering contract in one place instead of also
            # matching against ai_narration.py's source-string values,
            # which could drift independently.
            explained = bool(how_to_fix) and bool(next_step)
        else:
            impact, how_to_fix, next_step, explained = f.raw_detail, "", "", False

        findings_by_severity[f.severity.value].append({
            "check_id": f.check_id,
            "resource": f.resource_arn.rsplit("/", 1)[-1] if "/" in f.resource_arn else f.resource_arn,
            "resource_arn": f.resource_arn,
            "impact": impact,
            "confidence": confidence,
            "evidence": evidence,
            "next_step": next_step,
            "how_to_fix": how_to_fix,
            "explained": explained,
        })

    return {
        "account_id": account_id,
        "scan_date": datetime.now(timezone.utc).strftime("%B %d, %Y"),
        "score": score_result.score,
        "rating": score_result.rating,
        "summary_line": score_result.summary_line(),
        "counts_by_severity": score_result.counts_by_severity,
        "counts_by_category": score_result.counts_by_category,
        "total_findings": score_result.total_findings,
        "findings_by_severity": findings_by_severity,
        "severity_order": SEVERITY_ORDER,
    }


def generate_html(report_data: dict) -> str:
    """Render report_data through the Jinja2 template into a complete
    HTML document string."""
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["markdown_inline"] = _markdown_inline
    template = env.get_template("report.html.j2")
    return template.render(**report_data)
