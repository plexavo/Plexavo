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

# Inline SVG per chain-node kind, shared by the Visual Attack Path stepper
# and the Important tab's card badges. Kept as pre-built Markup here
# (presentation-only, not detection logic) rather than duplicated as
# Jinja if/elif blocks in two places in the template.
NODE_ICONS = {
    "internet": Markup(
        '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6">'
        '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.8 2.6 4.2 5.7 4.2 9s-1.4 6.4-4.2 9c-2.8-2.6-4.2-5.7-4.2-9s1.4-6.4 4.2-9z"/></svg>'
    ),
    "ec2": Markup(
        '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6">'
        '<rect x="3.5" y="4" width="17" height="6.5" rx="1.2"/><rect x="3.5" y="13.5" width="17" height="6.5" rx="1.2"/>'
        '<circle cx="7" cy="7.25" r="0.9" fill="currentColor" stroke="none"/><circle cx="7" cy="16.75" r="0.9" fill="currentColor" stroke="none"/></svg>'
    ),
    "iam-role": Markup(
        '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6">'
        '<path d="M12 3l7 3v5c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6z"/><path d="M9.5 12l1.8 1.8L14.8 10"/></svg>'
    ),
    "s3": Markup(
        '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6">'
        '<ellipse cx="12" cy="6" rx="7.5" ry="2.6"/><path d="M4.5 6v11c0 1.4 3.4 2.6 7.5 2.6s7.5-1.2 7.5-2.6V6"/>'
        '<path d="M4.5 12c0 1.4 3.4 2.6 7.5 2.6s7.5-1.2 7.5-2.6"/></svg>'
    ),
}

CONNECTOR_ICON = Markup(
    '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8">'
    '<path d="M4 12h14M13 6l6 6-6 6"/></svg>'
)

RAIL_ICONS = {
    "path": Markup('<svg class="rail-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M4 12h4l2-6 4 12 2-6h4"/></svg>'),
    "important": Markup('<svg class="rail-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 3l2.4 5.3 5.6.6-4.2 3.9 1.2 5.7L12 15.8 6.9 18.5l1.2-5.7L4 8.9l5.6-.6z"/></svg>'),
    "all": Markup('<svg class="rail-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M5 4h14M5 10h14M5 16h9"/></svg>'),
}


def _slug(text: str) -> str:
    """Slug-friendly anchor fragment for the Important tab's card ids and
    the stepper's data-jump targets. Not a general-purpose slugifier —
    just enough to turn a resource id/name into a valid, stable HTML id."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "resource"


def _chain_report_views(chains, findings_by_resource_arn):
    """Turn attack_paths.AttackChain objects into the two view structures
    the template needs: chains_view (for the Visual Attack Path stepper)
    and important_cards (deduplicated across all chains — a node shared
    by two chains gets exactly one card, per the build plan's "Important
    is the cast of findings inside the chain narrative" framing).

    Where a node's resource is already independently flagged by an
    existing check (matched via finding_resource_arn against the real
    findings this scan produced), the card reuses that finding's real
    content — same check_id, impact, confidence, evidence. Where no
    existing check flags it (e.g. "this role is attached via an instance
    profile" isn't itself a check anywhere), the card is built from the
    node's own already-honest detail text instead, badged with the
    node's title rather than a fabricated check code - never inventing a
    check that doesn't exist, per the no-optics-tuning rule."""
    if not chains:
        return [], []

    # Imported here, not at module level, to avoid a needless import for
    # every report render that isn't touching chains at all.
    from plexavo.attack_paths import compute_chain_participation

    participation = compute_chain_participation(chains)
    total_chains = len(chains)

    chains_view = []
    seen_cards = {}
    important_cards = []

    for i, chain in enumerate(chains, start=1):
        nodes_view = []
        for node in chain.nodes:
            anchor = None
            if node.kind != "internet":
                anchor = f"chain-{node.kind}-{_slug(node.resource_id)}"
                key = (node.kind, node.resource_id)
                if key not in seen_cards:
                    backing = (
                        findings_by_resource_arn.get(node.finding_resource_arn)
                        if node.finding_resource_arn else None
                    )
                    if backing:
                        card = dict(backing)
                        card["badge"] = card["check_id"]
                    else:
                        card = {
                            "check_id": None,
                            "resource": node.resource_id,
                            "resource_arn": node.finding_resource_arn or "",
                            "impact": node.detail,
                            "confidence": None,
                            "evidence": "",
                            "next_step": "",
                            "how_to_fix": "",
                            "explained": False,
                            "badge": node.title,
                        }
                    card["anchor"] = anchor
                    card["breaks_count"] = participation.get(key, 0)
                    card["total_chains"] = total_chains
                    seen_cards[key] = card
                    important_cards.append(card)
            nodes_view.append({
                "kind": node.kind,
                "title": node.title,
                "detail": node.detail,
                "anchor": anchor,
            })
        chains_view.append({"number": i, "template": chain.template, "nodes": nodes_view})

    return chains_view, important_cards


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


def build_report_data(findings, score_result, account_id, explanations=None, chains=None):
    """Assemble the shared data structure both HTML and PDF generation
    read from.

    `explanations`, if given, must be a list the same length as
    `findings` (parallel, matched by index) — use None for any finding
    that wasn't explained (--explain wasn't passed, or --explain-limit
    cut it off before reaching that finding). Those fall back to the
    finding's raw technical detail instead of silently vanishing from
    the report.

    `chains`, if given, is the list of attack_paths.AttackChain objects
    this scan produced (already capped at MAX_CHAINS). Defaults to None
    so every existing caller (PDF generation, and any code not yet
    passing chains) keeps working unchanged and simply gets an empty
    Visual Attack Path / Important tab.
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
            "chain_breaks_count": f.chain_breaks_count,
        })

    # Highest-severity finding wins when a resource has more than one
    # (e.g. an instance flagged by both NET-01 and NET-03) — iterating in
    # SEVERITY_ORDER and using setdefault means the first one seen per
    # resource_arn is always the most severe.
    findings_by_resource_arn = {}
    for sev in SEVERITY_ORDER:
        for fd in findings_by_severity[sev]:
            findings_by_resource_arn.setdefault(fd["resource_arn"], fd)

    chains_view, important_cards = _chain_report_views(chains or [], findings_by_resource_arn)

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
        "chains": chains_view,
        "important_cards": important_cards,
    }


def generate_html(report_data: dict) -> str:
    """Render report_data through the Jinja2 template into a complete
    HTML document string."""
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["markdown_inline"] = _markdown_inline
    env.globals["node_icons"] = NODE_ICONS
    env.globals["connector_icon"] = CONNECTOR_ICON
    env.globals["rail_icons"] = RAIL_ICONS
    template = env.get_template("report.html.j2")
    return template.render(**report_data)
