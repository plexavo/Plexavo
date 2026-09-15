"""report/json_report.py — machine-readable JSON output, additive
alongside the existing HTML/PDF reports (see html_report.py). Built for
agent/orchestration callers (the Claude Code Agent Skill this feeds) that
need a stable, parseable shape rather than rendered markup.

This module never computes anything new. It reuses the exact same
findings/score/chain objects every report already gets from _run_scan,
including _chain_report_views (the same chain-dedup/badge logic the HTML
Important tab uses) — a JSON consumer must see the identical picture a
human reading the HTML report would, never a second, independently
derived interpretation.

schema_version is bumped only on a breaking shape change, so a consumer
(the Skill) can pin to a known version and fail loudly instead of
silently misparsing a future release.
"""

from datetime import datetime, timezone

from plexavo import __version__
from plexavo.report.html_report import _chain_report_views

SCHEMA_VERSION = "1.0"

# Limitations that must stay disclosed in every surface Plexavo ships,
# this one included — never let a machine-readable summary imply broader
# coverage than what actually ran, per the no-optics-tuning rule.
DISCLOSED_LIMITATIONS = [
    "Attack-path detection covers single-account chains only, matched against "
    "two hardcoded templates — not an exhaustive graph traversal.",
    "Privilege-escalation detection is one-hop only.",
    "Cross-account trust resolution is not performed.",
]


def build_json_report(findings, score_result, account_id, explanations=None, chains=None) -> dict:
    """Same inputs as html_report.build_report_data — a second view over
    the identical scan output, not a second computation of it.

    Findings are ordered most-severe-first (Critical -> Low), matching how
    the HTML report groups them, so a consumer presenting "top findings
    first" doesn't need to re-sort. Where a resource has more than one
    finding, `findings_by_resource_arn` (used to back attack-chain nodes
    with real finding content) keeps the most severe one, same rule
    build_report_data uses.
    """
    if explanations is None:
        explanations = [None] * len(findings)
    if len(explanations) != len(findings):
        raise ValueError(
            f"explanations must be the same length as findings ({len(findings)}), "
            f"got {len(explanations)} — pass None for any unexplained finding, not a shorter list"
        )

    paired = sorted(zip(findings, explanations), key=lambda pair: -pair[0].severity.rank)

    findings_view = []
    findings_by_resource_arn = {}
    for f, exp in paired:
        if exp is not None:
            impact, how_to_fix, next_step = exp.impact, exp.how_to_fix, exp.next_step
            # Same derivation build_report_data uses: judged from actual
            # content, not exp.source, so "fallback"/"api-unparsed" (which
            # carry the same empty how_to_fix/next_step shape as "never
            # attempted") don't falsely claim to be explained.
            explained = bool(how_to_fix) and bool(next_step)
        else:
            impact, how_to_fix, next_step, explained = f.raw_detail, "", "", False

        entry = {
            "check_id": f.check_id,
            "title": f.title,
            "severity": f.severity.value,
            "resource": f.resource_arn.rsplit("/", 1)[-1] if "/" in f.resource_arn else f.resource_arn,
            "resource_arn": f.resource_arn,
            "confidence": f.confidence,
            "evidence": f.evidence,
            "impact": impact,
            "explained": explained,
            "next_step": next_step,
            "how_to_fix": how_to_fix,
            "chain_breaks_count": f.chain_breaks_count,
        }
        findings_view.append(entry)
        findings_by_resource_arn.setdefault(f.resource_arn, entry)

    chains_view, important_findings = _chain_report_views(chains or [], findings_by_resource_arn)

    return {
        "schema_version": SCHEMA_VERSION,
        "plexavo_version": __version__,
        "account_id": account_id,
        "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "score": score_result.score,
        "rating": score_result.rating,
        "summary_line": score_result.summary_line(),
        "counts_by_severity": score_result.counts_by_severity,
        "counts_by_category": score_result.counts_by_category,
        "total_findings": score_result.total_findings,
        "findings": findings_view,
        "attack_chains": chains_view,
        "important_findings": important_findings,
        "disclosed_limitations": DISCLOSED_LIMITATIONS,
    }
