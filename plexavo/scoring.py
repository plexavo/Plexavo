"""Single Security Score (0-100) — blueprint Part 3, Difference 4.

Pure arithmetic on already-collected findings. No AWS calls, so no
Terraform ground truth needed — verified with unit tests only, same as
any pure-function code would be.

Rating bands are my own calibration, anchored against the one worked
example the blueprint actually gives: "34/100 (Poor)". The band edges
below are chosen so 34 lands in "Poor" — see test_scoring.py, which
checks this exact example explicitly, not just the boundary math.
"""

from dataclasses import dataclass

from plexavo.findings import Finding, Severity

RATING_BANDS = [
    (90, "Excellent"),
    (70, "Good"),
    (50, "Fair"),
    (25, "Poor"),
    (0, "Critical"),
]


@dataclass
class ScoreResult:
    score: int
    rating: str
    total_findings: int
    counts_by_severity: dict
    deductions_by_severity: dict
    counts_by_category: dict  # e.g. {"IAM": 12, "NET": 3, "STOR": 2}

    def summary_line(self) -> str:
        return f"Your AWS Security Score: {self.score}/100 ({self.rating})"


def _rating_for_score(score: int) -> str:
    for threshold, label in RATING_BANDS:
        if score >= threshold:
            return label
    return RATING_BANDS[-1][1]  # unreachable (0 is always a match), safe fallback


def _category_for_check_id(check_id: str) -> str:
    """'IAM-01' -> 'IAM', 'NET-03' -> 'NET', 'STOR-19' -> 'STOR'."""
    return check_id.split("-")[0] if "-" in check_id else check_id


def calculate_score(findings: list[Finding]) -> ScoreResult:
    """Start at 100, subtract score_penalty per finding, floor at 0."""
    counts_by_severity = {s.value: 0 for s in Severity}
    deductions_by_severity = {s.value: 0 for s in Severity}
    counts_by_category: dict = {}

    for f in findings:
        counts_by_severity[f.severity.value] += 1
        deductions_by_severity[f.severity.value] += f.severity.score_penalty
        cat = _category_for_check_id(f.check_id)
        counts_by_category[cat] = counts_by_category.get(cat, 0) + 1

    total_deduction = sum(deductions_by_severity.values())
    score = max(0, 100 - total_deduction)

    return ScoreResult(
        score=score,
        rating=_rating_for_score(score),
        total_findings=len(findings),
        counts_by_severity=counts_by_severity,
        deductions_by_severity=deductions_by_severity,
        counts_by_category=counts_by_category,
    )
