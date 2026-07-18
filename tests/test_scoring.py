"""Unit tests for scoring.py. Pure logic, no AWS — no fakes needed.

Run: python test_scoring.py
"""

import sys
from plexavo.findings import Finding, Severity
from plexavo.scoring import calculate_score

failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


def f(check_id, severity):
    return Finding(check_id=check_id, title="x", severity=severity, resource_arn="x", raw_detail="x")


print("=== Empty findings list ===")
result = calculate_score([])
assert_true(result.score == 100, f"Score is 100 with no findings (got {result.score})")
assert_true(result.rating == "Excellent", f"Rating is Excellent at 100 (got {result.rating})")

print("\n=== Single Critical finding ===")
result = calculate_score([f("IAM-01", Severity.CRITICAL)])
assert_true(result.score == 85, f"100 - 15 = 85 (got {result.score})")
assert_true(result.rating == "Good", f"85 falls in the Good band (got {result.rating})")

print("\n=== Mixed severities: exact arithmetic ===")
findings = (
    [f("IAM-01", Severity.CRITICAL)] * 2 +
    [f("IAM-07", Severity.HIGH)] * 1 +
    [f("STOR-29", Severity.MEDIUM)] * 3 +
    [f("IAM-11", Severity.LOW)] * 5
)
result = calculate_score(findings)
assert_true(result.score == 48, f"2 Critical + 1 High + 3 Medium + 5 Low = 48 (got {result.score})")
assert_true(result.rating == "Poor", f"48 falls in the Poor band (got {result.rating})")
assert_true(result.total_findings == 11, f"11 total findings counted (got {result.total_findings})")
assert_true(result.counts_by_severity["Critical"] == 2, "2 Critical counted correctly")
assert_true(result.deductions_by_severity["Critical"] == 30, "Critical deduction = 30 (2 x 15)")

print("\n=== THE blueprint's own worked example: 34/100 (Poor) ===")
findings = [f("IAM-01", Severity.CRITICAL)] * 4 + [f("IAM-11", Severity.LOW)] * 6
result = calculate_score(findings)
assert_true(result.score == 34, f"4 Critical + 6 Low = 34 (got {result.score})")
assert_true(result.rating == "Poor", f"Blueprint's own example rates 'Poor' (got {result.rating})")
assert_true(result.summary_line() == "Your AWS Security Score: 34/100 (Poor)",
            f"summary_line() matches the blueprint's exact wording (got: {result.summary_line()!r})")

print("\n=== Floor at 0 — many Critical findings must not go negative ===")
findings = [f("IAM-01", Severity.CRITICAL)] * 10
result = calculate_score(findings)
assert_true(result.score == 0, f"Score floors at 0, never negative (got {result.score})")
assert_true(result.rating == "Critical", f"0 falls in the Critical band (got {result.rating})")

print("\n=== Rating band boundaries, exact edges ===")
boundary_cases = [
    (90, "Excellent"), (89, "Good"),
    (70, "Good"), (69, "Fair"),
    (50, "Fair"), (49, "Poor"),
    (25, "Poor"), (24, "Critical"),
    (0, "Critical"),
]
for target_score, expected_rating in boundary_cases:
    deduction_needed = 100 - target_score
    findings = [f("X-01", Severity.LOW)] * deduction_needed
    result = calculate_score(findings)
    assert_true(
        result.score == target_score and result.rating == expected_rating,
        f"Score {target_score} -> {expected_rating} (got score={result.score}, rating={result.rating})",
    )

print("\n=== Category breakdown ===")
findings = [f("IAM-01", Severity.CRITICAL), f("IAM-07", Severity.HIGH), f("NET-01", Severity.CRITICAL), f("STOR-19", Severity.CRITICAL)]
result = calculate_score(findings)
assert_true(result.counts_by_category == {"IAM": 2, "NET": 1, "STOR": 1},
            f"Category breakdown correctly groups by check_id prefix (got {result.counts_by_category})")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
