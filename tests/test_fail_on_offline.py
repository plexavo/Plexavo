"""Offline tests for `plexavo scan --fail-on`: the severity threshold that
makes a scheduled run exit non-zero when something is at or above it.

Run: python test_fail_on_offline.py
"""

import sys

from plexavo.cli import FAIL_ON_LEVELS, FAIL_ON_EXIT_CODE, _findings_at_or_above
from plexavo.findings import Finding, Severity

failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


def finding(severity):
    return Finding(
        check_id="TST-01",
        title="test",
        severity=severity,
        resource_arn="arn:aws:iam::123456789012:user/test",
        raw_detail="test finding",
    )


print("=== Severity.rank ordering ===")
assert_true(
    Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank > Severity.LOW.rank,
    "Critical > High > Medium > Low",
)

print("\n=== FAIL_ON_LEVELS covers every severity, once ===")
assert_true(
    set(FAIL_ON_LEVELS) == {"critical", "high", "medium", "low"},
    "one --fail-on keyword per Severity member",
)
assert_true(FAIL_ON_EXIT_CODE != 0 and FAIL_ON_EXIT_CODE != 1, "trip exit code is non-zero and not 1")

print("\n=== _findings_at_or_above ===")
mixed = [
    finding(Severity.LOW),
    finding(Severity.MEDIUM),
    finding(Severity.HIGH),
    finding(Severity.CRITICAL),
]
assert_true(len(_findings_at_or_above(mixed, "high")) == 2,
            "fail-on high matches the High and the Critical")
assert_true(len(_findings_at_or_above(mixed, "critical")) == 1,
            "fail-on critical matches only the Critical")
assert_true(len(_findings_at_or_above(mixed, "medium")) == 3,
            "fail-on medium matches Medium, High, Critical")
assert_true(len(_findings_at_or_above(mixed, "low")) == 4,
            "fail-on low matches everything")

assert_true(_findings_at_or_above([], "critical") == [],
            "no findings, nothing to trip on")
assert_true(_findings_at_or_above([finding(Severity.LOW), finding(Severity.MEDIUM)], "high") == [],
            "only Low/Medium present, fail-on high stays clean")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
