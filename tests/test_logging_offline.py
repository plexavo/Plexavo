"""Offline regression test for logging.py. No AWS calls.

Run: python test_logging_offline.py
"""

import sys
from botocore.exceptions import ClientError

from plexavo.checks import logging as logging_checks


class FakeCloudTrail:
    def __init__(self, trails, logging_status_by_arn):
        self._trails = trails
        self._logging_status = logging_status_by_arn

    def describe_trails(self):
        return {"trailList": self._trails}

    def get_trail_status(self, Name):
        return {"IsLogging": self._logging_status.get(Name, False)}


class FakeGuardDuty:
    def __init__(self, detector_ids=None, raise_subscription_required=False):
        self._detector_ids = detector_ids or []
        self._raise_subscription_required = raise_subscription_required

    def list_detectors(self):
        if self._raise_subscription_required:
            raise ClientError(
                {"Error": {"Code": "SubscriptionRequiredException", "Message": "x"}},
                "ListDetectors",
            )
        return {"DetectorIds": self._detector_ids}


def trail(name, arn, multi_region=False, kms_key=None):
    t = {"Name": name, "TrailARN": arn, "IsMultiRegionTrail": multi_region}
    if kms_key:
        t["KmsKeyId"] = kms_key
    return t


failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


def run_ct_checks(trails, logging_status):
    ct = FakeCloudTrail(trails, logging_status)
    enriched = logging_checks._trails_with_status(ct)
    findings = []
    findings += logging_checks.check_22_cloudtrail_not_enabled(enriched)
    findings += logging_checks.check_23_cloudtrail_not_all_regions(enriched)
    findings += logging_checks.check_24_cloudtrail_logs_not_encrypted(enriched)
    return findings


print("=== LOG-22: no trails at all ===")
findings = run_ct_checks([], {})
assert_true(any(f.check_id == "LOG-22" for f in findings), "Fires when zero trails exist")

print("\n=== LOG-22: trail exists but is stopped (not logging) — must still fire ===")
t = trail("stopped-trail", "arn:aws:cloudtrail:us-east-1:111111111111:trail/stopped-trail")
findings = run_ct_checks([t], {t["TrailARN"]: False})
assert_true(any(f.check_id == "LOG-22" for f in findings),
            "Fires on a trail that EXISTS but isn't logging — 'exists' != 'enabled'")

print("\n=== FALSE POSITIVE GUARD: trail exists and IS logging ===")
t = trail("active-trail", "arn:aws:cloudtrail:us-east-1:111111111111:trail/active-trail")
findings = run_ct_checks([t], {t["TrailARN"]: True})
assert_true(not any(f.check_id == "LOG-22" for f in findings), "Does NOT fire when a trail is actively logging")

print("\n=== LOG-23: logging trail exists but is single-region ===")
t = trail("single-region", "arn:aws:cloudtrail:us-east-1:111111111111:trail/single-region", multi_region=False)
findings = run_ct_checks([t], {t["TrailARN"]: True})
assert_true(any(f.check_id == "LOG-23" for f in findings), "Fires when the only logging trail isn't multi-region")

print("\n=== FALSE POSITIVE GUARD: logging, multi-region trail exists ===")
t = trail("multi-region", "arn:aws:cloudtrail:us-east-1:111111111111:trail/multi-region", multi_region=True)
findings = run_ct_checks([t], {t["TrailARN"]: True})
assert_true(not any(f.check_id == "LOG-23" for f in findings), "Does NOT fire when a logging multi-region trail exists")

print("\n=== LOG-23 FALSE POSITIVE GUARD: multi-region trail exists but is STOPPED — must still fire ===")
t = trail("stopped-multi-region", "arn:aws:cloudtrail:us-east-1:111111111111:trail/stopped-mr", multi_region=True)
findings = run_ct_checks([t], {t["TrailARN"]: False})
assert_true(any(f.check_id == "LOG-23" for f in findings),
            "A stopped multi-region trail provides no real coverage — still fires")

print("\n=== LOG-24: logging trail with no KMS key ===")
t = trail("no-kms", "arn:aws:cloudtrail:us-east-1:111111111111:trail/no-kms", multi_region=True)
findings = run_ct_checks([t], {t["TrailARN"]: True})
assert_true(any(f.check_id == "LOG-24" for f in findings), "Fires on a logging trail with no KmsKeyId")

print("\n=== FALSE POSITIVE GUARD: logging trail WITH a KMS key ===")
t = trail("with-kms", "arn:aws:cloudtrail:us-east-1:111111111111:trail/with-kms", multi_region=True, kms_key="arn:aws:kms:us-east-1:111111111111:key/abc")
findings = run_ct_checks([t], {t["TrailARN"]: True})
assert_true(not any(f.check_id == "LOG-24" for f in findings), "Does NOT fire when a KMS key is configured")

print("\n=== LOG-24 FALSE POSITIVE GUARD: stopped trail with no KMS key does NOT fire LOG-24 (22/23 already cover it) ===")
t = trail("stopped-no-kms", "arn:aws:cloudtrail:us-east-1:111111111111:trail/stopped-no-kms")
findings = run_ct_checks([t], {t["TrailARN"]: False})
assert_true(not any(f.check_id == "LOG-24" for f in findings), "A stopped trail is skipped by LOG-24, not double-flagged")

print("\n=== LOG-25: GuardDuty not enabled (empty detector list) ===")
findings = logging_checks.check_25_guardduty_not_enabled(FakeGuardDuty(detector_ids=[]))
assert_true(any(f.check_id == "LOG-25" for f in findings), "Fires when no detectors exist")

print("\n=== LOG-25: GuardDuty NEVER activated at all (SubscriptionRequiredException) ===")
findings = logging_checks.check_25_guardduty_not_enabled(FakeGuardDuty(raise_subscription_required=True))
assert_true(any(f.check_id == "LOG-25" for f in findings),
            "Fires (not crashes) when the account has never activated GuardDuty at all — real bug this test now covers")

print("\n=== FALSE POSITIVE GUARD: GuardDuty enabled ===")
findings = logging_checks.check_25_guardduty_not_enabled(FakeGuardDuty(detector_ids=["detector-abc123"]))
assert_true(len(findings) == 0, "Does NOT fire when a detector exists")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
