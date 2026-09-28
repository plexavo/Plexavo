"""Offline regression test for storage.py. No AWS calls.

Run: python test_storage_offline.py
"""

import sys
import json

from botocore.exceptions import ClientError

from plexavo.checks import storage


class FakeS3:
    def __init__(self, buckets, pab=None, policies=None, acls=None, logging=None, denied=None):
        self._buckets = buckets
        self._pab = pab or {}
        self._policies = policies or {}
        self._acls = acls or {}
        self._logging = logging or {}
        self._denied = denied or set()

    def list_buckets(self):
        return {"Buckets": [{"Name": b} for b in self._buckets]}

    def get_public_access_block(self, Bucket):
        if Bucket in self._denied:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "GetPublicAccessBlock")
        if Bucket not in self._pab:
            raise ClientError({"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": "x"}}, "GetPublicAccessBlock")
        return {"PublicAccessBlockConfiguration": self._pab[Bucket]}

    def get_bucket_policy(self, Bucket):
        if Bucket in self._denied:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "GetBucketPolicy")
        if Bucket not in self._policies:
            raise ClientError({"Error": {"Code": "NoSuchBucketPolicy", "Message": "x"}}, "GetBucketPolicy")
        return {"Policy": self._policies[Bucket]}

    def get_bucket_acl(self, Bucket):
        if Bucket in self._denied:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "GetBucketAcl")
        return self._acls.get(Bucket, {"Grants": []})

    def get_bucket_logging(self, Bucket):
        # Real S3 behavior: always 200, 'LoggingEnabled' simply absent when
        # logging was never configured — never raises.
        if Bucket in self._denied:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "GetBucketLogging")
        if Bucket in self._logging:
            return {"LoggingEnabled": self._logging[Bucket]}
        return {}


class FakeSession:
    def __init__(self, s3):
        self._s3 = s3

    def client(self, name):
        assert name == "s3"
        return self._s3


FULL_PAB = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}

failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


def run_checks(s3, buckets):
    findings = []
    findings += storage.check_19_missing_public_access_block(s3, buckets)
    findings += storage.check_20_public_bucket_policy(s3, buckets)
    findings += storage.check_21_public_acl(s3, buckets)
    findings += storage.check_22_access_logging_disabled(s3, buckets)
    return findings


print("=== STOR-19: no PublicAccessBlock configuration at all ===")
s3 = FakeS3(["no-pab-bucket"], pab={})
findings = run_checks(s3, ["no-pab-bucket"])
assert_true(any(f.check_id == "STOR-19" for f in findings), "Fires when PAB is entirely absent")

print("\n=== STOR-19: PAB present but partially disabled ===")
s3 = FakeS3(["partial-pab-bucket"], pab={"partial-pab-bucket": {**FULL_PAB, "BlockPublicPolicy": False}})
findings = run_checks(s3, ["partial-pab-bucket"])
matched = [f for f in findings if f.check_id == "STOR-19"]
assert_true(matched and "BlockPublicPolicy" in matched[0].raw_detail, "Fires and names the specific disabled setting")

print("\n=== FALSE POSITIVE GUARD: PAB fully enabled ===")
s3 = FakeS3(["clean-pab-bucket"], pab={"clean-pab-bucket": FULL_PAB})
findings = run_checks(s3, ["clean-pab-bucket"])
assert_true(not any(f.check_id == "STOR-19" for f in findings), "Does NOT fire when all 4 PAB settings are true")

print("\n=== STOR-20: bucket policy grants Principal:* ===")
public_policy = json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::pub/*"}
]})
s3 = FakeS3(["pub-policy-bucket"], pab={"pub-policy-bucket": FULL_PAB}, policies={"pub-policy-bucket": public_policy})
findings = run_checks(s3, ["pub-policy-bucket"])
matched20 = [f for f in findings if f.check_id == "STOR-20"]
assert_true(bool(matched20), "Fires on Principal:* bucket policy")
assert_true(matched20 and matched20[0].severity.value == "Critical" and matched20[0].confidence == "Confirmed",
            "An UNCONDITIONED Principal:* grant stays Critical/Confirmed — this fix must not soften the real case")

print("\n=== REGRESSION: reported bug (Hall of Bugs, found by fusiontechstrategies) — "
      "STOR-20 must downgrade, not assert unconditional public access, when a Condition scopes the grant ===")
conditioned_policy = json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::internal/*",
     "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abcd1234"}}}
]})
s3 = FakeS3(["conditioned-bucket"], pab={"conditioned-bucket": FULL_PAB}, policies={"conditioned-bucket": conditioned_policy})
findings = run_checks(s3, ["conditioned-bucket"])
matched_cond = [f for f in findings if f.check_id == "STOR-20"]
assert_true(bool(matched_cond), "Still fires — a Condition doesn't fully suppress the finding, only downgrades it")
assert_true(matched_cond[0].severity.value == "High", f"Downgraded to High, not Critical (got: {matched_cond[0].severity.value})")
assert_true(matched_cond[0].confidence == "Likely — see note", f"Confidence downgraded to reflect the uncertainty (got: {matched_cond[0].confidence})")
assert_true("StringEquals" in matched_cond[0].evidence, "The Condition operator is named in evidence, not buried in raw_detail")
assert_true("no AWS account required, can perform these actions" not in matched_cond[0].raw_detail,
            "raw_detail does NOT assert unconditional public access when a Condition scopes it")
assert_true("Condition block" in matched_cond[0].raw_detail, "raw_detail names the Condition as the reason for the downgrade")

print("\n=== FALSE POSITIVE GUARD: bucket policy scoped to a specific account ===")
scoped_policy = json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111111111111:root"}, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::priv/*"}
]})
s3 = FakeS3(["scoped-policy-bucket"], pab={"scoped-policy-bucket": FULL_PAB}, policies={"scoped-policy-bucket": scoped_policy})
findings = run_checks(s3, ["scoped-policy-bucket"])
assert_true(not any(f.check_id == "STOR-20" for f in findings), "Does NOT fire on a policy scoped to a specific account")

print("\n=== FALSE POSITIVE GUARD: no bucket policy at all ===")
s3 = FakeS3(["no-policy-bucket"], pab={"no-policy-bucket": FULL_PAB})
findings = run_checks(s3, ["no-policy-bucket"])
assert_true(not any(f.check_id == "STOR-20" for f in findings), "Does NOT fire when there's no bucket policy")

print("\n=== STOR-21: ACL grants READ to AllUsers ===")
s3 = FakeS3(["public-acl-bucket"], pab={"public-acl-bucket": FULL_PAB}, acls={
    "public-acl-bucket": {"Grants": [{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]}
})
findings = run_checks(s3, ["public-acl-bucket"])
assert_true(any(f.check_id == "STOR-21" for f in findings), "Fires on ACL granting READ to AllUsers")

print("\n=== STOR-21: ACL grants to AuthenticatedUsers too ===")
s3 = FakeS3(["auth-acl-bucket"], pab={"auth-acl-bucket": FULL_PAB}, acls={
    "auth-acl-bucket": {"Grants": [{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"}, "Permission": "WRITE"}]}
})
findings = run_checks(s3, ["auth-acl-bucket"])
assert_true(any(f.check_id == "STOR-21" for f in findings), "Fires on ACL granting WRITE to AuthenticatedUsers")

print("\n=== FALSE POSITIVE GUARD: ACL grants only to the bucket owner (CanonicalUser) ===")
s3 = FakeS3(["owner-only-bucket"], pab={"owner-only-bucket": FULL_PAB}, acls={
    "owner-only-bucket": {"Grants": [{"Grantee": {"Type": "CanonicalUser", "ID": "abc123"}, "Permission": "FULL_CONTROL"}]}
})
findings = run_checks(s3, ["owner-only-bucket"])
assert_true(not any(f.check_id == "STOR-21" for f in findings), "Does NOT fire on an owner-only ACL grant")

print("\n=== STOR-22: bucket has no access logging configured ===")
s3 = FakeS3(["no-logging-bucket"], pab={"no-logging-bucket": FULL_PAB})
findings = run_checks(s3, ["no-logging-bucket"])
assert_true(any(f.check_id == "STOR-22" for f in findings), "Fires when access logging was never configured")

print("\n=== FALSE POSITIVE GUARD: STOR-22 does not fire when access logging is enabled ===")
s3 = FakeS3(["logged-bucket"], pab={"logged-bucket": FULL_PAB},
            logging={"logged-bucket": {"TargetBucket": "log-archive", "TargetPrefix": "logged-bucket/"}})
findings = run_checks(s3, ["logged-bucket"])
assert_true(not any(f.check_id == "STOR-22" for f in findings), "Does NOT fire when LoggingEnabled is present")

print("\n=== REGRESSION: reported bug (Hall of Bugs #1, found by ThePettyReviewer) — a bucket with logging genuinely off must be flagged ===")
s3 = FakeS3(["reported-bucket"], pab={"reported-bucket": FULL_PAB})
findings = run_checks(s3, ["reported-bucket"])
matched = [f for f in findings if f.check_id == "STOR-22"]
assert_true(bool(matched), "STOR-22 fires on a bucket with logging off (previously: no check existed at all, so nothing ever fired)")
assert_true(bool(matched) and matched[0].severity.value == "Medium", "Severity is Medium — a visibility gap, not exposure like STOR-19/20/21")

print("\n=== REGRESSION: reported bug (Hall of Bugs, found by fusiontechstrategies) — "
      "an AccessDenied bucket must not crash the whole scan ===")
for check_fn, check_id in [
    (storage.check_19_missing_public_access_block, "STOR-19"),
    (storage.check_20_public_bucket_policy, "STOR-20"),
    (storage.check_21_public_acl, "STOR-21"),
    (storage.check_22_access_logging_disabled, "STOR-22"),
]:
    s3 = FakeS3(["clean-bucket", "denied-bucket"], pab={"clean-bucket": FULL_PAB}, denied={"denied-bucket"})
    skipped = set()
    try:
        findings = check_fn(s3, ["clean-bucket", "denied-bucket"], skipped)
    except ClientError:
        assert_true(False, f"{check_id}: AccessDenied on 'denied-bucket' incorrectly raised and crashed the scan")
        continue
    assert_true(True, f"{check_id}: AccessDenied on 'denied-bucket' does not raise")
    assert_true("denied-bucket" in skipped, f"{check_id}: 'denied-bucket' recorded in skipped set")
    assert_true(not any("denied-bucket" in f.resource_arn for f in findings),
                f"{check_id}: never fabricates a finding for the bucket it couldn't read")

print("\n=== REGRESSION: run_all() returns (findings, skipped_buckets) and keeps scanning past AccessDenied ===")
s3 = FakeS3(
    ["reachable-bucket", "denied-bucket"],
    pab={},  # both buckets: no PAB at all -> STOR-19 should fire on the reachable one
    denied={"denied-bucket"},
)
# get_public_access_block for "denied-bucket" must raise AccessDenied specifically, not the
# NoSuchPublicAccessBlockConfiguration fallback both buckets would otherwise share via `pab={}`.
findings, skipped_buckets = storage.run_all(FakeSession(s3))
assert_true(skipped_buckets == ["denied-bucket"], "run_all() reports the denied bucket in skipped_buckets")
assert_true(any(f.check_id == "STOR-19" and "reachable-bucket" in f.resource_arn for f in findings),
            "run_all() still evaluates the reachable bucket instead of aborting the whole scan")
assert_true(not any("denied-bucket" in f.resource_arn for f in findings),
            "run_all() never fabricates a finding for a bucket it couldn't read")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
