"""Offline regression test for storage.py. No AWS calls.

Run: python test_storage_offline.py
"""

import sys
import json

from botocore.exceptions import ClientError

from plexavo.checks import storage


class FakeS3:
    def __init__(self, buckets, pab=None, policies=None, acls=None):
        self._buckets = buckets
        self._pab = pab or {}
        self._policies = policies or {}
        self._acls = acls or {}

    def list_buckets(self):
        return {"Buckets": [{"Name": b} for b in self._buckets]}

    def get_public_access_block(self, Bucket):
        if Bucket not in self._pab:
            raise ClientError({"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": "x"}}, "GetPublicAccessBlock")
        return {"PublicAccessBlockConfiguration": self._pab[Bucket]}

    def get_bucket_policy(self, Bucket):
        if Bucket not in self._policies:
            raise ClientError({"Error": {"Code": "NoSuchBucketPolicy", "Message": "x"}}, "GetBucketPolicy")
        return {"Policy": self._policies[Bucket]}

    def get_bucket_acl(self, Bucket):
        return self._acls.get(Bucket, {"Grants": []})


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
assert_true(any(f.check_id == "STOR-20" for f in findings), "Fires on Principal:* bucket policy")

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

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
