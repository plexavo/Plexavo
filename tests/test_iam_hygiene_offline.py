"""Offline regression test for iam_hygiene.py. No AWS calls.

Run: python test_iam_hygiene_offline.py
"""

import sys
import json
from datetime import datetime, timedelta, timezone

from plexavo.principals import Principal
from plexavo.checks import iam_hygiene as hygiene


class NoSuchEntityException(Exception):
    pass


class FakeExceptions:
    NoSuchEntityException = NoSuchEntityException


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return self._pages


class FakeIAM:
    def __init__(self, users_login_profiles: dict, access_keys_by_user: dict, mfa_enabled: bool):
        # users_login_profiles: {username: True/False} — True = has console access
        self._login_profiles = users_login_profiles
        self._access_keys = access_keys_by_user
        self._mfa_enabled = mfa_enabled
        self.exceptions = FakeExceptions

    def get_login_profile(self, UserName):
        if self._login_profiles.get(UserName):
            return {"LoginProfile": {"UserName": UserName}}
        raise NoSuchEntityException()

    def list_access_keys(self, UserName):
        return {"AccessKeyMetadata": self._access_keys.get(UserName, [])}

    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": 1 if self._mfa_enabled else 0}}


class FakeCloudTrail:
    def __init__(self, events):
        self._pages = [{"Events": events}]

    def get_paginator(self, name):
        return FakePaginator(self._pages)


class FakeLambda:
    def __init__(self, functions):
        self._pages = [{"Functions": functions}]

    def get_paginator(self, name):
        return FakePaginator(self._pages)


def role(name, trust_statements):
    arn = f"arn:aws:iam::111111111111:role/{name}"
    return Principal(type="role", name=name, arn=arn, policies=[],
                      trust_policy={"Version": "2012-10-17", "Statement": trust_statements})


def user_raw(name, create_date, password_last_used=None):
    return {
        "UserName": name,
        "Arn": f"arn:aws:iam::111111111111:user/{name}",
        "CreateDate": create_date,
        "PasswordLastUsed": password_last_used,
    }


def key(key_id, create_date, status="Active"):
    return {"AccessKeyId": key_id, "CreateDate": create_date, "Status": status}


failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


NOW = datetime.now(timezone.utc)
OWN_ACCOUNT = "111111111111"
EXTERNAL_ACCOUNT = "222222222222"

# --- IAM-07: wildcard trust ---
print("=== IAM-07: wildcard cross-account trust ===")
r1 = role("wildcard-trust-bare", [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}])
r1b = role("wildcard-trust-typed", [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}])
r2 = role("self-trust-clean", [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OWN_ACCOUNT}:root"}, "Action": "sts:AssumeRole"}])
findings = hygiene.check_07_cross_account_wildcard_trust([r1, r1b, r2])
assert_true(any(f.resource_arn == r1.arn for f in findings), "IAM-07 fires on bare Principal:* (defensive — AWS itself rejects this form at role-creation time, see iam-hygiene-misconfigs.tf)")
assert_true(any(f.resource_arn == r1b.arn for f in findings), "IAM-07 fires on Principal:{AWS:*} — the form AWS actually accepts and the one ground-truthed against real AWS")
assert_true(not any(f.resource_arn == r2.arn for f in findings), "IAM-07 does NOT fire on same-account trust")

# --- IAM-08: external account trust ---
print("\n=== IAM-08: external account trust ===")
r3 = role("external-trust", [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{EXTERNAL_ACCOUNT}:root"}, "Action": "sts:AssumeRole"}])
r4 = role("bare-id-external-trust", [{"Effect": "Allow", "Principal": {"AWS": EXTERNAL_ACCOUNT}, "Action": "sts:AssumeRole"}])
findings = hygiene.check_08_cross_account_external([r2, r3, r4], OWN_ACCOUNT)
assert_true(any(f.resource_arn == r3.arn for f in findings), "IAM-08 fires on external account via full ARN")
assert_true(any(f.resource_arn == r4.arn for f in findings), "IAM-08 fires on external account via bare 12-digit ID")
assert_true(not any(f.resource_arn == r2.arn for f in findings), "IAM-08 does NOT fire on same-account trust")

# --- IAM-09: dormant console users (threshold trick) ---
print("\n=== IAM-09: dormant console users — threshold parametrization proof ===")
fresh_user = user_raw("fresh-console-user", NOW)  # created right now, never logged in
old_login_user = user_raw("old-login-user", NOW - timedelta(days=400), password_last_used=NOW - timedelta(days=120))
no_console_user = user_raw("no-console-user", NOW)
iam1 = FakeIAM(
    users_login_profiles={"fresh-console-user": True, "old-login-user": True, "no-console-user": False},
    access_keys_by_user={},
    mfa_enabled=True,
)
users = [fresh_user, old_login_user, no_console_user]
findings_thresh0 = hygiene.check_09_dormant_console_users(iam1, users, threshold_days=0)
assert_true(any(f.resource_arn == fresh_user["Arn"] for f in findings_thresh0),
            "threshold=0: fires on freshly-created never-logged-in user (proves the 'never used' branch)")
findings_thresh365 = hygiene.check_09_dormant_console_users(iam1, users, threshold_days=365)
assert_true(not any(f.resource_arn == fresh_user["Arn"] for f in findings_thresh365),
            "threshold=365: does NOT fire on the same fresh user (proves the comparison direction is correct)")
findings_real = hygiene.check_09_dormant_console_users(iam1, users, threshold_days=90)
assert_true(any(f.resource_arn == old_login_user["Arn"] for f in findings_real),
            "threshold=90 (real default): fires on a user with a synthetic 120-day-old login")
assert_true(not any(f.resource_arn == no_console_user["Arn"] for f in findings_real),
            "No console access at all -> never evaluated, never fires")

# --- IAM-10: old access keys (threshold trick) ---
print("\n=== IAM-10: old access keys — threshold parametrization proof ===")
fresh_key_user = user_raw("fresh-key-user", NOW)
iam2 = FakeIAM(
    users_login_profiles={},
    access_keys_by_user={"fresh-key-user": [key("AKIAFRESH000000000", NOW)]},
    mfa_enabled=True,
)
findings_thresh0 = hygiene.check_10_old_access_keys(iam2, [fresh_key_user], high_threshold_days=0, critical_threshold_days=1000)
assert_true(any(f.resource_arn == fresh_key_user["Arn"] and f.severity.value == "High" for f in findings_thresh0),
            "high_threshold=0: fires High on a freshly-created key (proves comparison logic)")
findings_thresh365 = hygiene.check_10_old_access_keys(iam2, [fresh_key_user], high_threshold_days=365, critical_threshold_days=1000)
assert_true(not any(f.resource_arn == fresh_key_user["Arn"] for f in findings_thresh365),
            "high_threshold=365: does NOT fire on the same fresh key")

print("\n=== IAM-10: severity escalates Critical past the critical threshold ===")
old_key_user = user_raw("old-key-user", NOW)
iam3 = FakeIAM(users_login_profiles={}, access_keys_by_user={
    "old-key-user": [key("AKIAOLD00000000000", NOW - timedelta(days=200))]
}, mfa_enabled=True)
findings = hygiene.check_10_old_access_keys(iam3, [old_key_user], high_threshold_days=90, critical_threshold_days=180)
from plexavo.findings import Severity
matched = [f for f in findings if f.resource_arn == old_key_user["Arn"]]
assert_true(matched and matched[0].severity == Severity.CRITICAL, "A 200-day-old key exceeds the 180-day critical threshold -> Critical, not High")

print("\n=== FALSE POSITIVE GUARD: inactive key, no matter how old, does not fire ===")
inactive_user = user_raw("inactive-key-user", NOW)
iam4 = FakeIAM(users_login_profiles={}, access_keys_by_user={
    "inactive-key-user": [key("AKIAINACTIVE00000", NOW - timedelta(days=400), status="Inactive")]
}, mfa_enabled=True)
findings = hygiene.check_10_old_access_keys(iam4, [inactive_user], high_threshold_days=90, critical_threshold_days=180)
assert_true(len(findings) == 0, "A 400-day-old INACTIVE key does not fire — only Active keys are live risk")

# --- IAM-11: multiple active keys ---
print("\n=== IAM-11: multiple active access keys ===")
two_key_user = user_raw("two-key-user", NOW)
iam5 = FakeIAM(users_login_profiles={}, access_keys_by_user={
    "two-key-user": [key("AKIAONE00000000000", NOW), key("AKIATWO00000000000", NOW)]
}, mfa_enabled=True)
findings = hygiene.check_11_multiple_active_keys(iam5, [two_key_user])
assert_true(any(f.resource_arn == two_key_user["Arn"] for f in findings), "IAM-11 fires on 2 active keys")

print("\n=== FALSE POSITIVE GUARD: single active key does not fire IAM-11 ===")
one_key_user = user_raw("one-key-user", NOW)
iam6 = FakeIAM(users_login_profiles={}, access_keys_by_user={
    "one-key-user": [key("AKIAONLY00000000000", NOW)]
}, mfa_enabled=True)
findings = hygiene.check_11_multiple_active_keys(iam6, [one_key_user])
assert_true(len(findings) == 0, "A single active key does not fire IAM-11")

# --- IAM-12: root account usage ---
print("\n=== IAM-12: no root usage in the lookback window ===")
ct1 = FakeCloudTrail(events=[])
findings = hygiene.check_12_root_account_usage(ct1)
assert_true(len(findings) == 0, "No events at all -> no finding")

print("\n=== IAM-12: a genuine root event fires ===")
root_event = {
    "EventId": "abc-123",
    "EventName": "ConsoleLogin",
    "EventSource": "signin.amazonaws.com",
    "EventTime": "2026-07-01T12:00:00Z",
    "Username": "root",
    "CloudTrailEvent": json.dumps({"userIdentity": {"type": "Root"}}),
}
ct2 = FakeCloudTrail(events=[root_event])
findings = hygiene.check_12_root_account_usage(ct2)
assert_true(len(findings) == 1 and findings[0].check_id == "IAM-12", "A genuine root-typed event fires exactly one finding")
assert_true("ConsoleLogin" in findings[0].raw_detail, "Detail names the actual event")

print("\n=== FALSE POSITIVE GUARD: Username='root' filter match, but userIdentity.type is NOT Root ===")
fake_root_named_user_event = {
    "EventId": "def-456",
    "EventName": "GetObject",
    "EventSource": "s3.amazonaws.com",
    "EventTime": "2026-07-01T12:00:00Z",
    "Username": "root",
    "CloudTrailEvent": json.dumps({"userIdentity": {"type": "IAMUser", "userName": "root"}}),
}
ct3 = FakeCloudTrail(events=[fake_root_named_user_event])
findings = hygiene.check_12_root_account_usage(ct3)
assert_true(len(findings) == 0, "An IAM user literally named 'root' (not the account root) does NOT fire — client-side type check catches what the server-side filter alone would miss")

# --- IAM-13: root MFA ---
print("\n=== IAM-13: root MFA ===")
iam_no_mfa = FakeIAM(users_login_profiles={}, access_keys_by_user={}, mfa_enabled=False)
findings = hygiene.check_13_root_mfa(iam_no_mfa)
assert_true(len(findings) == 1 and findings[0].severity == Severity.CRITICAL, "IAM-13 fires Critical when root MFA is off")

iam_with_mfa = FakeIAM(users_login_profiles={}, access_keys_by_user={}, mfa_enabled=True)
findings = hygiene.check_13_root_mfa(iam_with_mfa)
assert_true(len(findings) == 0, "IAM-13 produces nothing when root MFA is on")

# --- IAM-14: Lambda admin roles ---
print("\n=== IAM-14: Lambda execution role with admin access ===")
admin_role = role("lambda-admin-role", [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}])
admin_role.policies = [("AdministratorAccess", [{"Effect": "Allow", "Action": "*", "Resource": "*"}])]
clean_role = role("lambda-clean-role", [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}])
clean_role.policies = [("read-only", [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}])]

fn_admin = {"FunctionName": "risky-fn", "FunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:risky-fn", "Role": admin_role.arn}
fn_clean = {"FunctionName": "safe-fn", "FunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:safe-fn", "Role": clean_role.arn}
lambda_client = FakeLambda([fn_admin, fn_clean])
findings = hygiene.check_14_lambda_admin_roles(lambda_client, [admin_role, clean_role])
assert_true(any(f.resource_arn == fn_admin["FunctionArn"] for f in findings), "IAM-14 fires on a Lambda function whose role has admin access")
assert_true(not any(f.resource_arn == fn_clean["FunctionArn"] for f in findings), "IAM-14 does NOT fire on a Lambda function with a least-privilege role")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
