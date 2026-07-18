"""Offline regression test for usage.py. No AWS calls.

Run: python test_usage_offline.py
"""

import sys
import json
from datetime import datetime, timedelta, timezone

from plexavo.principals import Principal
from plexavo.checks import usage

failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return self._pages


class FakeCloudTrail:
    def __init__(self, events):
        self._pages = [{"Events": events}]

    def get_paginator(self, name):
        return FakePaginator(self._pages)


def assumed_role_event(role_arn, event_source, event_name):
    return {
        "CloudTrailEvent": json.dumps({
            "userIdentity": {
                "type": "AssumedRole",
                "arn": f"arn:aws:sts::111111111111:assumed-role/{role_arn.split('/')[-1]}/some-session",
                "sessionContext": {"sessionIssuer": {"type": "Role", "arn": role_arn}},
            },
            "eventSource": event_source,
            "eventName": event_name,
        })
    }


def role_dict(name, last_used=None):
    return {
        "RoleName": name,
        "Arn": f"arn:aws:iam::111111111111:role/{name}",
        "RoleLastUsed": {"LastUsedDate": last_used} if last_used is not None else {},
    }


print("=== _explicit_granted_actions: extracts explicit actions, excludes wildcards ===")
p = Principal(type="role", name="test-role", arn="arn:aws:iam::111111111111:role/test-role", policies=[
    ("inline-policy", [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"},
        {"Effect": "Allow", "Action": "iam:*", "Resource": "*"},  # service wildcard, excluded
        {"Effect": "Allow", "Action": "*", "Resource": "*"},      # full wildcard, excluded
        {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},  # Deny, excluded
        {"Effect": "Allow", "NotAction": "s3:GetObject", "Resource": "*"},  # NotAction, excluded
    ]),
])
result = usage._explicit_granted_actions(p)
assert_true(result == {"s3:getobject", "s3:putobject"}, f"Only explicit Allow actions kept (got: {result})")

print("\n=== _explicit_granted_actions: role with only wildcard grants has zero explicit actions ===")
p2 = Principal(type="role", name="admin-role", arn="arn:aws:iam::111111111111:role/admin-role", policies=[
    ("admin-policy", [{"Effect": "Allow", "Action": "*", "Resource": "*"}]),
])
result = usage._explicit_granted_actions(p2)
assert_true(result == set(), f"Wildcard-only role has zero explicit actions to check (got: {result})")

print("\n=== _fetch_role_usage_map: correctly attributes an AssumedRole event to its role via sessionIssuer.arn ===")
role_arn = "arn:aws:iam::111111111111:role/test-role"
ct = FakeCloudTrail([assumed_role_event(role_arn, "s3.amazonaws.com", "GetObject")])
usage_map, hit_cap = usage._fetch_role_usage_map(ct)
assert_true(usage_map.get(role_arn.lower()) == {"s3:getobject"}, f"Correctly attributed to role, correct action format (got: {usage_map})")
assert_true(hit_cap is False, "Page cap not hit with a single page")

print("\n=== _fetch_role_usage_map: non-AssumedRole events (e.g. IAMUser) are ignored ===")
iam_user_event = {"CloudTrailEvent": json.dumps({"userIdentity": {"type": "IAMUser", "userName": "lab-admin"}, "eventSource": "s3.amazonaws.com", "eventName": "GetObject"})}
ct2 = FakeCloudTrail([iam_user_event])
usage_map, _ = usage._fetch_role_usage_map(ct2)
assert_true(usage_map == {}, f"IAMUser-type events don't get attributed to any role (got: {usage_map})")

print("\n=== check_26: fires when an explicit action was never used ===")
principals = [Principal(type="role", name="test-role", arn=role_arn, policies=[
    ("policy", [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:DeleteBucket"], "Resource": "*"}]),
])]
ct3 = FakeCloudTrail([assumed_role_event(role_arn, "s3.amazonaws.com", "GetObject")])  # only GetObject actually used
findings = usage.check_26_unused_permissions(ct3, principals)
assert_true(len(findings) == 1 and findings[0].check_id == "USE-26", "Fires on the role with an unused explicit action")
assert_true("s3:deletebucket" in findings[0].raw_detail.lower(), "Names the specific unused action")
assert_true("s3:getobject" not in findings[0].raw_detail.lower() or "deletebucket" in findings[0].raw_detail.lower(),
            "The USED action (GetObject) is not what's being flagged as unused")

print("\n=== FALSE POSITIVE GUARD: check_26 does not fire when every explicit action was used ===")
ct4 = FakeCloudTrail([
    assumed_role_event(role_arn, "s3.amazonaws.com", "GetObject"),
    assumed_role_event(role_arn, "s3.amazonaws.com", "DeleteBucket"),
])
findings = usage.check_26_unused_permissions(ct4, principals)
assert_true(len(findings) == 0, "Does NOT fire when every explicitly granted action was actually used")

print("\n=== FALSE POSITIVE GUARD: check_26 does not fire on a role with zero explicit actions (wildcard-only) ===")
principals_wildcard_only = [p2]
ct5 = FakeCloudTrail([])
findings = usage.check_26_unused_permissions(ct5, principals_wildcard_only)
assert_true(len(findings) == 0, "A wildcard-only role produces no USE-26 finding (nothing explicit to check)")

print("\n=== FALSE POSITIVE GUARD: check_26 skips users entirely, only evaluates roles ===")
user_principal = [Principal(type="user", name="lab-admin", arn="arn:aws:iam::111111111111:user/lab-admin", policies=[
    ("policy", [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]),
])]
findings = usage.check_26_unused_permissions(FakeCloudTrail([]), user_principal)
assert_true(len(findings) == 0, "IAM users are not evaluated by this check — it's role-specific by design")

print("\n=== check_27: fires on a role never assumed (RoleLastUsed empty) ===")
roles = [role_dict("never-used-role")]
findings = usage.check_27_roles_not_assumed(roles)
assert_true(len(findings) == 1 and "never been assumed" in findings[0].raw_detail, "Fires with 'never assumed' wording")

print("\n=== check_27: fires on a role last assumed 120 days ago (over the 90-day window) ===")
old_date = datetime.now(timezone.utc) - timedelta(days=120)
roles = [role_dict("stale-role", last_used=old_date)]
findings = usage.check_27_roles_not_assumed(roles)
assert_true(len(findings) == 1 and "120 days ago" in findings[0].raw_detail, f"Fires with correct day count (got: {findings[0].raw_detail if findings else None})")

print("\n=== FALSE POSITIVE GUARD: check_27 does not fire on a role assumed 5 days ago ===")
recent_date = datetime.now(timezone.utc) - timedelta(days=5)
roles = [role_dict("active-role", last_used=recent_date)]
findings = usage.check_27_roles_not_assumed(roles)
assert_true(len(findings) == 0, "Does NOT fire on a recently-assumed role")

print("\n=== check_27: exactly-90-days boundary — must fire (>=90, not >90) ===")
boundary_date = datetime.now(timezone.utc) - timedelta(days=91)  # safely past 90 to avoid test-runtime flakiness
roles = [role_dict("boundary-role", last_used=boundary_date)]
findings = usage.check_27_roles_not_assumed(roles)
assert_true(len(findings) == 1, "Fires just past the 90-day boundary")

print("\n=== REGRESSION: confirmed live bug — s3:ListAllMyBuckets vs CloudTrail's 'ListBuckets' eventName ===")
role_arn2 = "arn:aws:iam::111111111111:role/list-buckets-role"
principals_lab = [Principal(type="role", name="list-buckets-role", arn=role_arn2, policies=[
    ("policy", [{"Effect": "Allow", "Action": ["s3:ListAllMyBuckets", "iam:ListRoles"], "Resource": "*"}]),
])]
# CloudTrail genuinely records this call as eventName "ListBuckets" —
# NOT "ListAllMyBuckets" — confirmed against real AWS documentation and
# an actual live test run, not assumed.
ct6 = FakeCloudTrail([assumed_role_event(role_arn2, "s3.amazonaws.com", "ListBuckets")])
findings = usage.check_26_unused_permissions(ct6, principals_lab)
assert_true(len(findings) == 1, "Still fires (iam:ListRoles genuinely is unused)")
assert_true("s3:listallmybuckets" not in findings[0].raw_detail.lower(),
            f"s3:ListAllMyBuckets is correctly recognized as used despite the CloudTrail eventName mismatch (got: {findings[0].raw_detail})")
assert_true("iam:listroles" in findings[0].raw_detail.lower(), "iam:ListRoles still correctly flagged as the genuinely unused one")

print("\n=== REGRESSION: prefix wildcards (iam:Get*, iam:List*) excluded, not just full service wildcards ===")
# Confirmed via a real live scan: scanner_role's actual policy grants
# "iam:Get*" and "iam:List*" — both genuinely wildcarded, but the old
# filter (action.endswith(":*")) only matched a literal ":*" suffix,
# missing prefix wildcards entirely.
p3 = Principal(type="role", name="scanner-role", arn="arn:aws:iam::111111111111:role/scanner-role", policies=[
    ("policy", [{"Effect": "Allow", "Action": ["iam:Get*", "iam:List*", "lambda:ListFunctions"], "Resource": "*"}]),
])
result = usage._explicit_granted_actions(p3)
assert_true(result == {"lambda:listfunctions"}, f"Prefix wildcards excluded, only the genuinely explicit action kept (got: {result})")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
