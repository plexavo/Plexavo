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


def role_dict(name, last_used=None, create_date=None):
    return {
        "RoleName": name,
        "Arn": f"arn:aws:iam::111111111111:role/{name}",
        "RoleLastUsed": {"LastUsedDate": last_used} if last_used is not None else {},
        "CreateDate": create_date,
    }


print("=== _explicit_granted_actions: extracts explicit actions, excludes wildcards ===")
# Deliberately uses management-plane actions (ec2:*, iam:ListRoles) here,
# not s3:GetObject/PutObject — those are now excluded as known data-plane
# actions (see the dedicated regression below), which would make this
# fixture test the wrong thing.
p = Principal(type="role", name="test-role", arn="arn:aws:iam::111111111111:role/test-role", policies=[
    ("inline-policy", [
        {"Effect": "Allow", "Action": ["ec2:RunInstances", "iam:ListRoles"], "Resource": "*"},
        {"Effect": "Allow", "Action": "iam:*", "Resource": "*"},  # service wildcard, excluded
        {"Effect": "Allow", "Action": "*", "Resource": "*"},      # full wildcard, excluded
        {"Effect": "Deny", "Action": "ec2:TerminateInstances", "Resource": "*"},  # Deny, excluded
        {"Effect": "Allow", "NotAction": "ec2:RunInstances", "Resource": "*"},  # NotAction, excluded
    ]),
])
result = usage._explicit_granted_actions(p)
assert_true(result == {"ec2:runinstances", "iam:listroles"}, f"Only explicit Allow actions kept (got: {result})")

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

print("\n=== check_27: fires on a role never assumed (RoleLastUsed empty), no CreateDate at all ===")
roles = [role_dict("never-used-role")]
findings = usage.check_27_roles_not_assumed(roles)
assert_true(len(findings) == 1 and "never been assumed" in findings[0].raw_detail, "Fires with 'never assumed' wording")
assert_true(findings[0].severity.value == "High" and findings[0].confidence == "Confirmed",
            "No CreateDate at all falls through to the unchanged Confirmed/High behavior (defensive default)")

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

print("\n=== FIX: a freshly-created role with empty RoleLastUsed downgrades instead of asserting Confirmed ===")
# Confirmed live (2026-09-28): a role assumed via a real sts:AssumeRole call
# still showed RoleLastUsed={} more than 20 minutes later — AWS's own
# propagation can genuinely take hours, not just in this compressed test.
just_created = datetime.now(timezone.utc) - timedelta(hours=1)
roles = [role_dict("brand-new-role", create_date=just_created)]
findings = usage.check_27_roles_not_assumed(roles)
assert_true(len(findings) == 1, "Still fires — a Condition/grace period downgrades, never fully suppresses")
assert_true(findings[0].severity.value == "Medium", f"Downgraded to Medium, not High (got: {findings[0].severity.value})")
assert_true(findings[0].confidence == "Likely — see note", f"Confidence downgraded (got: {findings[0].confidence})")
assert_true("propagate" in findings[0].evidence.lower(), "Evidence explains the AWS propagation ambiguity, not buried in raw_detail")

print("\n=== REGRESSION: a role created well past the grace window stays at full Confirmed/High ===")
long_ago = datetime.now(timezone.utc) - timedelta(hours=48)
roles = [role_dict("old-unused-role", create_date=long_ago)]
findings = usage.check_27_roles_not_assumed(roles)
assert_true(len(findings) == 1, "Fires")
assert_true(findings[0].severity.value == "High" and findings[0].confidence == "Confirmed",
            "Past the grace window, stays at full Confirmed/High — the fix doesn't quietly weaken the check generally")

print("\n=== REGRESSION: the grace period only applies to the empty-RoleLastUsed case, never a stale-but-real timestamp ===")
stale_but_recent_role = datetime.now(timezone.utc) - timedelta(hours=1)
old_last_used = datetime.now(timezone.utc) - timedelta(days=120)
roles = [role_dict("stale-fresh-role", last_used=old_last_used, create_date=stale_but_recent_role)]
findings = usage.check_27_roles_not_assumed(roles)
assert_true(len(findings) == 1, "Fires")
assert_true(findings[0].severity.value == "High" and findings[0].confidence == "Confirmed",
            "A real (non-empty) stale LastUsedDate is unambiguous regardless of CreateDate — full Confirmed/High, no grace-period downgrade")

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

print("\n=== REGRESSION: reported bug (Hall of Bugs, found by fusiontechstrategies) — "
      "data-plane actions (s3:GetObject/PutObject) must never be flagged as unused ===")
p4 = Principal(type="role", name="app-role", arn="arn:aws:iam::111111111111:role/app-role", policies=[
    ("policy", [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "arn:aws:s3:::demo/*"}]),
])
result = usage._explicit_granted_actions(p4)
assert_true(result == set(), f"s3:GetObject/PutObject are excluded from the candidate set entirely (got: {result})")

# End-to-end: a role actively calling GetObject/PutObject nonstop, with NO
# CloudTrail LookupEvents activity at all (the real-world state, since
# LookupEvents can never see data events regardless of actual usage) — must
# produce ZERO USE-26 findings, not "confirmed unused, remove it."
role_arn3 = "arn:aws:iam::111111111111:role/app-role"
principals_dataplane = [Principal(type="role", name="app-role", arn=role_arn3, policies=[
    ("policy", [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "arn:aws:s3:::demo/*"}]),
])]
findings = usage.check_26_unused_permissions(FakeCloudTrail([]), principals_dataplane)
assert_true(len(findings) == 0,
            f"An actively-used data-plane-only role produces zero USE-26 findings (got: {[f.raw_detail for f in findings]})")

print("\n=== REGRESSION: a role with BOTH a data-plane action and a genuinely unused management action — "
      "only the management action is flagged, the data-plane one is silently excluded, not fabricated as used ===")
principals_mixed = [Principal(type="role", name="mixed-role", arn="arn:aws:iam::111111111111:role/mixed-role", policies=[
    ("policy", [{"Effect": "Allow", "Action": ["s3:GetObject", "iam:ListRoles"], "Resource": "*"}]),
])]
findings = usage.check_26_unused_permissions(FakeCloudTrail([]), principals_mixed)
assert_true(len(findings) == 1, "Fires once, for the genuinely-unused management action only")
assert_true("iam:listroles" in findings[0].raw_detail.lower(), "Names iam:ListRoles as unused")
assert_true("s3:getobject" not in findings[0].raw_detail.lower(), "Does NOT name s3:GetObject — it was never a checkable candidate")

print("\n=== FALSE POSITIVE GUARD: other known data-plane actions (DynamoDB, Lambda, KMS, SQS) are excluded too ===")
p5 = Principal(type="role", name="multi-service-role", arn="arn:aws:iam::111111111111:role/multi-service-role", policies=[
    ("policy", [{"Effect": "Allow", "Action": [
        "dynamodb:GetItem", "dynamodb:PutItem", "lambda:InvokeFunction",
        "kms:Decrypt", "sqs:SendMessage",
    ], "Resource": "*"}]),
])
result = usage._explicit_granted_actions(p5)
assert_true(result == set(), f"All known data-plane actions across services are excluded (got: {result})")

print("\n=== REGRESSION: management-plane actions are still correctly checkable and still fire when genuinely unused ===")
# Confirms the fix didn't over-broaden into suppressing real findings —
# management actions (which LookupEvents genuinely CAN observe) must stay
# fully checked, exactly as before.
principals_mgmt = [Principal(type="role", name="mgmt-role", arn="arn:aws:iam::111111111111:role/mgmt-role", policies=[
    ("policy", [{"Effect": "Allow", "Action": ["ec2:RunInstances", "ec2:TerminateInstances"], "Resource": "*"}]),
])]
ct_mgmt = FakeCloudTrail([assumed_role_event("arn:aws:iam::111111111111:role/mgmt-role", "ec2.amazonaws.com", "RunInstances")])
findings = usage.check_26_unused_permissions(ct_mgmt, principals_mgmt)
assert_true(len(findings) == 1 and "ec2:terminateinstances" in findings[0].raw_detail.lower(),
            "A genuinely-unused MANAGEMENT action still fires (the fix didn't disable the check generally)")

print("\n=== REGRESSION: reported bug (Hall of Bugs, found by fusiontechstrategies) — "
      "run_all() must use get_role, not list_roles' own RoleLastUsed, for USE-27 ===")


class FakeIAM:
    """Simulates the real, reported AWS behavior: list_roles' own Roles[]
    entries omit RoleLastUsed even for a role assumed minutes ago, while
    get_role for that exact role returns it correctly."""

    def __init__(self, roles_by_name):
        self._roles_by_name = roles_by_name

    def get_paginator(self, name):
        assert name == "list_roles"
        summary = [{"RoleName": n, "Arn": r["Arn"], "Path": r.get("Path", "/")}
                   for n, r in self._roles_by_name.items()]
        return FakePaginator([{"Roles": summary}])

    def get_role(self, RoleName):
        return {"Role": self._roles_by_name[RoleName]}


class FakeSessionForRunAll:
    def __init__(self, cloudtrail, iam):
        self._cloudtrail = cloudtrail
        self._iam = iam

    def client(self, name):
        return {"cloudtrail": self._cloudtrail, "iam": self._iam}[name]


recent = datetime.now(timezone.utc) - timedelta(days=5)
fake_iam = FakeIAM({
    "recently-used-role": {
        "RoleName": "recently-used-role",
        "Arn": "arn:aws:iam::111111111111:role/recently-used-role",
        "Path": "/",
        "RoleLastUsed": {"LastUsedDate": recent},  # only visible via get_role, per the bug
    },
    "genuinely-unused-role": {
        "RoleName": "genuinely-unused-role",
        "Arn": "arn:aws:iam::111111111111:role/genuinely-unused-role",
        "Path": "/",
        "RoleLastUsed": {},
    },
})
findings = usage.run_all(FakeSessionForRunAll(FakeCloudTrail([]), fake_iam), [])
use27 = [f for f in findings if f.check_id == "USE-27"]
assert_true(not any(f.resource_arn.endswith("recently-used-role") for f in use27),
            f"A role recently assumed (per get_role) does NOT fire USE-27, even though list_roles omits RoleLastUsed (got: {[f.resource_arn for f in use27]})")
assert_true(any(f.resource_arn.endswith("genuinely-unused-role") for f in use27),
            "A genuinely-never-assumed role still correctly fires USE-27")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
