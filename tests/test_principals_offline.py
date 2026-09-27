"""Offline regression test for principals.py's action-matching core
(_action_matches, statement_grants, statement_denies) and the higher-level
functions built directly on it (find_blocking_deny, action_within_boundary).
No AWS calls.

Written alongside the fix for a real bug found scanning the "capital_one
stack" demo terraform: _action_matches only recognized an exact action, a
literal "*", or a full "service:*" wildcard - it silently missed prefix
wildcards like "s3:Get*", which is exactly how AWS-managed *ReadOnlyAccess
policies (and many others) are actually written. That made every check
built on statement_grants/find_blocking_deny/action_within_boundary/
has_full_wildcard_deny, plus checks/iam.py's is_admin_equivalent and
attack_paths.py's chain detection, blind to that entire class of grant.

Run: python test_principals_offline.py
"""

import sys

from plexavo.principals import (
    Principal,
    _action_matches,
    statement_grants,
    statement_denies,
    find_blocking_deny,
    action_within_boundary,
)

failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


def allow(**kw):
    return {"Effect": "Allow", **kw}


def deny(**kw):
    return {"Effect": "Deny", **kw}


def role(name, statements, boundary=None):
    arn = f"arn:aws:iam::111111111111:role/{name}"
    return Principal(type="role", name=name, arn=arn,
                      policies=[("test-policy", statements)],
                      permission_boundary=[("boundary", boundary)] if boundary else [],
                      has_permission_boundary=boundary is not None)


# === REGRESSION: exact action match still works ===
print("=== REGRESSION: exact action match ===")
assert_true(_action_matches(allow(Action="s3:GetObject"), "s3:GetObject"), "Exact action match")
assert_true(not _action_matches(allow(Action="s3:GetObject"), "s3:PutObject"), "Different exact action does not match")
assert_true(_action_matches(allow(Action="s3:GetObject"), "S3:GETOBJECT"), "Match is case-insensitive")

# === REGRESSION: literal "*" and full "service:*" wildcards still work ===
print("\n=== REGRESSION: literal '*' and full 'service:*' wildcards ===")
assert_true(_action_matches(allow(Action="*"), "iam:CreatePolicyVersion"), "Literal '*' matches anything")
assert_true(_action_matches(allow(Action="s3:*"), "s3:GetObject"), "'s3:*' matches an s3 action")
assert_true(not _action_matches(allow(Action="s3:*"), "iam:GetRole"), "'s3:*' does not match a different service")

# === THE FIX: prefix wildcards (the actual AmazonS3ReadOnlyAccess form) ===
print("\n=== FIX: prefix wildcards like 's3:Get*' ===")
assert_true(_action_matches(allow(Action="s3:Get*"), "s3:GetObject"), "'s3:Get*' matches 's3:GetObject'")
assert_true(_action_matches(allow(Action="s3:Get*"), "s3:GetObjectTagging"), "'s3:Get*' matches any Get-prefixed s3 action")
assert_true(not _action_matches(allow(Action="s3:Get*"), "s3:PutObject"), "'s3:Get*' does NOT match a Put action")
assert_true(not _action_matches(allow(Action="s3:Get*"), "s3:DeleteObject"), "'s3:Get*' does NOT match a Delete action")
assert_true(_action_matches(allow(Action=["s3:Get*", "s3:List*"]), "s3:ListBucket"), "A list of prefix wildcards - second entry matches")

# === '?' wildcard (exactly one character) ===
print("\n=== '?' wildcard (single character) ===")
assert_true(_action_matches(allow(Action="iam:Tag?ole"), "iam:TagRole"), "'?' matches exactly one character")
assert_true(not _action_matches(allow(Action="iam:Tag?ole"), "iam:TagRRRole"), "'?' does not match more than one character")

# === statement_grants/statement_denies respect Effect and return the matched subset ===
print("\n=== statement_grants / statement_denies with prefix wildcards ===")
readonly_stmt = allow(Action=["s3:Get*", "s3:List*", "s3:Describe*"], Resource="*")
granted = statement_grants(readonly_stmt, {"s3:GetObject", "s3:PutObject", "s3:DeleteObject"})
assert_true(granted == {"s3:GetObject"}, f"Only the genuinely-covered action is returned (got: {granted})")

deny_stmt = deny(Action=["s3:Put*", "s3:Delete*"], Resource="*")
denied = statement_denies(deny_stmt, {"s3:GetObject", "s3:PutObject", "s3:DeleteObject"})
assert_true(denied == {"s3:PutObject", "s3:DeleteObject"}, f"Deny-side prefix wildcards matched too (got: {denied})")

# === find_blocking_deny / action_within_boundary see prefix-wildcard grants too ===
print("\n=== find_blocking_deny / action_within_boundary with prefix wildcards ===")
denied_role = role("denied-role", [
    allow(Action=["s3:Get*"], Resource="arn:aws:s3:::demo-bucket/*"),
    deny(Action=["s3:Get*"], Resource="arn:aws:s3:::demo-bucket/*"),
])
blocked, conditioned = find_blocking_deny(denied_role, "s3:GetObject", "arn:aws:s3:::demo-bucket/*")
assert_true(blocked and not conditioned, "An unconditioned Deny written as a prefix wildcard is now actually seen")

boundary_role = role(
    "boundary-role",
    [allow(Action=["s3:Get*"], Resource="*")],
    boundary=[allow(Action=["ec2:Describe*"], Resource="*")],
)
assert_true(not action_within_boundary(boundary_role, "s3:GetObject", None),
            "A boundary that only allows a different prefix wildcard still correctly caps s3 access")
assert_true(action_within_boundary(boundary_role, "ec2:DescribeInstances", None),
            "The boundary's own prefix wildcard correctly permits what it actually covers")

# === NotAction with a prefix wildcard entry ===
print("\n=== NotAction with a prefix wildcard entry ===")
notaction_stmt = {"Effect": "Allow", "NotAction": ["iam:Get*", "iam:List*"], "Resource": "*"}
assert_true(not _action_matches(notaction_stmt, "iam:GetRole"), "NotAction excludes what its prefix wildcard covers")
assert_true(_action_matches(notaction_stmt, "iam:DeleteRole"), "NotAction still grants everything outside its excluded set")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
