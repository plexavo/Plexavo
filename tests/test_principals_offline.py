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
    resource_is_wildcard,
    resource_includes,
    resource_grants_any_role,
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

# === REGRESSION: reported bug (Hall of Bugs, found by fusiontechstrategies) —
# resource_includes only did literal-"*"/exact-string matching, never real
# ARN wildcard semantics, so "arn:...:role/*" never matched a specific target
# role ARN ===
print("\n=== FIX: resource_includes with a prefix-wildcard ARN ===")
any_role_stmt = allow(Action="sts:AssumeRole", Resource="arn:aws:iam::111111111111:role/*")
assert_true(resource_includes(any_role_stmt, "arn:aws:iam::111111111111:role/AdminRole"),
            "'role/*' now correctly matches a specific role ARN in that account")
assert_true(resource_includes(any_role_stmt, "arn:aws:iam::111111111111:role/AnyOtherRole"),
            "'role/*' matches ANY role name, not just one")
assert_true(not resource_includes(any_role_stmt, "arn:aws:iam::222222222222:role/AdminRole"),
            "'role/*' does NOT match a different account's role ARN (case/account-sensitive)")

named_prefix_stmt = allow(Action="sts:AssumeRole", Resource="arn:aws:iam::111111111111:role/Admin*")
assert_true(resource_includes(named_prefix_stmt, "arn:aws:iam::111111111111:role/AdminRole"),
            "'role/Admin*' matches a role starting with Admin")
assert_true(not resource_includes(named_prefix_stmt, "arn:aws:iam::111111111111:role/OtherRole"),
            "'role/Admin*' does NOT match a role that doesn't start with Admin")

s3_prefix_stmt = allow(Action="s3:GetObject", Resource="arn:aws:s3:::demo-bucket/*")
assert_true(resource_includes(s3_prefix_stmt, "arn:aws:s3:::demo-bucket/some/key.txt"),
            "Same fix benefits any prefix-wildcard resource, not just IAM role ARNs")

# NotResource with a wildcard entry — same excluded-set semantics, now pattern-aware
notresource_stmt = {"Effect": "Allow", "Action": "sts:AssumeRole", "NotResource": ["arn:aws:iam::111111111111:role/Protected*"]}
assert_true(not resource_includes(notresource_stmt, "arn:aws:iam::111111111111:role/ProtectedAdmin"),
            "NotResource excludes what its prefix wildcard covers")
assert_true(resource_includes(notresource_stmt, "arn:aws:iam::111111111111:role/OtherRole"),
            "NotResource still grants everything outside its excluded pattern")

# === resource_grants_any_role: the IAM-06-specific "any role" existential check ===
print("\n=== FIX: resource_grants_any_role distinguishes 'any role' from a narrower prefix ===")
assert_true(resource_grants_any_role(allow(Action="sts:AssumeRole", Resource="*")),
            "A literal '*' still counts as 'any role' (unchanged existing case)")
assert_true(resource_grants_any_role(allow(Action="sts:AssumeRole", Resource="arn:aws:iam::111111111111:role/*")),
            "'role/*' counts as 'any role' — the exact reported bug")
assert_true(not resource_grants_any_role(allow(Action="sts:AssumeRole", Resource="arn:aws:iam::111111111111:role/Admin*")),
            "'role/Admin*' does NOT count as 'any role' — it's a narrower, specific-target grant (IAM-05's job)")
assert_true(not resource_grants_any_role(allow(Action="s3:GetObject", Resource="arn:aws:s3:::bucket/*")),
            "An unrelated S3 prefix wildcard is never treated as 'assume any role'")

# resource_is_wildcard itself must stay narrow — an ordinary S3 object-prefix
# grant is ubiquitous and must NEVER be treated as ''grants against anything''
print("\n=== REGRESSION: resource_is_wildcard stays narrow (no false positives from this fix) ===")
assert_true(not resource_is_wildcard(allow(Action="s3:GetObject", Resource="arn:aws:s3:::bucket/*")),
            "A normal S3 bucket/* object-prefix grant is still NOT 'resource_is_wildcard'")
assert_true(resource_is_wildcard(allow(Action="s3:GetObject", Resource="*")),
            "A literal '*' is still 'resource_is_wildcard'")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
