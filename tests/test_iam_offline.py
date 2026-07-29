"""Offline regression test. No AWS calls — builds Principal objects by hand
that mirror exactly what terraform-testbed produces (plus new synthetic
cases for the v2 fixes) and asserts on check output directly.

Run: python test_iam_offline.py
"""

import sys
from plexavo.principals import Principal
from plexavo.checks import iam as iam_checks

ROOT_TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111111111111:root"}, "Action": "sts:AssumeRole"}]}
EC2_TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}


def role(name, statements, trust=ROOT_TRUST, boundary=None):
    arn = f"arn:aws:iam::111111111111:role/{name}"
    return Principal(type="role", name=name, arn=arn,
                      policies=[("test-policy", statements)], trust_policy=trust,
                      permission_boundary=[("boundary", boundary)] if boundary else [],
                      has_permission_boundary=boundary is not None)


def user(name, statements, boundary=None):
    arn = f"arn:aws:iam::111111111111:user/{name}"
    return Principal(type="user", name=name, arn=arn, policies=[("test-policy", statements)],
                      permission_boundary=[("boundary", boundary)] if boundary else [],
                      has_permission_boundary=boundary is not None)


def allow(**kw):
    return {"Effect": "Allow", **kw}


# --- Replay of the exact validated testbed state (checks 1-6 + clean) ---

check01 = role("check01-wildcard-admin", [allow(Action="*", Resource="*")])
check02 = role("check02-self-escalation", [allow(Action=["iam:PutRolePolicy", "iam:AttachRolePolicy"], Resource="*")])
check03_owner = role("check03-policy-owner", [allow(Action=["s3:GetObject"], Resource="*")])
check03_attacker = role("check03-attacker", [allow(
    Action=["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
    Resource=["arn:aws:iam::111111111111:policy/protected-policy"],
)])
check04_target = role("check04-target-admin", [allow(Action="*", Resource="*")], trust=EC2_TRUST)
check04_attacker = role("check04-attacker", [allow(
    Action="iam:PassRole", Resource="arn:aws:iam::111111111111:role/check04-target-admin",
), allow(Action="ec2:RunInstances", Resource="*")])
check05_target = role("check05-target-admin", [allow(Action="*", Resource="*")])
check05_attacker = role("check05-attacker", [allow(
    Action="sts:AssumeRole", Resource="arn:aws:iam::111111111111:role/check05-target-admin",
)])
check06 = role("check06-wildcard-assumerole", [allow(Action="sts:AssumeRole", Resource="*")])
clean = role("clean-least-privilege", [allow(Action=["s3:GetObject", "s3:ListBucket"], Resource=["arn:aws:s3:::example-bucket"])])
scanner_role = role("scanner-role", [allow(Action=["iam:List*", "iam:Get*", "sts:GetCallerIdentity"], Resource="*")])

baseline_principals = [
    check01, check02, check03_owner, check03_attacker,
    check04_target, check04_attacker, check05_target, check05_attacker,
    check06, clean, scanner_role,
]

policy_owners = {
    "arn:aws:iam::111111111111:policy/protected-policy": check03_owner.arn,
}


def run(principals):
    findings = []
    findings += iam_checks.check_01_wildcard_admin(principals)
    findings += iam_checks.check_02_self_escalation(principals)
    findings += iam_checks.check_03_create_policy_version(principals, policy_owners)
    findings += iam_checks.check_04_passrole_compute(principals)
    findings += iam_checks.check_05_assumerole_chain_to_admin(principals)
    findings += iam_checks.check_06_wildcard_assumerole(principals)
    return findings


def by_check(findings, check_id):
    return [f for f in findings if f.check_id == check_id]


def assert_true(cond, msg):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        global failures
        failures += 1


failures = 0

print("=== Regression: replay of validated testbed state ===")
findings = run(baseline_principals)

assert_true(any(f.resource_arn == check01.arn for f in by_check(findings, "IAM-01")), "IAM-01 fires on check01")
assert_true(any(f.resource_arn == check02.arn for f in by_check(findings, "IAM-02")), "IAM-02 fires on check02")
assert_true(any(f.resource_arn == check03_attacker.arn for f in by_check(findings, "IAM-03")), "IAM-03 fires on check03-attacker")
assert_true(not any(f.resource_arn == check03_owner.arn for f in findings), "IAM-03 does NOT fire on check03-owner")
assert_true(any(f.resource_arn == check04_attacker.arn for f in by_check(findings, "IAM-04")), "IAM-04 fires on check04-attacker")
assert_true(not any(f.resource_arn == check04_target.arn and f.account_context == f"target_role={check04_target.arn}" for f in by_check(findings, "IAM-04")), "IAM-04 does NOT self-reference check04-target-admin (the bug we fixed earlier)")
assert_true(any(f.resource_arn == check05_attacker.arn for f in by_check(findings, "IAM-05")), "IAM-05 fires on check05-attacker")
assert_true(any(f.resource_arn == check06.arn for f in by_check(findings, "IAM-06")), "IAM-06 fires on check06")
assert_true(not any(f.resource_arn == clean.arn for f in findings), "CLEAN role produces zero findings")
assert_true(not any(f.resource_arn == scanner_role.arn for f in findings), "scanner_role itself produces zero findings")

print("\n=== New: group-membership inheritance (was a silent false negative) ===")
# A user with NO direct/inline policy, but AdministratorAccess via a group.
# principals.py attaches group policies the same way as direct ones, so we
# simulate that pre-merged state here (the merge itself happens in
# list_all_principals, which needs live AWS — this proves the check logic
# correctly sees group-sourced policies once merged).
group_admin_user = user("group-admin-user", [allow(Action="*", Resource="*")])  # simulates post-merge state
findings2 = run(baseline_principals + [group_admin_user])
assert_true(any(f.resource_arn == group_admin_user.arn for f in by_check(findings2, "IAM-01")), "Group-sourced AdministratorAccess is detected once merged into policies")

print("\n=== New: NotAction inversion (was silently invisible) ===")
notaction_role = role("notaction-role", [
    {"Effect": "Allow", "NotAction": ["iam:DeleteRole"], "Resource": "*"}
])
findings3 = run(baseline_principals + [notaction_role])
assert_true(any(f.resource_arn == notaction_role.arn for f in by_check(findings3, "IAM-01")),
            "NotAction (Allow, everything except DeleteRole) is now treated as wildcard-equivalent")

print("\n=== New: Condition block downgrades severity instead of being ignored ===")
from plexavo.findings import Severity
conditioned_role = role("conditioned-admin", [
    {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}
])
findings4 = run(baseline_principals + [conditioned_role])
cond_findings = [f for f in by_check(findings4, "IAM-01") if f.resource_arn == conditioned_role.arn]
assert_true(len(cond_findings) == 1, "Conditioned wildcard-admin still produces exactly one finding (not suppressed)")
assert_true(cond_findings and cond_findings[0].severity == Severity.HIGH, "Conditioned wildcard-admin is downgraded to High, not Critical")
assert_true(cond_findings and cond_findings[0].confidence == "Likely — see note",
            "Confidence is explicitly downgraded as a structured field, not just implied by severity")
assert_true(cond_findings and "Condition block" in cond_findings[0].evidence,
            "The unevaluated condition is captured in evidence — a distinct, structured fact, not free text buried in raw_detail")
assert_true(cond_findings and "verify manually" not in cond_findings[0].raw_detail.lower(),
            "raw_detail stays clean — the uncertainty caveat lives in confidence/evidence, not appended prose")

print("\n=== New: full wildcard Deny suppresses the finding entirely (break-glass pattern) ===")
breakglass_role = role("breakglass-admin", [
    allow(Action="*", Resource="*"),
    {"Effect": "Deny", "Action": "*", "Resource": "*"},
])
findings5 = run(baseline_principals + [breakglass_role])
assert_true(not any(f.resource_arn == breakglass_role.arn for f in findings5),
            "AdministratorAccess + full Deny:*/*  produces ZERO findings (correctly not exploitable)")

print("\n=== New: partial Deny (iam:*) suppresses IAM-specific checks but NOT the generic wildcard-admin check ===")
partial_deny_role = role("partial-deny-admin", [
    allow(Action="*", Resource="*"),
    {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
])
findings6 = run(baseline_principals + [partial_deny_role])
assert_true(any(f.resource_arn == partial_deny_role.arn and f.check_id == "IAM-01" for f in findings6),
            "IAM-01 (generic wildcard) still fires — partial per-service Deny doesn't suppress it (stated scope limit)")
assert_true(not any(f.resource_arn == partial_deny_role.arn and f.check_id == "IAM-02" for f in findings6),
            "IAM-02 (self-escalation, all iam:* actions) is correctly suppressed by the iam:* Deny")
assert_true(not any(f.resource_arn == partial_deny_role.arn and f.check_id == "IAM-03" for f in findings6),
            "IAM-03 (CreatePolicyVersion, an iam:* action) is correctly suppressed by the iam:* Deny")

print("\n=== New: permission boundary Deny on sts:AssumeRole suppresses IAM-06 ===")
boundary_deny_assumerole = [{"Effect": "Allow", "Action": "*", "Resource": "*"},
                             {"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"}]
bounded_role = role("bounded-wildcard-assumerole", [allow(Action="sts:AssumeRole", Resource="*")],
                     boundary=boundary_deny_assumerole)
findings7 = run(baseline_principals + [bounded_role])
assert_true(not any(f.resource_arn == bounded_role.arn for f in findings7),
            "A permission-boundary Deny on sts:AssumeRole suppresses IAM-06, not just identity-policy Denies")

print("\n=== New: non-wildcard permission boundary disqualifies a role as an escalation TARGET ===")
narrow_boundary = [allow(Action=["s3:GetObject"], Resource="*")]
capped_admin_target = role("capped-admin-target", [allow(Action="*", Resource="*")],
                            trust=EC2_TRUST, boundary=narrow_boundary)
capped_attacker = role("capped-attacker", [
    allow(Action="iam:PassRole", Resource=capped_admin_target.arn),
    allow(Action="ec2:RunInstances", Resource="*"),
])
findings8 = run(baseline_principals + [capped_admin_target, capped_attacker])
assert_true(
    not any(f.check_id == "IAM-04" and f.account_context == f"target_role={capped_admin_target.arn}" for f in findings8),
    "A role with AdministratorAccess but a narrow (non-wildcard) permission boundary is NOT treated as an IAM-04 escalation target",
)

print("\n=== New: the actual bug — a boundary-capped principal must not fire on ITSELF either (IAM-01/02/03/06), not just be excluded as a target ===")
findings9 = run(baseline_principals + [capped_admin_target])
own_findings = [f for f in findings9 if f.resource_arn == capped_admin_target.arn]
assert_true(len(own_findings) == 0,
            f"capped-admin-target (AdministratorAccess + narrow boundary) produces ZERO findings on itself — got {[f.check_id for f in own_findings]}")

print("\n=== New: is_admin_equivalent() heuristic path — iam:* + 2 broad service wildcards, no literal '*' ===")
heuristic_admin_target = role("heuristic-admin-target", [allow(
    Action=["iam:*", "ec2:*", "s3:*"], Resource="*",
)], trust=EC2_TRUST)
heuristic_attacker = role("heuristic-attacker", [
    allow(Action="iam:PassRole", Resource=heuristic_admin_target.arn),
    allow(Action="ec2:RunInstances", Resource="*"),
])
findings10 = run(baseline_principals + [heuristic_admin_target, heuristic_attacker])
assert_true(
    any(f.check_id == "IAM-04" and f.account_context == f"target_role={heuristic_admin_target.arn}" for f in findings10),
    "iam:* + 2 broad service wildcards (no literal '*') IS correctly picked up as an IAM-04 escalation target",
)

print("\n=== New: the same heuristic must NOT fire below its threshold — iam:* + only 1 broad service wildcard ===")
below_threshold_target = role("below-threshold-target", [allow(
    Action=["iam:*", "ec2:*"], Resource="*",  # only ONE other broad service — below the 2-service threshold
)], trust=EC2_TRUST)
below_threshold_attacker = role("below-threshold-attacker", [
    allow(Action="iam:PassRole", Resource=below_threshold_target.arn),
    allow(Action="ec2:RunInstances", Resource="*"),
])
findings11 = run(baseline_principals + [below_threshold_target, below_threshold_attacker])
assert_true(
    not any(f.check_id == "IAM-04" and f.account_context == f"target_role={below_threshold_target.arn}" for f in findings11),
    "iam:* + only 1 broad service wildcard correctly does NOT qualify — proves the threshold is precise, not just 'any non-empty set'",
)

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
