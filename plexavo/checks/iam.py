"""Category 1: IAM Privilege Escalation Paths — checks 1-6 (Critical severity).

This is the core differentiator. Each function takes the full list of
Principal objects (already loaded with policies + group-inherited
policies + permission boundary via principals.py) and returns a list of
Finding objects.

IMPORTANT on false positives: check_04 (PassRole+Compute) and check_05
(AssumeRole Chain) both verify the prerequisite actually exists before
flagging. check_02/03/04/05/06 additionally verify the relevant action
isn't blocked by an explicit Deny (identity policy or permission
boundary) before flagging. These verification steps are the exact gap
the blueprint calls out in PMapper/CloudSplaining — don't strip them out
to "simplify" later.

v3 changes (Deny statements + permission boundaries):
- Every check now calls _apply_deny_and_boundary() before finalizing a finding: an
  unconditioned matching Deny suppresses the finding entirely (it's not
  actually exploitable); a conditioned Deny downgrades Critical to High
  with a note, since we can't be certain the condition always applies.
- check_01 (wildcard admin) only suppresses on a FULL wildcard Deny
  (Action:*/Resource:* or NotAction/NotResource equivalent) — partial
  per-service Denies don't suppress it. Stated limitation, not an
  oversight: resolving exactly what remains after a partial Deny needs
  real policy simulation, out of MVP scope.
- is_admin_equivalent() now returns False for any principal with a
  permission boundary that ISN'T itself a wildcard grant, regardless of
  what the identity policy says — a non-wildcard boundary caps effective
  permissions below admin. Also returns False if has_full_wildcard_deny()
  is true, even with AdministratorAccess attached (a real break-glass
  pattern: broad Allow + full Deny).
"""

from __future__ import annotations

from plexavo.findings import Finding, Severity
from plexavo.principals import (
    Principal,
    statement_grants,
    statement_has_wildcard_action,
    resource_is_wildcard,
    resource_includes,
    find_blocking_deny,
    has_full_wildcard_deny,
    action_within_boundary,
    _normalize,
)

SELF_ESCALATION_ACTIONS = {
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutGroupPolicy",
    "iam:AddUserToGroup",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
}

COMPUTE_LAUNCH_ACTIONS = {
    "ec2:RunInstances",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionConfiguration",
    "ecs:RunTask",
    "ecs:CreateService",
    "glue:CreateJob",
    "sagemaker:CreateNotebookInstance",
    "apprunner:CreateService",
}

COMPUTE_SERVICE_PRINCIPALS = {
    "ec2.amazonaws.com",
    "lambda.amazonaws.com",
    "ecs-tasks.amazonaws.com",
    "glue.amazonaws.com",
    "sagemaker.amazonaws.com",
    "apprunner.amazonaws.com",
}

BROAD_OTHER_SERVICE_WILDCARDS = {"ec2:*", "s3:*", "rds:*", "lambda:*", "dynamodb:*"}


def _all_statements(principal: Principal):
    for policy_name, statements in principal.policies:
        for stmt in statements:
            yield policy_name, stmt


def _condition_adjustment(stmt: dict) -> tuple[Severity, str]:
    """A Condition block on the ALLOW statement itself means we can't
    safely claim this grant is unconditional. Downgrade Critical -> High
    and say so, rather than suppressing or overclaiming."""
    condition = stmt.get("Condition")
    if condition:
        keys = ", ".join(condition.keys())
        return (
            Severity.HIGH,
            f" NOTE: this grant is scoped by a Condition block ({keys}) — "
            f"not evaluated automatically; verify manually whether it "
            f"meaningfully restricts access.",
        )
    return Severity.CRITICAL, ""


def _apply_deny_and_boundary(principal: Principal, action: str, resource_arn: str | None,
                              severity: Severity, note: str):
    """Combined evaluator: explicit Deny (identity + boundary) can suppress
    or downgrade; a permission boundary that doesn't allow this action caps
    it away entirely (implicit deny by omission — not a Condition-style
    uncertainty, so this always suppresses rather than downgrades).
    Returns (severity, note) or None if the finding should be suppressed."""
    blocked, is_conditioned = find_blocking_deny(principal, action, resource_arn)
    if blocked and not is_conditioned:
        return None
    if blocked and is_conditioned:
        severity = Severity.HIGH if severity == Severity.CRITICAL else severity
        note = note + (
            " Also potentially blocked by a conditioned Deny elsewhere in "
            "this principal's policies — verify manually."
        )
    if not action_within_boundary(principal, action, resource_arn):
        return None
    return severity, note


def _principal_has_wildcard_grant(principal: Principal) -> bool:
    return any(
        stmt.get("Effect") == "Allow"
        and statement_has_wildcard_action(stmt)
        and resource_is_wildcard(stmt)
        for _, statements in principal.policies
        for stmt in statements
    )


def is_admin_equivalent(principal: Principal) -> bool:
    """True if this principal is 'admin-equivalent' for escalation-target
    purposes:
      - False immediately if a full wildcard Deny exists (break-glass
        pattern: broad Allow neutered by an equally broad Deny).
      - False if a permission boundary is attached and it ISN'T itself a
        wildcard grant — a non-wildcard boundary caps real permissions
        below admin regardless of the identity policy.
      - Otherwise True if there's a literal Action:*/Resource:* grant, OR
        iam:* combined with broad wildcards on 2+ other core services
        (heuristic for functionally-admin custom policies).
    This is a heuristic, not full policy simulation — see principals.py
    docstring for the exact limitation (boundary Allow-sets aren't used
    to compute a true intersection, only boundary Deny statements and
    "is the boundary itself wildcard" are considered).
    """
    if has_full_wildcard_deny(principal):
        return False

    if principal.has_permission_boundary and not action_within_boundary(principal, "*", None):
        return False

    if _principal_has_wildcard_grant(principal):
        return True

    granted_iam_star = False
    broad_other_services = set()
    for _policy_name, statements in principal.policies:
        for stmt in statements:
            if stmt.get("Effect") != "Allow" or "Action" not in stmt:
                continue
            for a in _normalize(stmt.get("Action")):
                al = a.lower()
                if al == "iam:*":
                    granted_iam_star = True
                elif al in BROAD_OTHER_SERVICE_WILDCARDS:
                    broad_other_services.add(al)
    return granted_iam_star and len(broad_other_services) >= 2


def check_01_wildcard_admin(principals: list[Principal]) -> list[Finding]:
    """IAM-01: Any principal with effectively Action:* on effectively Resource:*,
    unless neutered by a Deny or capped below wildcard by a permission boundary."""
    findings = []
    for p in principals:
        for policy_name, stmt in _all_statements(p):
            if stmt.get("Effect") != "Allow":
                continue
            if statement_has_wildcard_action(stmt) and resource_is_wildcard(stmt):
                severity, note = _condition_adjustment(stmt)
                result = _apply_deny_and_boundary(p, "*", None, severity, note)
                if result is None:
                    continue
                severity, note = result
                findings.append(Finding(
                    check_id="IAM-01",
                    title="Wildcard Admin Access",
                    severity=severity,
                    resource_arn=p.arn,
                    raw_detail=f"Policy '{policy_name}' on {p.type} '{p.name}' grants "
                               f"effectively unrestricted access on all resources "
                               f"(full administrator access).{note}",
                    account_context=f"policy={policy_name}",
                ))
    return findings


def check_02_self_escalation(principals: list[Principal]) -> list[Finding]:
    """IAM-02: Principal can attach/put policies, join groups, or create
    credentials on a resource scope that includes itself."""
    findings = []
    for p in principals:
        for policy_name, stmt in _all_statements(p):
            if stmt.get("Effect") != "Allow":
                continue
            granted = statement_grants(stmt, SELF_ESCALATION_ACTIONS)
            if not granted:
                continue
            if not (resource_is_wildcard(stmt) or resource_includes(stmt, p.arn)):
                continue

            target_resource = None if resource_is_wildcard(stmt) else p.arn
            severity, note = _condition_adjustment(stmt)
            remaining = set()
            any_conditioned_deny = False
            for action in granted:
                result = _apply_deny_and_boundary(p, action, target_resource, severity, note)
                if result is None:
                    continue  # this specific action is unconditionally blocked
                action_severity, _ = result
                if action_severity != severity:
                    any_conditioned_deny = True
                remaining.add(action)
            if not remaining:
                continue  # every granted action was unconditionally denied

            if any_conditioned_deny:
                severity = Severity.HIGH if severity == Severity.CRITICAL else severity
                note += " Some of this access may additionally be blocked by a conditioned Deny — verify manually."

            findings.append(Finding(
                check_id="IAM-02",
                title="IAM Self-Escalation",
                severity=severity,
                resource_arn=p.arn,
                raw_detail=f"Policy '{policy_name}' on {p.type} '{p.name}' grants "
                           f"{', '.join(sorted(remaining))} on a resource scope that "
                           f"includes itself — this principal can grant itself any "
                           f"additional permission or credential.{note}",
                account_context=f"policy={policy_name}",
            ))
    return findings


def check_03_create_policy_version(principals: list[Principal], all_managed_policy_owners: dict) -> list[Finding]:
    """IAM-03: iam:CreatePolicyVersion on a managed policy this principal doesn't own."""
    findings = []
    for p in principals:
        for policy_name, stmt in _all_statements(p):
            if stmt.get("Effect") != "Allow":
                continue
            granted = statement_grants(stmt, {"iam:CreatePolicyVersion"})
            if not granted:
                continue
            severity, note = _condition_adjustment(stmt)

            if resource_is_wildcard(stmt):
                result = _apply_deny_and_boundary(p, "iam:CreatePolicyVersion", None, severity, note)
                if result is None:
                    continue
                severity, note = result
                findings.append(Finding(
                    check_id="IAM-03",
                    title="CreatePolicyVersion Escalation",
                    severity=severity,
                    resource_arn=p.arn,
                    raw_detail=f"Policy '{policy_name}' on {p.type} '{p.name}' grants "
                               f"iam:CreatePolicyVersion on all policies. This principal "
                               f"can rewrite any managed policy in the account to grant "
                               f"itself full access and set it as the default version.{note}",
                    account_context=f"policy={policy_name}",
                ))
            else:
                for r in _normalize(stmt.get("Resource")):
                    owner = all_managed_policy_owners.get(r)
                    if owner is None or owner == p.arn:
                        continue
                    result = _apply_deny_and_boundary(p, "iam:CreatePolicyVersion", r, severity, note)
                    if result is None:
                        continue
                    r_severity, r_note = result
                    findings.append(Finding(
                        check_id="IAM-03",
                        title="CreatePolicyVersion Escalation",
                        severity=r_severity,
                        resource_arn=p.arn,
                        raw_detail=f"Policy '{policy_name}' on {p.type} '{p.name}' "
                                   f"grants iam:CreatePolicyVersion on '{r}', a policy "
                                   f"it doesn't own. It can rewrite that policy to grant "
                                   f"broader access.{r_note}",
                        account_context=f"policy={policy_name}",
                    ))
    return findings


def check_04_passrole_compute(principals: list[Principal]) -> list[Finding]:
    """IAM-04: PassRole + compute launch, verified against a real high-priv
    target role whose trust policy actually allows a compute service to
    assume it, and that iam:PassRole to that specific target isn't Denied."""
    findings = []

    dangerous_roles = {}
    for p in principals:
        if p.type != "role" or not p.trust_policy:
            continue
        trust_statements = _normalize(p.trust_policy.get("Statement"))
        trusts_compute = False
        for stmt in trust_statements:
            if stmt.get("Effect") != "Allow":
                continue
            principal_field = stmt.get("Principal", {})
            services = _normalize(principal_field.get("Service")) if isinstance(principal_field, dict) else []
            if any(s in COMPUTE_SERVICE_PRINCIPALS for s in services):
                trusts_compute = True
                break
        if trusts_compute and is_admin_equivalent(p):
            dangerous_roles[p.arn] = p.name

    if not dangerous_roles:
        return findings

    for p in principals:
        for policy_name, stmt in _all_statements(p):
            if stmt.get("Effect") != "Allow":
                continue
            if not statement_grants(stmt, {"iam:PassRole"}):
                continue
            has_launch = any(
                statement_grants(s, COMPUTE_LAUNCH_ACTIONS)
                for _, s in _all_statements(p)
            )
            if not has_launch:
                continue
            reachable = {
                arn: name for arn, name in dangerous_roles.items()
                if resource_includes(stmt, arn)
            }
            base_severity, base_note = _condition_adjustment(stmt)
            for role_arn, role_name in reachable.items():
                if role_arn == p.arn:
                    continue
                result = _apply_deny_and_boundary(p, "iam:PassRole", role_arn, base_severity, base_note)
                if result is None:
                    continue
                severity, note = result
                findings.append(Finding(
                    check_id="IAM-04",
                    title="PassRole + Compute Privilege Escalation",
                    severity=severity,
                    resource_arn=p.arn,
                    raw_detail=f"{p.type} '{p.name}' has iam:PassRole (policy '{policy_name}') "
                               f"plus a compute-launch permission, and can pass the "
                               f"high-privilege role '{role_name}' ({role_arn}) — which trusts "
                               f"a compute service — to a new EC2 instance or Lambda function, "
                               f"gaining that role's permissions.{note}",
                    account_context=f"target_role={role_arn}",
                ))
    return findings


def check_05_assumerole_chain_to_admin(principals: list[Principal]) -> list[Finding]:
    """IAM-05: Role A can assume Role B, and Role B has admin-level access.
    One-hop only for MVP, as the blueprint specifies."""
    findings = []
    roles_by_arn = {p.arn: p for p in principals if p.type == "role"}
    admin_roles = {p.arn for p in principals if p.type == "role" and is_admin_equivalent(p)}

    for p in principals:
        for policy_name, stmt in _all_statements(p):
            if stmt.get("Effect") != "Allow":
                continue
            if not statement_grants(stmt, {"sts:AssumeRole"}):
                continue
            if resource_is_wildcard(stmt):
                continue  # that's check IAM-06, not IAM-05
            base_severity, base_note = _condition_adjustment(stmt)
            for target_arn in _normalize(stmt.get("Resource")):
                if target_arn not in admin_roles or target_arn == p.arn:
                    continue
                result = _apply_deny_and_boundary(p, "sts:AssumeRole", target_arn, base_severity, base_note)
                if result is None:
                    continue
                severity, note = result
                target_name = roles_by_arn[target_arn].name
                findings.append(Finding(
                    check_id="IAM-05",
                    title="AssumeRole Chain to Admin",
                    severity=severity,
                    resource_arn=p.arn,
                    raw_detail=f"{p.type} '{p.name}' (policy '{policy_name}') can call "
                               f"sts:AssumeRole on '{target_name}' ({target_arn}), which "
                               f"has administrator-equivalent access. One hop from "
                               f"'{p.name}' reaches full admin.{note}",
                    account_context=f"target_role={target_arn}",
                ))
    return findings


def check_06_wildcard_assumerole(principals: list[Principal]) -> list[Finding]:
    """IAM-06: sts:AssumeRole on effectively Resource:* — can assume any role in the account."""
    findings = []
    for p in principals:
        for policy_name, stmt in _all_statements(p):
            if stmt.get("Effect") != "Allow":
                continue
            if not statement_grants(stmt, {"sts:AssumeRole"}):
                continue
            if not resource_is_wildcard(stmt):
                continue
            severity, note = _condition_adjustment(stmt)
            result = _apply_deny_and_boundary(p, "sts:AssumeRole", None, severity, note)
            if result is None:
                continue
            severity, note = result
            findings.append(Finding(
                check_id="IAM-06",
                title="Wildcard AssumeRole",
                severity=severity,
                resource_arn=p.arn,
                raw_detail=f"Policy '{policy_name}' on {p.type} '{p.name}' grants "
                           f"sts:AssumeRole on effectively all resources — this "
                           f"principal can assume ANY role in the account, including "
                           f"admin roles created after this scan.{note}",
                account_context=f"policy={policy_name}",
            ))
    return findings


def run_all(session, principals: list[Principal]) -> list[Finding]:
    """Run checks 1-6 and return the combined finding list."""
    iam = session.client("iam")

    policy_owners = {}
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            entities = iam.list_entities_for_policy(PolicyArn=policy["Arn"])
            owner_arn = None
            if entities["PolicyUsers"]:
                owner_arn = f"arn:aws:iam::{policy['Arn'].split(':')[4]}:user/{entities['PolicyUsers'][0]['UserName']}"
            elif entities["PolicyRoles"]:
                owner_arn = f"arn:aws:iam::{policy['Arn'].split(':')[4]}:role/{entities['PolicyRoles'][0]['RoleName']}"
            policy_owners[policy["Arn"]] = owner_arn

    findings = []
    findings += check_01_wildcard_admin(principals)
    findings += check_02_self_escalation(principals)
    findings += check_03_create_policy_version(principals, policy_owners)
    findings += check_04_passrole_compute(principals)
    findings += check_05_assumerole_chain_to_admin(principals)
    findings += check_06_wildcard_assumerole(principals)
    return findings
