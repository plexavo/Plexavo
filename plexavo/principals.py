"""Enumeration of IAM principals (users + roles) and their policy documents.

v3 changes (closing the Deny/permission-boundary gap):
- Every Principal now also carries its permission boundary's statements
  (if one is attached), fetched the same way as any other managed policy.
- _action_matches() is effect-agnostic — it just answers "does this
  statement's Action/NotAction field match this action", independent of
  Allow/Deny. statement_grants() (Allow-only) and the new statement_denies()
  (Deny-only) both build on it, so there's one matching implementation
  instead of two that could drift apart.
- find_blocking_deny() scans identity policies (direct + group) AND the
  permission boundary for a Deny that would block a given action on a
  given resource, and reports whether that Deny is itself conditioned
  (i.e., we can't be certain it always applies).

Known limitation, stated plainly: a permission boundary's own Allow
statements aren't used to cap identity-policy grants (a full boundary
simulation would compute the intersection of boundary-allow and
identity-allow). Only the boundary's explicit Deny statements are
evaluated. A boundary that grants nothing beyond a narrow allow-list,
with no explicit Deny, will not be caught by find_blocking_deny() —
is_admin_equivalent() in checks/iam.py handles that specific case
separately by treating any non-wildcard boundary as disqualifying.
"""

from dataclasses import dataclass, field


@dataclass
class Principal:
    type: str          # "user" or "role"
    name: str
    arn: str
    # list of (policy_name, statements) — statements already normalized to
    # always be a list, and Action/Resource/Principal within them normalized too
    policies: list = field(default_factory=list)
    trust_policy: dict | None = None  # roles only
    # (policy_name, statements) for the permission boundary, or [] if none attached
    permission_boundary: list = field(default_factory=list)
    has_permission_boundary: bool = False


def _normalize(val):
    """AWS lets Action/Resource/Principal/NotAction/NotResource be a single
    string OR a list. Normalize to a list everywhere so check logic doesn't
    have to branch."""
    if val is None:
        return []
    return val if isinstance(val, list) else [val]


def _fetch_managed_policy_statements(iam, policy_arn: str) -> list:
    version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
    doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)["PolicyVersion"]["Document"]
    return _normalize(doc.get("Statement"))


def _policy_documents_for_user(iam, name: str) -> list:
    docs = []
    for p in iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]:
        docs.append((f"{p['PolicyName']} (direct)", _fetch_managed_policy_statements(iam, p["PolicyArn"])))
    for name_ in iam.list_user_policies(UserName=name)["PolicyNames"]:
        doc = iam.get_user_policy(UserName=name, PolicyName=name_)["PolicyDocument"]
        docs.append((f"{name_} (direct inline)", _normalize(doc.get("Statement"))))
    return docs


def _policy_documents_for_group(iam, group_name: str) -> list:
    docs = []
    for p in iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]:
        docs.append((f"{p['PolicyName']} (via group '{group_name}')", _fetch_managed_policy_statements(iam, p["PolicyArn"])))
    for name_ in iam.list_group_policies(GroupName=group_name)["PolicyNames"]:
        doc = iam.get_group_policy(GroupName=group_name, PolicyName=name_)["PolicyDocument"]
        docs.append((f"{name_} (inline via group '{group_name}')", _normalize(doc.get("Statement"))))
    return docs


def _policy_documents_for_role(iam, name: str) -> list:
    docs = []
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        docs.append((f"{p['PolicyName']} (direct)", _fetch_managed_policy_statements(iam, p["PolicyArn"])))
    for name_ in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        doc = iam.get_role_policy(RoleName=name, PolicyName=name_)["PolicyDocument"]
        docs.append((f"{name_} (direct inline)", _normalize(doc.get("Statement"))))
    return docs


def _permission_boundary(iam, boundary_field: dict | None) -> tuple[list, bool]:
    """boundary_field is the raw 'PermissionsBoundary' dict from list_users/
    list_roles, or None. Returns ([(name, statements)], has_boundary)."""
    if not boundary_field:
        return [], False
    arn = boundary_field.get("PermissionsBoundaryArn")
    if not arn:
        return [], False
    statements = _fetch_managed_policy_statements(iam, arn)
    return [(f"permission-boundary ({arn.split('/')[-1]})", statements)], True


def list_all_principals(session) -> list[Principal]:
    """Return every IAM user and role in the account with policies pre-loaded,
    including group-inherited policies and permission boundaries."""
    iam = session.client("iam")
    principals: list[Principal] = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for u in page["Users"]:
            policies = _policy_documents_for_user(iam, u["UserName"])
            for group in iam.list_groups_for_user(UserName=u["UserName"])["Groups"]:
                policies += _policy_documents_for_group(iam, group["GroupName"])
            # PermissionsBoundary from list_users has proven unreliable —
            # fetch via get_user instead, the documented-reliable path.
            full_user = iam.get_user(UserName=u["UserName"])["User"]
            boundary_stmts, has_boundary = _permission_boundary(iam, full_user.get("PermissionsBoundary"))
            principals.append(Principal(
                type="user",
                name=u["UserName"],
                arn=u["Arn"],
                policies=policies,
                permission_boundary=boundary_stmts,
                has_permission_boundary=has_boundary,
            ))

    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for r in page["Roles"]:
            if "/aws-service-role/" in r["Arn"]:
                continue
            # Same fix: get_role instead of trusting list_roles for this field.
            full_role = iam.get_role(RoleName=r["RoleName"])["Role"]
            boundary_stmts, has_boundary = _permission_boundary(iam, full_role.get("PermissionsBoundary"))
            principals.append(Principal(
                type="role",
                name=r["RoleName"],
                arn=r["Arn"],
                policies=_policy_documents_for_role(iam, r["RoleName"]),
                trust_policy=r.get("AssumeRolePolicyDocument"),
                permission_boundary=boundary_stmts,
                has_permission_boundary=has_boundary,
            ))

    return principals


def _action_matches(statement: dict, action: str) -> bool:
    """Does this statement's Action/NotAction field match `action`,
    independent of Effect? Shared by statement_grants (Allow) and
    statement_denies (Deny) so there's one matching implementation."""
    service, _, _verb = action.partition(":")
    if "NotAction" in statement and "Action" not in statement:
        excluded = {a.lower() for a in _normalize(statement.get("NotAction"))}
        return not (
            action.lower() in excluded
            or f"{service.lower()}:*" in excluded
            or "*" in excluded
        )
    for a in _normalize(statement.get("Action")):
        a = a.lower()
        if a == "*" or a == action.lower() or a == f"{service.lower()}:*":
            return True
    return False


def statement_grants(statement: dict, action_set: set[str]) -> set[str]:
    """Which actions from action_set this Allow statement grants."""
    if statement.get("Effect") != "Allow":
        return set()
    return {a for a in action_set if _action_matches(statement, a)}


def statement_denies(statement: dict, action_set: set[str]) -> set[str]:
    """Which actions from action_set this Deny statement blocks."""
    if statement.get("Effect") != "Deny":
        return set()
    return {a for a in action_set if _action_matches(statement, a)}


def statement_has_wildcard_action(statement: dict) -> bool:
    if statement.get("Effect") != "Allow":
        return False
    if "Action" in statement:
        return "*" in _normalize(statement.get("Action"))
    if "NotAction" in statement:
        return True
    return False


def resource_is_wildcard(statement: dict) -> bool:
    if "Resource" in statement:
        return "*" in _normalize(statement.get("Resource"))
    if "NotResource" in statement:
        return True
    return False


def resource_includes(statement: dict, target_arn: str) -> bool:
    if "NotResource" in statement and "Resource" not in statement:
        excluded = set(_normalize(statement.get("NotResource")))
        if "*" in excluded:
            return False
        return target_arn not in excluded
    resources = _normalize(statement.get("Resource"))
    return "*" in resources or target_arn in resources


def action_within_boundary(principal: Principal, action: str, resource_arn: str | None) -> bool:
    """True if this principal has no permission boundary, OR the boundary's
    Allow statements actually permit `action` on `resource_arn` (Resource:*
    scope if resource_arn is None). A boundary that doesn't explicitly
    allow an action implicitly denies it — that's how permission boundaries
    work: effective access is the intersection of identity policy and
    boundary, not the identity policy alone."""
    if not principal.has_permission_boundary:
        return True
    for _name, statements in principal.permission_boundary:
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            if not _action_matches(stmt, action):
                continue
            if resource_arn is not None and resource_includes(stmt, resource_arn):
                return True
            if resource_arn is None and resource_is_wildcard(stmt):
                return True
    return False


def find_blocking_deny(principal: Principal, action: str, resource_arn: str | None = None) -> tuple[bool, bool]:
    """Scan identity policies (direct + group, already merged into
    principal.policies) AND the permission boundary for a Deny statement
    that matches `action` on a resource scope covering resource_arn (or
    Resource:* if resource_arn is None).

    Returns (found_matching_deny, deny_is_conditioned). If the Deny itself
    has a Condition block, we can't be certain it always applies — callers
    should downgrade rather than fully suppress in that case.
    """
    all_sources = list(principal.policies) + list(principal.permission_boundary)
    for _name, statements in all_sources:
        for stmt in statements:
            if stmt.get("Effect") != "Deny":
                continue
            if not _action_matches(stmt, action):
                continue
            if resource_arn is not None and not resource_includes(stmt, resource_arn):
                continue
            if resource_arn is None and not resource_is_wildcard(stmt):
                continue
            return True, bool(stmt.get("Condition"))
    return False, False


def has_full_wildcard_deny(principal: Principal) -> bool:
    """True if a Deny statement grants Action:*/Resource:* (or NotAction/
    NotResource equivalent) — a full deny-all. Deliberately narrow: this
    only catches the unambiguous full-deny case, not partial per-service
    denies, which would require real policy simulation to resolve safely."""
    all_sources = list(principal.policies) + list(principal.permission_boundary)
    for _name, statements in all_sources:
        for stmt in statements:
            if stmt.get("Effect") != "Deny":
                continue
            action_is_wildcard = (
                ("Action" in stmt and "*" in _normalize(stmt.get("Action")))
                or ("NotAction" in stmt and "Action" not in stmt)
            )
            if action_is_wildcard and resource_is_wildcard(stmt):
                return True
    return False
