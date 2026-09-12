"""Attack-path chaining: connects findings and relationship data from
existing checks into end-to-end attack paths, when a real, unblocked
connection exists between them - not just findings that happen to
co-occur in the same scan.

Runs after all other checks complete. Capped at MAX_CHAINS chains - a
curated top-N of the clearest paths, not an exhaustive graph traversal
(the build plan is explicit: 2-3 hardcoded templates, no generic graph
engine).

Every edge that depends on an IAM policy grant is verified against the
same Deny/permission-boundary standard the one-hop IAM escalation checks
already use (plexavo/principals.py: find_blocking_deny,
action_within_boundary), and the same admin-equivalence heuristic
(plexavo/checks/iam.py: is_admin_equivalent) - reused directly here, not
reimplemented, so this can never silently drift from what those checks
already consider "actually exploitable." A chain that looks plausible on
the policy alone but is actually blocked in practice must never be shown
as real - this is the accuracy risk the build plan calls out as more
important than shipping fast.

Two templates, both requiring the entry EC2 instance to be internet-
exposed on some port (the same exposure data analyze_security_groups
already computes for NET-01/02/03, just read for chain purposes too):

- ec2-role-s3:   Internet -> EC2 -> IAM role (attached via instance
                 profile) -> S3 bucket (the role's own policy grants
                 GetObject/PutObject/DeleteObject on it).
- ec2-role-role: Internet -> EC2 -> IAM role (attached via instance
                 profile) -> another, admin-equivalent IAM role (the
                 first role can sts:AssumeRole into it, whether that
                 grant names the target role specifically - the IAM-05
                 relationship - or is a Resource:* wildcard grant - the
                 IAM-06 relationship) - re-scoped to just this one role
                 rather than every principal in the account. Tried
                 before ec2-role-s3 when both match the same instance:
                 reaching an admin-equivalent role is account-wide
                 compromise, a strictly worse outcome than one bucket's
                 data, so it's the story that should surface.

Deliberately out of scope, per the build plan: cross-account trust
resolution, and any chain shape beyond these two fixed templates.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from botocore.exceptions import ClientError

from plexavo.findings import Finding
from plexavo.principals import (
    Principal,
    _normalize,
    find_blocking_deny,
    action_within_boundary,
    statement_grants,
    resource_is_wildcard,
)
from plexavo.checks.network import analyze_security_groups, ADMIN_PORTS, DATABASE_PORTS
from plexavo.checks.iam import is_admin_equivalent

MAX_CHAINS = 2

S3_DATA_ACTIONS = {"s3:GetObject", "s3:PutObject", "s3:DeleteObject"}


@dataclass
class ChainNode:
    kind: str                    # "internet" | "ec2" | "iam-role" | "s3"
    title: str                    # e.g. "EC2 instance"
    detail: str                    # human-readable, e.g. "i-0a3f9c21 - sg-0d41 allows port 22 from the internet"
    resource_id: str               # stable, slug-friendly id for this node - instance id / role
                                     # name / bucket name. Used for the report's clickable jump
                                     # anchors (#3) and as the key for chain-participation counting.
    check_id: str | None = None    # an existing Finding this node is grounded in (e.g. "NET-01"), if any
    finding_resource_arn: str | None = None  # the exact Finding.resource_arn form this node
                                               # corresponds to (e.g. the role's full ARN, not just
                                               # its name) - used only to link this node back to a
                                               # real Finding for chain-impact purposes
                                               # (apply_chain_impact below). None for the "internet"
                                               # node, which isn't a scannable resource at all.


@dataclass
class AttackChain:
    chain_id: str                  # "path-1", "path-2"
    template: str                   # "ec2-role-s3" | "ec2-role-role"
    nodes: list = field(default_factory=list)


def _exposure_detail(sg_map: dict, sg_ids: list) -> tuple[str, str] | None:
    """(sg_id, human-readable exposure text) for the first sg among sg_ids
    that's actually open to the internet, or None. Reads the exact
    exposure facts analyze_security_groups already computes for
    NET-01/02/03 - no new exposure logic, just a different presentation
    of the same data."""
    for sg_id in sg_ids:
        info = sg_map.get(sg_id)
        if not info:
            continue
        if info["all_ports_open"]:
            scope = "all ports and protocols" if info["all_protocols"] else "all ports (one protocol)"
            return sg_id, f"{info['name']} ({sg_id}) allows {scope} from the internet"
        if info["open_ranges"]:
            lo, hi = info["open_ranges"][0]
            label = ADMIN_PORTS.get(lo) or DATABASE_PORTS.get(lo)
            port_desc = f"port {lo}" if lo == hi else f"ports {lo}-{hi}"
            if label:
                port_desc += f" ({label})"
            return sg_id, f"{info['name']} ({sg_id}) allows {port_desc} from the internet"
    return None


def _resolve_instance_profile_role(iam, profile_arn: str) -> str | None:
    profile_name = profile_arn.rsplit("/", 1)[-1]
    try:
        profile = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
    except ClientError:
        return None
    roles = profile.get("Roles", [])
    return roles[0]["Arn"] if roles else None


def _list_exposed_instances_with_role(ec2, iam) -> list[dict]:
    """Public, running/pending EC2 instances that are internet-exposed on
    some port AND have an IAM instance profile attached, resolved to the
    role's ARN.

    New data collection: describe_instances already returns
    IamInstanceProfile, but nothing in the codebase resolves that profile
    to its role today. Deliberately NOT reusing network.py's
    list_public_instances - that function is shared by NET-01/02/03/04
    and already tested against a fixed tuple shape; this queries the same
    API independently instead of changing a shipped function's contract.
    """
    sg_map = analyze_security_groups(ec2)
    profile_role_cache: dict[str, str | None] = {}
    results = []

    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(Filters=[
        {"Name": "instance-state-name", "Values": ["pending", "running"]}
    ]):
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                public_ip = instance.get("PublicIpAddress")
                if not public_ip:
                    continue
                profile = instance.get("IamInstanceProfile")
                if not profile or not profile.get("Arn"):
                    continue
                sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
                exposure = _exposure_detail(sg_map, sg_ids)
                if not exposure:
                    continue
                sg_id, exposure_text = exposure

                profile_arn = profile["Arn"]
                if profile_arn not in profile_role_cache:
                    profile_role_cache[profile_arn] = _resolve_instance_profile_role(iam, profile_arn)
                role_arn = profile_role_cache[profile_arn]
                if not role_arn:
                    continue

                name = next(
                    (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                    instance["InstanceId"],
                )
                results.append({
                    "instance_id": instance["InstanceId"],
                    "name": name,
                    "public_ip": public_ip,
                    "sg_id": sg_id,
                    "exposure_text": exposure_text,
                    "role_arn": role_arn,
                })
    return results


def _role_s3_grants(principal: Principal, bucket_names: list[str]) -> list[tuple[str, set]]:
    """Buckets this role's own policies grant s3:GetObject/PutObject/
    DeleteObject on (directly, or via s3:*/Action:* wildcards -
    _action_matches in principals.py already resolves those), that
    survive Deny/permission-boundary verification. Returns
    [(bucket_name, granted_actions)].

    Resource matching is a deliberate prefix check against the bucket's
    own ARN (exact bucket ARN, or anything under "bucket/") rather than
    principals.resource_includes' exact-match - a policy scoped to a
    sub-prefix or a specific key still genuinely grants access into this
    bucket, and missing that would be a false negative on a real path.
    """
    grants: dict[str, set] = {}
    for _policy_name, statements in principal.policies:
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            granted = statement_grants(stmt, S3_DATA_ACTIONS)
            if not granted:
                continue
            resources = _normalize(stmt.get("Resource"))
            is_wildcard = resource_is_wildcard(stmt)
            for bucket in bucket_names:
                bucket_arn = f"arn:aws:s3:::{bucket}"
                matches = is_wildcard or any(
                    r == bucket_arn or r.startswith(bucket_arn + "/") for r in resources
                )
                if not matches:
                    continue
                grants.setdefault(bucket, set()).update(granted)

    confirmed = []
    for bucket, actions in grants.items():
        # Representative resource ARN for the Deny/boundary check, same
        # approximation pattern checks/iam.py's check_04 already uses
        # when passing a single representative target_role_arn.
        representative_arn = f"arn:aws:s3:::{bucket}/*"
        still_granted = set()
        for action in actions:
            blocked, conditioned = find_blocking_deny(principal, action, representative_arn)
            if blocked and not conditioned:
                continue
            if not action_within_boundary(principal, action, representative_arn):
                continue
            still_granted.add(action)
        if still_granted:
            confirmed.append((bucket, still_granted))
    return confirmed


def _role_admin_assume_targets(principal: Principal, admin_roles: dict) -> list[tuple[str, str]]:
    """Admin-equivalent roles this principal can sts:AssumeRole into,
    verified against Deny/boundary - the same relationship IAM-05 checks,
    re-scoped to just this one principal instead of every principal in
    the account, PLUS the IAM-06 (wildcard AssumeRole) relationship
    folded in: a Resource:* grant means every admin-equivalent role is a
    candidate target, each still verified individually against
    Deny/boundary before being accepted. Deliberately broader than a
    literal replay of check_05 alone - excluding the wildcard case would
    mean the single most dangerous grant (assume ANY role) produces no
    chain while a narrower, less severe one does, which is exactly
    backwards for a feature whose job is showing real risk.
    admin_roles is {role_arn: role_name}."""
    targets = []
    for _policy_name, statements in principal.policies:
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            if not statement_grants(stmt, {"sts:AssumeRole"}):
                continue
            if resource_is_wildcard(stmt):
                candidate_arns = set(admin_roles)
            else:
                candidate_arns = set(_normalize(stmt.get("Resource"))) & set(admin_roles)
            for target_arn in sorted(candidate_arns):
                if target_arn == principal.arn:
                    continue
                blocked, conditioned = find_blocking_deny(principal, "sts:AssumeRole", target_arn)
                if blocked and not conditioned:
                    continue
                if not action_within_boundary(principal, "sts:AssumeRole", target_arn):
                    continue
                targets.append((target_arn, admin_roles[target_arn]))
    return targets


def build_attack_chains(session, principals: list[Principal]) -> list[AttackChain]:
    """Build up to MAX_CHAINS attack chains from this scan's data.
    Single-account only - cross-account trust resolution is explicitly
    out of scope (see module docstring and the build plan).

    At most one chain per exposed instance (the first template that
    matches - role-to-admin-role tried before S3, since reaching an
    admin-equivalent role is account-wide compromise and a strictly
    worse outcome than one bucket's data; showing the S3 path instead
    when both exist would bury the more severe story), so two instances
    that happen to share the same role/grant don't both spend the
    two-chain budget on near-duplicate paths."""
    ec2 = session.client("ec2")
    iam = session.client("iam")
    s3 = session.client("s3")

    exposed = _list_exposed_instances_with_role(ec2, iam)
    if not exposed:
        return []

    roles_by_arn = {p.arn: p for p in principals if p.type == "role"}
    admin_roles = {
        p.arn: p.name for p in principals
        if p.type == "role" and is_admin_equivalent(p)
    }
    bucket_names = [b["Name"] for b in s3.list_buckets()["Buckets"]]

    chains: list[AttackChain] = []

    for entry in exposed:
        if len(chains) >= MAX_CHAINS:
            break
        role = roles_by_arn.get(entry["role_arn"])
        if role is None:
            continue

        internet_node = ChainNode(
            kind="internet", title="Internet", detail="Unauthenticated, from anywhere",
            resource_id="internet",
        )
        ec2_node = ChainNode(
            kind="ec2", title="EC2 instance",
            detail=f"{entry['instance_id']} - {entry['exposure_text']}",
            resource_id=entry["instance_id"],
            finding_resource_arn=entry["instance_id"],  # NET-01/02/03 use the bare instance id as resource_arn too
        )
        role_node = ChainNode(
            kind="iam-role", title="IAM role",
            detail=f"{role.name} - attached via instance profile",
            resource_id=role.name,
            finding_resource_arn=role.arn,
        )

        assume_targets = _role_admin_assume_targets(role, admin_roles)
        if assume_targets:
            target_arn, target_name = assume_targets[0]
            target_role_node = ChainNode(
                kind="iam-role", title="IAM role",
                detail=f"{target_name} - admin-equivalent, reachable via sts:AssumeRole",
                resource_id=target_name,
                finding_resource_arn=target_arn,
            )
            chains.append(AttackChain(
                chain_id=f"path-{len(chains) + 1}", template="ec2-role-role",
                nodes=[internet_node, ec2_node, role_node, target_role_node],
            ))
            continue

        s3_grants = _role_s3_grants(role, bucket_names)
        if s3_grants:
            bucket, actions = s3_grants[0]
            s3_node = ChainNode(
                kind="s3", title="S3 bucket",
                detail=f"{bucket} - role policy grants {', '.join(sorted(actions))}",
                finding_resource_arn=f"arn:aws:s3:::{bucket}",
                resource_id=bucket,
            )
            chains.append(AttackChain(
                chain_id=f"path-{len(chains) + 1}", template="ec2-role-s3",
                nodes=[internet_node, ec2_node, role_node, s3_node],
            ))

    return chains


def compute_chain_participation(chains: list[AttackChain]) -> dict:
    """For every (kind, resource_id) node across all given chains
    (excluding the "internet" node - not a fixable resource), how many
    of those chains it appears in. This is the actual prioritization
    signal the build plan calls for: remediating a node that appears in
    N chains breaks all N of them at once - severity alone doesn't tell
    you that.

    Returns {(kind, resource_id): count}. The denominator for a "breaks
    N of M" display is simply len(chains) - the total chains this scan
    produced (capped at MAX_CHAINS)."""
    counts: dict = {}
    for chain in chains:
        # A set, not a list - a node kind could in principle repeat within
        # one chain (it doesn't with the current two templates, but this
        # stays correct if a future template ever revisits a resource).
        node_keys = {(n.kind, n.resource_id) for n in chain.nodes if n.kind != "internet"}
        for key in node_keys:
            counts[key] = counts.get(key, 0) + 1
    return counts


def apply_chain_impact(findings: list[Finding], chains: list[AttackChain]) -> None:
    """Sets Finding.chain_breaks_count on every finding whose resource_arn
    matches a chain node's finding_resource_arn - e.g. the EC2 instance
    behind a chain's entry point is very likely already flagged by
    NET-01/02/03, and that existing finding now carries "this sits inside
    N attack chain(s)" as prioritization metadata.

    Mutates findings in place; findings not touched by any chain are left
    at the dataclass default of 0. Purely additive - never reads or
    writes severity or score_penalty. See the no-optics-tuning rule: this
    changes how findings are PRIORITIZED for reading order, never what
    was detected or how severe it's scored."""
    node_counts = compute_chain_participation(chains)
    resource_to_count: dict = {}
    for chain in chains:
        for node in chain.nodes:
            if node.finding_resource_arn is None:
                continue
            count = node_counts.get((node.kind, node.resource_id), 0)
            existing = resource_to_count.get(node.finding_resource_arn, 0)
            resource_to_count[node.finding_resource_arn] = max(existing, count)

    for finding in findings:
        finding.chain_breaks_count = resource_to_count.get(finding.resource_arn, 0)
