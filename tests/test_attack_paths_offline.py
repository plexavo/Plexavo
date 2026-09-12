"""Offline regression test for attack_paths.py. No AWS calls - fake boto3
clients matching the paginator interface the module actually uses, plus
hand-built Principal objects mirroring test_iam_offline.py's conventions.

Run: python test_attack_paths_offline.py
"""

import sys

from plexavo.principals import Principal
from plexavo.findings import Finding, Severity
from plexavo import attack_paths as ap


# --- Fakes -------------------------------------------------------------

class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return self._pages


class FakeEC2:
    def __init__(self, security_groups, instances):
        self._sg_pages = [{"SecurityGroups": security_groups}]
        self._instance_pages = [{"Reservations": [{"Instances": instances}]}]

    def get_paginator(self, name):
        if name == "describe_security_groups":
            return FakePaginator(self._sg_pages)
        if name == "describe_instances":
            return FakePaginator(self._instance_pages)
        raise ValueError(name)


class FakeClientError(Exception):
    def __init__(self):
        self.response = {"Error": {"Code": "NoSuchEntity"}}


class FakeIAM:
    def __init__(self, profile_to_role: dict):
        # profile_to_role: {profile_name: role_arn or None}
        self._profile_to_role = profile_to_role

    def get_instance_profile(self, InstanceProfileName):
        if InstanceProfileName not in self._profile_to_role:
            raise FakeClientError()
        role_arn = self._profile_to_role[InstanceProfileName]
        roles = [{"Arn": role_arn}] if role_arn else []
        return {"InstanceProfile": {"Roles": roles}}


class FakeS3:
    def __init__(self, bucket_names):
        self._bucket_names = bucket_names

    def list_buckets(self):
        return {"Buckets": [{"Name": n} for n in self._bucket_names]}


class FakeSession:
    def __init__(self, ec2, iam, s3):
        self._clients = {"ec2": ec2, "iam": iam, "s3": s3}

    def client(self, name):
        return self._clients[name]


def sg(group_id, name, rules):
    return {"GroupId": group_id, "GroupName": name, "IpPermissions": rules}


def open_rule(from_port, to_port, protocol="tcp"):
    return {"IpProtocol": protocol, "FromPort": from_port, "ToPort": to_port,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}


def private_rule(from_port, to_port, cidr="10.0.0.0/16"):
    return {"IpProtocol": "tcp", "FromPort": from_port, "ToPort": to_port,
            "IpRanges": [{"CidrIp": cidr}], "Ipv6Ranges": []}


def instance(instance_id, name, public_ip, sg_ids, profile_arn=None):
    inst = {
        "InstanceId": instance_id,
        "Tags": [{"Key": "Name", "Value": name}],
        "SecurityGroups": [{"GroupId": g} for g in sg_ids],
    }
    if public_ip:
        inst["PublicIpAddress"] = public_ip
    if profile_arn:
        inst["IamInstanceProfile"] = {"Arn": profile_arn}
    return inst


def role(name, statements, boundary=None):
    arn = f"arn:aws:iam::111111111111:role/{name}"
    return Principal(type="role", name=name, arn=arn,
                      policies=[("test-policy", statements)],
                      permission_boundary=[("boundary", boundary)] if boundary else [],
                      has_permission_boundary=boundary is not None)


def allow(**kw):
    return {"Effect": "Allow", **kw}


def deny(**kw):
    return {"Effect": "Deny", **kw}


PROFILE_ARN = "arn:aws:iam::111111111111:instance-profile/app-profile"

failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


def build(session_kwargs, principals):
    session = FakeSession(**session_kwargs)
    return ap.build_attack_chains(session, principals)


# === No exposed instance at all -> zero chains ===
print("=== No exposed instances ===")
app_role = role("app-server-role", [allow(Action=["s3:GetObject", "s3:PutObject"], Resource="arn:aws:s3:::plexavo-app-data/*")])
chains = build(
    dict(
        ec2=FakeEC2([sg("sg-priv", "priv", [private_rule(22, 22)])],
                    [instance("i-priv", "priv-box", None, ["sg-priv"], PROFILE_ARN)]),
        iam=FakeIAM({"app-profile": app_role.arn}),
        s3=FakeS3(["plexavo-app-data"]),
    ),
    [app_role],
)
assert_true(chains == [], "Private instance (no public IP) produces zero chains")

# === Exposed instance, no instance profile attached -> zero chains ===
print("\n=== Exposed instance, no instance profile ===")
chains = build(
    dict(
        ec2=FakeEC2([sg("sg-open", "open", [open_rule(22, 22)])],
                    [instance("i-noprof", "no-profile-box", "1.2.3.4", ["sg-open"])]),
        iam=FakeIAM({}),
        s3=FakeS3(["plexavo-app-data"]),
    ),
    [app_role],
)
assert_true(chains == [], "Exposed instance with no IAM instance profile produces zero chains")

# === Template A: EC2 -> role -> S3, real chain ===
print("\n=== Template A: EC2 -> role -> S3 ===")
chains = build(
    dict(
        ec2=FakeEC2([sg("sg-0d41", "web-sg", [open_rule(22, 22)])],
                    [instance("i-0a3f9c21", "web-01", "1.2.3.4", ["sg-0d41"], PROFILE_ARN)]),
        iam=FakeIAM({"app-profile": app_role.arn}),
        s3=FakeS3(["plexavo-app-data", "unrelated-bucket"]),
    ),
    [app_role],
)
assert_true(len(chains) == 1, "Exactly one chain found")
if chains:
    c = chains[0]
    assert_true(c.template == "ec2-role-s3", "Template is ec2-role-s3")
    assert_true(c.chain_id == "path-1", "Chain id is path-1")
    kinds = [n.kind for n in c.nodes]
    assert_true(kinds == ["internet", "ec2", "iam-role", "s3"], "Node kinds in order: internet, ec2, iam-role, s3")
    assert_true(c.nodes[1].resource_id == "i-0a3f9c21", "EC2 node resource_id is the instance id")
    assert_true(c.nodes[2].resource_id == "app-server-role", "IAM role node resource_id is the role name")
    assert_true(c.nodes[3].resource_id == "plexavo-app-data", "S3 node resource_id is the actual granted bucket, not the unrelated one")
    assert_true("GetObject" in c.nodes[3].detail and "PutObject" in c.nodes[3].detail, "S3 node detail names the granted actions")

# === ACCURACY GUARD: unconditioned explicit Deny suppresses the S3 hop entirely ===
print("\n=== ACCURACY GUARD: explicit Deny on the S3 grant suppresses the chain ===")
denied_role = role("denied-role", [
    allow(Action=["s3:GetObject", "s3:PutObject"], Resource="arn:aws:s3:::plexavo-app-data/*"),
    deny(Action=["s3:GetObject", "s3:PutObject"], Resource="arn:aws:s3:::plexavo-app-data/*"),
])
chains = build(
    dict(
        ec2=FakeEC2([sg("sg-0d41", "web-sg", [open_rule(22, 22)])],
                    [instance("i-denied", "web-02", "1.2.3.5", ["sg-0d41"], PROFILE_ARN)]),
        iam=FakeIAM({"app-profile": denied_role.arn}),
        s3=FakeS3(["plexavo-app-data"]),
    ),
    [denied_role],
)
assert_true(chains == [], "An unconditioned explicit Deny on the exact grant suppresses the chain - never shown as real")

# === ACCURACY GUARD: permission boundary without S3 access suppresses the S3 hop ===
print("\n=== ACCURACY GUARD: permission boundary excluding S3 suppresses the chain ===")
boundary_role = role(
    "boundary-role",
    [allow(Action=["s3:GetObject", "s3:PutObject"], Resource="arn:aws:s3:::plexavo-app-data/*")],
    boundary=[allow(Action=["ec2:Describe*"], Resource="*")],
)
chains = build(
    dict(
        ec2=FakeEC2([sg("sg-0d41", "web-sg", [open_rule(22, 22)])],
                    [instance("i-boundary", "web-03", "1.2.3.6", ["sg-0d41"], PROFILE_ARN)]),
        iam=FakeIAM({"app-profile": boundary_role.arn}),
        s3=FakeS3(["plexavo-app-data"]),
    ),
    [boundary_role],
)
assert_true(chains == [], "A permission boundary that doesn't allow S3 access suppresses the chain")

# === Template B: EC2 -> role -> admin-equivalent role ===
print("\n=== Template B: EC2 -> role -> admin-equivalent role ===")
admin_role = role("admin-role", [allow(Action="*", Resource="*")])
assume_role = role("assume-role", [allow(Action="sts:AssumeRole", Resource=admin_role.arn)])
chains = build(
    dict(
        ec2=FakeEC2([sg("sg-x", "x-sg", [open_rule(3389, 3389)])],
                    [instance("i-assume", "jump-box", "5.6.7.8", ["sg-x"], PROFILE_ARN)]),
        iam=FakeIAM({"app-profile": assume_role.arn}),
        s3=FakeS3([]),
    ),
    [assume_role, admin_role],
)
assert_true(len(chains) == 1, "Exactly one chain found")
if chains:
    c = chains[0]
    assert_true(c.template == "ec2-role-role", "Template is ec2-role-role")
    kinds = [n.kind for n in c.nodes]
    assert_true(kinds == ["internet", "ec2", "iam-role", "iam-role"], "Node kinds: internet, ec2, iam-role, iam-role")
    assert_true(c.nodes[3].resource_id == "admin-role", "Target role node resource_id is the admin role's name")

# === COVERAGE: wildcard sts:AssumeRole (the IAM-06 relationship) also produces a chain ===
print("\n=== Template B, wildcard grant: role can assume ANY role, including an admin one ===")
admin_role2 = role("admin-role-2", [allow(Action="*", Resource="*")])
wildcard_assume_role = role("wildcard-assume-role", [allow(Action="sts:AssumeRole", Resource="*")])
chains = build(
    dict(
        ec2=FakeEC2([sg("sg-w", "w-sg", [open_rule(22, 22)])],
                    [instance("i-wildcard", "wildcard-box", "6.6.6.6", ["sg-w"], PROFILE_ARN)]),
        iam=FakeIAM({"app-profile": wildcard_assume_role.arn}),
        s3=FakeS3([]),
    ),
    [wildcard_assume_role, admin_role2],
)
assert_true(len(chains) == 1, "A wildcard sts:AssumeRole grant produces a chain, not zero - it's the most dangerous case, not an excluded one")
if chains:
    assert_true(chains[0].template == "ec2-role-role", "Template is ec2-role-role even though the grant was Resource:*, not a named target")
    assert_true(chains[0].nodes[3].resource_id == "admin-role-2", "Target role node names a real admin-equivalent role reachable under the wildcard")

# === PRIORITY: when a role can BOTH assume an admin role AND reach S3, the admin chain wins ===
print("\n=== Priority: role-to-admin-role chain shown over S3 when both are possible ===")
admin_role3 = role("admin-role-3", [allow(Action="*", Resource="*")])
both_role = role("both-role", [
    allow(Action="sts:AssumeRole", Resource=admin_role3.arn),
    allow(Action=["s3:GetObject"], Resource="arn:aws:s3:::plexavo-app-data/*"),
])
chains = build(
    dict(
        ec2=FakeEC2([sg("sg-p", "p-sg", [open_rule(22, 22)])],
                    [instance("i-both", "both-box", "7.7.7.7", ["sg-p"], PROFILE_ARN)]),
        iam=FakeIAM({"app-profile": both_role.arn}),
        s3=FakeS3(["plexavo-app-data"]),
    ),
    [both_role, admin_role3],
)
assert_true(len(chains) == 1, "Exactly one chain, not two - one chain per instance still holds")
if chains:
    assert_true(chains[0].template == "ec2-role-role", "The admin-role-escalation story wins over the S3 story - it's the more severe outcome")

# === Cap: two eligible instances -> exactly two chains, not more ===
print("\n=== Cap at MAX_CHAINS ===")
role_a = role("role-a", [allow(Action=["s3:GetObject"], Resource="arn:aws:s3:::bucket-a/*")])
role_b = role("role-b", [allow(Action=["s3:GetObject"], Resource="arn:aws:s3:::bucket-b/*")])
role_c = role("role-c", [allow(Action=["s3:GetObject"], Resource="arn:aws:s3:::bucket-c/*")])
chains = build(
    dict(
        ec2=FakeEC2(
            [sg("sg-y", "y-sg", [open_rule(22, 22)])],
            [
                instance("i-a", "box-a", "9.9.9.1", ["sg-y"], "arn:aws:iam::111111111111:instance-profile/profile-a"),
                instance("i-b", "box-b", "9.9.9.2", ["sg-y"], "arn:aws:iam::111111111111:instance-profile/profile-b"),
                instance("i-c", "box-c", "9.9.9.3", ["sg-y"], "arn:aws:iam::111111111111:instance-profile/profile-c"),
            ],
        ),
        iam=FakeIAM({"profile-a": role_a.arn, "profile-b": role_b.arn, "profile-c": role_c.arn}),
        s3=FakeS3(["bucket-a", "bucket-b", "bucket-c"]),
    ),
    [role_a, role_b, role_c],
)
assert_true(len(chains) == ap.MAX_CHAINS, f"Capped at {ap.MAX_CHAINS} chains even with 3 eligible instances")
assert_true([c.chain_id for c in chains] == ["path-1", "path-2"], "Chain ids are path-1, path-2 in order")

# === Clean account: exposed instance + role with no S3/assume grants at all -> zero chains ===
print("\n=== Clean role: no exploitable grant at all ===")
clean_role = role("clean-role", [allow(Action=["s3:GetObject"], Resource="arn:aws:s3:::completely-unrelated-bucket/*")])
chains = build(
    dict(
        ec2=FakeEC2([sg("sg-clean", "clean-sg", [open_rule(22, 22)])],
                    [instance("i-clean", "clean-box", "1.1.1.1", ["sg-clean"], PROFILE_ARN)]),
        iam=FakeIAM({"app-profile": clean_role.arn}),
        s3=FakeS3(["plexavo-app-data"]),  # clean_role's grant references a bucket that doesn't exist in this account
    ),
    [clean_role],
)
assert_true(chains == [], "A role whose only grant targets a bucket outside this account's actual bucket list produces zero chains")

# === #2: risk prioritization - compute_chain_participation + apply_chain_impact ===
print("\n=== compute_chain_participation: a node shared across both chains counts 2, not 1 ===")
shared_admin = role("shared-admin", [allow(Action="*", Resource="*")])
role_x = role("role-x", [allow(Action="sts:AssumeRole", Resource=shared_admin.arn)])
role_y = role("role-y", [allow(Action="sts:AssumeRole", Resource=shared_admin.arn)])
session = FakeSession(
    ec2=FakeEC2(
        [sg("sg-z", "z-sg", [open_rule(22, 22)])],
        [
            instance("i-x", "box-x", "8.8.8.1", ["sg-z"], "arn:aws:iam::111111111111:instance-profile/profile-x"),
            instance("i-y", "box-y", "8.8.8.2", ["sg-z"], "arn:aws:iam::111111111111:instance-profile/profile-y"),
        ],
    ),
    iam=FakeIAM({"profile-x": role_x.arn, "profile-y": role_y.arn}),
    s3=FakeS3([]),
)
chains = ap.build_attack_chains(session, [role_x, role_y, shared_admin])
assert_true(len(chains) == 2, "Two chains built, one per exposed instance")

participation = ap.compute_chain_participation(chains)
assert_true(participation.get(("iam-role", "shared-admin")) == 2, "shared-admin appears in both chains - participation count 2")
assert_true(participation.get(("ec2", "i-x")) == 1, "i-x's own EC2 node only appears in its one chain")
assert_true(participation.get(("iam-role", "role-x")) == 1, "role-x only appears in its one chain")
assert_true(("internet", "internet") not in participation, "The internet node is excluded - it isn't a fixable resource")

print("\n=== apply_chain_impact: real Finding objects get chain_breaks_count set from matching chain nodes ===")
f_shared_admin = Finding(check_id="IAM-01", title="Wildcard Admin Access", severity=Severity.CRITICAL,
                          resource_arn=shared_admin.arn, raw_detail="...")
f_ix = Finding(check_id="NET-01", title="Admin Port Open to the Internet", severity=Severity.CRITICAL,
                resource_arn="i-x", raw_detail="...")
f_unrelated = Finding(check_id="STOR-19", title="S3 Bucket Missing PublicAccessBlock Protection",
                       severity=Severity.CRITICAL, resource_arn="arn:aws:s3:::totally-unrelated-bucket",
                       raw_detail="...")
findings = [f_shared_admin, f_ix, f_unrelated]
ap.apply_chain_impact(findings, chains)

assert_true(f_shared_admin.chain_breaks_count == 2, "Finding on the shared admin role: breaks 2 of 2 chains if fixed")
assert_true(f_ix.chain_breaks_count == 1, "Finding on i-x's instance: breaks 1 of 2 chains if fixed")
assert_true(f_unrelated.chain_breaks_count == 0, "Finding with no matching chain node: 0 - not part of any chain")
assert_true(f_shared_admin.severity == Severity.CRITICAL, "REGRESSION GUARD: severity is never touched by chain-impact")
assert_true(f_shared_admin.severity.score_penalty == 15, "REGRESSION GUARD: score_penalty is never touched by chain-impact")

print("\n=== apply_chain_impact: zero chains leaves every finding at the dataclass default (0) ===")
f_default = Finding(check_id="LOG-25", title="GuardDuty Not Enabled", severity=Severity.HIGH,
                     resource_arn="account", raw_detail="...")
assert_true(f_default.chain_breaks_count == 0, "Untouched finding defaults to 0 even before apply_chain_impact runs")
ap.apply_chain_impact([f_default], [])
assert_true(f_default.chain_breaks_count == 0, "apply_chain_impact with zero chains leaves every finding at 0")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
