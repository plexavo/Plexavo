"""Offline regression test for network.py. No AWS calls — fake boto3
clients with the exact paginator interface network.py uses.

Run: python test_network_offline.py
"""

import sys
from plexavo.checks import network as net


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


class FakeRDS:
    def __init__(self, db_instances):
        self._pages = [{"DBInstances": db_instances}]

    def get_paginator(self, name):
        if name == "describe_db_instances":
            return FakePaginator(self._pages)
        raise ValueError(name)


class FakeSession:
    def __init__(self, ec2=None, rds=None):
        self._ec2 = ec2
        self._rds = rds

    def client(self, name):
        return {"ec2": self._ec2, "rds": self._rds}[name]


def sg(group_id, name, rules):
    return {"GroupId": group_id, "GroupName": name, "IpPermissions": rules}


def open_rule(from_port, to_port, protocol="tcp"):
    return {"IpProtocol": protocol, "FromPort": from_port, "ToPort": to_port,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}


def all_ports_rule():
    return {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}


def private_rule(from_port, to_port, cidr="10.0.0.0/16"):
    return {"IpProtocol": "tcp", "FromPort": from_port, "ToPort": to_port,
            "IpRanges": [{"CidrIp": cidr}], "Ipv6Ranges": []}


def instance(instance_id, name, public_ip, sg_ids):
    return {
        "InstanceId": instance_id,
        "Tags": [{"Key": "Name", "Value": name}],
        "PublicIpAddress": public_ip,
        "SecurityGroups": [{"GroupId": g} for g in sg_ids],
    }


def private_instance(instance_id, name, sg_ids):
    return {
        "InstanceId": instance_id,
        "Tags": [{"Key": "Name", "Value": name}],
        "SecurityGroups": [{"GroupId": g} for g in sg_ids],
        # no PublicIpAddress key at all — matches real boto3 behavior for private instances
    }


failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


def run_ec2_checks(security_groups, instances):
    ec2 = FakeEC2(security_groups, instances)
    sg_map = net.analyze_security_groups(ec2)
    pub_instances = net.list_public_instances(ec2)
    findings = []
    findings += net.check_net01_admin_port_open(sg_map, pub_instances)
    findings += net.check_net02_database_port_open(sg_map, pub_instances)
    findings += net.check_net03_all_ports_open(sg_map, pub_instances)
    return findings


print("=== NET-01: SSH open to the internet on a public instance ===")
sgs = [sg("sg-ssh", "ssh-open", [open_rule(22, 22)])]
insts = [instance("i-ssh", "ssh-box", "1.2.3.4", ["sg-ssh"])]
findings = run_ec2_checks(sgs, insts)
assert_true(any(f.check_id == "NET-01" and f.resource_arn == "i-ssh" for f in findings), "NET-01 fires on SSH open + public IP")

print("\n=== NET-02: database port open to the internet on a public instance ===")
sgs = [sg("sg-db", "db-open", [open_rule(3306, 3306)])]
insts = [instance("i-db", "db-box", "1.2.3.5", ["sg-db"])]
findings = run_ec2_checks(sgs, insts)
assert_true(any(f.check_id == "NET-02" and f.resource_arn == "i-db" for f in findings), "NET-02 fires on MySQL port open + public IP")

print("\n=== NET-03: all ports open to the internet on a public instance ===")
sgs = [sg("sg-all", "all-open", [all_ports_rule()])]
insts = [instance("i-all", "all-box", "1.2.3.6", ["sg-all"])]
findings = run_ec2_checks(sgs, insts)
assert_true(any(f.check_id == "NET-03" and f.resource_arn == "i-all" for f in findings), "NET-03 fires on all-ports-open + public IP")
assert_true(any(f.check_id == "NET-01" and f.resource_arn == "i-all" for f in findings), "NET-01 ALSO fires (stacking is intentional — all-ports-open includes SSH too)")
assert_true(any(f.check_id == "NET-02" and f.resource_arn == "i-all" for f in findings), "NET-02 ALSO fires (stacking is intentional — all-ports-open includes DB ports too)")

print("\n=== REGRESSION: TCP-only full port range (0-65535) still fires NET-03, but wording doesn't overclaim 'all protocols' ===")
# Confirmed via a real live scan + direct AWS verification: a rule with
# IpProtocol="tcp" (not "-1") spanning the full port range was being
# described as "all ports and protocols" — overclaiming protocol
# coverage UDP/ICMP aren't actually touched by a TCP-scoped rule, even
# though every TCP port being reachable is still a genuinely severe,
# correctly-fired finding on its own.
sgs = [sg("sg-tcp-full", "tcp-full-range", [open_rule(0, 65535, "tcp")])]
insts = [instance("i-tcp-full", "tcp-box", "1.2.3.7", ["sg-tcp-full"])]
findings = run_ec2_checks(sgs, insts)
net03 = [f for f in findings if f.check_id == "NET-03" and f.resource_arn == "i-tcp-full"]
assert_true(len(net03) == 1, "NET-03 still correctly fires on a TCP-only full-range rule")
assert_true("all protocols" not in net03[0].raw_detail.lower(), f"Does NOT overclaim 'all protocols' for a TCP-scoped rule (got: {net03[0].raw_detail})")

print("\n=== FALSE POSITIVE GUARD (inverse): a genuine protocol=-1 rule DOES correctly say 'all protocols' ===")
sgs_all = [sg("sg-genuinely-all", "genuinely-all", [all_ports_rule()])]
insts_all = [instance("i-genuinely-all", "all-box-2", "1.2.3.8", ["sg-genuinely-all"])]
findings_all = run_ec2_checks(sgs_all, insts_all)
net03_all = [f for f in findings_all if f.check_id == "NET-03" and f.resource_arn == "i-genuinely-all"]
assert_true(len(net03_all) == 1 and "protocols" in net03_all[0].raw_detail.lower(),
            f"A genuine protocol=-1 rule still correctly claims 'all protocols' — the fix didn't undercorrect (got: {net03_all[0].raw_detail if net03_all else None})")

print("\n=== FALSE POSITIVE GUARD: dangerous SG attached to a PRIVATE instance (no public IP) must not fire ===")
sgs = [sg("sg-priv", "ssh-open-private", [open_rule(22, 22)])]
insts = [private_instance("i-priv", "private-box", ["sg-priv"])]
findings = run_ec2_checks(sgs, insts)
assert_true(len(findings) == 0, "No findings for a wide-open SG on an instance with no public IP")

print("\n=== FALSE POSITIVE GUARD: dangerous SG that exists but is attached to NOTHING must not fire ===")
sgs = [sg("sg-orphan", "orphaned-ssh-open", [open_rule(22, 22)])]
insts = []  # no instances at all
findings = run_ec2_checks(sgs, insts)
assert_true(len(findings) == 0, "No findings for an orphaned SG with no attached instance")

print("\n=== FALSE POSITIVE GUARD: internally-scoped rule (specific CIDR, not 0.0.0.0/0) must not fire ===")
sgs = [sg("sg-office", "office-only-ssh", [private_rule(22, 22, cidr="203.0.113.0/24")])]
insts = [instance("i-office", "office-box", "1.2.3.7", ["sg-office"])]
findings = run_ec2_checks(sgs, insts)
assert_true(len(findings) == 0, "No findings for SSH scoped to a specific office CIDR, not 0.0.0.0/0")

print("\n=== FALSE POSITIVE GUARD: clean instance, restrictive SG (HTTPS only, from anywhere) ===")
sgs = [sg("sg-clean", "https-only", [open_rule(443, 443)])]
insts = [instance("i-clean", "web-box", "1.2.3.8", ["sg-clean"])]
findings = run_ec2_checks(sgs, insts)
assert_true(len(findings) == 0, "No findings for HTTPS-only exposure — not an admin port, not a DB port, not all-ports")

print("\n=== NET-04 (offline only — no AWS ground truth yet): publicly accessible RDS with exposed SG ===")
sgs = [sg("sg-rds-open", "rds-open", [open_rule(3306, 3306)])]
db_instances = [{
    "DBInstanceIdentifier": "db-exposed",
    "Engine": "mysql",
    "PubliclyAccessible": True,
    "Endpoint": {"Port": 3306},
    "DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:db-exposed",
    "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-rds-open", "Status": "active"}],
}]
session = FakeSession(ec2=FakeEC2(sgs, []), rds=FakeRDS(db_instances))
findings = net.check_net04_rds_publicly_accessible(session)
assert_true(any(f.check_id == "NET-04" and "db-exposed" in f.resource_arn for f in findings), "NET-04 fires on PubliclyAccessible RDS with an exposed SG")

print("\n=== NET-04 FALSE POSITIVE GUARD: PubliclyAccessible=True but SG doesn't actually open the DB port ===")
sgs = [sg("sg-rds-locked", "rds-locked", [private_rule(3306, 3306, cidr="10.0.0.0/16")])]
db_instances = [{
    "DBInstanceIdentifier": "db-locked",
    "Engine": "postgres",
    "PubliclyAccessible": True,
    "Endpoint": {"Port": 5432},
    "DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:db-locked",
    "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-rds-locked", "Status": "active"}],
}]
session = FakeSession(ec2=FakeEC2(sgs, []), rds=FakeRDS(db_instances))
findings = net.check_net04_rds_publicly_accessible(session)
assert_true(len(findings) == 0, "PubliclyAccessible=True alone doesn't fire — SG must actually expose the DB port too")

print("\n=== NET-04 FALSE POSITIVE GUARD: PubliclyAccessible=False, even with a wide-open SG, must not fire ===")
sgs = [sg("sg-rds-open2", "rds-open2", [open_rule(5432, 5432)])]
db_instances = [{
    "DBInstanceIdentifier": "db-not-public",
    "Engine": "postgres",
    "PubliclyAccessible": False,
    "Endpoint": {"Port": 5432},
    "DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:db-not-public",
    "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-rds-open2", "Status": "active"}],
}]
session = FakeSession(ec2=FakeEC2(sgs, []), rds=FakeRDS(db_instances))
findings = net.check_net04_rds_publicly_accessible(session)
assert_true(len(findings) == 0, "PubliclyAccessible=False doesn't fire even with a wide-open SG — RDS has no public endpoint to reach")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
