"""Offline regression test for compute.py (EC2-32, IMDSv2 enforcement).
No AWS calls — fake boto3 client with the exact paginator interface
compute.py uses.

Fixtures mirror the real "capital_one stack" demo terraform that surfaced
this gap: metadata_options { http_tokens = "optional", http_endpoint =
"enabled" } on an instance with an attached (over-permissioned) IAM role.

Run: python test_compute_offline.py
"""

import sys
from plexavo.checks import compute


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return self._pages


class FakeEC2:
    def __init__(self, instances):
        self._pages = [{"Reservations": [{"Instances": instances}]}]

    def get_paginator(self, name):
        if name == "describe_instances":
            return FakePaginator(self._pages)
        raise ValueError(name)


def instance(instance_id, name, http_tokens="required", http_endpoint="enabled", has_role=False,
             omit_metadata_options=False):
    inst = {
        "InstanceId": instance_id,
        "Tags": [{"Key": "Name", "Value": name}],
    }
    if not omit_metadata_options:
        inst["MetadataOptions"] = {"HttpTokens": http_tokens, "HttpEndpoint": http_endpoint}
    if has_role:
        inst["IamInstanceProfile"] = {"Arn": "arn:aws:iam::111111111111:instance-profile/demo-profile"}
    return inst


failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


def run(instances):
    ec2 = FakeEC2(instances)
    return compute.check_32_imdsv2_not_enforced(compute.list_instances_with_metadata(ec2))


# === BASELINE: IMDSv2 required -> no finding, whether or not a role is attached ===
print("=== IMDSv2 required (good posture) ===")
findings = run([instance("i-good1", "hardened-with-role", http_tokens="required", has_role=True),
                instance("i-good2", "hardened-no-role", http_tokens="required", has_role=False)])
assert_true(findings == [], "No finding when http_tokens='required', regardless of role attachment")

# === Real "capital_one stack" shape: IMDSv1 allowed + role attached -> CRITICAL ===
print("\n=== IMDSv1 allowed + IAM role attached (the Capital One shape) -> CRITICAL ===")
findings = run([instance("i-waf-analog", "waf-analog-instance", http_tokens="optional", has_role=True)])
assert_true(len(findings) == 1, "Exactly one finding")
f = findings[0]
assert_true(f.check_id == "EC2-32", "check_id is EC2-32")
assert_true(f.severity.value == "Critical", f"Severity is Critical when a role is attached (got: {f.severity.value})")
assert_true(f.resource_arn == "i-waf-analog", "resource_arn is the instance id")
assert_true("Capital One" in f.raw_detail, "Finding text names the real-world precedent for the credential-theft case")
assert_true("iam_role_attached=True" in f.evidence, "Evidence states the role attachment fact plainly")

# === IMDSv1 allowed, no role attached -> Medium, not Critical ===
print("\n=== IMDSv1 allowed, no IAM role attached -> Medium ===")
findings = run([instance("i-norole", "standalone-box", http_tokens="optional", has_role=False)])
assert_true(len(findings) == 1, "Exactly one finding")
assert_true(findings[0].severity.value == "Medium", f"Severity is Medium with no role attached (got: {findings[0].severity.value})")
assert_true("Capital One" not in findings[0].raw_detail, "No-role case does not invoke the credential-theft precedent it doesn't apply to")

# === FALSE POSITIVE GUARD: metadata service disabled entirely -> no finding ===
print("\n=== FALSE POSITIVE GUARD: http_endpoint='disabled' (IMDS fully off) ===")
findings = run([instance("i-noimds", "imds-disabled", http_tokens="optional", http_endpoint="disabled", has_role=True)])
assert_true(findings == [], "http_tokens='optional' is irrelevant if the metadata endpoint is disabled outright - strongest posture, not a gap")

# === Defensive default: a fixture (or a real API response on some edge case) with no MetadataOptions key at all ===
print("\n=== Defensive default: MetadataOptions missing entirely ===")
findings = run([instance("i-nometa", "no-metadata-options-key", has_role=True, omit_metadata_options=True)])
assert_true(len(findings) == 1, "Missing MetadataOptions defaults to the insecure 'optional'/'enabled' assumption, not silently skipped")
assert_true(findings[0].severity.value == "Critical", "Defaulted case still applies the role-attached severity correctly")

# === Mixed fleet: only the IMDSv1 instances produce findings, each with its own correct severity ===
print("\n=== Mixed fleet ===")
findings = run([
    instance("i-a", "a", http_tokens="required", has_role=True),
    instance("i-b", "b", http_tokens="optional", has_role=True),
    instance("i-c", "c", http_tokens="optional", has_role=False),
    instance("i-d", "d", http_tokens="required", has_role=False),
])
by_id = {f.resource_arn: f for f in findings}
assert_true(set(by_id) == {"i-b", "i-c"}, f"Only the two IMDSv1 instances produce findings (got: {sorted(by_id)})")
assert_true(by_id["i-b"].severity.value == "Critical", "i-b (role attached) is Critical")
assert_true(by_id["i-c"].severity.value == "Medium", "i-c (no role) is Medium")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
