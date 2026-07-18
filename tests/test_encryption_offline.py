"""Offline regression test for encryption.py. No AWS calls.

Run: python test_encryption_offline.py
"""

import sys
from botocore.exceptions import ClientError

from plexavo.checks import encryption


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return self._pages


class FakeEC2:
    def __init__(self, volumes):
        self._pages = [{"Volumes": volumes}]

    def get_paginator(self, name):
        return FakePaginator(self._pages)


class FakeRDS:
    def __init__(self, db_instances):
        self._pages = [{"DBInstances": db_instances}]

    def get_paginator(self, name):
        return FakePaginator(self._pages)


class FakeS3:
    def __init__(self, encryption_configs=None):
        self._encryption_configs = encryption_configs or {}

    def get_bucket_encryption(self, Bucket):
        if Bucket not in self._encryption_configs:
            raise ClientError(
                {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": "x"}},
                "GetBucketEncryption",
            )
        return {"ServerSideEncryptionConfiguration": self._encryption_configs[Bucket]}


failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


print("=== ENC-29: unencrypted EBS volume ===")
volumes = [{"VolumeId": "vol-unenc", "Encrypted": False, "Attachments": [{"InstanceId": "i-abc123"}]}]
findings = encryption.check_29_unencrypted_ebs_volumes(FakeEC2(volumes))
assert_true(any(f.resource_arn == "vol-unenc" for f in findings), "Fires on Encrypted=False")
assert_true(any("i-abc123" in f.raw_detail for f in findings), "Names the attached instance")

print("\n=== FALSE POSITIVE GUARD: encrypted EBS volume ===")
volumes = [{"VolumeId": "vol-enc", "Encrypted": True, "Attachments": []}]
findings = encryption.check_29_unencrypted_ebs_volumes(FakeEC2(volumes))
assert_true(len(findings) == 0, "Does NOT fire on Encrypted=True")

print("\n=== ENC-29: unattached unencrypted volume still fires ===")
volumes = [{"VolumeId": "vol-orphan", "Encrypted": False, "Attachments": []}]
findings = encryption.check_29_unencrypted_ebs_volumes(FakeEC2(volumes))
assert_true(any("not attached to any instance" in f.raw_detail for f in findings),
            "Still fires on an unattached unencrypted volume, correctly labeled")

print("\n=== ENC-30: unencrypted RDS instance ===")
dbs = [{"DBInstanceIdentifier": "db-unenc", "Engine": "mysql", "StorageEncrypted": False,
        "DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:db-unenc"}]
findings = encryption.check_30_unencrypted_rds_instances(FakeRDS(dbs))
assert_true(any("db-unenc" in f.resource_arn for f in findings), "Fires on StorageEncrypted=False")

print("\n=== FALSE POSITIVE GUARD: encrypted RDS instance ===")
dbs = [{"DBInstanceIdentifier": "db-enc", "Engine": "postgres", "StorageEncrypted": True,
        "DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:db-enc"}]
findings = encryption.check_30_unencrypted_rds_instances(FakeRDS(dbs))
assert_true(len(findings) == 0, "Does NOT fire on StorageEncrypted=True")

print("\n=== ENC-31: bucket with no encryption configuration ===")
s3 = FakeS3(encryption_configs={})
findings = encryption.check_31_s3_missing_default_encryption(s3, ["no-enc-bucket"])
assert_true(any(f.check_id == "ENC-31" for f in findings), "Fires when GetBucketEncryption raises NotFound")

print("\n=== FALSE POSITIVE GUARD: bucket with default encryption configured ===")
s3 = FakeS3(encryption_configs={"enc-bucket": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}})
findings = encryption.check_31_s3_missing_default_encryption(s3, ["enc-bucket"])
assert_true(len(findings) == 0, "Does NOT fire when a default encryption config exists")

print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
