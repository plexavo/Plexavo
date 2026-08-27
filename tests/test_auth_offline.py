"""Offline tests for auth.py. No real AWS calls — boto3.Session.client is
monkeypatched to raise the errors AWS itself would raise, to prove
get_local_session converts them into a clear RuntimeError instead of
letting them crash the caller.

Run: python test_auth_offline.py
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from plexavo.auth import get_local_session

failures = 0


def assert_true(cond, msg):
    global failures
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        failures += 1


class _RaisingClient:
    def __init__(self, exc):
        self._exc = exc

    def get_caller_identity(self):
        raise self._exc


def _patch_client(monkeypatch_exc):
    original_client = boto3.Session.client

    def fake_client(self, service_name, *args, **kwargs):
        if service_name == "sts":
            return _RaisingClient(monkeypatch_exc)
        return original_client(self, service_name, *args, **kwargs)

    return original_client, fake_client


# --- InvalidClientTokenId (deactivated/deleted access key) surfaces as a clear RuntimeError ---
original_client, fake_client = _patch_client(
    ClientError(
        {"Error": {"Code": "InvalidClientTokenId", "Message": "The security token included in the request is invalid."}},
        "GetCallerIdentity",
    )
)
boto3.Session.region_name = property(lambda self: "us-east-1")
boto3.Session.client = fake_client
try:
    raised = None
    try:
        # profile_name=None: boto3.Session() itself always succeeds
        # regardless of what's in this machine's real ~/.aws config —
        # only the (monkeypatched) sts call should fail.
        get_local_session(profile_name=None)
    except RuntimeError as e:
        raised = e
    except Exception as e:
        raised = e

    assert_true(isinstance(raised, RuntimeError), "ClientError (InvalidClientTokenId) is converted to RuntimeError, not left to crash")
    assert_true(raised is not None and "InvalidClientTokenId" in str(raised), "RuntimeError message names the AWS error code")
finally:
    boto3.Session.client = original_client


# --- NoCredentialsError still produces the pre-existing clear message ---
original_client, fake_client = _patch_client(NoCredentialsError())
boto3.Session.client = fake_client
try:
    raised = None
    try:
        get_local_session(profile_name=None)
    except RuntimeError as e:
        raised = e
    except Exception as e:
        raised = e

    assert_true(isinstance(raised, RuntimeError), "NoCredentialsError still converts to RuntimeError (regression check)")
    assert_true(raised is not None and "No AWS credentials found" in str(raised), "NoCredentialsError message unchanged")
finally:
    boto3.Session.client = original_client
    del boto3.Session.region_name


print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
import sys
sys.exit(1 if failures else 0)
