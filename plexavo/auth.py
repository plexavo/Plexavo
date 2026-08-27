"""Local AWS credential handling.

Design constraint: nothing is ever handed to anyone else. Plexavo uses
the caller's own configured credentials directly — the default profile,
a named profile, or environment variables — exactly the same resolution
order the AWS CLI itself uses. There is no cross-account access, no
CloudFormation role, and no server in between. Run it yourself, with
your own credentials, and nothing leaves your machine.
"""

from __future__ import annotations

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


def get_local_session(profile_name: str | None = None, region: str | None = None) -> boto3.Session:
    """Build a session from the caller's own local credentials.

    Raises RuntimeError with a clear message on failure — auth failures
    should stop the scan immediately, not surface as a confusing
    downstream permission error buried inside an individual check.
    """
    try:
        session = boto3.Session(profile_name=profile_name)
    except ProfileNotFound as e:
        raise RuntimeError(
            f"{e}. Run `aws configure list-profiles` to see what's "
            "available, or `aws configure` to set up the default profile."
        ) from e

    resolved_region = region or session.region_name
    if not resolved_region:
        raise RuntimeError(
            "No AWS region configured. Run `aws configure` to set a "
            "default region, or pass --region explicitly."
        )

    # boto3.Session() doesn't fail on missing credentials until you
    # actually make a call — force that check now, with a clear message,
    # instead of letting it surface later as an opaque error from deep
    # inside the first check that happens to run.
    try:
        boto3.Session(
            profile_name=profile_name, region_name=resolved_region
        ).client("sts").get_caller_identity()
    except NoCredentialsError as e:
        raise RuntimeError(
            "No AWS credentials found. Run `aws configure` "
            f"{f'--profile {profile_name} ' if profile_name else ''}"
            "to set them up."
        ) from e
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        raise RuntimeError(
            f"AWS rejected these credentials ({code}). The access key may "
            "be invalid, deactivated, or deleted — run `aws configure "
            f"{f'--profile {profile_name} ' if profile_name else ''}"
            "` to update them."
        ) from e

    return boto3.Session(profile_name=profile_name, region_name=resolved_region)


def get_account_id(session: boto3.Session) -> str:
    """Confirm which account we actually landed in — always verify this
    before running checks, so a misconfigured profile doesn't silently
    scan the wrong account."""
    return session.client("sts").get_caller_identity()["Account"]
