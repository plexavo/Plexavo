"""plexavo/aws_profile_setup.py — writes a new named AWS profile to disk.

Used by the interactive "+ Configure new profile" flow. Writes in the
same layout `aws configure --profile NAME` itself produces:
  ~/.aws/credentials  ->  [NAME]                 aws_access_key_id / aws_secret_access_key
  ~/.aws/config       ->  [profile NAME]         region
                          (bare [default] for the "default" profile)

Only the target profile's section is added/updated — every other
section in either file is read back untouched via configparser's
read-modify-write round trip. One known limitation: configparser does
not preserve comment lines on rewrite, so hand-written comments in
these files (uncommon, since they're normally CLI/tool-managed) would
be dropped. Actual key/value data for every other profile is preserved
exactly.

Respects AWS_SHARED_CREDENTIALS_FILE / AWS_CONFIG_FILE if set, same as
the AWS CLI and boto3 itself.
"""

from __future__ import annotations

import configparser
import os
from pathlib import Path


def credentials_path() -> Path:
    return Path(os.environ.get("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials")).expanduser()


def config_path() -> Path:
    return Path(os.environ.get("AWS_CONFIG_FILE", "~/.aws/config")).expanduser()


def _write_ini(path: Path, section: str, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    parser = configparser.ConfigParser()
    if path.exists():
        parser.read(path)
    if not parser.has_section(section):
        parser.add_section(section)
    for key, value in values.items():
        parser.set(section, key, value)
    with open(path, "w", encoding="utf-8") as f:
        parser.write(f)
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Windows doesn't support POSIX file-mode bits the same way —
        # best-effort only, same as the AWS CLI itself does here.
        pass


def write_profile(name: str, access_key_id: str, secret_access_key: str, region: str) -> None:
    """Write/overwrite one named profile's credentials and region.

    Never logs or returns the secret — callers must not print it either.
    """
    _write_ini(credentials_path(), name, {
        "aws_access_key_id": access_key_id,
        "aws_secret_access_key": secret_access_key,
    })

    config_section = "default" if name == "default" else f"profile {name}"
    _write_ini(config_path(), config_section, {"region": region})
