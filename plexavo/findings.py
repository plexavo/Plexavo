"""Finding data model. Every check module produces a list of these."""

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

    @property
    def score_penalty(self) -> int:
        return {
            Severity.CRITICAL: 15,
            Severity.HIGH: 8,
            Severity.MEDIUM: 3,
            Severity.LOW: 1,
        }[self]


@dataclass
class Finding:
    check_id: str          # e.g. "IAM-01"
    title: str              # e.g. "Wildcard Admin Access"
    severity: Severity
    resource_arn: str
    raw_detail: str          # technical description used as input to the AI explainer
    account_context: str = ""  # extra context (e.g. which policy attached it)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "resource_arn": self.resource_arn,
            "raw_detail": self.raw_detail,
            "account_context": self.account_context,
        }
