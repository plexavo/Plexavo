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
    account_context: str = ""  # extra context (e.g. which policy attached it) — AI-prompt input only, never shown directly
    confidence: str = "Confirmed"  # "Confirmed" | "Likely — see note" (set explicitly wherever a check's own
                                     # logic can't be fully certain — a Condition block, a conditioned Deny,
                                     # a CloudTrail lookup that hit its page cap — instead of burying that
                                     # uncertainty as prose inside raw_detail)
    evidence: str = ""       # the concrete account-state fact backing this finding — e.g.
                              # "granted=15, used=0, unused=15" or "last_used=never" — shown to the
                              # reader directly, not just fed silently into the AI prompt

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "resource_arn": self.resource_arn,
            "raw_detail": self.raw_detail,
            "account_context": self.account_context,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }
