from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(StrEnum):
    ALLOW_READ_ONLY = "allow_read_only"
    QUARANTINE_FOR_REVIEW = "quarantine_for_review"
    DENY_AND_ISOLATE = "deny_and_isolate"


class Assessment(BaseModel):
    risk: Risk
    action: Action
    reason: str


def enforce_policy(assessment: Assessment, *, canaries_healthy: bool) -> Action:
    if not canaries_healthy:
        return Action.DENY_AND_ISOLATE
    if assessment.risk in {Risk.HIGH, Risk.CRITICAL}:
        return Action.DENY_AND_ISOLATE
    if assessment.risk is Risk.MEDIUM:
        return Action.QUARANTINE_FOR_REVIEW
    return Action.ALLOW_READ_ONLY
