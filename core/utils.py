"""
VAEL – Shared utility functions used across multiple modules.
"""

from __future__ import annotations

from typing import Optional

from schemas.stage1 import Severity


def severity_from_score(score: Optional[float]) -> Severity:
    """Map a CVSS numeric score to a Severity enum value."""
    if score is None:
        return Severity.UNKNOWN
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.NONE
