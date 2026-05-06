"""
VAEL – Stage 1 Output Schemas
Pydantic v2 models for Known Vulnerability Mapping.
All downstream stages consume these models.
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class CVSSv3(BaseModel):
    score: Optional[float] = Field(None, ge=0.0, le=10.0)
    vector: Optional[str] = None
    severity: Severity = Severity.UNKNOWN
    attack_vector: Optional[str] = None          # NETWORK / ADJACENT / LOCAL / PHYSICAL
    attack_complexity: Optional[str] = None      # LOW / HIGH
    privileges_required: Optional[str] = None   # NONE / LOW / HIGH
    user_interaction: Optional[str] = None      # NONE / REQUIRED
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None


class CVSSv2(BaseModel):
    score: Optional[float] = Field(None, ge=0.0, le=10.0)
    vector: Optional[str] = None
    severity: Severity = Severity.UNKNOWN


class Reference(BaseModel):
    url: str
    source: Optional[str] = None
    tags: list[str] = Field(default_factory=list)


class CWEEntry(BaseModel):
    cwe_id: str                  # e.g. "CWE-79"
    name: Optional[str] = None
    description: Optional[str] = None


class CPEMatch(BaseModel):
    cpe23: str
    version_start_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    vulnerable: bool = True


class CVERecord(BaseModel):
    cve_id: str                                  # e.g. "CVE-2021-44228"
    source: str                                  # "NVD" | "OSV" | "VULNDB"
    description: Optional[str] = None
    published: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    cvss_v3: Optional[CVSSv3] = None
    cvss_v2: Optional[CVSSv2] = None
    cwes: list[CWEEntry] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    cpe_matches: list[CPEMatch] = Field(default_factory=list)
    affected_versions_raw: list[str] = Field(default_factory=list)
    fixed_versions_raw: list[str] = Field(default_factory=list)   # from OSV fixed events
    version_matched: bool = False                # True if input version is confirmed affected


class MisconfigFlag(BaseModel):
    source: str                                  # "CIS" | "CWE"
    rule_id: str
    title: str
    description: Optional[str] = None
    severity: Severity = Severity.MEDIUM
    remediation: Optional[str] = None


class Stage1Result(BaseModel):
    """Top-level output of Stage 1 – consumed by all downstream stages."""
    software: str
    version: str
    cpe_string: Optional[str] = None            # CPE 2.3 if provided or auto-detected
    query_ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Core outputs
    cves: list[CVERecord] = Field(default_factory=list)
    misconfig_flags: list[MisconfigFlag] = Field(default_factory=list)

    # Summary stats (pre-computed for quick downstream use)
    total_cves: int = 0
    critical_count: int = 0
    high_count: int = 0
    version_matched_count: int = 0              # CVEs confirmed for this exact version
    sources_queried: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    rate_limit_warnings: list[str] = Field(default_factory=list)

    def compute_summary(self) -> None:
        self.total_cves = len(self.cves)
        self.critical_count = sum(
            1 for c in self.cves
            if c.cvss_v3 and c.cvss_v3.severity == Severity.CRITICAL
        )
        self.high_count = sum(
            1 for c in self.cves
            if c.cvss_v3 and c.cvss_v3.severity == Severity.HIGH
        )
        self.version_matched_count = sum(1 for c in self.cves if c.version_matched)
