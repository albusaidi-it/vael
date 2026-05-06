"""
VAEL – Stage 2 Output Schemas
Real Exploitability Evaluation.

Consumes Stage1Result and enriches each CVE with:
  - EPSS score (exploitation probability, 0-1)
  - CISA KEV status (exploited in the wild, yes/no)
  - Exploit maturity tier
  - Patch availability
  - Computed VEP (Vulnerability Exploitability Priority) tier
"""

from __future__ import annotations
from datetime import datetime, date, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

from schemas.stage1 import CVERecord


class ExploitMaturity(str, Enum):
    WEAPONIZED       = "WEAPONIZED"        # In KEV or widely used by threat actors
    FUNCTIONAL       = "FUNCTIONAL"        # Public working PoC exists
    PROOF_OF_CONCEPT = "PROOF_OF_CONCEPT"  # Theoretical / conceptual PoC
    UNPROVEN         = "UNPROVEN"          # No known exploit code
    UNKNOWN          = "UNKNOWN"


class VEPTier(str, Enum):
    """VAEL Exploitability Priority — drives final KEV-style verdict."""
    T0_PATCH_NOW = "T0_PATCH_NOW"   # In KEV or EPSS > 0.7 AND version-matched
    T1_HIGH      = "T1_HIGH"        # EPSS > 0.3 OR functional PoC + critical CVSS
    T2_MONITOR   = "T2_MONITOR"     # EPSS > 0.05 OR high CVSS without exploit
    T3_DEFER     = "T3_DEFER"       # No evidence of exploitation
    T_UNKNOWN    = "T_UNKNOWN"


class KEVEntry(BaseModel):
    """CISA Known Exploited Vulnerabilities catalog entry."""
    cve_id: str
    vendor_project: Optional[str] = None
    product: Optional[str] = None
    vulnerability_name: Optional[str] = None
    date_added: Optional[date] = None
    short_description: Optional[str] = None
    required_action: Optional[str] = None
    due_date: Optional[date] = None
    known_ransomware_campaign_use: Optional[str] = None
    notes: Optional[str] = None


class EPSSEntry(BaseModel):
    """EPSS (Exploit Prediction Scoring System) entry."""
    cve_id: str
    epss: float = Field(..., ge=0.0, le=1.0)
    percentile: float = Field(..., ge=0.0, le=1.0)
    score_date: Optional[date] = None


class PatchInfo(BaseModel):
    patch_available: bool = False
    fixed_versions: list[str] = Field(default_factory=list)
    vendor_advisory_url: Optional[str] = None
    patch_urls: list[str] = Field(default_factory=list)


class ThreatIntel(BaseModel):
    """VulnCheck threat actor / ransomware group attribution."""
    threat_actors: list[str] = Field(default_factory=list)
    ransomware_groups: list[str] = Field(default_factory=list)
    in_the_wild: bool = False
    exploitation_notes: list[str] = Field(default_factory=list)


class ExploitabilityEnrichment(BaseModel):
    """Per-CVE enrichment. Pairs with a Stage 1 CVERecord."""
    cve_id: str
    epss: Optional[EPSSEntry] = None
    in_kev: bool = False
    kev_entry: Optional[KEVEntry] = None
    exploit_maturity: ExploitMaturity = ExploitMaturity.UNKNOWN
    patch: PatchInfo = Field(default_factory=PatchInfo)
    threat_intel: Optional[ThreatIntel] = None

    # Computed outputs
    vep_tier: VEPTier = VEPTier.T_UNKNOWN
    vep_score: float = Field(0.0, ge=0.0, le=100.0)
    reasoning: list[str] = Field(default_factory=list)


class Stage2Result(BaseModel):
    """Top-level output of Stage 2."""
    software: str
    version: str
    query_ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    stage1_cves: list[CVERecord] = Field(default_factory=list)
    enrichments: list[ExploitabilityEnrichment] = Field(default_factory=list)

    kev_count: int = 0
    high_epss_count: int = 0
    t0_patch_now_count: int = 0
    t1_high_count: int = 0
    t2_monitor_count: int = 0
    sources_queried: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    rate_limit_warnings: list[str] = Field(default_factory=list)
    epss_score_date: Optional[date] = None   # date of the EPSS feed used

    def compute_summary(self) -> None:
        self.kev_count          = sum(1 for e in self.enrichments if e.in_kev)
        self.high_epss_count    = sum(1 for e in self.enrichments if e.epss and e.epss.epss > 0.5)
        self.t0_patch_now_count = sum(1 for e in self.enrichments if e.vep_tier == VEPTier.T0_PATCH_NOW)
        self.t1_high_count      = sum(1 for e in self.enrichments if e.vep_tier == VEPTier.T1_HIGH)
        self.t2_monitor_count   = sum(1 for e in self.enrichments if e.vep_tier == VEPTier.T2_MONITOR)

    def top_priority_cves(self, limit: int = 10) -> list[tuple[CVERecord, ExploitabilityEnrichment]]:
        """Return CVEs sorted by VEP score descending, paired with enrichment."""
        by_id = {c.cve_id: c for c in self.stage1_cves}
        paired = [(by_id[e.cve_id], e) for e in self.enrichments if e.cve_id in by_id]
        paired.sort(key=lambda p: p[1].vep_score, reverse=True)
        return paired[:limit]
