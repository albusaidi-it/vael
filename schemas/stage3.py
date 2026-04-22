"""
VAEL – Stage 3 Output Schemas
Public Exploit / PoC Harvesting.

Searches GitHub, Exploit-DB, Packet Storm, and Nuclei templates for
public exploit code matching CVEs from Stage 1. Validates version
compatibility via static analysis.
"""

from __future__ import annotations
from datetime import datetime, date
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

from schemas.stage1 import CVERecord
from schemas.stage2 import ExploitabilityEnrichment


class PoCSource(str, Enum):
    GITHUB       = "GITHUB"
    EXPLOIT_DB   = "EXPLOIT_DB"
    PACKET_STORM = "PACKET_STORM"
    NUCLEI       = "NUCLEI"
    METASPLOIT   = "METASPLOIT"
    OTHER        = "OTHER"


class PoCQuality(str, Enum):
    """Heuristic quality classification of a PoC."""
    WEAPONIZED   = "WEAPONIZED"    # Metasploit module, Nuclei template, or proven working exploit
    FUNCTIONAL   = "FUNCTIONAL"    # Has executable code + clear exploitation steps
    CONCEPTUAL   = "CONCEPTUAL"    # Describes the vuln but no executable code
    FAKE         = "FAKE"          # Likely spam/fake repo (common on GitHub for famous CVEs)
    UNKNOWN      = "UNKNOWN"


class VersionCompatibility(str, Enum):
    CONFIRMED    = "CONFIRMED"      # PoC explicitly mentions target version
    LIKELY       = "LIKELY"         # Version range indicated, target falls within
    UNKNOWN      = "UNKNOWN"        # No version info in PoC
    INCOMPATIBLE = "INCOMPATIBLE"   # PoC targets a different version range


class PoCRecord(BaseModel):
    """A single public exploit / PoC artifact."""
    cve_id: str
    source: PoCSource
    url: str
    title: Optional[str] = None
    author: Optional[str] = None
    published: Optional[date] = None
    stars: Optional[int] = None              # GitHub-specific
    forks: Optional[int] = None              # GitHub-specific
    description: Optional[str] = None        # Short description / readme excerpt

    # Quality & compatibility (computed by static analysis)
    quality: PoCQuality = PoCQuality.UNKNOWN
    version_compatibility: VersionCompatibility = VersionCompatibility.UNKNOWN
    detected_versions: list[str] = Field(default_factory=list)

    # Indicators discovered during analysis
    has_executable_code: bool = False
    has_readme: bool = False
    language: Optional[str] = None            # "python", "bash", "ruby", etc.

    # Raw metadata for debugging
    raw_meta: dict = Field(default_factory=dict)


class CVEPoCBundle(BaseModel):
    """All PoCs found for a single CVE."""
    cve_id: str
    pocs: list[PoCRecord] = Field(default_factory=list)
    total_found: int = 0

    # Aggregate signal: best-quality PoC we found for this CVE
    best_quality: PoCQuality = PoCQuality.UNKNOWN
    compatible_pocs_count: int = 0             # PoCs confirmed/likely for target version

    def compute_aggregate(self) -> None:
        self.total_found = len(self.pocs)
        quality_rank = {
            PoCQuality.WEAPONIZED: 4,
            PoCQuality.FUNCTIONAL: 3,
            PoCQuality.CONCEPTUAL: 2,
            PoCQuality.UNKNOWN:    1,
            PoCQuality.FAKE:       0,
        }
        if self.pocs:
            self.best_quality = max(self.pocs, key=lambda p: quality_rank[p.quality]).quality
        self.compatible_pocs_count = sum(
            1 for p in self.pocs
            if p.version_compatibility in (VersionCompatibility.CONFIRMED, VersionCompatibility.LIKELY)
        )


class Stage3Result(BaseModel):
    """Top-level output of Stage 3."""
    software: str
    version: str
    query_ts: datetime = Field(default_factory=datetime.utcnow)

    # Per-CVE PoC bundles
    bundles: list[CVEPoCBundle] = Field(default_factory=list)

    # Summary stats
    total_pocs: int = 0
    weaponized_count: int = 0
    cves_with_compatible_pocs: int = 0
    sources_queried: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    def compute_summary(self) -> None:
        self.total_pocs = sum(len(b.pocs) for b in self.bundles)
        self.weaponized_count = sum(
            1 for b in self.bundles if b.best_quality == PoCQuality.WEAPONIZED
        )
        self.cves_with_compatible_pocs = sum(
            1 for b in self.bundles if b.compatible_pocs_count > 0
        )

    def get_bundle(self, cve_id: str) -> Optional[CVEPoCBundle]:
        for b in self.bundles:
            if b.cve_id == cve_id:
                return b
        return None
