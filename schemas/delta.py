"""
VAEL – Delta / Monitoring Schemas

Represents changes between two VAEL analyses of the same software version,
run at different points in time.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

from schemas.stage2 import VEPTier, ExploitMaturity


class ChangeType(str, Enum):
    NEW_CVE         = "NEW_CVE"          # CVE not present in baseline
    REMOVED_CVE     = "REMOVED_CVE"      # CVE in baseline but not in current
    TIER_UPGRADE    = "TIER_UPGRADE"     # VEP tier moved to higher severity
    TIER_DOWNGRADE  = "TIER_DOWNGRADE"   # VEP tier moved to lower severity
    KEV_ADDED       = "KEV_ADDED"        # CVE newly added to CISA KEV
    KEV_REMOVED     = "KEV_REMOVED"      # rare
    EPSS_SPIKE      = "EPSS_SPIKE"       # EPSS score increased by ≥ 0.10
    EPSS_DROP       = "EPSS_DROP"        # EPSS score dropped by ≥ 0.10
    MATURITY_CHANGE = "MATURITY_CHANGE"  # exploit maturity upgraded
    NEW_POC         = "NEW_POC"          # new public PoC discovered
    NEW_WEAPON      = "NEW_WEAPON"       # weaponized PoC appeared


class CVEDelta(BaseModel):
    cve_id: str
    change_type: ChangeType
    severity: str = ""            # for sorting/display
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    detail: str = ""

    @property
    def is_high_signal(self) -> bool:
        return self.change_type in (
            ChangeType.NEW_CVE,
            ChangeType.TIER_UPGRADE,
            ChangeType.KEV_ADDED,
            ChangeType.EPSS_SPIKE,
            ChangeType.NEW_WEAPON,
            ChangeType.MATURITY_CHANGE,
        )


class DeltaReport(BaseModel):
    """Diff between two VAEL runs for the same software@version."""
    software: str
    version: str

    baseline_ts: Optional[datetime] = None
    current_ts: datetime = Field(default_factory=datetime.utcnow)

    changes: list[CVEDelta] = Field(default_factory=list)

    # Summary counts
    new_cves: int = 0
    removed_cves: int = 0
    tier_upgrades: int = 0
    kev_additions: int = 0
    epss_spikes: int = 0
    new_pocs: int = 0
    new_weapons: int = 0

    # Convenience
    high_signal_changes: list[CVEDelta] = Field(default_factory=list)
    has_critical_changes: bool = False

    def compute_summary(self) -> None:
        self.new_cves       = sum(1 for c in self.changes if c.change_type == ChangeType.NEW_CVE)
        self.removed_cves   = sum(1 for c in self.changes if c.change_type == ChangeType.REMOVED_CVE)
        self.tier_upgrades  = sum(1 for c in self.changes if c.change_type == ChangeType.TIER_UPGRADE)
        self.kev_additions  = sum(1 for c in self.changes if c.change_type == ChangeType.KEV_ADDED)
        self.epss_spikes    = sum(1 for c in self.changes if c.change_type == ChangeType.EPSS_SPIKE)
        self.new_pocs       = sum(1 for c in self.changes if c.change_type == ChangeType.NEW_POC)
        self.new_weapons    = sum(1 for c in self.changes if c.change_type == ChangeType.NEW_WEAPON)
        self.high_signal_changes = [c for c in self.changes if c.is_high_signal]
        self.has_critical_changes = bool(
            self.tier_upgrades or self.kev_additions or
            self.new_weapons or self.new_cves
        )
