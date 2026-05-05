"""
VAEL – Stage 4 Output Schemas
Internet Exposure Analysis.

Queries Shodan and/or Censys to count publicly reachable hosts running
the affected software/version, giving a real-world attack surface estimate.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class ExposureLevel(str, Enum):
    CRITICAL  = "CRITICAL"   # thousands of exposed hosts
    HIGH      = "HIGH"        # hundreds
    MODERATE  = "MODERATE"   # tens
    LOW       = "LOW"         # single digits
    NONE      = "NONE"        # no internet-exposed hosts found
    UNKNOWN   = "UNKNOWN"     # could not determine (no API key, error)


class HostSample(BaseModel):
    ip: str
    port: Optional[int] = None
    country: Optional[str] = None
    org: Optional[str] = None
    banner: Optional[str] = None


class ExposureResult(BaseModel):
    """Exposure data for one CVE / CPE."""
    cve_id: Optional[str] = None
    cpe_query: Optional[str] = None
    product_query: str = ""

    # Per-source counts (each source has independent coverage; total_exposed = max to avoid double-counting)
    shodan_count: Optional[int] = None
    censys_count: Optional[int] = None
    fofa_count: Optional[int] = None
    zoomeye_count: Optional[int] = None
    total_exposed: int = 0

    # Top samples (IPs never stored — only for analyst context)
    samples: list[HostSample] = Field(default_factory=list)

    # Breakdown
    top_countries: dict[str, int] = Field(default_factory=dict)   # {CC: count}
    top_ports: list[int] = Field(default_factory=list)

    level: ExposureLevel = ExposureLevel.UNKNOWN
    source: str = ""       # "shodan" | "censys" | "both" | ""
    errors: list[str] = Field(default_factory=list)
    queried_at: Optional[datetime] = None

    def compute_total(self) -> None:
        """
        Set total_exposed to the maximum count across all sources.
        Sources overlap significantly; summing would double-count.
        Max gives a defensible lower-bound: "at least this many exposed hosts."
        """
        counts = [
            c for c in (self.shodan_count, self.censys_count, self.fofa_count, self.zoomeye_count)
            if c is not None
        ]
        self.total_exposed = max(counts) if counts else 0

    def compute_level(self) -> None:
        n = self.total_exposed
        if n == 0:
            self.level = ExposureLevel.NONE
        elif n < 10:
            self.level = ExposureLevel.LOW
        elif n < 100:
            self.level = ExposureLevel.MODERATE
        elif n < 1000:
            self.level = ExposureLevel.HIGH
        else:
            self.level = ExposureLevel.CRITICAL


class Stage4Result(BaseModel):
    """Top-level output of Stage 4."""
    software: str
    version: str
    query_ts: datetime = Field(default_factory=datetime.utcnow)

    exposures: list[ExposureResult] = Field(default_factory=list)
    total_exposed: int = 0
    peak_level: ExposureLevel = ExposureLevel.UNKNOWN
    sources_queried: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    def compute_summary(self) -> None:
        self.total_exposed = sum(e.total_exposed for e in self.exposures)
        levels = [e.level for e in self.exposures if e.level != ExposureLevel.UNKNOWN]
        order  = [ExposureLevel.CRITICAL, ExposureLevel.HIGH,
                  ExposureLevel.MODERATE, ExposureLevel.LOW, ExposureLevel.NONE]
        for lvl in order:
            if lvl in levels:
                self.peak_level = lvl
                return
        self.peak_level = ExposureLevel.UNKNOWN
