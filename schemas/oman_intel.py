"""
VAEL – Oman Internet Intelligence schemas.
Represents results from Shodan, FOFA, and Censys filtered to country:OM.
"""
from __future__ import annotations

from typing import Optional
from pydantic import BaseModel


class OmanHost(BaseModel):
    """A single internet-exposed host found in Oman."""
    ip: str
    port: int = 0
    protocol: str = "tcp"
    city: Optional[str] = None
    organization: Optional[str] = None
    banner: Optional[str] = None          # first 200 chars of service banner
    source: str                           # "shodan" | "fofa" | "censys"


class OmanSourceResult(BaseModel):
    """Results from one data source (Shodan, FOFA, or Censys)."""
    source: str                           # display name: "Shodan", "FOFA", "Censys"
    total_found: int = 0                  # total count reported by the source
    hosts: list[OmanHost] = []            # up to 50 sample hosts
    query_used: str = ""
    error: Optional[str] = None           # set when source failed or key missing
    debug_info: dict = {}                 # diagnostic details for troubleshooting


class OmanCVEHits(BaseModel):
    """CVE-specific exposure: how many Oman hosts appear vulnerable to this CVE."""
    cve_id: str
    shodan_count: int = 0
    fofa_count: int = 0
    censys_count: int = 0
    zoomeye_count: int = 0
    total: int = 0


class OmanIntelReport(BaseModel):
    """Combined Oman exposure intelligence report."""
    software: str
    version: str
    country: str = "OM"
    country_name: str = "Oman"

    # Aggregate counts
    total_exposed: int = 0               # sum across all sources (may include overlap)
    unique_ips_sampled: int = 0          # unique IPs in the sampled host list

    # Breakdowns
    hosts_by_city: dict[str, int] = {}   # {"Muscat": 45, "Sohar": 12, ...}
    hosts_by_port: dict[str, int] = {}   # {"443": 23, "80": 19, ...}
    hosts_by_source: dict[str, int] = {} # {"Shodan": 120, "FOFA": 88, "Censys": 34}

    # Per-source details
    sources_queried: list[str] = []
    source_results: list[OmanSourceResult] = []

    # CVE-specific hits (only populated when CVE IDs are provided)
    cve_hits: list[OmanCVEHits] = []
    cve_ids_searched: list[str] = []     # CVEs actually used in the search
    cve_source: str = ""                 # "user_provided" | "auto_nvd" | "none"

    rate_limit_warnings: list[str] = []
    queried_at: str = ""
