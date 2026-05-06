"""
VAEL – Stage 5 Output Schemas
Attack Path Graph: maps CVEs to MITRE ATT&CK tactics/techniques.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


# ── Tactic catalogue ─────────────────────────────────────────────────────────

TACTIC_NAMES: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}

TACTIC_SHORT: dict[str, str] = {
    "TA0043": "recon",
    "TA0042": "resource-dev",
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "priv-esc",
    "TA0005": "defense-evasion",
    "TA0006": "cred-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0010": "exfiltration",
    "TA0011": "c2",
    "TA0040": "impact",
}

# Canonical kill-chain order (reconnaissance → impact)
KILL_CHAIN_ORDER: list[str] = [
    "TA0043",  # Reconnaissance
    "TA0001",  # Initial Access
    "TA0002",  # Execution
    "TA0003",  # Persistence
    "TA0004",  # Privilege Escalation
    "TA0005",  # Defense Evasion
    "TA0006",  # Credential Access
    "TA0007",  # Discovery
    "TA0008",  # Lateral Movement
    "TA0009",  # Collection
    "TA0010",  # Exfiltration
    "TA0011",  # Command and Control
    "TA0040",  # Impact
]


# ── Models ────────────────────────────────────────────────────────────────────

class MappedTechnique(BaseModel):
    """A single ATT&CK technique activated by one or more CVEs."""
    technique_id: str                              # e.g. "T1190"
    technique_name: str                            # e.g. "Exploit Public-Facing Application"
    tactic_ids: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    cwe_sources: list[str] = Field(default_factory=list)   # CWE IDs that triggered this
    cvss_sources: list[str] = Field(default_factory=list)  # CVSS heuristic labels


class TacticNode(BaseModel):
    """One tactic in the kill-chain graph with its contributing techniques."""
    tactic_id: str
    tactic_name: str
    techniques: list[MappedTechnique] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    risk_score: float = Field(0.0, ge=0.0, le=10.0)

    @property
    def cve_count(self) -> int:
        return len(self.cve_ids)

    @property
    def technique_count(self) -> int:
        return len(self.techniques)


class AttackPathEdge(BaseModel):
    """Directed edge between two adjacent tactic nodes in the kill chain."""
    from_tactic: str
    to_tactic: str
    cve_count: int = 0


class Stage5Result(BaseModel):
    """Top-level output of Stage 5 — the full ATT&CK kill-chain graph."""
    software: str
    version: str

    tactic_nodes: list[TacticNode] = Field(default_factory=list)
    edges: list[AttackPathEdge] = Field(default_factory=list)
    kill_chain_path: list[str] = Field(default_factory=list)  # ordered tactic IDs with coverage

    total_techniques: int = 0
    total_tactics: int = 0
    highest_risk_tactic: Optional[str] = None
    highest_risk_tactic_id: Optional[str] = None

    sources_queried: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
