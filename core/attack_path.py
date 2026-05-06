"""
VAEL – Stage 5: Attack Path Graph

Maps Stage 2 CVE enrichments to MITRE ATT&CK tactics/techniques using:
  1. CWE → ATT&CK cross-walk (static lookup table)
  2. CVSS vector heuristics (structured fields from CVSSv3 model)

Builds a directed kill-chain DAG ordered by the ATT&CK tactic sequence.

Usage:
    from core.attack_path import run_stage5
    stage5 = run_stage5(stage2_result)
"""

from __future__ import annotations

import logging
from typing import Optional

from schemas.stage2 import Stage2Result, VEPTier
from schemas.stage1 import CVERecord
from schemas.stage5 import (
    Stage5Result, TacticNode, MappedTechnique, AttackPathEdge,
    KILL_CHAIN_ORDER, TACTIC_NAMES,
)

logger = logging.getLogger(__name__)


# ── CWE → ATT&CK technique mapping ───────────────────────────────────────────
# Each entry: CWE_ID → [(technique_id, technique_name, [tactic_id, ...])]
# Source: MITRE ATT&CK/CWE cross-walk + manual curation for common weakness types.

_CWE_MAP: dict[str, list[tuple[str, str, list[str]]]] = {
    # ── Injection ────────────────────────────────────────────────────────────
    "CWE-77":  [("T1059", "Command and Scripting Interpreter", ["TA0002"])],
    "CWE-78":  [("T1059", "Command and Scripting Interpreter", ["TA0002"])],
    "CWE-88":  [("T1059", "Command and Scripting Interpreter", ["TA0002"])],
    "CWE-89":  [("T1190", "Exploit Public-Facing Application", ["TA0001"]),
                ("T1565", "Data Manipulation",                  ["TA0040"])],
    "CWE-90":  [("T1190", "Exploit Public-Facing Application", ["TA0001"])],
    "CWE-93":  [("T1190", "Exploit Public-Facing Application", ["TA0001"])],
    "CWE-94":  [("T1059", "Command and Scripting Interpreter", ["TA0002"]),
                ("T1190", "Exploit Public-Facing Application", ["TA0001"])],
    "CWE-917": [("T1059", "Command and Scripting Interpreter", ["TA0002"])],

    # ── File / Path ───────────────────────────────────────────────────────────
    "CWE-22":  [("T1083", "File and Directory Discovery", ["TA0007"]),
                ("T1005", "Data from Local System",        ["TA0009"])],
    "CWE-23":  [("T1083", "File and Directory Discovery", ["TA0007"])],
    "CWE-36":  [("T1083", "File and Directory Discovery", ["TA0007"])],
    "CWE-73":  [("T1083", "File and Directory Discovery", ["TA0007"])],
    "CWE-434": [("T1505", "Server Software Component",    ["TA0003"]),
                ("T1190", "Exploit Public-Facing Application", ["TA0001"])],

    # ── Authentication / Access Control ───────────────────────────────────────
    "CWE-287": [("T1078", "Valid Accounts",  ["TA0001", "TA0003", "TA0004"])],
    "CWE-288": [("T1078", "Valid Accounts",  ["TA0001"])],
    "CWE-306": [("T1078", "Valid Accounts",  ["TA0001"])],
    "CWE-307": [("T1110", "Brute Force",     ["TA0006"])],
    "CWE-521": [("T1110", "Brute Force",     ["TA0006"])],
    "CWE-620": [("T1110", "Brute Force",     ["TA0006"])],
    "CWE-640": [("T1078", "Valid Accounts",  ["TA0001"])],

    # ── Credentials / Crypto ──────────────────────────────────────────────────
    "CWE-259": [("T1552", "Unsecured Credentials", ["TA0006"])],
    "CWE-295": [("T1557", "Adversary-in-the-Middle", ["TA0006", "TA0009"])],
    "CWE-311": [("T1552", "Unsecured Credentials", ["TA0006"])],
    "CWE-312": [("T1552", "Unsecured Credentials", ["TA0006"])],
    "CWE-319": [("T1557", "Adversary-in-the-Middle", ["TA0006", "TA0009"])],
    "CWE-320": [("T1552", "Unsecured Credentials", ["TA0006"])],
    "CWE-321": [("T1552", "Unsecured Credentials", ["TA0006"])],
    "CWE-322": [("T1557", "Adversary-in-the-Middle", ["TA0006"])],
    "CWE-323": [("T1552", "Unsecured Credentials", ["TA0006"])],
    "CWE-327": [("T1552", "Unsecured Credentials", ["TA0006"])],
    "CWE-330": [("T1552", "Unsecured Credentials", ["TA0006"])],
    "CWE-335": [("T1552", "Unsecured Credentials", ["TA0006"])],
    "CWE-798": [("T1552", "Unsecured Credentials", ["TA0006"])],

    # ── Information Disclosure ────────────────────────────────────────────────
    "CWE-200": [("T1552", "Unsecured Credentials",         ["TA0006"]),
                ("T1083", "File and Directory Discovery",   ["TA0007"])],
    "CWE-201": [("T1040", "Network Sniffing",              ["TA0006"])],
    "CWE-203": [("T1082", "System Information Discovery",  ["TA0007"])],
    "CWE-209": [("T1082", "System Information Discovery",  ["TA0007"])],
    "CWE-532": [("T1552", "Unsecured Credentials",         ["TA0006"])],

    # ── Memory Safety ─────────────────────────────────────────────────────────
    "CWE-119": [("T1068", "Exploitation for Privilege Escalation", ["TA0004"]),
                ("T1499", "Endpoint Denial of Service",            ["TA0040"])],
    "CWE-120": [("T1068", "Exploitation for Privilege Escalation", ["TA0004"]),
                ("T1499", "Endpoint Denial of Service",            ["TA0040"])],
    "CWE-121": [("T1068", "Exploitation for Privilege Escalation", ["TA0004"])],
    "CWE-122": [("T1068", "Exploitation for Privilege Escalation", ["TA0004"])],
    "CWE-125": [("T1499", "Endpoint Denial of Service",            ["TA0040"])],
    "CWE-190": [("T1499", "Endpoint Denial of Service",            ["TA0040"]),
                ("T1068", "Exploitation for Privilege Escalation", ["TA0004"])],
    "CWE-191": [("T1499", "Endpoint Denial of Service",            ["TA0040"])],
    "CWE-369": [("T1499", "Endpoint Denial of Service",            ["TA0040"])],
    "CWE-416": [("T1068", "Exploitation for Privilege Escalation", ["TA0004"]),
                ("T1499", "Endpoint Denial of Service",            ["TA0040"])],
    "CWE-476": [("T1499", "Endpoint Denial of Service",            ["TA0040"])],
    "CWE-787": [("T1068", "Exploitation for Privilege Escalation", ["TA0004"]),
                ("T1499", "Endpoint Denial of Service",            ["TA0040"])],
    "CWE-824": [("T1068", "Exploitation for Privilege Escalation", ["TA0004"])],

    # ── SSRF / XXE / Deserialization ──────────────────────────────────────────
    "CWE-502": [("T1059", "Command and Scripting Interpreter",     ["TA0002"]),
                ("T1190", "Exploit Public-Facing Application",     ["TA0001"])],
    "CWE-611": [("T1190", "Exploit Public-Facing Application",     ["TA0001"]),
                ("T1005", "Data from Local System",                 ["TA0009"])],
    "CWE-918": [("T1090", "Proxy",                                 ["TA0011"]),
                ("T1071", "Application Layer Protocol",            ["TA0011"])],

    # ── Web / Client-side ─────────────────────────────────────────────────────
    "CWE-79":  [("T1189", "Drive-by Compromise",      ["TA0001"]),
                ("T1185", "Browser Session Hijacking", ["TA0009"])],
    "CWE-80":  [("T1189", "Drive-by Compromise",      ["TA0001"])],
    "CWE-352": [("T1204", "User Execution",            ["TA0002"])],
    "CWE-601": [("T1189", "Drive-by Compromise",      ["TA0001"])],

    # ── Privilege Escalation ──────────────────────────────────────────────────
    "CWE-264": [("T1068", "Exploitation for Privilege Escalation", ["TA0004"])],
    "CWE-269": [("T1068", "Exploitation for Privilege Escalation", ["TA0004"])],
    "CWE-273": [("T1068", "Exploitation for Privilege Escalation", ["TA0004"])],
    "CWE-276": [("T1083", "File and Directory Discovery",          ["TA0007"]),
                ("T1068", "Exploitation for Privilege Escalation", ["TA0004"])],
    "CWE-362": [("T1068", "Exploitation for Privilege Escalation", ["TA0004"])],
    "CWE-367": [("T1068", "Exploitation for Privilege Escalation", ["TA0004"])],
    "CWE-732": [("T1068", "Exploitation for Privilege Escalation", ["TA0004"]),
                ("T1083", "File and Directory Discovery",          ["TA0007"])],

    # ── Denial of Service ─────────────────────────────────────────────────────
    "CWE-400": [("T1499", "Endpoint Denial of Service", ["TA0040"])],
    "CWE-407": [("T1499", "Endpoint Denial of Service", ["TA0040"])],
    "CWE-674": [("T1499", "Endpoint Denial of Service", ["TA0040"])],
    "CWE-770": [("T1499", "Endpoint Denial of Service", ["TA0040"])],
    "CWE-835": [("T1499", "Endpoint Denial of Service", ["TA0040"])],

    # ── Persistence / Supply Chain ────────────────────────────────────────────
    "CWE-494": [("T1195", "Supply Chain Compromise",   ["TA0001"]),
                ("T1505", "Server Software Component", ["TA0003"])],

    # ── Generic ───────────────────────────────────────────────────────────────
    "CWE-20":  [("T1190", "Exploit Public-Facing Application", ["TA0001"])],
    "CWE-74":  [("T1190", "Exploit Public-Facing Application", ["TA0001"])],
}


# ── VEP tier → risk weight ────────────────────────────────────────────────────

_VEP_WEIGHT: dict[str, float] = {
    "T0_PATCH_NOW": 1.0,
    "T1_HIGH":      0.75,
    "T2_MONITOR":   0.45,
    "T3_DEFER":     0.20,
    "T_UNKNOWN":    0.30,
}


# ── CVSS heuristics ───────────────────────────────────────────────────────────

def _techniques_from_cvss(
    cve: CVERecord,
) -> list[tuple[str, str, list[str], str]]:
    """
    Infer ATT&CK techniques from structured CVSS v3 fields.
    Returns [(technique_id, technique_name, [tactic_ids], reason_label)].
    """
    cvss = cve.cvss_v3
    if not cvss:
        return []

    results: list[tuple[str, str, list[str], str]] = []

    # Network attack vector → Initial Access via public-facing exploit
    if cvss.attack_vector == "NETWORK":
        results.append((
            "T1190", "Exploit Public-Facing Application", ["TA0001"],
            "CVSS AV:Network",
        ))

    # Scope:Changed → container/sandbox escape → Privilege Escalation
    if getattr(cvss, "scope", None) == "CHANGED":
        results.append((
            "T1068", "Exploitation for Privilege Escalation", ["TA0004"],
            "CVSS Scope:Changed",
        ))

    # High Confidentiality impact → Credential Access / Collection
    if cvss.confidentiality_impact == "HIGH":
        results.append((
            "T1552", "Unsecured Credentials", ["TA0006"],
            "CVSS C:High",
        ))

    # High Integrity impact → Data Manipulation (Impact)
    if cvss.integrity_impact == "HIGH":
        results.append((
            "T1565", "Data Manipulation", ["TA0040"],
            "CVSS I:High",
        ))

    # High Availability impact → DoS (Impact)
    if cvss.availability_impact == "HIGH":
        results.append((
            "T1499", "Endpoint Denial of Service", ["TA0040"],
            "CVSS A:High",
        ))

    # Unauthenticated network RCE pattern → Execution
    if (
        cvss.attack_vector == "NETWORK"
        and cvss.privileges_required == "NONE"
        and cvss.user_interaction == "NONE"
        and cvss.attack_complexity == "LOW"
    ):
        results.append((
            "T1059", "Command and Scripting Interpreter", ["TA0002"],
            "CVSS AV:N/AC:L/PR:N/UI:N (unauthenticated RCE pattern)",
        ))

    return results


# ── Main entry point ──────────────────────────────────────────────────────────

def run_stage5(stage2: Stage2Result) -> Stage5Result:
    """
    Map Stage 2 CVE enrichments to MITRE ATT&CK tactics and techniques.

    Args:
        stage2: Output of run_stage2() (must include stage1_cves).

    Returns:
        Stage5Result with tactic nodes, edges, and ordered kill-chain path.
    """
    result = Stage5Result(software=stage2.software, version=stage2.version)

    # Fast lookup: cve_id → CVERecord
    cve_lookup: dict[str, CVERecord] = {c.cve_id: c for c in stage2.stage1_cves}

    # Accumulation structures
    tactic_map: dict[str, TacticNode] = {}
    # (tactic_id, technique_id) → MappedTechnique (deduplicate across CVEs)
    technique_map: dict[tuple[str, str], MappedTechnique] = {}

    for enr in stage2.enrichments:
        cve = cve_lookup.get(enr.cve_id)
        if not cve:
            continue

        # Gather all (technique_id, name, [tactic_ids], source_label) tuples
        raw: list[tuple[str, str, list[str], str]] = []

        for cwe in cve.cwes:
            for tech_id, tech_name, tactic_ids in _CWE_MAP.get(cwe.cwe_id, []):
                raw.append((tech_id, tech_name, tactic_ids, f"CWE:{cwe.cwe_id}"))

        raw.extend(_techniques_from_cvss(cve))

        # Risk contribution of this CVE
        cvss_score = (cve.cvss_v3.score or 5.0) if cve.cvss_v3 else 5.0
        vep_weight = _VEP_WEIGHT.get(enr.vep_tier.value, 0.30)
        risk_contrib = cvss_score * vep_weight * 0.25  # scale to keep 0-10 sane

        # Deduplicate: each (tactic, technique) pair counts once per CVE
        seen_keys: set[tuple[str, str]] = set()

        for tech_id, tech_name, tactic_ids, source_label in raw:
            for tactic_id in tactic_ids:
                key = (tactic_id, tech_id)
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                # Ensure tactic node exists
                if tactic_id not in tactic_map:
                    tactic_map[tactic_id] = TacticNode(
                        tactic_id=tactic_id,
                        tactic_name=TACTIC_NAMES.get(tactic_id, tactic_id),
                    )
                node = tactic_map[tactic_id]

                # Add CVE once per tactic
                if enr.cve_id not in node.cve_ids:
                    node.cve_ids.append(enr.cve_id)
                    node.risk_score = min(10.0, node.risk_score + risk_contrib)

                # Ensure technique node exists
                if key not in technique_map:
                    technique_map[key] = MappedTechnique(
                        technique_id=tech_id,
                        technique_name=tech_name,
                        tactic_ids=[tactic_id],
                    )
                tech_node = technique_map[key]
                if enr.cve_id not in tech_node.cve_ids:
                    tech_node.cve_ids.append(enr.cve_id)
                if source_label.startswith("CWE:"):
                    cwe_id = source_label[4:]
                    if cwe_id not in tech_node.cwe_sources:
                        tech_node.cwe_sources.append(cwe_id)
                else:
                    if source_label not in tech_node.cvss_sources:
                        tech_node.cvss_sources.append(source_label)

    # Attach technique nodes to their tactic
    for (tactic_id, _), tech_node in technique_map.items():
        if tactic_id in tactic_map:
            tactic_map[tactic_id].techniques.append(tech_node)

    # Build ordered kill-chain path (only active tactics, in canonical order)
    kill_chain = [tid for tid in KILL_CHAIN_ORDER if tid in tactic_map]

    # Build directed edges between consecutive active tactics
    edges: list[AttackPathEdge] = []
    for i in range(len(kill_chain) - 1):
        src, dst = kill_chain[i], kill_chain[i + 1]
        # Edge weight = CVEs that appear in both tactics (shared attack surface)
        src_cves = set(tactic_map[src].cve_ids)
        dst_cves = set(tactic_map[dst].cve_ids)
        shared = len(src_cves & dst_cves) or 1  # always ≥ 1 when path is connected
        edges.append(AttackPathEdge(from_tactic=src, to_tactic=dst, cve_count=shared))

    # Highest-risk tactic
    highest: Optional[TacticNode] = (
        max(tactic_map.values(), key=lambda n: n.risk_score)
        if tactic_map else None
    )

    result.tactic_nodes = [
        tactic_map[tid] for tid in KILL_CHAIN_ORDER if tid in tactic_map
    ]
    result.edges = edges
    result.kill_chain_path = kill_chain
    result.total_tactics = len(kill_chain)
    result.total_techniques = len({tech_id for (_, tech_id) in technique_map})
    result.highest_risk_tactic = highest.tactic_name if highest else None
    result.highest_risk_tactic_id = highest.tactic_id if highest else None
    result.sources_queried = ["CWE-ATT&CK-map", "CVSS-heuristics"]

    logger.info(
        "Stage 5 complete: %d tactics, %d techniques for %s %s",
        result.total_tactics, result.total_techniques,
        stage2.software, stage2.version,
    )
    return result
