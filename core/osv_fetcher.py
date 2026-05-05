"""
VAEL – Stage 1 / OSV Fetcher
Queries OSV.dev (Open Source Vulnerabilities) REST API.

Docs: https://google.github.io/osv.dev/api/
Great for: npm, PyPI, Go, Maven, RubyGems, Linux distros.
"""

from __future__ import annotations

import logging
import random as _random
from typing import Optional
import httpx
from core import http_client

from schemas.stage1 import CVERecord, CVSSv3, CWEEntry, Reference, Severity
from core import cache as _cache
from core.rate_limiter import rate_limiter
from core.utils import severity_from_score

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL  = "https://api.osv.dev/v1/vulns/{osv_id}"
_TTL = int(12 * 3600 * (0.9 + _random.random() * 0.2))  # 10.8–13.2 h jitter


def _cache_load(software: str, version: str, ecosystem: Optional[str]):
    key  = _cache.make_key("osv", software, version, ecosystem or "")
    data = _cache.get(key)
    if data is None:
        return None
    try:
        return [CVERecord.model_validate(r) for r in data["cves"]], data.get("errors", [])
    except Exception:
        return None


def _cache_save(software: str, version: str, ecosystem: Optional[str],
                cves: list[CVERecord], errors: list[str]) -> None:
    key = _cache.make_key("osv", software, version, ecosystem or "")
    _cache.set(key, "osv", {"cves": [r.model_dump(mode="json") for r in cves], "errors": errors}, _TTL)


ECOSYSTEM_GUESSES: dict[str, list[str]] = {
    # Language packages — exact ecosystem names
    "log4j":           ["Maven"],
    "log4j2":          ["Maven"],
    "spring":          ["Maven"],
    "spring-core":     ["Maven"],
    "struts":          ["Maven"],
    "jackson":         ["Maven"],
    "jackson-databind":["Maven"],
    "shiro":           ["Maven"],
    "django":          ["PyPI"],
    "flask":           ["PyPI"],
    "requests":        ["PyPI"],
    "numpy":           ["PyPI"],
    "pillow":          ["PyPI"],
    "cryptography":    ["PyPI"],
    "paramiko":        ["PyPI"],
    "express":         ["npm"],
    "lodash":          ["npm"],
    "axios":           ["npm"],
    "webpack":         ["npm"],
    "minimist":        ["npm"],
    "node":            ["npm"],
    "wordpress":       [""],
    # System / network packages — covered by Linux distro advisories in OSV
    "nginx":       ["Debian", "Ubuntu", "Alpine", "AlmaLinux"],
    "openssl":     ["Debian", "Ubuntu", "Alpine", "AlmaLinux"],
    "curl":        ["Debian", "Ubuntu", "Alpine"],
    "libcurl":     ["Debian", "Ubuntu", "Alpine"],
    "openssh":     ["Debian", "Ubuntu", "Alpine"],
    "bash":        ["Debian", "Ubuntu"],
    "glibc":       ["Debian", "Ubuntu", "AlmaLinux"],
    "linux":       ["Debian", "Ubuntu", "AlmaLinux"],
    "sudo":        ["Debian", "Ubuntu", "Alpine"],
    "php":         ["Debian", "Ubuntu", "Alpine"],
    "python":      ["Debian", "Ubuntu"],
    "ruby":        ["Debian", "Ubuntu", "RubyGems"],
    "samba":       ["Debian", "Ubuntu"],
    "sqlite":      ["Debian", "Ubuntu"],
    "git":         ["Debian", "Ubuntu", "Alpine"],
    "httpd":       ["AlmaLinux"],
    "apache":      ["Debian", "Ubuntu"],
}


def _guess_ecosystems(software: str) -> list[str]:
    key = software.lower().split("/")[-1].split(":")[-1]  # handle "org.apache/log4j" and "group:artifact"
    return ECOSYSTEM_GUESSES.get(key, ["PyPI", "npm", "Maven"])



def _parse_osv_cvss(severity_list: list) -> Optional[CVSSv3]:
    for s in severity_list:
        if s.get("type") in ("CVSS_V3", "CVSS_V3_1"):
            vector = s.get("score", "")  # OSV stores vector string here, not a number
            score: Optional[float] = None

            # If the value is already numeric (some sources normalise it)
            if isinstance(s.get("score"), (int, float)):
                score = float(s["score"])
            else:
                # Extract base score from CVSS vector: "CVSS:3.1/AV:N/.../S:C/C:H/I:H/A:H"
                # Try the cvss library first, fall back to a lightweight regex heuristic.
                try:
                    from cvss import CVSS3
                    score = float(CVSS3(vector).base_score)
                except Exception:
                    pass
                if score is None:
                    # Heuristic: many OSV records embed numeric score elsewhere
                    import re as _re
                    m = _re.search(r'"baseScore"\s*:\s*(\d+(?:\.\d+)?)', str(s))
                    if m:
                        score = float(m.group(1))

            return CVSSv3(
                score=score,
                vector=vector if isinstance(vector, str) else None,
                severity=severity_from_score(score),
            )
    return None


def _severity_from_db_specific(db_specific: dict) -> Optional[Severity]:
    """Extract severity from OSV database_specific block as a fallback."""
    sev = (db_specific.get("severity") or "").upper()
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH":     Severity.HIGH,
        "MODERATE": Severity.MEDIUM,
        "MEDIUM":   Severity.MEDIUM,
        "LOW":      Severity.LOW,
    }
    return mapping.get(sev)


def _check_osv_range(target_version: str, ranges: list) -> bool:
    """
    Check whether target_version falls within any OSV affected range.

    OSV ranges carry an ordered list of events like:
        [{"introduced": "2.0.0"}, {"fixed": "2.17.1"}, {"introduced": "3.0.0"}]

    We walk the events in order, tracking whether we are currently in a
    vulnerable window (introduced → fixed pairs).
    """
    if not target_version:
        return False

    from packaging.version import Version, InvalidVersion
    try:
        target = Version(target_version)
    except InvalidVersion:
        return False

    for r in ranges:
        if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue

        events = r.get("events", [])
        in_window = False

        for event in events:
            intro = event.get("introduced")
            fixed = event.get("fixed")
            last_affected = event.get("last_affected")

            if intro is not None:
                try:
                    intro_v = Version("0") if intro == "0" else Version(intro)
                    if target >= intro_v:
                        in_window = True
                except InvalidVersion:
                    pass

            if fixed is not None and in_window:
                try:
                    fix_v = Version(fixed)
                    if target >= fix_v:
                        in_window = False  # target is patched
                except InvalidVersion:
                    pass

            if last_affected is not None and in_window:
                try:
                    last_v = Version(last_affected)
                    if target > last_v:
                        in_window = False  # target is beyond last affected
                except InvalidVersion:
                    pass

        if in_window:
            return True

    return False


def _osv_item_to_cve_record(vuln: dict, target_version: str) -> CVERecord:
    osv_id = vuln.get("id", "UNKNOWN")

    # Map OSV IDs to CVE IDs if available
    cve_id = osv_id
    aliases = vuln.get("aliases", [])
    for alias in aliases:
        if alias.startswith("CVE-"):
            cve_id = alias
            break

    description = vuln.get("details") or vuln.get("summary") or ""

    # References
    refs = [
        Reference(url=r.get("url", ""), type=r.get("type"))
        for r in vuln.get("references", [])
        if r.get("url")
    ]

    # CWEs from database_specific
    cwes = []
    db_specific = vuln.get("database_specific", {})
    for cwe in db_specific.get("cwe_ids", []):
        cwes.append(CWEEntry(cwe_id=cwe))

    # Version affected — check if target_version is in any affected range
    version_matched = False
    affected_versions_raw = []
    fixed_versions_from_osv: list[str] = []

    from packaging.version import Version, InvalidVersion

    for affected in vuln.get("affected", []):
        # Exact version list match — normalize before comparing to handle "2.14.1" vs "2.14.1.0"
        for version_info in affected.get("versions", []):
            v_str = str(version_info)
            affected_versions_raw.append(v_str)
            if v_str == target_version:
                version_matched = True
            elif not version_matched:
                try:
                    if Version(v_str) == Version(target_version):
                        version_matched = True
                except InvalidVersion:
                    pass

        # Extract fixed versions from ranges (for patch_detector)
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                fixed = event.get("fixed")
                if fixed and fixed != "0":
                    fixed_versions_from_osv.append(fixed)

        # Structured range check: parse introduced/fixed event pairs
        if not version_matched:
            version_matched = _check_osv_range(
                target_version, affected.get("ranges", [])
            )

    cvss = _parse_osv_cvss(vuln.get("severity", []))
    # Supplement CVSS severity from database_specific when CVSS score is absent
    if cvss is None or (cvss.score is None and cvss.severity == Severity.UNKNOWN):
        db_sev = _severity_from_db_specific(db_specific)
        if db_sev:
            cvss = CVSSv3(score=None, severity=db_sev) if cvss is None else cvss.model_copy(update={"severity": db_sev})

    return CVERecord(
        cve_id=cve_id,
        source="OSV",
        description=description[:1000] if description else None,
        published=vuln.get("published"),
        last_modified=vuln.get("modified"),
        cvss_v3=cvss,
        cwes=cwes,
        references=refs,
        affected_versions_raw=affected_versions_raw[:20],
        fixed_versions_raw=list(dict.fromkeys(fixed_versions_from_osv))[:10],
        version_matched=version_matched,
    )


def fetch_osv(
    software: str,
    version: str,
    ecosystem: Optional[str] = None,
    max_results: int = 100,
) -> tuple[list[CVERecord], list[str]]:
    """Query OSV.dev for vulnerabilities matching software + version. Returns (cve_records, errors)."""
    cached = _cache_load(software, version, ecosystem)
    if cached is not None:
        logger.info("OSV cache hit for %s %s (%d CVEs)", software, version, len(cached[0]))
        return cached

    ecosystems = [ecosystem] if ecosystem else _guess_ecosystems(software)
    seen_ids: set[str] = set()
    cve_records: list[CVERecord] = []
    errors: list[str] = []

    client = http_client.api
    for eco in ecosystems:
        payload: dict = {
            "version": version,
            "package": {"name": software},
        }
        if eco:
            payload["package"]["ecosystem"] = eco

        try:
            resp = client.post(OSV_QUERY_URL, json=payload, timeout=20)
            rate_limiter.record("osv", dict(resp.headers), resp.status_code)
            if resp.status_code == 429:
                errors.append("[RateLimit] OSV rate limit hit — reduce request frequency")
                continue
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            errors.append(f"OSV HTTP error ({eco}): {e}")
            continue
        except httpx.RequestError as e:
            errors.append(f"OSV request error ({eco}): {e}")
            continue

        vulns = resp.json().get("vulns", [])
        for vuln in vulns[:max_results]:
            vid = vuln.get("id", "")
            if vid in seen_ids:
                continue
            seen_ids.add(vid)
            record = _osv_item_to_cve_record(vuln, version)
            cve_records.append(record)

    logger.info("OSV: fetched %d unique vulns for %s %s", len(cve_records), software, version)
    _cache_save(software, version, ecosystem, cve_records, errors)
    return cve_records, errors
