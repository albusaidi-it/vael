"""
VAEL – Stage 3 / Nuclei Template Harvester
ProjectDiscovery's curated Nuclei template repository.

Nuclei templates are high-signal indicators:
  - Curated by a trusted organization
  - YAML format with built-in version matchers
  - Indicate an exploit is reproducible at scale

Strategy:
  - Use GitHub's raw content to search the nuclei-templates repo
  - Direct URL pattern: templates indexed by CVE ID in their cves/ directory
  - Check for CVE-specific YAML files without downloading the whole repo
"""

from __future__ import annotations

import logging
from datetime import datetime, date
from typing import Optional
import httpx
from core import http_client
from core import cache as _cache

from schemas.stage3 import (
    PoCRecord, PoCSource, PoCQuality, VersionCompatibility,
)

logger = logging.getLogger(__name__)

_NUCLEI_CACHE_TTL = 12 * 3600   # 12 hours — templates don't change often


def _cache_load(cve_id: str) -> Optional[list[PoCRecord]]:
    key  = _cache.make_key("nuclei_pocs", cve_id.upper())
    data = _cache.get(key)
    if data is None:
        return None
    try:
        return [PoCRecord.model_validate(r) for r in data]
    except Exception:
        return None


def _cache_save(cve_id: str, pocs: list[PoCRecord]) -> None:
    key = _cache.make_key("nuclei_pocs", cve_id.upper())
    _cache.set(key, "nuclei_pocs", [p.model_dump(mode="json") for p in pocs], _NUCLEI_CACHE_TTL)

# Nuclei templates may live in several category directories.
# Check all of them — a CVE can have both an HTTP and a network template.
_NUCLEI_RAW_BASE = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/"
_NUCLEI_WEB_BASE = "https://github.com/projectdiscovery/nuclei-templates/blob/main/"

NUCLEI_CATEGORY_PATHS = [
    "http/cves/{year}/{cve_id}.yaml",
    "network/cves/{year}/{cve_id}.yaml",
    "file/cves/{year}/{cve_id}.yaml",
    "cloud/cves/{year}/{cve_id}.yaml",
]


def _parse_nuclei_template(yaml_text: str, cve_id: str, target_version: str) -> dict:
    """
    Extract key fields from a Nuclei template without a full YAML parser.
    We do lightweight string parsing to stay dependency-free for Stage 3.
    """
    info = {
        "name": "",
        "severity": "",
        "description": "",
        "tags": "",
        "references": [],
        "detected_versions": [],
        "version_matched": False,
    }

    import re
    # name:
    m = re.search(r"^\s*name:\s*(.+)$", yaml_text, re.MULTILINE)
    if m:
        info["name"] = m.group(1).strip().strip('"\'')

    # severity:
    m = re.search(r"^\s*severity:\s*(\w+)", yaml_text, re.MULTILINE)
    if m:
        info["severity"] = m.group(1).strip().lower()

    # description:
    m = re.search(r"^\s*description:\s*[\|\>]?\s*\n?\s*(.+?)(?=\n\s*\w+:|\Z)",
                  yaml_text, re.MULTILINE | re.DOTALL)
    if m:
        info["description"] = m.group(1).strip().strip('"\'')[:500]

    # tags:
    m = re.search(r"^\s*tags:\s*(.+)$", yaml_text, re.MULTILINE)
    if m:
        info["tags"] = m.group(1).strip().strip('"\'')

    # Version detection: look for version strings in matchers and description
    version_pattern = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")
    versions = list(set(version_pattern.findall(yaml_text)))
    info["detected_versions"] = versions[:10]
    if target_version in yaml_text:
        info["version_matched"] = True

    return info


def _fetch_template(
    path: str,
    cve_id: str,
    target_version: str,
) -> Optional[PoCRecord]:
    """Fetch one template path and return a PoCRecord, or None if not found."""
    raw_url = _NUCLEI_RAW_BASE + path
    web_url = _NUCLEI_WEB_BASE + path
    try:
        resp = http_client.scrape.get(raw_url, timeout=10)
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            return None
        parsed = _parse_nuclei_template(resp.text, cve_id, target_version)
        compat = VersionCompatibility.CONFIRMED if parsed["version_matched"] else (
            VersionCompatibility.LIKELY if parsed["detected_versions"] else
            VersionCompatibility.UNKNOWN
        )
        category = path.split("/")[0]   # "http", "network", "file", "cloud"
        return PoCRecord(
            cve_id=cve_id,
            source=PoCSource.NUCLEI,
            url=web_url,
            title=parsed["name"] or f"Nuclei {category} template for {cve_id}",
            author="projectdiscovery",
            description=parsed["description"],
            quality=PoCQuality.WEAPONIZED,
            version_compatibility=compat,
            detected_versions=parsed["detected_versions"],
            has_executable_code=True,
            has_readme=False,
            language="yaml",
            raw_meta={"severity": parsed["severity"], "tags": parsed["tags"], "category": category},
        )
    except httpx.RequestError:
        return None


def search_nuclei(
    cve_id: str,
    target_version: str,
    allow_network: bool = True,
) -> tuple[list[PoCRecord], list[str]]:
    """
    Check all Nuclei template directories for a given CVE.
    Checks http/, network/, file/, and cloud/ in parallel.
    """
    cached = _cache_load(cve_id)
    if cached is not None:
        logger.info("Nuclei cache hit for %s (%d templates)", cve_id, len(cached))
        return cached, []

    pocs: list[PoCRecord] = []
    errors: list[str] = []

    if not allow_network:
        return pocs, ["Nuclei harvester skipped (offline mode)"]

    import re
    m = re.match(r"CVE-(\d{4})-", cve_id, re.I)
    if not m:
        return pocs, [f"Invalid CVE ID format: {cve_id}"]
    year = m.group(1)

    from concurrent.futures import ThreadPoolExecutor, as_completed
    paths = [p.format(year=year, cve_id=cve_id.upper()) for p in NUCLEI_CATEGORY_PATHS]

    with ThreadPoolExecutor(max_workers=4) as pool:
        futs = {pool.submit(_fetch_template, path, cve_id, target_version): path for path in paths}
        for fut in as_completed(futs):
            try:
                record = fut.result()
                if record:
                    pocs.append(record)
            except Exception as e:
                errors.append(f"Nuclei fetch error for {cve_id}: {e}")

    if pocs:
        logger.info("Nuclei: found %d template(s) for %s", len(pocs), cve_id)
        _cache_save(cve_id, pocs)
    return pocs, errors
