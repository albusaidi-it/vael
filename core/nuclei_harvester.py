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

from schemas.stage3 import (
    PoCRecord, PoCSource, PoCQuality, VersionCompatibility,
)

logger = logging.getLogger(__name__)

# Nuclei templates org naming convention: templates/cves/YYYY/CVE-YYYY-NNNN.yaml
NUCLEI_TEMPLATE_URL = (
    "https://raw.githubusercontent.com/projectdiscovery/"
    "nuclei-templates/main/http/cves/{year}/{cve_id}.yaml"
)
NUCLEI_WEB_URL = (
    "https://github.com/projectdiscovery/nuclei-templates/blob/main/"
    "http/cves/{year}/{cve_id}.yaml"
)


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


def search_nuclei(
    cve_id: str,
    target_version: str,
    allow_network: bool = True,
) -> tuple[list[PoCRecord], list[str]]:
    """
    Check if a Nuclei template exists for a given CVE.

    A Nuclei template's existence alone is a strong signal that the CVE
    is weaponized and reproducibly detectable.
    """
    pocs: list[PoCRecord] = []
    errors: list[str] = []

    if not allow_network:
        return pocs, ["Nuclei harvester skipped (offline mode)"]

    # Parse year from CVE ID
    import re
    m = re.match(r"CVE-(\d{4})-", cve_id, re.I)
    if not m:
        return pocs, [f"Invalid CVE ID format: {cve_id}"]
    year = m.group(1)

    url = NUCLEI_TEMPLATE_URL.format(year=year, cve_id=cve_id.upper())
    web_url = NUCLEI_WEB_URL.format(year=year, cve_id=cve_id.upper())

    try:
        with httpx.Client(timeout=10, follow_redirects=True) as client:
            resp = client.get(url)
            if resp.status_code == 404:
                # No template — normal for most CVEs
                return pocs, errors
            if resp.status_code != 200:
                errors.append(f"Nuclei fetch error {resp.status_code} for {cve_id}")
                return pocs, errors
            yaml_text = resp.text
    except httpx.RequestError as e:
        errors.append(f"Nuclei fetch failed for {cve_id}: {e}")
        return pocs, errors

    parsed = _parse_nuclei_template(yaml_text, cve_id, target_version)

    compat = VersionCompatibility.CONFIRMED if parsed["version_matched"] else (
        VersionCompatibility.LIKELY if parsed["detected_versions"] else
        VersionCompatibility.UNKNOWN
    )

    pocs.append(PoCRecord(
        cve_id=cve_id,
        source=PoCSource.NUCLEI,
        url=web_url,
        title=parsed["name"] or f"Nuclei template for {cve_id}",
        author="projectdiscovery",
        description=parsed["description"],
        quality=PoCQuality.WEAPONIZED,      # All Nuclei templates are weaponized
        version_compatibility=compat,
        detected_versions=parsed["detected_versions"],
        has_executable_code=True,
        has_readme=False,
        language="yaml",
        raw_meta={
            "severity": parsed["severity"],
            "tags": parsed["tags"],
        },
    ))

    logger.info("Nuclei: found template for %s", cve_id)
    return pocs, errors
