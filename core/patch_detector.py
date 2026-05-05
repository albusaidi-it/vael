"""
VAEL – Stage 2 / Patch Detector
Derives patch availability info from a Stage 1 CVERecord.

Data sources used (all from the CVE record — no additional network calls):
  - NVD references with tags like "Patch", "Vendor Advisory", "Release Notes"
  - CPE match version_end_excluding → implied fixed version
  - OSV affected.ranges with "fixed" events

Heuristic-based — intended as a best-effort signal, not authoritative.
"""

from __future__ import annotations

import logging
from typing import Optional

from schemas.stage1 import CVERecord
from schemas.stage2 import PatchInfo

logger = logging.getLogger(__name__)

PATCH_TAGS = {"patch", "vendor advisory", "release notes", "mitigation"}
VENDOR_ADVISORY_HOSTS = {
    "support.apache.org", "logging.apache.org",
    "nginx.org", "httpd.apache.org",
    "www.openssl.org", "openssl.org",
    "support.microsoft.com", "msrc.microsoft.com",
    "ubuntu.com", "access.redhat.com", "security.debian.org",
}

# GitHub URL path prefixes that indicate a real advisory or release — not issues/PRs/wikis
_GITHUB_ADVISORY_PATHS = (
    "/security/advisories/",   # GHSA advisories
    "/releases/",              # release pages
    "/releases/tag/",          # specific release tags
    "github.com/advisories/",  # global advisory database
)


def detect_patch(cve: CVERecord) -> PatchInfo:
    """Extract patch info from a CVERecord."""
    info = PatchInfo()

    # ── 1. Extract patch URLs from references ──────────────────────────
    patch_urls: list[str] = []
    vendor_advisory_url: Optional[str] = None

    for ref in cve.references:
        tags_lower = [t.lower() for t in ref.tags]
        url_lower = ref.url.lower()

        # Tagged as Patch / Vendor Advisory
        if any(t in PATCH_TAGS for t in tags_lower):
            patch_urls.append(ref.url)
            if "vendor advisory" in tags_lower and not vendor_advisory_url:
                vendor_advisory_url = ref.url

        # Heuristic: host-based vendor advisory detection
        elif any(host in url_lower for host in VENDOR_ADVISORY_HOSTS):
            if not vendor_advisory_url:
                vendor_advisory_url = ref.url
        # GitHub: only advisory/release paths count, not issues, PRs, wikis, or PoC repos
        elif "github.com" in url_lower and any(p in url_lower for p in _GITHUB_ADVISORY_PATHS):
            patch_urls.append(ref.url)
            if not vendor_advisory_url:
                vendor_advisory_url = ref.url

    # ── 2. Derive fixed_versions from CPE version_end_excluding (NVD) ──
    fixed_versions: set[str] = set()
    for match in cve.cpe_matches:
        if match.version_end_excluding:
            fixed_versions.add(match.version_end_excluding)

    # ── 3. OSV fixed versions from affected ranges ───────────────────
    for fv in cve.fixed_versions_raw:
        fixed_versions.add(fv)

    # ── 4. Decision: patch available if we have any signal ─────────────
    info.patch_urls = patch_urls
    info.vendor_advisory_url = vendor_advisory_url
    info.fixed_versions = sorted(fixed_versions)
    info.patch_available = bool(patch_urls or fixed_versions or vendor_advisory_url)

    return info
