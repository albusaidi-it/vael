"""
VAEL – SBOM Parser
Parses CycloneDX and SPDX Software Bill of Materials files and extracts
(software, version) pairs for bulk analysis.

Supported formats:
  CycloneDX JSON  (.json) – spec 1.4, 1.5, 1.6
  CycloneDX XML   (.xml)  – spec 1.4, 1.5, 1.6
  SPDX JSON       (.json) – spec 2.x
  SPDX tag-value  (.spdx) – spec 2.x
  Requirements    (.txt)  – pip requirements.txt (bonus: quick Python support)

Usage:
    from core.sbom_parser import parse_sbom, SBOMComponent
    components = parse_sbom("bom.json")
    for c in components:
        print(c.name, c.version, c.ecosystem)
"""

from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# CycloneDX XML namespace (varies slightly by version; match any)
_CDX_NS_RE = re.compile(r"http://cyclonedx\.org/schema/bom/[\d.]+")
_CDX_NS    = "http://cyclonedx.org/schema/bom/1.4"  # default for tag building


@dataclass
class SBOMComponent:
    name: str
    version: str
    ecosystem: Optional[str] = None      # npm, PyPI, Maven, Go, ...
    purl: Optional[str] = None           # pkg:maven/org.apache:log4j-core@2.14.1
    cpe: Optional[str] = None
    group: Optional[str] = None          # Maven groupId

    def display(self) -> str:
        return f"{self.name}@{self.version}" + (f" ({self.ecosystem})" if self.ecosystem else "")


def _purl_to_ecosystem(purl: str) -> Optional[str]:
    """pkg:maven/... → 'Maven', pkg:npm/... → 'npm', etc."""
    if not purl:
        return None
    m = re.match(r"pkg:([^/]+)/", purl.lower())
    if not m:
        return None
    mapping = {
        "maven": "Maven", "npm": "npm", "pypi": "PyPI",
        "golang": "Go", "gem": "RubyGems", "nuget": "NuGet",
        "cargo": "crates.io", "hex": "Hex", "pub": "Pub",
        "swift": "SwiftURL", "hackage": "Hackage",
    }
    return mapping.get(m.group(1))


def _parse_cyclonedx_json(data: dict) -> list[SBOMComponent]:
    components: list[SBOMComponent] = []
    for comp in data.get("components", []):
        name    = comp.get("name", "")
        version = comp.get("version", "")
        if not name or not version:
            continue
        purl    = comp.get("purl", "")
        cpe     = comp.get("cpe", "")
        group   = comp.get("group", "")
        eco     = _purl_to_ecosystem(purl)
        # For Maven, combine group + name as the canonical package name
        canonical = f"{group}:{name}" if group and eco == "Maven" else name
        components.append(SBOMComponent(
            name=canonical,
            version=version,
            ecosystem=eco,
            purl=purl or None,
            cpe=cpe or None,
            group=group or None,
        ))
    return components


def _parse_cyclonedx_xml(root: ET.Element) -> list[SBOMComponent]:
    # Detect actual namespace from root tag
    ns_match = re.match(r"\{([^}]+)\}", root.tag)
    ns = ns_match.group(1) if ns_match else _CDX_NS

    components: list[SBOMComponent] = []
    for comp in root.findall(f".//{{{ns}}}component"):
        name    = (comp.findtext(f"{{{ns}}}name") or "").strip()
        version = (comp.findtext(f"{{{ns}}}version") or "").strip()
        if not name or not version:
            continue
        purl    = (comp.findtext(f"{{{ns}}}purl") or "").strip()
        cpe     = (comp.findtext(f"{{{ns}}}cpe") or "").strip()
        group   = (comp.findtext(f"{{{ns}}}group") or "").strip()
        eco     = _purl_to_ecosystem(purl)
        canonical = f"{group}:{name}" if group and eco == "Maven" else name
        components.append(SBOMComponent(
            name=canonical,
            version=version,
            ecosystem=eco,
            purl=purl or None,
            cpe=cpe or None,
            group=group or None,
        ))
    return components


def _parse_spdx_json(data: dict) -> list[SBOMComponent]:
    components: list[SBOMComponent] = []
    for pkg in data.get("packages", []):
        name    = pkg.get("name", "")
        version = pkg.get("versionInfo", "")
        if not name or not version or version == "NOASSERTION":
            continue
        # SPDX external refs may contain PURL
        purl = None
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                break
        eco = _purl_to_ecosystem(purl or "")
        components.append(SBOMComponent(
            name=name,
            version=version,
            ecosystem=eco,
            purl=purl,
        ))
    return components


def _parse_spdx_tagvalue(text: str) -> list[SBOMComponent]:
    """Parse SPDX tag-value format (.spdx files)."""
    components: list[SBOMComponent] = []
    current: dict[str, str] = {}

    def flush():
        name    = current.get("PackageName", "")
        version = current.get("PackageVersion", "")
        if name and version and version != "NOASSERTION":
            purl = current.get("ExternalRef_purl", "")
            eco  = _purl_to_ecosystem(purl)
            components.append(SBOMComponent(
                name=name, version=version, ecosystem=eco,
                purl=purl or None,
            ))

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("PackageName:"):
            if current.get("PackageName"):
                flush()
                current = {}
            current["PackageName"] = line.split(":", 1)[1].strip()
        elif line.startswith("PackageVersion:"):
            current["PackageVersion"] = line.split(":", 1)[1].strip()
        elif "ExternalRef: PACKAGE-MANAGER purl" in line:
            # ExternalRef: PACKAGE-MANAGER purl pkg:npm/lodash@4.17.21
            parts = line.split()
            if len(parts) >= 4:
                current["ExternalRef_purl"] = parts[-1]

    if current.get("PackageName"):
        flush()
    return components


def _parse_requirements_txt(text: str) -> list[SBOMComponent]:
    """Parse pip requirements.txt for quick Python package extraction."""
    components: list[SBOMComponent] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Match: package==version, package>=version, package~=version
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*[=~!<>]+\s*([A-Za-z0-9_.\-]+)", line)
        if m:
            components.append(SBOMComponent(
                name=m.group(1),
                version=m.group(2),
                ecosystem="PyPI",
            ))
    return components


def parse_sbom(path: str | Path) -> list[SBOMComponent]:
    """
    Parse a SBOM file and return a list of SBOMComponents.
    Auto-detects format from file extension and content.
    Raises ValueError for unrecognised format.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"SBOM file not found: {path}")

    suffix = path.suffix.lower()
    content = path.read_text(encoding="utf-8", errors="replace")

    # JSON — could be CycloneDX or SPDX
    if suffix == ".json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in SBOM: {e}")

        # CycloneDX has "bomFormat" or "components" key
        if data.get("bomFormat", "").lower() == "cyclonedx" or "components" in data:
            comps = _parse_cyclonedx_json(data)
            logger.info("Parsed CycloneDX JSON SBOM: %d components", len(comps))
            return comps

        # SPDX has "spdxVersion" key
        if "spdxVersion" in data or "packages" in data:
            comps = _parse_spdx_json(data)
            logger.info("Parsed SPDX JSON SBOM: %d components", len(comps))
            return comps

        raise ValueError("JSON file is neither CycloneDX nor SPDX format")

    # XML — CycloneDX
    if suffix in (".xml", ".cdx"):
        try:
            root = ET.fromstring(content)
        except ET.ParseError as e:
            raise ValueError(f"Invalid XML in SBOM: {e}")
        comps = _parse_cyclonedx_xml(root)
        logger.info("Parsed CycloneDX XML SBOM: %d components", len(comps))
        return comps

    # SPDX tag-value
    if suffix in (".spdx", ".tv"):
        comps = _parse_spdx_tagvalue(content)
        logger.info("Parsed SPDX tag-value SBOM: %d components", len(comps))
        return comps

    # pip requirements.txt
    if suffix == ".txt" or path.name.startswith("requirements"):
        comps = _parse_requirements_txt(content)
        logger.info("Parsed requirements.txt: %d packages", len(comps))
        return comps

    raise ValueError(f"Unsupported SBOM format: {suffix}. "
                     "Supported: .json (CycloneDX/SPDX), .xml, .cdx, .spdx, .txt")
