"""
VAEL – Software Name Resolver

Normalises free-text software names to canonical CPE vendor/product strings
and ecosystem hints for OSV. Uses a five-layer pipeline:

  1. Exact alias lookup (O(1), curated YAML)
  2. Normalised key match (strip version, lowercase, collapse punctuation)
  3. Fuzzy match via rapidfuzz (token_set_ratio ≥ 85)
  4. Version string extraction (strips v-prefix, build metadata, SNAPSHOT)

Returns a ResolvedName with best-effort CPE parts and OSV ecosystem.
Falls back gracefully: if rapidfuzz is not installed it skips layer 3.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

_ALIAS_FILE = Path(__file__).parent.parent / "data" / "software_aliases.yaml"

# ── Version normalisation patterns ────────────────────────────────────────────
_VERSION_STRIP = re.compile(
    r"^v",                          # leading "v"
    re.IGNORECASE,
)
_VERSION_METADATA = re.compile(
    r"[-._]?(SNAPSHOT|RELEASE|FINAL|GA|RC\d*|ALPHA|BETA|BUILD[-.\w]*)$",
    re.IGNORECASE,
)
_VERSION_EXTRACT = re.compile(r"\d+(?:\.\d+)*")

# ── Name normalisation ────────────────────────────────────────────────────────
_PUNCT = re.compile(r"[\s\-_./]+")


def _normalise(name: str) -> str:
    """Lowercase + collapse punctuation: 'Apache Log4J 2' → 'apachelog4j2'"""
    return _PUNCT.sub("", name.lower())


def _clean_version(version: str) -> str:
    """'v2.14.1-SNAPSHOT' → '2.14.1'"""
    v = _VERSION_STRIP.sub("", version.strip())
    v = _VERSION_METADATA.sub("", v)
    return v.strip(".-")


@dataclass
class ResolvedName:
    """Result of name resolution."""
    input_software: str
    input_version: str
    canonical_name: str          # best-known canonical name
    clean_version: str           # normalised version string
    cpe_vendor: Optional[str] = None
    cpe_product: Optional[str] = None
    ecosystem: Optional[str] = None
    package_name: Optional[str] = None
    confidence: float = 1.0      # 1.0 = exact, 0.0-1.0 = fuzzy score
    match_method: str = "none"   # exact | normalised | fuzzy | fallback

    def cpe_string(self) -> Optional[str]:
        if self.cpe_vendor and self.cpe_product and self.clean_version:
            return (
                f"cpe:2.3:a:{self.cpe_vendor}:{self.cpe_product}"
                f":{self.clean_version}:*:*:*:*:*:*:*"
            )
        return None

    def osv_package_name(self) -> str:
        """Best name to pass to OSV /v1/query."""
        return self.package_name or self.canonical_name


@lru_cache(maxsize=1)
def _load_aliases() -> dict:
    """Load and cache the alias YAML once per process."""
    if not _ALIAS_FILE.exists():
        logger.warning("Alias file not found: %s", _ALIAS_FILE)
        return {}
    try:
        with _ALIAS_FILE.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning("Failed to load alias file: %s", e)
        return {}


@lru_cache(maxsize=1)
def _build_lookup() -> tuple[dict[str, tuple[str, dict]], list[str]]:
    """
    Build two lookup structures from the alias YAML:
      - norm_map: normalised_key → (canonical_name, entry_dict)
      - fuzzy_keys: list of all searchable strings for rapidfuzz
    """
    aliases = _load_aliases()
    norm_map: dict[str, tuple[str, dict]] = {}
    fuzzy_keys: list[str] = []

    for canonical, entry in aliases.items():
        if not isinstance(entry, dict):
            continue
        # canonical name itself
        for key in [canonical] + (entry.get("aliases") or []):
            nk = _normalise(str(key))
            if nk and nk not in norm_map:
                norm_map[nk] = (canonical, entry)
            if key and key not in fuzzy_keys:
                fuzzy_keys.append(str(key))

    return norm_map, fuzzy_keys


_PARENS = re.compile(r"\([^)]*\)")
_ACRONYM = re.compile(r"\b[A-Z]{2,}\b")


def _prep_for_fuzzy(software: str) -> str:
    """Strip parenthetical acronyms like '(EPMM)' before fuzzy matching."""
    return _PARENS.sub("", software).strip()


def _fuzzy_match(
    software: str,
    norm_map: dict,
    fuzzy_keys: list[str],
    threshold: float = 0.78,
) -> Optional[tuple[str, dict, float]]:
    """Try rapidfuzz token_set_ratio match. Returns (canonical, entry, score) or None."""
    try:
        from rapidfuzz import process, fuzz
    except ImportError:
        return None

    query = _prep_for_fuzzy(software)
    result = process.extractOne(
        query, fuzzy_keys,
        scorer=fuzz.token_set_ratio,
        score_cutoff=threshold * 100,
    )
    if result is None:
        return None
    matched_key, score, _ = result
    nk = _normalise(matched_key)
    entry_tuple = norm_map.get(nk)
    if entry_tuple:
        canonical, entry = entry_tuple
        return canonical, entry, score / 100.0
    return None


def resolve(software: str, version: str = "") -> ResolvedName:
    """
    Resolve a free-text software name to canonical CPE + ecosystem data.

    Always returns a ResolvedName — worst case it echoes back the input
    with match_method='fallback' so callers never have to handle None.
    """
    clean_ver = _clean_version(version) if version else ""
    norm_map, fuzzy_keys = _build_lookup()

    # Layer 1: exact normalised key match
    nk = _normalise(software)
    hit = norm_map.get(nk)
    if hit:
        canonical, entry = hit
        return ResolvedName(
            input_software=software,
            input_version=version,
            canonical_name=canonical,
            clean_version=clean_ver,
            cpe_vendor=entry.get("cpe_vendor") or None,
            cpe_product=entry.get("cpe_product") or None,
            ecosystem=entry.get("ecosystem") or None,
            package_name=entry.get("package_name") or None,
            confidence=1.0,
            match_method="exact",
        )

    # Layer 2: strip trailing version from software name then retry
    # e.g. "log4j 2.14.1" → "log4j"
    stripped = re.sub(r"\s+\d[\d.]*$", "", software).strip()
    if stripped != software:
        nk2 = _normalise(stripped)
        hit2 = norm_map.get(nk2)
        if hit2:
            canonical, entry = hit2
            return ResolvedName(
                input_software=software,
                input_version=version,
                canonical_name=canonical,
                clean_version=clean_ver,
                cpe_vendor=entry.get("cpe_vendor") or None,
                cpe_product=entry.get("cpe_product") or None,
                ecosystem=entry.get("ecosystem") or None,
                package_name=entry.get("package_name") or None,
                confidence=0.95,
                match_method="normalised",
            )

    # Layer 3: rapidfuzz fuzzy match
    fuzz_result = _fuzzy_match(software, norm_map, fuzzy_keys)
    if fuzz_result:
        canonical, entry, score = fuzz_result
        logger.debug("Fuzzy match '%s' → '%s' (%.0f%%)", software, canonical, score * 100)
        return ResolvedName(
            input_software=software,
            input_version=version,
            canonical_name=canonical,
            clean_version=clean_ver,
            cpe_vendor=entry.get("cpe_vendor") or None,
            cpe_product=entry.get("cpe_product") or None,
            ecosystem=entry.get("ecosystem") or None,
            package_name=entry.get("package_name") or None,
            confidence=score,
            match_method="fuzzy",
        )

    # Layer 4: fallback — return input as-is
    logger.debug("No alias match for '%s' — using raw name", software)
    return ResolvedName(
        input_software=software,
        input_version=version,
        canonical_name=software,
        clean_version=clean_ver,
        confidence=0.0,
        match_method="fallback",
    )


def resolve_ecosystem(software: str, user_hint: Optional[str] = None) -> list[str]:
    """
    Return list of OSV ecosystems to try for this software.
    user_hint takes priority; alias DB second; heuristics last.
    """
    if user_hint:
        return [user_hint]
    r = resolve(software)
    if r.ecosystem:
        return [r.ecosystem] if r.ecosystem else []
    # Generic heuristics for common suffixes
    low = software.lower()
    if any(low.endswith(s) for s in (".js", "-js", "/js")):
        return ["npm"]
    if any(low.startswith(s) for s in ("py-", "python-")):
        return ["PyPI"]
    if ":" in software:               # "org.foo:bar" → Maven groupId:artifactId
        return ["Maven"]
    # Default: try all major ecosystems
    return ["PyPI", "npm", "Maven", "Go", "RubyGems"]
