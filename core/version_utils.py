"""
VAEL – Version Utilities
Handles semver comparisons and CPE version range matching.
"""

from __future__ import annotations

import re
from typing import Optional, TYPE_CHECKING

from packaging.version import Version, InvalidVersion

if TYPE_CHECKING:
    from schemas.stage1 import CPEMatch


# Pre-release label weights — all negative so they sort BEFORE the release.
# e.g. "1.0.0-beta" < "1.0.0" < "1.0.0.1"
_PRE_LABELS = re.compile(
    r'^(alpha|a|beta|b|rc|cr|preview|snapshot|final|ga|release|sp)(\d*)$',
    re.I,
)
_PRE_WEIGHTS = {
    'snapshot': -40,
    'alpha': -30, 'a': -30,
    'beta':  -20, 'b': -20,
    'preview': -20,
    'rc':    -10, 'cr': -10,
    'final': 0,   'ga': 0, 'release': 0, 'sp': 1,  # sp = service pack > release
}


def _normalize(version: str) -> tuple[int, ...]:
    """
    Convert a version string to a comparable tuple of ints.
    Pre-release labels map to negative weights so they sort before the release:
      "1.0.0-beta" → (1, 0, 0, -20) < "1.0.0" → (1, 0, 0)
    """
    parts = re.split(r'[.\-_+]', version.lower())
    result: list[int] = []
    for p in parts:
        m = _PRE_LABELS.match(p)
        if m:
            label = m.group(1).lower()
            result.append(_PRE_WEIGHTS.get(label, -1))
            if m.group(2):
                result.append(int(m.group(2)))
        else:
            digits = re.match(r'(\d+)', p)
            result.append(int(digits.group(1)) if digits else 0)
    return tuple(result)


def _cmp(a: str, b: str) -> int:
    """
    Compare two version strings. Returns -1, 0, or 1.

    Uses packaging.version.Version for PEP 440-compliant strings
    (correctly handles 1.0b1 < 1.0rc1 < 1.0 < 1.0.post1).
    Falls back to _normalize-based tuple comparison for non-PEP-440 formats
    (Java build numbers, OpenSSH pN suffixes, Apache .x.y strings, etc.).
    """
    try:
        va, vb = Version(a), Version(b)
        if va < vb: return -1
        if va > vb: return 1
        return 0
    except InvalidVersion:
        pass
    na, nb = _normalize(a), _normalize(b)
    length = max(len(na), len(nb))
    na = na + (0,) * (length - len(na))
    nb = nb + (0,) * (length - len(nb))
    if na < nb: return -1
    if na > nb: return 1
    return 0


def version_in_range(target: str, match: "CPEMatch") -> bool:
    """
    Check if `target` falls within the affected version range of a CPEMatch.

    CPE range semantics:
      version_start_including <= target < version_end_excluding
      version_start_including <= target <= version_end_including
    """
    try:
        start_inc = match.version_start_including
        end_exc   = match.version_end_excluding
        end_inc   = match.version_end_including

        # If explicit range bounds exist, use them — more reliable than substring.
        if any([start_inc, end_exc, end_inc]):
            if start_inc and _cmp(target, start_inc) < 0:
                return False
            if end_exc and _cmp(target, end_exc) >= 0:
                return False
            if end_inc and _cmp(target, end_inc) > 0:
                return False
            return True

        # No range bounds — fall back to substring match in the CPE string.
        # e.g. cpe:2.3:a:apache:log4j:2.14.1:*:... contains "2.14.1"
        return target.lower() in match.cpe23.lower()

    except Exception:
        return False


def best_cpe(software: str, version: str) -> Optional[str]:
    """
    Attempt to construct a plausible CPE 2.3 string from software name + version.
    This is a heuristic — exact CPE should come from the user or NVD CPE dictionary.

    Format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
    """
    clean = software.lower().strip().replace(" ", "_")
    if "/" in clean:
        _, clean = clean.split("/", 1)
    ver = version.strip()
    return f"cpe:2.3:a:*:{clean}:{ver}:*:*:*:*:*:*:*"
