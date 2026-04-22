"""
VAEL – Version Utilities
Handles semver comparisons and CPE version range matching.
"""

from __future__ import annotations

import re
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from schemas.stage1 import CPEMatch


def _normalize(version: str) -> tuple[int, ...]:
    """Convert version string to comparable tuple of ints. e.g. '2.14.1' → (2,14,1)"""
    parts = re.split(r"[.\-_]", version)
    result = []
    for p in parts:
        digits = re.match(r"(\d+)", p)
        result.append(int(digits.group(1)) if digits else 0)
    return tuple(result)


def _cmp(a: str, b: str) -> int:
    """Returns -1, 0, or 1 comparing version strings."""
    na, nb = _normalize(a), _normalize(b)
    # Pad to same length
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
        # Exact CPE match: if CPE contains the version directly
        if target.lower() in match.cpe23.lower():
            return True

        start_inc = match.version_start_including
        end_exc   = match.version_end_excluding
        end_inc   = match.version_end_including

        # If no range info at all, can't determine — return False
        if not any([start_inc, end_exc, end_inc]):
            return False

        if start_inc:
            if _cmp(target, start_inc) < 0:     # target < start
                return False

        if end_exc:
            if _cmp(target, end_exc) >= 0:       # target >= end_excluding
                return False

        if end_inc:
            if _cmp(target, end_inc) > 0:        # target > end_including
                return False

        return True

    except Exception:
        return False


def best_cpe(software: str, version: str) -> Optional[str]:
    """
    Attempt to construct a plausible CPE 2.3 string from software name + version.
    This is a heuristic — exact CPE should come from the user or NVD CPE dictionary.

    Format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
    """
    clean = software.lower().strip().replace(" ", "_")
    # Strip common org prefixes like "org.apache/"
    if "/" in clean:
        _, clean = clean.split("/", 1)
    ver = version.strip()
    return f"cpe:2.3:a:*:{clean}:{ver}:*:*:*:*:*:*:*"
