"""
Supply-chain heuristics — catch threats that have *no CVE yet*.

CVE matching is reactive; the XZ backdoor, torchtriton dependency-confusion and
the steady drip of PyPI typosquats were never in a CVE feed at attack time. This
module is the proactive layer. v0.1 ships typosquat + dependency-confusion
distance checks; behavioral install-script / network-capability analysis is the
v0.5 expansion that makes this a true Socket.dev-class signal.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.model import ResolvedPackage
from ..data import top_packages


@dataclass(slots=True)
class SupplyChainSignal:
    package: ResolvedPackage
    kind: str            # "typosquat" | "dependency-confusion"
    detail: str
    nearest: str | None  # the legitimate package it resembles
    distance: int
    severity: float      # 0..1 synthetic severity for the risk engine


def levenshtein(a: str, b: str, *, cap: int = 3) -> int:
    """Bounded Levenshtein — returns >cap early once the threshold is exceeded."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        row_min = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            val = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            cur.append(val)
            row_min = min(row_min, val)
        if row_min > cap:
            return cap + 1
        prev = cur
    return prev[-1]


# Names that are legitimately close to popular ones — suppress known false alarms.
_ALLOWLIST = {
    "requests-oauthlib", "google-api-core", "googleapis-common-protos",
    "djangorestframework", "typing-extensions",
}


def analyze(packages: list[ResolvedPackage]) -> list[SupplyChainSignal]:
    popular = set(top_packages())
    signals: list[SupplyChainSignal] = []

    for pkg in packages:
        name = pkg.name
        if name in popular or name in _ALLOWLIST or len(name) < 4:
            continue

        best_name: str | None = None
        best_dist = 99
        for cand in popular:
            # Skip wildly different lengths cheaply.
            if abs(len(cand) - len(name)) > 2:
                continue
            d = levenshtein(name, cand, cap=2)
            if d < best_dist:
                best_dist, best_name = d, cand
                if d == 1:
                    break

        if best_name and 1 <= best_dist <= 2:
            severity = 0.9 if best_dist == 1 else 0.55
            signals.append(SupplyChainSignal(
                package=pkg,
                kind="typosquat",
                detail=(f"declared dependency '{name}' is edit-distance {best_dist} "
                        f"from popular package '{best_name}'"),
                nearest=best_name,
                distance=best_dist,
                severity=severity,
            ))
    return signals
