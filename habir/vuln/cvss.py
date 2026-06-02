"""
CVSS v3.0/3.1 base-score computation from a vector string.

We compute the base score ourselves rather than trusting a precomputed number,
because (a) OSV records sometimes carry only the vector, and (b) a transparent,
auditable score is a product promise. The formula is the FIRST.org spec.
"""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}   # privileges matter more when scope changes
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    # CVSS v3.1 Roundup: ceiling to one decimal, tolerant of fp error.
    rounded = round(x * 100000)
    if rounded % 10000 == 0:
        return rounded / 100000.0
    return (math.floor(rounded / 10000.0) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in vector.strip().split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k.upper()] = v.upper()
    return metrics


def base_score(vector: str) -> float | None:
    """Return the CVSS v3.x base score for a vector, or None if not computable."""
    m = parse_vector(vector)
    try:
        scope_changed = m["S"] == "C"
        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        ui = _UI[m["UI"]]
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        c, i, a = _IMPACT[m["C"]], _IMPACT[m["I"]], _IMPACT[m["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    if scope_changed:
        score = min(1.08 * (impact + exploitability), 10.0)
    else:
        score = min(impact + exploitability, 10.0)
    return _roundup(score)
