"""
Deterministic, explainable risk engine.

Pure math, no guessing, no ML. Same inputs always yield the same score, and
every contributing factor is recorded so a human can reconstruct the verdict:

    severity   = CVSS base / 10                      (unknown -> neutral 0.5)
    threat     = max(EPSS, 0.9 if KEV)               actively-exploited floors high
    exposure   = reachability weight                  symbol 1.0 / pkg .85 / unreach .3
    hazard     = severity * (0.7 + 0.3*threat)        severity-dominated, threat-amplified
    raw        = 100 * hazard * exposure              pre-confidence (nothing hidden)
    value      = raw * version_confidence             discount uncertain versions

Reachability precision matters: a package merely imported scores .85 exposure,
but a confirmed *affected-symbol* use is promoted to full 1.0 — symbol-level
evidence is stronger than presence. An unreachable vulnerability is heavily
discounted (.3), which is what turns a 9.8 unreachable CVE into a LOW.

Guardrails: an actively-exploited (KEV) match never falls below the MEDIUM band,
so a real-world threat is surfaced even on an unreachable/uncertain package.
"""

from __future__ import annotations

from ..core.model import (Enrichment, Reachability, ReachabilityResult,
                          RiskBand, RiskScore, VersionConfidence)

_EXPOSURE = {
    Reachability.REACHABLE: 0.85,    # imported, but vulnerable code path unconfirmed
    Reachability.UNKNOWN: 0.6,
    Reachability.UNREACHABLE: 0.3,
}

_BANDS = [(80.0, RiskBand.CRITICAL), (60.0, RiskBand.HIGH),
          (35.0, RiskBand.MEDIUM), (15.0, RiskBand.LOW)]


def _band(value: float) -> RiskBand:
    for threshold, band in _BANDS:
        if value >= threshold:
            return band
    return RiskBand.INFO


def _min_band(band: RiskBand, floor: RiskBand) -> RiskBand:
    order = [RiskBand.INFO, RiskBand.LOW, RiskBand.MEDIUM, RiskBand.HIGH, RiskBand.CRITICAL]
    return band if order.index(band) >= order.index(floor) else floor


def score_vulnerability(*, cvss_base: float | None, enrichment: Enrichment,
                        reachability: ReachabilityResult,
                        confidence: VersionConfidence) -> RiskScore:
    severity = (cvss_base / 10.0) if cvss_base else 0.5
    epss = enrichment.epss or 0.0
    threat = max(epss, 0.9 if enrichment.kev else 0.0)
    exposure = _EXPOSURE[reachability.status]
    conf = float(confidence)

    # A confirmed affected-symbol use is the strongest exposure evidence we have:
    # promote it to full weight rather than the discounted "merely imported".
    if getattr(reachability, "dynamic", False):
        exposure = 1.0
    elif reachability.symbol_hit:
        exposure = 1.0
    elif reachability.proven_sink_unreachable:
        # The dependency's own call graph proves the vulnerable function is not
        # reached from how this project uses it — near-unreachable, proven.
        exposure = min(exposure, 0.3)
    elif reachability.affected_fn_not_reached:
        # Package is used, but the (first-party) call graph never reaches the
        # vulnerable function — exposure is indirect at most. Honest discount.
        exposure = min(exposure, 0.6)

    hazard = severity * (0.7 + 0.3 * threat)
    raw = 100.0 * hazard * exposure
    value = raw * conf

    band = _band(value)
    factors = {
        "severity": round(severity, 4),
        "threat": round(threat, 4),
        "epss": round(epss, 4),
        "kev": 1.0 if enrichment.kev else 0.0,
        "exposure": round(exposure, 4),
        "confidence": round(conf, 4),
        "hazard": round(hazard, 4),
    }
    if getattr(reachability, "dynamic", False):
        factors["dynamic_trace_confirmed"] = 1.0
        factors["symbol_reached"] = 1.0
    elif reachability.symbol_hit:
        factors["symbol_reached"] = 1.0
        if reachability.deep:
            factors["cross_package_path"] = 1.0
    elif reachability.proven_sink_unreachable:
        factors["proven_sink_unreachable"] = 1.0
    elif reachability.affected_fn_not_reached:
        factors["affected_fn_not_reached"] = 1.0

    if enrichment.kev:
        floored = _min_band(band, RiskBand.MEDIUM)
        if floored != band:
            factors["kev_floor_applied"] = 1.0
        band = floored

    return RiskScore(value=round(value, 1), band=band, raw_value=round(raw, 1),
                     factors=factors)


def score_supply_chain(*, severity: float, reachability: ReachabilityResult,
                        confidence: VersionConfidence) -> RiskScore:
    """A declared typosquat is something the project actively installs, so
    exposure is treated as at least 'unknown', never discounted to unreachable."""
    exposure = max(_EXPOSURE[reachability.status], 0.7)
    conf = float(confidence)
    raw = 100.0 * severity * exposure
    value = raw * conf
    factors = {
        "severity": round(severity, 4),
        "exposure": round(exposure, 4),
        "confidence": round(conf, 4),
    }
    return RiskScore(value=round(value, 1), band=_band(value),
                     raw_value=round(raw, 1), factors=factors)
