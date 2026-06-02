"""Risk engine: determinism, monotonicity, KEV floor, confidence discount.

KEV is exercised here with clearly-synthetic fixtures (the bundled demo data
never falsely stamps a real CVE as actively-exploited)."""

from habir.analyze import risk
from habir.core.model import (Enrichment, Reachability, ReachabilityResult,
                              RiskBand, VersionConfidence)


def _reach(status, symbol=False):
    return ReachabilityResult(status=status, symbol_hit=symbol)


def test_determinism():
    args = dict(cvss_base=9.8, enrichment=Enrichment(epss=0.3),
                reachability=_reach(Reachability.REACHABLE),
                confidence=VersionConfidence.LOCKFILE)
    assert risk.score_vulnerability(**args).value == risk.score_vulnerability(**args).value


def test_reachability_monotonicity():
    common = dict(cvss_base=9.8, enrichment=Enrichment(epss=0.1),
                  confidence=VersionConfidence.LOCKFILE)
    reachable = risk.score_vulnerability(reachability=_reach(Reachability.REACHABLE), **common)
    unknown = risk.score_vulnerability(reachability=_reach(Reachability.UNKNOWN), **common)
    unreach = risk.score_vulnerability(reachability=_reach(Reachability.UNREACHABLE), **common)
    assert reachable.value > unknown.value > unreach.value


def test_symbol_hit_raises_exposure():
    common = dict(cvss_base=9.8, enrichment=Enrichment(epss=0.1),
                  confidence=VersionConfidence.LOCKFILE)
    pkg_level = risk.score_vulnerability(reachability=_reach(Reachability.REACHABLE), **common)
    sym_level = risk.score_vulnerability(
        reachability=_reach(Reachability.REACHABLE, symbol=True), **common)
    assert sym_level.value > pkg_level.value


def test_unreachable_critical_becomes_low():
    """The thesis: a 9.8 CVE that is unreachable must not stay CRITICAL."""
    score = risk.score_vulnerability(
        cvss_base=9.8, enrichment=Enrichment(epss=0.05),
        reachability=_reach(Reachability.UNREACHABLE),
        confidence=VersionConfidence.LOCKFILE)
    assert score.band in (RiskBand.LOW, RiskBand.INFO)


def test_kev_floor_surfaces_unreachable_threat():
    """An actively-exploited (KEV) finding must never be buried below MEDIUM."""
    score = risk.score_vulnerability(
        cvss_base=5.0, enrichment=Enrichment(kev=True, epss=0.2),
        reachability=_reach(Reachability.UNREACHABLE),
        confidence=VersionConfidence.IMPORTED)
    assert score.band in (RiskBand.MEDIUM, RiskBand.HIGH, RiskBand.CRITICAL)
    assert score.factors.get("kev_floor_applied") == 1.0


def test_confidence_discounts_but_preserves_raw():
    high_conf = risk.score_vulnerability(
        cvss_base=9.8, enrichment=Enrichment(epss=0.4),
        reachability=_reach(Reachability.REACHABLE),
        confidence=VersionConfidence.LOCKFILE)
    low_conf = risk.score_vulnerability(
        cvss_base=9.8, enrichment=Enrichment(epss=0.4),
        reachability=_reach(Reachability.REACHABLE),
        confidence=VersionConfidence.IMPORTED)
    assert low_conf.value < high_conf.value
    assert low_conf.raw_value == high_conf.raw_value     # nothing hidden
