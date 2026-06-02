from habir.core.model import AffectedRange
from habir.core.version import Version as V
from habir.vuln import osv


def _range(*events):
    return AffectedRange(type="ECOSYSTEM", events=list(events))


def test_introduced_fixed_boundaries():
    r = _range({"introduced": "0"}, {"fixed": "5.3.1"})
    assert osv.version_in_range(r, V("0.1"))
    assert osv.version_in_range(r, V("5.1"))
    assert osv.version_in_range(r, V("5.3.0"))
    assert not osv.version_in_range(r, V("5.3.1"))   # fixed is exclusive
    assert not osv.version_in_range(r, V("5.4"))


def test_last_affected_is_inclusive():
    r = _range({"introduced": "1.0"}, {"last_affected": "2.0"})
    assert not osv.version_in_range(r, V("0.9"))
    assert osv.version_in_range(r, V("1.0"))
    assert osv.version_in_range(r, V("2.0"))         # last_affected is inclusive
    assert not osv.version_in_range(r, V("2.0.1"))


def test_disjoint_intervals():
    r = _range({"introduced": "0"}, {"fixed": "1.0"},
               {"introduced": "2.0"}, {"fixed": "3.0"})
    assert osv.version_in_range(r, V("0.5"))
    assert not osv.version_in_range(r, V("1.5"))     # patched window
    assert osv.version_in_range(r, V("2.5"))
    assert not osv.version_in_range(r, V("3.0"))


def test_prerelease_ordering_in_range():
    # 5.4.0rc1 < 5.4 so it is still affected by a "< 5.4" advisory.
    r = _range({"introduced": "0"}, {"fixed": "5.4"})
    assert osv.version_in_range(r, V("5.4.0rc1"))
    assert not osv.version_in_range(r, V("5.4"))


def test_matches_end_to_end(store):
    vulns = store.lookup("PyPI", "pyyaml")
    assert vulns, "seed must contain pyyaml advisories"
    from habir.core.model import ResolvedPackage, VersionConfidence
    from habir.core.purl import PackageURL
    pkg = ResolvedPackage(
        ecosystem="PyPI", name="pyyaml", raw_name="PyYAML", version=V("5.1"),
        purl=PackageURL.for_package("pypi", "pyyaml", "5.1"),
        confidence=VersionConfidence.LOCKFILE)
    hits = [osv.matches(v, pkg) for v in vulns]
    assert any(hit for hit, _, _ in hits)
    # 5.1 is fixed by 5.3.1 and 5.4 — both should be suggested as upgrades.
    all_fixes = {f for _, fixes, _ in hits for f in fixes}
    assert {"5.3.1", "5.4"} <= all_fixes


def test_no_match_without_version(store):
    from habir.core.model import ResolvedPackage, VersionConfidence
    from habir.core.purl import PackageURL
    pkg = ResolvedPackage(
        ecosystem="PyPI", name="pyyaml", raw_name="PyYAML", version=None,
        purl=PackageURL.for_package("pypi", "pyyaml"),
        confidence=VersionConfidence.CONSTRAINED)
    for v in store.lookup("PyPI", "pyyaml"):
        hit, _, _ = osv.matches(v, pkg)
        assert not hit          # never match a guessed/missing version
