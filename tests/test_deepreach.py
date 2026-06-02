"""Cross-package (dependency-internal) reachability: upgrade + proven-safe."""

import json
from pathlib import Path

from habir.analyze.deepreach import DepReachability
from habir.engine import scan
from habir.mine.symbols import MineResult
from habir.report import vex
from habir.vuln import VulnStore

VENDOR = Path(__file__).resolve().parent.parent / "examples" / "demo-project" / "vendor"


def test_internal_reach_positive():
    dr = DepReachability([VENDOR])
    assert dr.active
    assert dr.locate("requests") is not None
    ok, path = dr.reaches("requests", {"get"}, {"rebuild_auth", "resolve_redirects"})
    assert ok
    assert path[0] == "get"
    assert path[-1] in {"rebuild_auth", "resolve_redirects"}


def test_internal_reach_negative_is_proven(tmp_path):
    pkg = tmp_path / "acme"
    pkg.mkdir()
    (pkg / "__init__.py").write_text(
        "def safe_entry():\n    return helper()\n"
        "def helper():\n    return 1\n"
        "def vulnerable_sink():\n    return danger()\n"
        "def danger():\n    return 2\n")
    dr = DepReachability([tmp_path])
    ok, path = dr.reaches("acme", {"safe_entry"}, {"vulnerable_sink"})
    assert ok is False and path == []          # proven: entry never reaches sink


def test_no_source_returns_none():
    dr = DepReachability([VENDOR])
    assert dr.reaches("totally-not-vendored", {"x"}, {"y"}) is None


def test_deps_path_upgrades_requests_to_deep(store, demo_dir):
    shallow = scan(demo_dir, store)
    deep = scan(demo_dir, store, deps_roots=[VENDOR])

    def find(result):
        return next(f for f in result.vulnerabilities if f.vuln.id == "GHSA-x84v-xcm2-53pg")

    s, d = find(shallow), find(deep)
    # shallow: first-party only → indirect, not symbol-confirmed
    assert s.reachability.affected_fn_not_reached and not s.reachability.symbol_hit
    # deep: cross-package path proves it → symbol hit, higher risk
    assert d.reachability.symbol_hit and d.reachability.deep
    assert d.reachability.analysis == "cross-package"
    assert "↘ requests internals" in d.reachability.call_path
    assert d.risk.value > s.risk.value


def _synthetic_store(tmp_path) -> VulnStore:
    seed = tmp_path / "seed"
    (seed / "osv").mkdir(parents=True)
    (seed / "osv" / "ACME-1.json").write_text(json.dumps({
        "id": "ACME-1",
        "severity": [{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"package": {"ecosystem": "PyPI", "name": "acme"},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}],
    }))
    store = VulnStore(tmp_path / "db.sqlite")
    store.sync_from_seed(seed)
    store.add_mined_symbols("ACME-1", "PyPI", "acme",
                            MineResult(short=["vulnerable_sink"],
                                       qualified=["vulnerable_sink"]))
    return store


def test_engine_proves_not_affected(tmp_path):
    proj = tmp_path / "proj"
    (proj / "vendor" / "acme").mkdir(parents=True)
    (proj / "requirements.txt").write_text("acme==1.0\n")
    (proj / "app.py").write_text("import acme\nacme.safe_entry()\n")
    (proj / "vendor" / "acme" / "__init__.py").write_text(
        "def safe_entry():\n    return helper()\n"
        "def helper():\n    return 1\n"
        "def vulnerable_sink():\n    return danger()\n"
        "def danger():\n    return 2\n")

    store = _synthetic_store(tmp_path)
    result = scan(proj, store, deps_roots=[proj / "vendor"])
    finding = next(f for f in result.vulnerabilities if f.vuln.id == "ACME-1")

    assert finding.reachability.proven_sink_unreachable is True
    assert finding.reachability.symbol_hit is False
    # proven-safe → VEX not_affected
    doc = json.loads(vex.render(result))
    stmt = next(s for s in doc["statements"] if s["vulnerability"]["@id"] == "ACME-1")
    assert stmt["status"] == "not_affected"
    store.close()
