"""End-to-end scan of the vulnerable demo project — the whole thesis in one test."""

import json

from habir.core.model import FindingKind, Reachability, RiskBand
from habir.engine import scan
from habir.report import sarif, vex, json_out


def _by_id(result):
    out = {}
    for f in result.findings:
        out.setdefault(f.identifier, f)
    return out


def test_demo_scan_findings(store, demo_dir):
    result = scan(demo_dir, store)
    found = _by_id(result)

    # every seeded advisory is matched against the pinned versions
    assert {"GHSA-6757-jp84-gxfx", "GHSA-8q59-q68h-6hv4", "GHSA-x84v-xcm2-53pg",
            "GHSA-462w-v97r-4m45", "GHSA-mh33-7rrq-662w"} <= set(found)

    # pyyaml RCE: reachable, symbol-confirmed, HIGH, with upgrade path
    pyyaml = found["GHSA-8q59-q68h-6hv4"]
    assert pyyaml.reachability.symbol_hit is True
    assert pyyaml.risk.band == RiskBand.HIGH
    assert "5.4" in pyyaml.fixed_versions

    # jinja2 9.8 RCE but UNREACHABLE → discounted to LOW (the core differentiator)
    jinja = found["GHSA-462w-v97r-4m45"]
    assert jinja.reachability.status == Reachability.UNREACHABLE
    assert jinja.risk.band in (RiskBand.LOW, RiskBand.INFO)

    # reachable findings outrank the unreachable critical
    assert pyyaml.risk.value > jinja.risk.value


def test_function_level_downranks_indirect_exposure(store, demo_dir):
    """The v0.5 payoff: a reachable package whose *vulnerable function* is never
    called ranks below one whose affected symbol is on a real call path."""
    result = scan(demo_dir, store)
    found = _by_id(result)
    req = found["GHSA-x84v-xcm2-53pg"]          # requests: get() called, not rebuild_auth
    pyy = found["GHSA-8q59-q68h-6hv4"]          # pyyaml: full_load() on the call path
    assert req.reachability.affected_fn_not_reached is True
    assert req.reachability.symbol_hit is False
    assert pyy.reachability.symbol_hit is True
    assert pyy.reachability.call_path[-1] == "pyyaml.full_load"
    assert pyy.risk.value > req.risk.value


def test_supply_chain_typosquat_detected(store, demo_dir):
    result = scan(demo_dir, store)
    sc = [f for f in result.findings if f.kind == FindingKind.SUPPLY_CHAIN]
    assert any("reqests" in f.package.name for f in sc)


def test_reproducibility_manifest(store, demo_dir):
    result = scan(demo_dir, store)
    m = result.manifest
    assert m.db_snapshot.get("content_hash", "").startswith("sha256:")
    assert m.inputs and all("sha256" in i for i in m.inputs)
    assert m.counts["vulnerabilities"] == 5
    assert m.counts["supply_chain"] == 1


def test_vex_status_from_reachability(store, demo_dir):
    result = scan(demo_dir, store)
    doc = json.loads(vex.render(result))
    status = {s["vulnerability"]["name"]: s for s in doc["statements"]}
    # unreachable → not_affected with the standard justification
    assert status["CVE-2019-10906"]["status"] == "not_affected"
    assert status["CVE-2019-10906"]["justification"] == "vulnerable_code_not_in_execute_path"
    # reachable → affected
    assert status["CVE-2020-14343"]["status"] == "affected"


def test_outputs_are_valid_json(store, demo_dir):
    result = scan(demo_dir, store)
    for renderer in (json_out.render, sarif.render, vex.render):
        json.loads(renderer(result))   # must not raise


def test_determinism_same_inputs(store, demo_dir):
    a = json_out.render(scan(demo_dir, store))
    b = json_out.render(scan(demo_dir, store))
    # strip the timestamp line, everything else must be byte-identical
    def strip_ts(doc):
        d = json.loads(doc)
        d["manifest"]["generated_at"] = "X"
        return json.dumps(d, sort_keys=True)
    assert strip_ts(a) == strip_ts(b)
