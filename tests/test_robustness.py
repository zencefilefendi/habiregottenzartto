"""Adversarial inputs: the engine must degrade gracefully, never crash."""

import json

from habir import cli
from habir.analyze import risk as risk_mod
from habir.analyze.callgraph import analyze_callgraph
from habir.core.model import (Enrichment, Reachability, ReachabilityResult,
                              VersionConfidence)
from habir.engine import scan
from habir.mine.diff import parse_unified_diff
from habir.resolve import resolve_target
from habir.vuln import VulnStore, osv


def test_malformed_lockfile_warns_not_crashes(store, tmp_path):
    (tmp_path / "poetry.lock").write_text("this is not ][ valid toml")
    graph, _ = resolve_target(tmp_path)
    assert graph.warnings                      # surfaced, not swallowed
    result = scan(tmp_path, store)             # must not raise
    assert result.manifest.warnings


def test_no_manifest_is_reported(store, tmp_path):
    result = scan(tmp_path, store)
    assert any("no supported manifest" in w for w in result.manifest.warnings)
    assert result.findings == []


def test_corrupt_osv_record_is_skipped(tmp_path):
    seed = tmp_path / "seed"
    (seed / "osv").mkdir(parents=True)
    (seed / "osv" / "good.json").write_text(json.dumps({
        "id": "GOOD-1",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "foo"},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}],
    }))
    (seed / "osv" / "bad.json").write_text("{ not valid json ]")
    s = VulnStore(tmp_path / "t.db")
    snap = s.sync_from_seed(seed)
    assert snap["record_count"] == 1
    assert snap.get("skipped_files") == 1
    assert s.lookup("PyPI", "foo")             # the good record still loaded
    s.close()


def test_store_skips_bad_epss_row(tmp_path):
    seed = tmp_path / "seed"
    (seed / "osv").mkdir(parents=True)
    (seed / "epss.csv").write_text(
        "cve,epss,percentile\nCVE-1,notanumber,0.5\nCVE-2,0.3,0.6\n")
    s = VulnStore(tmp_path / "t.db")
    snap = s.sync_from_seed(seed)
    assert snap["epss_count"] == 1             # the malformed row was skipped
    s.close()


def test_cvss_v4_is_handled_gracefully():
    raw = {
        "id": "V4-1",
        "severity": [{"type": "CVSS_V4",
                      "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"}],
        "affected": [{"package": {"ecosystem": "PyPI", "name": "foo"},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": "0"}]}]}],
    }
    vuln = osv.parse_record(raw)               # must not raise on v4
    cvss = vuln.best_cvss()
    assert cvss is not None and cvss.version == "4.0"
    # unscored v4 (base 0.0) must fall back to the neutral severity path
    score = risk_mod.score_vulnerability(
        cvss_base=cvss.base_score or None, enrichment=Enrichment(),
        reachability=ReachabilityResult(status=Reachability.REACHABLE),
        confidence=VersionConfidence.LOCKFILE)
    assert score.factors["severity"] == 0.5


def test_callgraph_terminates_on_recursion(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.1\n")
    (tmp_path / "m.py").write_text(
        "import requests\n"
        "def a():\n    b()\n    requests.get('x')\n"
        "def b():\n    a()\n"          # mutual recursion
        "a()\n")
    cg = analyze_callgraph(tmp_path)   # must terminate (visited set)
    assert "requests" in cg.external
    assert "get" in cg.external["requests"].reached_symbols


def test_diff_parser_tolerates_garbage():
    assert parse_unified_diff("") == []
    assert parse_unified_diff("\x00 random\nnot a diff\n@@ broken") == []


def test_cli_returns_clean_code_on_missing_target(tmp_path):
    code = cli.main(["scan", str(tmp_path / "does-not-exist"),
                     "--db", str(tmp_path / "x.db")])
    assert code == 2                           # clean exit, not a traceback


def test_cli_no_args_prints_help():
    assert cli.main([]) == 0


def test_weird_but_valid_names_normalize(tmp_path):
    (tmp_path / "requirements.txt").write_text("A.B_C==1.0\nZope.Interface==5.0\n")
    graph, _ = resolve_target(tmp_path)
    assert "a-b-c" in graph.packages
    assert "zope-interface" in graph.packages
