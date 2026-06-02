"""Function-level call-graph reachability + the honest symbol-vs-package contrast."""

from habir.analyze import reachability as reach_mod
from habir.analyze.callgraph import analyze_callgraph, refine
from habir.core.model import Reachability
from habir.resolve import resolve_target


def test_interprocedural_path_crosses_modules(demo_dir):
    cg = analyze_callgraph(demo_dir)
    assert cg.analyzed
    # __main__ → run → load_config → yaml.full_load, across app.main / app.config
    assert "full_load" in cg.external["pyyaml"].reached_symbols
    path = cg.external["pyyaml"].paths["full_load"]
    assert path[0].endswith(":<toplevel>")
    assert path[-1] == "pyyaml.full_load"
    assert any("load_config" in step for step in path)


def test_requests_get_reached_but_not_vulnerable_fn(demo_dir):
    cg = analyze_callgraph(demo_dir)
    # first-party calls requests.get, not the vulnerable redirect handlers
    assert cg.external["requests"].reached_symbols == {"get"}


def test_refine_symbol_hit_with_path(demo_dir):
    graph, _ = resolve_target(demo_dir)
    base = reach_mod.analyze(graph, demo_dir)
    cg = analyze_callgraph(demo_dir)
    r = refine(base["pyyaml"], "pyyaml", ["full_load", "FullLoader"], cg)
    assert r.symbol_hit is True
    assert r.call_path and r.call_path[-1] == "pyyaml.full_load"
    assert r.analysis == "function-level"


def test_refine_affected_fn_not_reached(demo_dir):
    graph, _ = resolve_target(demo_dir)
    base = reach_mod.analyze(graph, demo_dir)
    cg = analyze_callgraph(demo_dir)
    # mined vulnerable functions are the internal redirect handlers
    r = refine(base["requests"], "requests", ["rebuild_auth", "resolve_redirects"], cg)
    assert r.symbol_hit is False
    assert r.affected_fn_not_reached is True


def test_refine_unreachable_stays_unreachable(demo_dir):
    graph, _ = resolve_target(demo_dir)
    base = reach_mod.analyze(graph, demo_dir)
    cg = analyze_callgraph(demo_dir)
    r = refine(base["jinja2"], "jinja2", ["format_map"], cg)
    assert r.status == Reachability.UNREACHABLE
    assert r.symbol_hit is False


def test_dead_code_call_is_not_reached(tmp_path):
    (tmp_path / "requirements.txt").write_text("PyYAML==5.1\n")
    (tmp_path / "main.py").write_text(
        "import yaml\n"
        "def used():\n"
        "    return yaml.safe_load('a: 1')\n"
        "def never_called():\n"
        "    return yaml.full_load('a: 1')\n"   # vulnerable, but unreachable
        "used()\n"                              # only `used` is an entrypoint call
    )
    cg = analyze_callgraph(tmp_path)
    reached = cg.external["pyyaml"].reached_symbols
    assert "safe_load" in reached
    assert "full_load" not in reached          # dead code is not on a call path


def test_no_source_not_analyzed(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.1\n")
    cg = analyze_callgraph(tmp_path)
    assert cg.analyzed is False
