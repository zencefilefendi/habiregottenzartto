from habir.analyze import reachability
from habir.core.model import Reachability
from habir.resolve import resolve_target


def test_demo_reachability_distinguishes_used_from_unused(demo_dir):
    graph, _ = resolve_target(demo_dir)
    results = reachability.analyze(graph, demo_dir)

    # imported directly / transitively
    assert results["requests"].status == Reachability.REACHABLE
    assert results["pyyaml"].status == Reachability.REACHABLE
    assert results["urllib3"].status == Reachability.REACHABLE   # transitive via requests

    # declared but never imported
    assert results["jinja2"].status == Reachability.UNREACHABLE
    assert results["markupsafe"].status == Reachability.UNREACHABLE
    assert results["reqests"].status == Reachability.UNREACHABLE


def test_symbol_capture_from_attribute_use(demo_dir):
    graph, _ = resolve_target(demo_dir)
    results = reachability.analyze(graph, demo_dir)
    # app/config.py calls `yaml.full_load(...)` → attribute promoted to a symbol.
    assert "full_load" in results["pyyaml"].imported_symbols


def test_no_source_yields_unknown(tmp_path):
    # A lockfile with no analyzable first-party python source.
    (tmp_path / "requirements.txt").write_text("requests==2.19.1\n")
    graph, _ = resolve_target(tmp_path / "requirements.txt")
    results = reachability.analyze(graph, tmp_path)
    assert results["requests"].status == Reachability.UNKNOWN


def test_alias_import_mapping(tmp_path):
    (tmp_path / "requirements.txt").write_text("PyYAML==5.1\n")
    (tmp_path / "code.py").write_text("import yaml as y\ny.safe_load('a: 1')\n")
    graph, _ = resolve_target(tmp_path / "requirements.txt")
    results = reachability.analyze(graph, tmp_path)
    # `import yaml as y` → mapped to pyyaml; `y.safe_load` → symbol captured.
    assert results["pyyaml"].status == Reachability.REACHABLE
    assert "safe_load" in results["pyyaml"].imported_symbols
