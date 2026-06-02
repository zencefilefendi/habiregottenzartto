from habir.core.model import VersionConfidence
from habir.resolve import requirements, resolve_target
from habir.resolve.graph import build_graph


def test_requirements_confidence_tiers(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text(
        "requests==2.19.1 --hash=sha256:abc\n"
        "PyYAML>=5.1\n"
        "urllib3==1.24.1\n"
    )
    pkgs = {p.name: p for p in requirements.resolve(f)}
    assert pkgs["requests"].confidence == VersionConfidence.LOCKFILE   # pin + hash
    assert pkgs["urllib3"].confidence == VersionConfidence.PINNED      # pin, no hash
    assert pkgs["pyyaml"].confidence == VersionConfidence.CONSTRAINED  # range only
    assert pkgs["pyyaml"].version is None                              # never guessed
    assert str(pkgs["requests"].version) == "2.19.1"


def test_name_normalization(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("Django.REST_framework==1.0\n")
    pkgs = requirements.resolve(f)
    assert pkgs[0].name == "django-rest-framework"   # PEP 503


def test_poetry_graph_roots_and_edges(demo_dir):
    graph, used = resolve_target(demo_dir)
    assert any(p.name == "poetry.lock" for p in used)
    # transitive edges captured
    assert set(graph.packages["requests"].depends_on) >= {"urllib3", "certifi", "idna"}
    # pyproject marks the true direct deps
    assert {"requests", "pyyaml", "jinja2", "reqests"} <= graph.roots
    # transitive deps are not roots
    assert "markupsafe" not in graph.roots


def test_in_degree_roots_without_pyproject():
    from habir.core.model import ResolvedPackage
    from habir.core.purl import PackageURL
    from habir.core.version import Version

    def pkg(name, deps):
        return ResolvedPackage(
            ecosystem="PyPI", name=name, raw_name=name, version=Version("1.0"),
            purl=PackageURL.for_package("pypi", name, "1.0"), depends_on=deps)

    graph = build_graph([pkg("app-root", ["lib-a"]), pkg("lib-a", ["lib-b"]),
                         pkg("lib-b", [])])
    assert graph.roots == {"app-root"}     # only the in-degree-0 node
