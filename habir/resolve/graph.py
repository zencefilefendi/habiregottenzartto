"""
Dependency graph assembly + manifest discovery.

Lockfile-first by design: when several manifests coexist we trust the most
authoritative *resolved* artifact (a lock file) over a loose requirements list,
because only the lock file tells us the exact versions actually installed.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

from ..core.model import DependencyGraph, ResolvedPackage
from ..core.purl import normalize_pypi_name
from . import pipfile, poetry, requirements, uvlock

# Errors a malformed manifest can realistically raise — caught so a single bad
# file never aborts a scan.
_PARSE_ERRORS = (OSError, ValueError, KeyError, TypeError,
                 tomllib.TOMLDecodeError, json.JSONDecodeError)

# (filename or glob, resolver, authority rank). Higher rank wins on conflict.
_MANIFESTS = [
    ("poetry.lock", poetry.resolve, 40),
    ("uv.lock", uvlock.resolve, 40),
    ("Pipfile.lock", pipfile.resolve, 35),
    ("requirements.txt", requirements.resolve, 20),
]


def discover(target: Path) -> list[tuple[Path, object, int]]:
    """Find manifests under a directory (or accept a single manifest file)."""
    if target.is_file():
        for name, resolver, rank in _MANIFESTS:
            if target.name == name or (name == "requirements.txt"
                                       and target.name.startswith("requirements")
                                       and target.suffix == ".txt"):
                return [(target, resolver, rank)]
        # default: treat unknown given file as a requirements file
        return [(target, requirements.resolve, 20)]

    found: list[tuple[Path, object, int]] = []
    for name, resolver, rank in _MANIFESTS:
        if name == "requirements.txt":
            for p in sorted(target.glob("requirements*.txt")):
                found.append((p, resolver, rank))
        else:
            p = target / name
            if p.exists():
                found.append((p, resolver, rank))
    return found


def roots_from_pyproject(directory: Path) -> set[str]:
    """Read true top-level deps from pyproject.toml (PEP 621 or poetry)."""
    pp = directory / "pyproject.toml"
    if not pp.exists():
        return set()
    try:
        data = tomllib.loads(pp.read_text(encoding="utf-8", errors="replace"))
    except (OSError, tomllib.TOMLDecodeError):
        return set()
    roots: set[str] = set()
    # PEP 621
    for dep in data.get("project", {}).get("dependencies", []) or []:
        parsed = requirements.parse_requirement(dep)
        if parsed:
            roots.add(parsed.canonical)
    # Poetry
    poetry_deps = (data.get("tool", {}).get("poetry", {}) or {}).get("dependencies", {})
    for name in poetry_deps:
        if name.lower() != "python":
            roots.add(normalize_pypi_name(name))
    return roots


def build_graph(packages: list[ResolvedPackage], *,
                explicit_roots: set[str] | None = None) -> DependencyGraph:
    graph = DependencyGraph(ecosystem="PyPI")
    for pkg in packages:
        # Keep the higher-confidence / more-specific record on duplicate names.
        existing = graph.packages.get(pkg.name)
        if existing is None or (pkg.version and not existing.version):
            graph.packages[pkg.name] = pkg

    names = set(graph.packages)

    # Determine roots.
    if explicit_roots:
        for name in explicit_roots & names:
            graph.packages[name].direct = True
    declared_direct = {p.name for p in graph.packages.values() if p.direct}
    if declared_direct:
        graph.roots = declared_direct
    else:
        # Fall back to in-degree-0 nodes (nothing depends on them).
        depended = set()
        for pkg in graph.packages.values():
            depended.update(d for d in pkg.depends_on if d in names)
        graph.roots = names - depended
        for name in graph.roots:
            graph.packages[name].direct = True
    return graph


def resolve_target(target: Path) -> tuple[DependencyGraph, list[Path]]:
    """Discover, resolve and graph a scan target. Returns (graph, manifests_used)."""
    manifests = discover(target)
    if not manifests:
        empty = DependencyGraph(ecosystem="PyPI")
        empty.warnings.append(
            f"no supported manifest (poetry.lock / uv.lock / Pipfile.lock / "
            f"requirements*.txt) found under {target}")
        return empty, []

    # Lockfile-first: keep only the highest-authority class present.
    top_rank = max(rank for _, _, rank in manifests)
    chosen = [(p, r) for p, r, rank in manifests if rank == top_rank]

    packages: list[ResolvedPackage] = []
    used: list[Path] = []
    warnings: list[str] = []
    for path, resolver in chosen:
        try:
            resolved = resolver(path)
        except _PARSE_ERRORS as exc:
            warnings.append(f"could not parse {path.name}: {type(exc).__name__}")
            continue
        packages.extend(resolved)
        used.append(path)
        if not resolved:
            warnings.append(f"{path.name} resolved to no packages")

    directory = target if target.is_dir() else target.parent
    graph = build_graph(packages, explicit_roots=roots_from_pyproject(directory))
    graph.warnings.extend(warnings)
    return graph, used
