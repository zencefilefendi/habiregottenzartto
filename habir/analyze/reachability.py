"""
Import-graph reachability — the noise filter that turns "you have a vulnerable
package" into "your code actually pulls it in."

This is package-level reachability with symbol awareness at direct import sites.
It walks first-party source (never the vendored dependencies), maps import names
to distributions, then takes the forward closure over the dependency graph: a
package is REACHABLE iff first-party code imports it, or something reachable
depends on it. Everything else is UNREACHABLE and gets discounted by the risk
engine. Function-level path analysis is the v0.5 successor to this.
"""

from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from ..core.model import DependencyGraph, Reachability, ReachabilityResult
from ..core.purl import normalize_pypi_name
from ..data import import_map

_VENDOR_DIRS = {
    ".venv", "venv", "env", ".env", "site-packages", "node_modules", ".git",
    "__pycache__", "build", "dist", ".tox", ".eggs", ".mypy_cache",
    ".pytest_cache", ".habir", ".idea", ".vscode", "vendor", "__pypackages__",
}


@dataclass
class _ImportInfo:
    files: set[str] = field(default_factory=set)
    symbols: set[str] = field(default_factory=set)


def _iter_python_files(root: Path):
    if root.is_file():
        if root.suffix == ".py":
            yield root
        # A manifest target: scan sibling source.
        root = root.parent
    for path in root.rglob("*.py"):
        if any(part in _VENDOR_DIRS for part in path.parts):
            continue
        yield path


def collect_first_party_imports(source_root: Path) -> tuple[dict[str, _ImportInfo], int]:
    """Return ({dist_name: import info}, files_scanned)."""
    imap = import_map()
    found: dict[str, _ImportInfo] = {}
    scanned = 0

    def record(top_module: str, file: Path, symbols: set[str]) -> None:
        if not top_module:
            return
        dist = imap.get(top_module.lower(), normalize_pypi_name(top_module))
        info = found.setdefault(dist, _ImportInfo())
        info.files.add(str(file))
        info.symbols |= symbols

    for py in _iter_python_files(source_root):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"), filename=str(py))
        except (SyntaxError, ValueError):
            continue
        scanned += 1

        # Pass 1: bindings. Track the local name each module is bound to, so that
        # `import numpy as np` lets us attribute `np.foo` back to numpy.
        alias_to_dist: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    dist = imap.get(top.lower(), normalize_pypi_name(top))
                    alias_to_dist[alias.asname or top] = dist
                    record(top, py, set())
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    continue  # any relative import is first-party, not a distribution
                if node.module:
                    symbols = {a.name for a in node.names if a.name != "*"}
                    record(node.module.split(".")[0], py, symbols)

        # Pass 2: attribute usage on a bound module (e.g. `yaml.full_load(...)`)
        # promotes the attribute to a used symbol — realistic symbol reachability.
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                mapped = alias_to_dist.get(node.value.id)
                if mapped:
                    found.setdefault(mapped, _ImportInfo()).symbols.add(node.attr)
    return found, scanned


def analyze(graph: DependencyGraph, source_root: Path) -> dict[str, ReachabilityResult]:
    imports, scanned = collect_first_party_imports(source_root)

    # No analyzable source → we honestly cannot claim reachability.
    if scanned == 0:
        return {name: ReachabilityResult(status=Reachability.UNKNOWN)
                for name in graph.packages}

    names = set(graph.packages)
    import_roots = set(imports) & names

    # Forward closure over depends_on edges.
    reachable: set[str] = set()
    queue: deque[str] = deque(import_roots)
    while queue:
        node = queue.popleft()
        if node in reachable:
            continue
        reachable.add(node)
        for dep in graph.packages[node].depends_on:
            if dep in names and dep not in reachable:
                queue.append(dep)

    results: dict[str, ReachabilityResult] = {}
    for name in names:
        if name in import_roots:
            info = imports[name]
            results[name] = ReachabilityResult(
                status=Reachability.REACHABLE,
                imported_symbols=sorted(info.symbols),
                entry_paths=sorted(info.files),
            )
        elif name in reachable:
            results[name] = ReachabilityResult(status=Reachability.REACHABLE)
        else:
            results[name] = ReachabilityResult(status=Reachability.UNREACHABLE)
    return results
