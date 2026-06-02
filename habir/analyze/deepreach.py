"""
Cross-package (dependency-internal) reachability.

First-party reachability proves your code reaches a dependency's *public* symbol
(e.g. ``requests.get``). It cannot, by itself, tell whether that public entry
leads to the *internal* function a CVE actually patched (e.g. ``rebuild_auth``).
This module closes that gap when the dependency's source is available (an
installed venv, a vendored tree, or ``--deps-path``): it builds the dependency's
own call graph and asks "does the entry you call reach the vulnerable sink?"

Direction of conservatism:
  * The intra-package graph is **name-based** (short function names), which
    *over-approximates* forward edges. For an "is it reachable?" question that is
    the safe direction — we will not wrongly clear a vulnerability.
  * Therefore a *positive* (entry → sink path found) is reported as reachable,
    while a *negative* (even the over-approximate graph cannot connect them) is
    strong evidence the sink is genuinely not on the path → a defensible
    ``not_affected``.

When no source is found we return ``None`` and the engine keeps the honest
first-party-only verdict.
"""

from __future__ import annotations

import ast
import functools
from collections import deque
from pathlib import Path

from ..data import import_map

_SKIP_DIRS = {"__pycache__", "tests", "test", ".dist-info", ".egg-info"}


class DepReachability:
    """Locates dependency sources and answers entry → sink reachability."""

    def __init__(self, roots: list[Path]) -> None:
        self.roots = [Path(r) for r in roots if Path(r).exists()]
        self._inverse = _inverse_import_map()
        self._graph_cache: dict[Path, dict[str, set[str]]] = {}

    @property
    def active(self) -> bool:
        return bool(self.roots)

    def _candidates(self, dist: str) -> list[str]:
        names = list(self._inverse.get(dist, []))
        names += [dist, dist.replace("-", "_")]
        seen: list[str] = []
        for n in names:
            if n not in seen:
                seen.append(n)
        return seen

    @functools.lru_cache(maxsize=512)
    def locate(self, dist: str) -> Path | None:
        for root in self.roots:
            for name in self._candidates(dist):
                pkg = root / name / "__init__.py"
                if pkg.is_file():
                    return pkg.parent
                module = root / f"{name}.py"
                if module.is_file():
                    return module
        return None

    def _graph(self, source: Path) -> dict[str, set[str]]:
        cached = self._graph_cache.get(source)
        if cached is None:
            cached = _build_name_callgraph(source)
            self._graph_cache[source] = cached
        return cached

    def reaches(self, dist: str, entries: set[str],
                sinks: set[str]) -> tuple[bool, list[str]] | None:
        """None → no source available. Else (reachable, name-path)."""
        source = self.locate(dist)
        if source is None:
            return None
        return _bfs(self._graph(source), entries, sinks)


@functools.lru_cache(maxsize=1)
def _inverse_import_map() -> dict[str, list[str]]:
    inv: dict[str, list[str]] = {}
    for import_name, dist in import_map().items():
        inv.setdefault(dist, []).append(import_name)
    return inv


def _iter_py(source: Path):
    if source.is_file():
        yield source
        return
    for p in source.rglob("*.py"):
        if not any(part in _SKIP_DIRS for part in p.parts):
            yield p


def _build_name_callgraph(source: Path) -> dict[str, set[str]]:
    """short function name → set of short names it calls (over-approximate)."""
    graph: dict[str, set[str]] = {}
    for py in _iter_py(source):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            callees = graph.setdefault(node.name, set())
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    name = _called_name(inner)
                    if name and name != node.name:
                        callees.add(name)
    return graph


def _called_name(call: ast.Call) -> str | None:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _bfs(graph: dict[str, set[str]], entries: set[str],
         sinks: set[str]) -> tuple[bool, list[str]]:
    if entries & sinks:                       # the entry itself is the sink
        hit = sorted(entries & sinks)[0]
        return (True, [hit])
    pred: dict[str, str] = {}
    queue: deque[str] = deque()
    seen: set[str] = set()
    for e in entries:
        if e in graph:
            queue.append(e)
            seen.add(e)
    while queue:
        node = queue.popleft()
        for callee in sorted(graph.get(node, ())):
            if callee in seen:
                continue
            pred[callee] = node
            if callee in sinks:
                return (True, _reconstruct(pred, callee))
            seen.add(callee)
            queue.append(callee)
    return (False, [])


def _reconstruct(pred: dict[str, str], sink: str) -> list[str]:
    path = [sink]
    while path[-1] in pred:
        path.append(pred[path[-1]])
    return list(reversed(path))
