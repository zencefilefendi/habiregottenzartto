"""
Function-level reachability — a conservative first-party call graph.

Package-level reachability answers "is this dependency imported?". This answers
the harder, more valuable question: *"starting from where my program actually
begins executing, does control flow reach a call to the vulnerable function?"*

That is the difference between "you use requests" and "you call the specific
redirect-handling function that leaks credentials." It is also, deliberately,
**honest about its limits**: Python dispatch is dynamic, so when a call target
cannot be resolved we record nothing rather than guess — we never fabricate an
"unreachable." Unresolved dynamism degrades gracefully to the package-level
signal.

Model:
  * entrypoints = module top-level code + ``if __name__ == '__main__'`` blocks
    (application mode). ``lib_mode`` additionally seeds every public function,
    for libraries whose callers we cannot see.
  * edges = resolved first-party calls (same-module names, ``self.method``,
    first-party imports).
  * result = the set of external ``(dist, symbol)`` calls reachable from any
    entrypoint, each with a reconstructable call path for evidence.
"""

from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from ..core.model import Reachability, ReachabilityResult
from ..core.purl import normalize_pypi_name
from ..data import import_map

_VENDOR = {".venv", "venv", "env", ".env", "site-packages", "node_modules", ".git",
           "__pycache__", "build", "dist", ".tox", ".eggs", ".mypy_cache",
           ".pytest_cache", ".habir", "vendor", "__pypackages__"}


# --------------------------------------------------------------------------- #
# bindings & call references
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class _Binding:
    kind: str                  # "mod" | "sym" | "fpmod" | "fpsym"
    dist: str | None = None    # external distribution (mod/sym)
    symbol: str | None = None  # external symbol (sym)
    fp_module: str | None = None  # first-party module (fpmod/fpsym)
    fp_name: str | None = None    # first-party symbol (fpsym)


@dataclass(slots=True)
class _Func:
    qualname: str
    module: str
    cls: str | None
    external: set[tuple[str, str]] = field(default_factory=set)  # (dist, symbol)
    fp_targets: set[str] = field(default_factory=set)            # resolved qualnames
    local_aliases: dict[str, tuple[str, str, str | None]] = field(default_factory=dict)


@dataclass(slots=True)
class ReachInfo:
    reached_symbols: set[str] = field(default_factory=set)
    paths: dict[str, list[str]] = field(default_factory=dict)    # symbol → call path


@dataclass(slots=True)
class CallGraphResult:
    analyzed: bool                       # was any first-party source parsed?
    external: dict[str, ReachInfo]       # dist → reach info (first-party-direct calls)

    def directly_calls(self, dist: str) -> bool:
        return dist in self.external


def _module_name(path: Path, root: Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    parts = [p for p in rel.parts if p != "__init__"]
    return ".".join(parts) if parts else rel.stem


def _iter_files(root: Path):
    if root.is_file():
        root = root.parent
    for p in root.rglob("*.py"):
        if not any(part in _VENDOR for part in p.parts):
            yield p


def _resolve_imports(tree: ast.AST, module: str, firstparty_tops: set[str],
                     imap: dict[str, str]) -> dict[str, _Binding]:
    bindings: dict[str, _Binding] = {}
    pkg_parts = module.split(".")
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                bound = alias.asname or top
                if top in firstparty_tops:
                    bindings[bound] = _Binding("fpmod", fp_module=alias.name)
                else:
                    dist = imap.get(top.lower(), normalize_pypi_name(top))
                    bindings[bound] = _Binding("mod", dist=dist)
        elif isinstance(node, ast.ImportFrom):
            if node.level:                       # relative → first-party
                base = pkg_parts[: len(pkg_parts) - node.level]
                base_mod = ".".join(base + (node.module.split(".") if node.module else []))
                for alias in node.names:
                    bindings[alias.asname or alias.name] = _Binding(
                        "fpsym", fp_module=base_mod, fp_name=alias.name)
            elif node.module:
                top = node.module.split(".")[0]
                if top in firstparty_tops:
                    for alias in node.names:
                        bindings[alias.asname or alias.name] = _Binding(
                            "fpsym", fp_module=node.module, fp_name=alias.name)
                else:
                    dist = imap.get(top.lower(), normalize_pypi_name(top))
                    for alias in node.names:
                        bindings[alias.asname or alias.name] = _Binding(
                            "sym", dist=dist, symbol=alias.name)
    return bindings


def _call_name(call: ast.Call):
    """Classify a call's target → ('name', x) | ('attr', base, attr) | None."""
    f = call.func
    if isinstance(f, ast.Name):
        return ("name", f.id, None)
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
        return ("attr", f.value.id, f.attr)
    return None


class _Collector:
    """Walks one module, attributing calls to their enclosing function/toplevel."""

    def __init__(self, module: str, bindings: dict[str, _Binding], imap: dict[str, str]) -> None:
        self.module = module
        self.bindings = bindings
        self.imap = imap
        self.funcs: dict[str, _Func] = {}
        self.toplevel = _Func(qualname=f"{module}:<toplevel>", module=module, cls=None)
        self.public: list[str] = []

    def run(self, tree: ast.AST) -> None:
        self._walk(tree, owner=self.toplevel, cls=None, prefix=self.module)

    def _walk(self, node: ast.AST, owner: _Func, cls: str | None, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{prefix}.{child.name}"
                fn = _Func(qualname=qual, module=self.module, cls=cls)
                self.funcs[qual] = fn
                if cls is None and not child.name.startswith("_"):
                    self.public.append(qual)
                # nested defs keep the same enclosing class context
                self._walk(child, owner=fn, cls=cls, prefix=qual)
            elif isinstance(child, ast.ClassDef):
                self._walk(child, owner=owner, cls=child.name,
                           prefix=f"{prefix}.{child.name}")
            else:
                if isinstance(child, ast.Assign):
                    if len(child.targets) == 1 and isinstance(child.targets[0], ast.Name):
                        alias_name = child.targets[0].id
                        if isinstance(child.value, ast.Name):
                            owner.local_aliases[alias_name] = ("name", child.value.id, None)
                        elif isinstance(child.value, ast.Attribute) and isinstance(
                            child.value.value, ast.Name
                        ):
                            owner.local_aliases[alias_name] = (
                                "attr", child.value.value.id, child.value.attr
                            )
                elif isinstance(child, ast.Call):
                    self._record_call(child, owner, cls)
                self._walk(child, owner=owner, cls=cls, prefix=prefix)

    def _record_call(self, call: ast.Call, owner: _Func, cls: str | None) -> None:
        ref = _call_name(call)
        if ref is None:
            return

        # Dynamic imports
        if (ref[0] == "name" and ref[1] == "__import__") or (
            ref[0] == "attr" and ref[2] == "import_module"
        ):
            if call.args and isinstance(call.args[0], ast.Constant) and isinstance(
                call.args[0].value, str
            ):
                top = call.args[0].value.split(".")[0]
                dist = self.imap.get(top.lower(), normalize_pypi_name(top))
                owner.external.add((dist, "<module>"))

        # Resolve local aliases (e.g. req = requests.get)
        kind = ref[0]
        if kind == "name" and ref[1] in owner.local_aliases:
            ref = owner.local_aliases[ref[1]]
            kind = ref[0]

        if kind == "name":
            name = ref[1]
            b = self.bindings.get(name)
            if b and b.kind == "sym":
                if b.dist and b.symbol:
                    owner.external.add((b.dist, b.symbol))
            elif b and b.kind == "fpsym":
                owner.fp_targets.add(f"{b.fp_module}.{b.fp_name}")
            else:
                # same-module function?
                owner.fp_targets.add(f"{self.module}.{name}")
        elif kind == "attr":
            base, attr = ref[1], ref[2]
            if base == "self" and cls is not None:
                owner.fp_targets.add(f"{self.module}.{cls}.{attr}")
                return
            b = self.bindings.get(base)
            if b and b.kind == "mod":
                if b.dist and attr:
                    owner.external.add((b.dist, attr))
            elif b and b.kind == "fpmod":
                owner.fp_targets.add(f"{b.fp_module}.{attr}")


def analyze_callgraph(source_root: Path, *, lib_mode: bool = False) -> CallGraphResult:
    root = source_root if source_root.is_dir() else source_root.parent
    files = sorted(_iter_files(root))          # deterministic traversal order
    if not files:
        return CallGraphResult(analyzed=False, external={})

    # Top-level importable names under the root (a package dir or a bare module).
    firstparty_tops = {p.relative_to(root).parts[0].removesuffix(".py")
                       for p in files}

    imap = import_map()
    all_funcs: dict[str, _Func] = {}
    toplevels: list[_Func] = []
    publics: list[str] = []
    parsed_any = False

    for f in files:
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError):
            continue
        parsed_any = True
        module = _module_name(f, root)
        bindings = _resolve_imports(tree, module, firstparty_tops, imap)
        col = _Collector(module, bindings, imap)
        col.run(tree)
        all_funcs.update(col.funcs)
        toplevels.append(col.toplevel)
        publics.extend(col.public)

    if not parsed_any:
        return CallGraphResult(analyzed=False, external={})

    # Entrypoints: every module's top-level code (+ public funcs in lib mode).
    roots = list(toplevels)
    index = {fn.qualname: fn for fn in all_funcs.values()}
    for tl in toplevels:
        index[tl.qualname] = tl
    if lib_mode:
        roots += [index[q] for q in publics if q in index]

    # BFS over first-party edges, remembering the path for evidence.
    external: dict[str, ReachInfo] = {}
    visited: set[str] = set()
    queue: deque[tuple[_Func, list[str]]] = deque(
        (r, [r.qualname]) for r in roots)

    while queue:
        fn, path = queue.popleft()
        if fn.qualname in visited:
            continue
        visited.add(fn.qualname)

        for dist, symbol in fn.external:
            info = external.setdefault(dist, ReachInfo())
            if symbol not in info.reached_symbols:
                info.reached_symbols.add(symbol)
                info.paths[symbol] = path + [f"{dist}.{symbol}"]

        for target in fn.fp_targets:
            tgt = index.get(target)
            if tgt and tgt.qualname not in visited:
                queue.append((tgt, path + [target]))

    return CallGraphResult(analyzed=True, external=external)


def refine(base: ReachabilityResult, dist: str, affected_symbols: list[str],
           cg: CallGraphResult) -> ReachabilityResult:
    """Combine the package-level result with the call graph + a vuln's affected
    functions into a precise per-finding reachability verdict."""
    affected = {s.split(".")[-1] for s in affected_symbols}
    out = ReachabilityResult(
        status=base.status,
        imported_symbols=list(base.imported_symbols),
        entry_paths=list(base.entry_paths),
        analysis="function-level" if cg.analyzed else "package-level",
    )

    # Unreachable / unknown packages need no function-level refinement.
    if base.status != Reachability.REACHABLE or not cg.analyzed:
        if affected and base.imported_symbols:        # package-level fallback
            out.symbol_hit = bool(affected & set(base.imported_symbols))
        return out

    info = cg.external.get(dist)
    if info is not None and affected:
        reached = info.reached_symbols & affected
        if reached:
            sym = sorted(reached)[0]
            out.symbol_hit = True
            out.call_path = info.paths.get(sym, [])
            out.imported_symbols = sorted(set(out.imported_symbols) | reached)
        elif info.reached_symbols:
            # First-party code calls this package, but never the vulnerable
            # function — the exploit's sink is not on a direct call path.
            out.affected_fn_not_reached = True
    elif affected and base.imported_symbols:
        out.symbol_hit = bool(affected & set(base.imported_symbols))
    return out
