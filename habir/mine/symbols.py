"""
Symbol miner — turns a fixing-commit diff into the set of functions it patched.

This is the data moat: the bottleneck in precise SCA is the CVE → affected-symbol
mapping, which Snyk/Endor curate by hand. We derive it automatically and
deterministically from the patch itself.

Two strategies, in order of precision:
  1. AST line-span (when the post-image source is available, e.g. from a local
     repo / `git show`): the changed line numbers are mapped to the innermost
     enclosing def/class, yielding fully-qualified names (Class.method).
  2. git hunk-header heuristic (source-free, works on a bare patch): git records
     the enclosing `def`/`class` in the `@@ ... @@` section context for Python.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from .diff import FileDiff, parse_unified_diff

__all__ = ["MineResult", "mine_patch", "symbols_from_source",
           "symbols_from_hunk_headers"]

_DEF_RE = re.compile(r"\b(?:def|class)\s+(\w+)")


def _def_spans(tree: ast.AST) -> list[tuple[int, int, str, str]]:
    """(start_line, end_line, qualified_name, kind) for every def/class."""
    spans: list[tuple[int, int, str, str]] = []

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qual = prefix + child.name
                start = child.lineno
                if child.decorator_list:
                    start = min(start, min(d.lineno for d in child.decorator_list))
                end = getattr(child, "end_lineno", child.lineno)
                spans.append((start, end, qual, type(child).__name__))
                visit(child, qual + ".")
            else:
                visit(child, prefix)

    visit(tree, "")
    return spans


def symbols_from_source(source: str, changed_lines: set[int]) -> set[str]:
    """Map changed line numbers to the innermost enclosing qualified symbol."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return set()
    spans = _def_spans(tree)
    out: set[str] = set()
    for ln in changed_lines:
        containing = [(end - start, qual) for start, end, qual, _ in spans
                      if start <= ln <= end]
        if containing:
            containing.sort()                # smallest span = innermost def
            out.add(containing[0][1])
    return out


def symbols_from_hunk_headers(file_diff: FileDiff) -> set[str]:
    """Extract def/class names git stored in each hunk's section context."""
    out: set[str] = set()
    for hunk in file_diff.hunks:
        m = _DEF_RE.search(hunk.section)
        if m:
            out.add(m.group(1))
    return out


@dataclass(slots=True)
class MineResult:
    short: list[str] = field(default_factory=list)        # leaf symbol names
    qualified: list[str] = field(default_factory=list)    # Class.method form
    per_file: dict[str, list[str]] = field(default_factory=dict)
    method: list[str] = field(default_factory=list)       # which strategies fired

    def is_empty(self) -> bool:
        return not self.short


def mine_patch(patch_text: str, source_provider=None) -> MineResult:
    """Mine affected symbols from a unified-diff patch.

    `source_provider(path) -> str | None` optionally returns the post-image
    source of a file (enables the precise AST strategy). Without it, the miner
    falls back to git hunk headers.
    """
    files = parse_unified_diff(patch_text)
    qualified: set[str] = set()
    per_file: dict[str, list[str]] = {}
    methods: set[str] = set()

    for fd in files:
        if not fd.is_python:
            continue
        path = fd.new_path or fd.old_path or "?"
        source = source_provider(path) if source_provider else None

        syms: set[str] = set()
        if source:
            syms = symbols_from_source(source, fd.changed_new_lines())
            if syms:
                methods.add("ast")
        if not syms:
            syms = symbols_from_hunk_headers(fd)
            if syms:
                methods.add("hunk-header")

        if syms:
            qualified |= syms
            per_file[path] = sorted(syms)

    short = sorted({q.split(".")[-1] for q in qualified})
    return MineResult(short=short, qualified=sorted(qualified),
                      per_file=per_file, method=sorted(methods))
