"""
Behavioral analysis of dependency source code.

Scans a dependency's source tree (like __init__.py, setup.py) for known
malicious patterns: e.g. eval, exec, base64 decoding followed by execution,
or direct network connections in top-level module scope.
"""

from __future__ import annotations

import ast
from pathlib import Path
from ..core.model import ResolvedPackage

class BehaviorVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings: list[str] = []

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name):
            name = node.func.id
            if name in ("eval", "exec"):
                self.findings.append(f"usage of {name}()")
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            base = node.func.value.id
            attr = node.func.attr
            if base == "base64" and attr in ("b64decode", "b32decode", "b16decode"):
                self.findings.append("base64 decoding (possible payload obfuscation)")
            elif base in ("urllib", "requests", "socket") and attr in (
                "urlopen", "get", "post", "connect"
            ):
                self.findings.append(f"network activity ({base}.{attr})")
            elif base == "os" and attr == "system":
                self.findings.append("os.system call")
            elif base == "subprocess" and attr in ("Popen", "run", "call", "check_output"):
                self.findings.append(f"subprocess execution ({base}.{attr})")
        self.generic_visit(node)

def analyze_package_behavior(pkg: ResolvedPackage, deps_roots: list[Path]) -> list[str]:
    """Find the package source in deps_roots and run AST behavioral analysis."""
    findings: list[str] = []

    # Try to find the package directory
    pkg_dir = None
    for root in deps_roots:
        # standard site-packages/pkg_name
        cand = root / pkg.name.replace("-", "_")
        if cand.is_dir():
            pkg_dir = cand
            break
        # handle single file modules
        cand_file = root / f"{pkg.name.replace('-', '_')}.py"
        if cand_file.is_file():
            pkg_dir = cand_file
            break

    if not pkg_dir:
        return findings

    files_to_scan = []
    if pkg_dir.is_file():
        files_to_scan.append(pkg_dir)
    else:
        for p in pkg_dir.rglob("*.py"):
            if p.is_file():
                files_to_scan.append(p)

    for py_file in files_to_scan:
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8", errors="replace"))
            visitor = BehaviorVisitor()
            visitor.visit(tree)
            if visitor.findings:
                # Deduplicate findings per file
                unique_findings = sorted(set(visitor.findings))
                findings.extend([f"{f} in {py_file.name}" for f in unique_findings])
        except Exception:
            continue

    return sorted(set(findings))
