"""
The scan pipeline — ties every layer into a single deterministic pass.

    resolve (lockfile-first)  ->  OSV range-match  ->  EPSS/KEV enrich
            ->  import-graph reachability  ->  supply-chain heuristics
            ->  deterministic risk  ->  ranked, evidence-bearing findings
                                       +  reproducibility manifest
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __tool__, __version__
from .analyze import callgraph as cg_mod
from .analyze import reachability as reach_mod
from .analyze import risk as risk_mod
from .analyze import supply_chain as sc_mod
from .analyze.deepreach import DepReachability
from .core.model import (DependencyGraph, Finding, FindingKind, ReachabilityResult,
                         ScanManifest)
from .report import evidence as ev
from .resolve import resolve_target
from .vuln import VulnStore, osv


@dataclass(slots=True)
class ScanResult:
    findings: list[Finding]
    graph: DependencyGraph
    manifest: ScanManifest
    reachability: dict[str, ReachabilityResult] = field(default_factory=dict)

    @property
    def vulnerabilities(self) -> list[Finding]:
        return [f for f in self.findings if f.kind == FindingKind.VULNERABILITY]

    @property
    def supply_chain(self) -> list[Finding]:
        return [f for f in self.findings if f.kind == FindingKind.SUPPLY_CHAIN]


def _sha256_file(path: Path) -> str:
    try:
        h = hashlib.sha256()
        h.update(path.read_bytes())
        return "sha256:" + h.hexdigest()
    except OSError:
        return "sha256:unavailable"


def _discover_deps_paths(source_root: Path, explicit: list[Path] | None) -> list[Path]:
    """Explicit --deps-path roots plus auto-detected venv site-packages / vendor."""
    roots: list[Path] = list(explicit or [])
    # Auto-detect standard local dependency locations (a project venv / PEP 582).
    for venv in (".venv", "venv", "env"):
        roots.extend((source_root / venv).glob("lib/python*/site-packages"))
    pypackages = source_root / "__pypackages__"
    if pypackages.is_dir():
        roots.extend(pypackages.glob("*/lib"))
    seen: list[Path] = []
    for r in roots:
        if r.exists() and r not in seen:
            seen.append(r)
    return seen


def _apply_deep(reach, dist: str, symbols: list[str],
                callgraph, deps: DepReachability) -> None:
    """Descend into a dependency's own call graph to confirm or refute that a
    reached public entry leads to the vulnerable sink."""
    if not deps.active or reach.symbol_hit or not reach.affected_fn_not_reached:
        return
    ext = callgraph.external.get(dist)
    entries = set(ext.reached_symbols) if ext else set()
    sinks = {s.split(".")[-1] for s in symbols}
    if not entries or not sinks:
        return
    result = deps.reaches(dist, entries, sinks)
    if result is None:
        return                                   # no source → keep honest verdict
    ok, internal = result
    reach.analysis = "cross-package"
    if ok:
        reach.symbol_hit = True
        reach.deep = True
        reach.affected_fn_not_reached = False
        entry = internal[0]
        fp_path = (ext.paths.get(entry, []) if ext else []) or [f"{dist}.{entry}"]
        reach.call_path = fp_path + [f"↘ {dist} internals"] + \
            [f"{dist}.{name}" for name in internal[1:]]
    else:
        reach.proven_sink_unreachable = True
        reach.affected_fn_not_reached = False


def scan(target: Path, store: VulnStore,
         deps_roots: list[Path] | None = None) -> ScanResult:
    target = Path(target)
    graph, manifests_used = resolve_target(target)

    source_root = target if target.is_dir() else target.parent
    reach_map = reach_mod.analyze(graph, source_root)
    callgraph = cg_mod.analyze_callgraph(source_root)
    deps = DepReachability(_discover_deps_paths(source_root, deps_roots))

    findings: list[Finding] = []

    # --- known vulnerabilities (OSV) -------------------------------------- #
    for pkg in graph:
        if pkg.version is None:
            continue
        for vuln in store.lookup(pkg.ecosystem, pkg.name):
            hit, fixes, symbols = osv.matches(vuln, pkg)
            if not hit:
                continue

            base_reach = reach_map.get(pkg.name, ReachabilityResult())
            # Function-level refinement: combine package-level reachability with
            # the call graph + this vuln's affected functions (per-finding).
            reach = cg_mod.refine(base_reach, pkg.name, symbols, callgraph)
            # Cross-package refinement: if first-party reaches the package but not
            # the sink, descend into the dependency's own source (when available).
            _apply_deep(reach, pkg.name, symbols, callgraph, deps)
            enrichment = store.enrichment_for(vuln)
            cvss = vuln.best_cvss()
            risk = risk_mod.score_vulnerability(
                cvss_base=cvss.base_score if cvss else None,
                enrichment=enrichment, reachability=reach, confidence=pkg.confidence,
            )
            finding = Finding(
                kind=FindingKind.VULNERABILITY,
                package=pkg,
                title=vuln.summary or vuln.id,
                vuln=vuln,
                fixed_versions=fixes,
                reachability=reach,
                enrichment=enrichment,
                risk=risk,
            )
            finding.evidence = ev.for_vulnerability(pkg, vuln, fixes, reach,
                                                    enrichment, risk)
            findings.append(finding)

    # --- supply-chain heuristics ------------------------------------------ #
    direct_pkgs = [p for p in graph if p.direct]
    for signal in sc_mod.analyze(direct_pkgs):
        reach = reach_map.get(signal.package.name, ReachabilityResult())
        risk = risk_mod.score_supply_chain(
            severity=signal.severity, reachability=reach,
            confidence=signal.package.confidence,
        )
        finding = Finding(
            kind=FindingKind.SUPPLY_CHAIN,
            package=signal.package,
            title=f"Possible {signal.kind}: {signal.package.name} ≈ {signal.nearest}",
            reachability=reach,
            risk=risk,
        )
        finding.evidence = ev.for_supply_chain(finding, signal.detail,
                                               f"typosquat distance · {signal.kind}")
        findings.append(finding)

    findings.sort(key=lambda f: (f.risk.value if f.risk else 0.0), reverse=True)

    manifest = ScanManifest(
        tool=__tool__,
        tool_version=__version__,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        ecosystem=graph.ecosystem,
        target=str(target),
        db_snapshot=store.snapshot_info(),
        inputs=[{"path": str(p), "sha256": _sha256_file(p)} for p in manifests_used],
        counts={
            "packages": len(graph),
            "direct": len(graph.roots),
            "vulnerabilities": sum(1 for f in findings
                                   if f.kind == FindingKind.VULNERABILITY),
            "supply_chain": sum(1 for f in findings
                                if f.kind == FindingKind.SUPPLY_CHAIN),
            "reachable_findings": sum(
                1 for f in findings
                if f.reachability.status.value == "reachable"),
        },
        warnings=list(graph.warnings),
    )
    return ScanResult(findings=findings, graph=graph, manifest=manifest,
                      reachability=reach_map)
