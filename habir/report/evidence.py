"""
Evidence DAG construction — makes every verdict auditable.

A finding's risk node is the root; under it hang the independent claims that
produced it (which version, why it matched, whether it's reachable, what threat
intel says). This is the deterministic, in-terminal answer to "why did you flag
this?" — the explainability layer, shipped in v0.1 rather than deferred.
"""

from __future__ import annotations

import os

from ..core.model import (Enrichment, EvidenceNode, Finding, ReachabilityResult,
                          Reachability, ResolvedPackage, RiskScore, Vulnerability)


def _version_node(pkg: ResolvedPackage) -> EvidenceNode:
    ver = str(pkg.version) if pkg.version else "unresolved"
    src = os.path.basename(pkg.source) if pkg.source else "n/a"
    return EvidenceNode(
        kind="version",
        claim=f"resolved {pkg.name}=={ver} ({'direct' if pkg.direct else 'transitive'})",
        source=f"{src} · {pkg.confidence.name.lower()}",
        confidence=float(pkg.confidence),
    )


def _match_node(vuln: Vulnerability, fixes: list[str]) -> EvidenceNode:
    fix = f"; fixed in {', '.join(fixes)}" if fixes else "; no fixed version published"
    return EvidenceNode(
        kind="match",
        claim=f"{vuln.id} affected-range contains installed version{fix}",
        source="OSV range-match (PEP 440 ordered)",
        confidence=1.0,
    )


def _reach_node(reach: ReachabilityResult) -> EvidenceNode:
    source = (f"{reach.analysis} analysis" if reach.analysis != "package-level"
              else "import-graph closure")
    if reach.status == Reachability.REACHABLE:
        if getattr(reach, "dynamic", False):
            detail = ("runtime execution confirms vulnerable function is called: " +
                      ", ".join(reach.call_path))
            conf = 1.00
        elif reach.symbol_hit and reach.deep and reach.call_path:
            detail = ("cross-package path reaches the vulnerable function through "
                      "dependency internals: " + " → ".join(reach.call_path))
            conf = 0.98
        elif reach.symbol_hit and reach.call_path:
            detail = "call path reaches affected function: " + " → ".join(reach.call_path)
            conf = 0.97
        elif reach.symbol_hit:
            detail = f"affected symbol(s) reached: {', '.join(reach.imported_symbols[:5])}"
            conf = 0.9
        elif reach.proven_sink_unreachable:
            detail = ("dependency call graph proves the public API used does not "
                      "reach the vulnerable function (not exploitable as used)")
            conf = 0.9
        elif reach.affected_fn_not_reached:
            detail = ("package is called, but the first-party call graph never "
                      "reaches the vulnerable function (give --deps-path to confirm)")
            conf = 0.85
        elif reach.entry_paths:
            detail = f"imported by first-party code ({len(reach.entry_paths)} entry file(s))"
            conf = 0.8
        else:
            detail = "reachable via the dependency graph (transitive)"
            conf = 0.75
    elif reach.status == Reachability.UNREACHABLE:
        detail = "present in graph but never imported"
        conf = 0.8
    else:
        detail = "no analyzable first-party source / dynamic import"
        conf = 0.5
    return EvidenceNode(kind="reachability", claim=detail, source=source,
                        confidence=conf)


def _enrichment_node(enr: Enrichment) -> EvidenceNode:
    bits = []
    if enr.epss is not None:
        bits.append(f"EPSS {enr.epss:.0%} (p{(enr.epss_percentile or 0)*100:.0f})")
    if enr.kev:
        bits.append(f"CISA KEV — actively exploited (added {enr.kev_date_added})")
    if not bits:
        bits.append("no threat-intel enrichment")
    return EvidenceNode(kind="enrichment", claim="; ".join(bits),
                        source=enr.enrichment_source, confidence=1.0)


def for_vulnerability(pkg: ResolvedPackage, vuln: Vulnerability, fixes: list[str],
                      reach: ReachabilityResult, enr: Enrichment,
                      risk: RiskScore) -> EvidenceNode:
    root = EvidenceNode(
        kind="risk",
        claim=f"risk {risk.value} ({risk.band.value}) — raw {risk.raw_value} "
              f"before confidence discount",
        source="deterministic risk engine",
        confidence=1.0,
        children=[_version_node(pkg), _match_node(vuln, fixes),
                  _reach_node(reach), _enrichment_node(enr)],
    )
    return root


def for_supply_chain(finding: Finding, detail: str, source: str) -> EvidenceNode:
    risk = finding.risk
    children = [_version_node(finding.package),
                EvidenceNode(kind="heuristic", claim=detail, source=source,
                             confidence=0.9),
                _reach_node(finding.reachability)]
    return EvidenceNode(
        kind="risk",
        claim=f"risk {risk.value if risk else 0} "
              f"({risk.band.value if risk else 'INFO'}) — supply-chain heuristic",
        source="deterministic risk engine",
        confidence=1.0,
        children=children,
    )
