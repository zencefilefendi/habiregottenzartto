"""Structured JSON report — the machine-readable source of truth."""

from __future__ import annotations

import json

from ..core.model import Finding


def _finding_dict(f: Finding) -> dict:
    cvss = f.vuln.best_cvss() if f.vuln else None
    return {
        "kind": f.kind.value,
        "title": f.title,
        "package": {
            "ecosystem": f.package.ecosystem,
            "name": f.package.name,
            "version": str(f.package.version) if f.package.version else None,
            "purl": str(f.package.purl),
            "direct": f.package.direct,
            "confidence": f.package.confidence.name.lower(),
        },
        "advisory": None if not f.vuln else {
            "id": f.vuln.id,
            "aliases": f.vuln.aliases,
            "cve": f.vuln.cve,
            "summary": f.vuln.summary,
            "cvss": None if not cvss else {
                "version": cvss.version, "base_score": cvss.base_score,
                "vector": cvss.vector,
            },
            "fix_commits": f.vuln.fix_commits,
        },
        "fixed_versions": f.fixed_versions,
        "reachability": {
            "status": f.reachability.status.value,
            "analysis": f.reachability.analysis,
            "symbol_hit": f.reachability.symbol_hit,
            "deep": f.reachability.deep,
            "proven_sink_unreachable": f.reachability.proven_sink_unreachable,
            "affected_fn_not_reached": f.reachability.affected_fn_not_reached,
            "call_path": f.reachability.call_path,
            "imported_symbols": f.reachability.imported_symbols,
            "entry_paths": f.reachability.entry_paths,
        },
        "threat_intel": {
            "epss": f.enrichment.epss,
            "epss_percentile": f.enrichment.epss_percentile,
            "kev": f.enrichment.kev,
            "kev_date_added": f.enrichment.kev_date_added,
            "source": f.enrichment.enrichment_source,
        },
        "risk": None if not f.risk else {
            "value": f.risk.value,
            "band": f.risk.band.value,
            "raw_value": f.risk.raw_value,
            "factors": f.risk.factors,
        },
        "evidence": f.evidence.to_dict() if f.evidence else None,
    }


def render(result) -> str:
    m = result.manifest
    doc = {
        "schema": "habiregottenzartto/scan-report/v1",
        "manifest": {
            "tool": m.tool,
            "tool_version": m.tool_version,
            "generated_at": m.generated_at,
            "ecosystem": m.ecosystem,
            "target": m.target,
            "db_snapshot": m.db_snapshot,
            "inputs": m.inputs,
            "counts": m.counts,
            "warnings": m.warnings,
        },
        "findings": [_finding_dict(f) for f in result.findings],
    }
    return json.dumps(doc, indent=2, sort_keys=False)
