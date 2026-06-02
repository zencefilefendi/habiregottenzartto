"""
SARIF 2.1.0 output — first-class CI / GitHub Code Scanning integration.

Risk band maps to SARIF level; the full deterministic risk, EPSS, KEV and
reachability ride along in result properties so downstream policy gates can
filter on *reachable + actively-exploited* instead of raw CVE counts.
"""

from __future__ import annotations

import json
import os

from .. import __tool__, __version__
from ..core.model import Finding, RiskBand

_LEVEL = {
    RiskBand.CRITICAL: "error",
    RiskBand.HIGH: "error",
    RiskBand.MEDIUM: "warning",
    RiskBand.LOW: "note",
    RiskBand.INFO: "note",
}


def _rule_id(f: Finding) -> str:
    return f.vuln.id if f.vuln else f"HABIR-{f.kind.value.upper()}"


def _rules(findings: list[Finding]) -> list[dict]:
    seen: dict[str, dict] = {}
    for f in findings:
        rid = _rule_id(f)
        if rid in seen:
            continue
        help_uri = ""
        if f.vuln and f.vuln.references:
            help_uri = f.vuln.references[0].get("url", "")
        seen[rid] = {
            "id": rid,
            "name": rid.replace("-", ""),
            "shortDescription": {"text": (f.title or rid)[:120]},
            "fullDescription": {"text": f.vuln.details[:1000] if f.vuln else f.title},
            "helpUri": help_uri,
            "properties": {
                "tags": ["security", "supply-chain", f.kind.value],
                "cve": f.vuln.cve if f.vuln else None,
            },
        }
    return list(seen.values())


def _result(f: Finding) -> dict:
    msg = (f"{f.package.name}@{f.package.version}: {f.title} "
           f"[risk {f.risk.value if f.risk else 0} {f.risk.band.value if f.risk else 'INFO'}, "
           f"reachability {f.reachability.status.value}]")
    return {
        "ruleId": _rule_id(f),
        "level": _LEVEL[f.risk.band] if f.risk else "note",
        "message": {"text": msg},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": _uri(f.package.source)},
            }
        }],
        "partialFingerprints": {
            "habir/v1": f"{_rule_id(f)}::{f.package.purl}",
        },
        "properties": {
            "security-severity": str(_security_severity(f)),
            "risk": f.risk.value if f.risk else 0,
            "riskBand": f.risk.band.value if f.risk else "INFO",
            "reachability": f.reachability.status.value,
            "symbolHit": f.reachability.symbol_hit,
            "epss": f.enrichment.epss,
            "kev": f.enrichment.kev,
            "confidence": f.package.confidence.name.lower(),
            "fixedVersions": f.fixed_versions,
            "purl": str(f.package.purl),
        },
    }


def _security_severity(f: Finding) -> float:
    # GitHub expects a 0-10 scale; reuse CVSS when present, else risk/10.
    cvss = f.vuln.best_cvss() if f.vuln else None
    if cvss and cvss.base_score:
        return round(cvss.base_score, 1)
    return round((f.risk.value if f.risk else 0) / 10.0, 1)


def _uri(path: str) -> str:
    return os.path.basename(path) if path else "manifest"


def render(result) -> str:
    findings = result.findings
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": __tool__,
                    "version": __version__,
                    "informationUri": "https://github.com/zencefilefendi/habiregottenzartto",
                    "rules": _rules(findings),
                }
            },
            "results": [_result(f) for f in findings],
            "properties": {
                "dbSnapshot": result.manifest.db_snapshot,
                "generatedAt": result.manifest.generated_at,
            },
        }],
    }
    return json.dumps(doc, indent=2)
