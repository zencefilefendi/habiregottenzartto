"""
OpenVEX output — the bridge from reachability to exploitability.

This is the sophisticated payoff of doing reachability: instead of dumping every
CVE on a downstream consumer, we emit a signed-able attestation that says, per
vulnerability, whether the product is actually *affected*. An unreachable
vulnerable dependency becomes ``not_affected`` with the standard justification
``vulnerable_code_not_in_execute_path`` — turning noise into a defensible claim.

Spec: https://github.com/openvex/spec
"""

from __future__ import annotations

import hashlib
import json

from ..core.model import Finding, Reachability


def _status(f: Finding) -> tuple[str, str | None, str | None]:
    """Map reachability -> VEX status (+ justification / action statement)."""
    r = f.reachability
    if r.status == Reachability.UNREACHABLE or r.proven_sink_unreachable:
        return ("not_affected", "vulnerable_code_not_in_execute_path", None)
    if r.status == Reachability.UNKNOWN:
        return ("under_investigation", None, None)
    # reachable
    action = None
    if f.fixed_versions:
        action = f"Upgrade {f.package.name} to {f.fixed_versions[0]} or later."
    return ("affected", None, action)


def render(result) -> str:
    statements = []
    for f in result.vulnerabilities:
        if not f.vuln:
            continue
        status, justification, action = _status(f)
        stmt = {
            "vulnerability": {
                "name": f.vuln.cve or f.vuln.id,
                "@id": f.vuln.id,
                "aliases": f.vuln.aliases,
            },
            "products": [{"@id": str(f.package.purl)}],
            "status": status,
        }
        if justification:
            stmt["justification"] = justification
            stmt["impact_statement"] = (
                "Static import-graph analysis shows the vulnerable distribution "
                "is not imported by first-party code.")
        if action:
            stmt["action_statement"] = action
        statements.append(stmt)

    ts = result.manifest.generated_at
    body = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "",
        "author": f"{result.manifest.tool} {result.manifest.tool_version}",
        "timestamp": ts,
        "version": 1,
        "statements": statements,
    }
    # Content-addressed @id for integrity/dedup.
    canonical = json.dumps(body, sort_keys=True).encode()
    body["@id"] = "https://openvex.dev/docs/habir/" + hashlib.sha256(canonical).hexdigest()[:24]
    return json.dumps(body, indent=2)
