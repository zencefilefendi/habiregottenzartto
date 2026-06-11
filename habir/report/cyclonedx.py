"""
CycloneDX 1.5 SBOM formatter.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..engine import ScanResult


def render(result: "ScanResult") -> str:
    """Render a ScanResult as a CycloneDX 1.5 JSON SBOM."""

    components = []
    dependencies = []

    # Components
    for pkg in result.graph:
        comp = {
            "type": "library",
            "name": pkg.name,
            "version": str(pkg.version) if pkg.version else "unknown",
            "purl": pkg.coordinate,
        }
        if pkg.hashes:
            # Assume first hash is sha256 for simplicity in formatting,
            # or just emit the string if we don't know the alg.
            alg = "SHA-256"
            hval = pkg.hashes[0]
            if ":" in hval:
                parts = hval.split(":", 1)
                if parts[0] == "sha256":
                    alg = "SHA-256"
                elif parts[0] == "sha512":
                    alg = "SHA-512"
                hval = parts[1]
            comp["hashes"] = [{"alg": alg, "content": hval}]
        components.append(comp)

        deps = []
        for d in pkg.depends_on:
            dpkg = result.graph.packages.get(d)
            if dpkg:
                deps.append({"ref": dpkg.coordinate})
        dependencies.append({
            "ref": pkg.coordinate,
            "dependsOn": [d["ref"] for d in deps]
        })

    # Add root dependencies
    root_refs = []
    for r in result.graph.roots:
        rpkg = result.graph.packages.get(r)
        if rpkg:
            root_refs.append(rpkg.coordinate)

    dependencies.append({
        "ref": result.manifest.target,
        "dependsOn": root_refs
    })

    # Vulnerabilities
    vulnerabilities = []
    for f in result.vulnerabilities:
        vuln_obj = {
            "id": f.identifier,
            "source": {"name": "OSV"},
            "affects": [{"ref": f.package.coordinate}],
        }
        if f.vuln:
            cvss = f.vuln.best_cvss()
            if cvss:
                vuln_obj["ratings"] = [
                    {
                        "source": {"name": "NVD" if "CVE" in f.identifier else "OSV"},
                        "score": cvss.base_score,
                        "severity": f.risk.band.name.lower() if f.risk else "unknown",
                        "method": f"CVSSv{cvss.version}",
                        "vector": cvss.vector,
                    }
                ]

        # Mapping Reachability to CycloneDX Analysis
        # CycloneDX states: exploitable, in_triage, false_positive, not_affected
        state = "in_triage"
        if f.reachability.status.value == "reachable":
            state = "exploitable"
            if f.reachability.symbol_hit:
                detail = "Vulnerable function is directly invoked."
            else:
                detail = "Package is imported but vulnerable function invocation not proven."
        elif f.reachability.status.value == "unreachable" or f.reachability.proven_sink_unreachable:
            state = "not_affected"
            detail = "Package is never imported or vulnerable function is unreachable."
        else:
            detail = "Reachability analysis could not conclusively determine exposure."

        vuln_obj["analysis"] = {
            "state": state,
            "detail": detail
        }

        if f.vuln and f.vuln.summary:
            vuln_obj["description"] = f.vuln.summary

        vulnerabilities.append(vuln_obj)

    raw_hash = str(result.manifest.db_snapshot.get("content_hash", "unknown"))
    clean_hash = raw_hash.replace("sha256:", "")[:32].ljust(32, "0")

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{clean_hash}",
        "version": 1,
        "metadata": {
            "timestamp": result.manifest.generated_at,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "author": "Zencefil Efendi",
                        "name": result.manifest.tool,
                        "version": result.manifest.tool_version
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": result.manifest.target,
            }
        },
        "components": components,
        "dependencies": dependencies,
        "vulnerabilities": vulnerabilities
    }

    return json.dumps(doc, indent=2)
