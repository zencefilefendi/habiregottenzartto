"""pdm.lock resolver."""

from __future__ import annotations

import tomllib
from pathlib import Path
import re

from ..core.model import ResolvedPackage, VersionConfidence
from ..core.purl import PackageURL, normalize_pypi_name
from ..core.version import InvalidVersion, Version

def _dep_names(dependencies: list[str]) -> list[str]:
    """Extract canonical names from a list of PEP 508 requirement strings."""
    names: list[str] = []
    # Simplified regex for PEP 508 package name parsing
    # Typically: "name>=1.0", "name[extras]", etc.
    req_re = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
    for req in dependencies:
        if isinstance(req, str):
            m = req_re.match(req)
            if m:
                names.append(normalize_pypi_name(m.group(1)))
    return names

def resolve(path: Path) -> list[ResolvedPackage]:
    data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))

    packages: list[ResolvedPackage] = []
    for entry in data.get("package", []):
        raw_name = entry.get("name", "")
        canonical = normalize_pypi_name(raw_name)
        ver_str = entry.get("version")
        try:
            version = Version(ver_str) if ver_str else None
        except InvalidVersion:
            version = None

        # PDM usually stores hashes in `files = [...]` under package
        files = entry.get("files") or []
        hashes = [f.get("hash", "") for f in files if isinstance(f, dict) and f.get("hash")]

        deps = entry.get("dependencies") or []
        depends_on = _dep_names(deps)

        packages.append(ResolvedPackage(
            ecosystem="PyPI",
            name=canonical,
            raw_name=raw_name,
            version=version,
            purl=PackageURL.for_package("pypi", canonical, ver_str),
            direct=False,   # lock files are usually transitively complete
            confidence=VersionConfidence.LOCKFILE,
            hashes=hashes,
            depends_on=depends_on,
            source=str(path),
        ))
    return packages
