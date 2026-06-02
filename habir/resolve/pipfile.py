"""Pipfile.lock resolver — JSON lock with hashes (no per-package edges)."""

from __future__ import annotations

import json
from pathlib import Path

from ..core.model import ResolvedPackage, VersionConfidence
from ..core.purl import PackageURL, normalize_pypi_name
from ..core.version import InvalidVersion, Version


def resolve(path: Path) -> list[ResolvedPackage]:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    packages: list[ResolvedPackage] = []

    for section, is_dev in (("default", False), ("develop", True)):
        for raw_name, spec in (data.get(section, {}) or {}).items():
            canonical = normalize_pypi_name(raw_name)
            ver_str = (spec.get("version", "") or "").lstrip("=")
            try:
                version = Version(ver_str) if ver_str else None
            except InvalidVersion:
                version = None
            hashes = spec.get("hashes", []) or []
            packages.append(ResolvedPackage(
                ecosystem="PyPI",
                name=canonical,
                raw_name=raw_name,
                version=version,
                purl=PackageURL.for_package("pypi", canonical, ver_str or None),
                direct=not is_dev,   # Pipfile.lock flattens transitives; default≈used set
                confidence=VersionConfidence.LOCKFILE,
                hashes=hashes,
                depends_on=[],
                source=str(path),
            ))
    return packages
