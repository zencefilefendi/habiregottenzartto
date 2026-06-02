"""uv.lock resolver — the modern, fast Rust resolver's lock format (TOML)."""

from __future__ import annotations

import tomllib
from pathlib import Path

from ..core.model import ResolvedPackage, VersionConfidence
from ..core.purl import PackageURL, normalize_pypi_name
from ..core.version import InvalidVersion, Version


def _edges(entry: dict) -> list[str]:
    # uv.lock dependencies are a list of tables: [[package.dependencies]] name = "..."
    out: list[str] = []
    for dep in entry.get("dependencies", []) or []:
        if isinstance(dep, dict) and dep.get("name"):
            out.append(normalize_pypi_name(dep["name"]))
    return out


def _hashes(entry: dict) -> list[str]:
    out: list[str] = []
    sdist = entry.get("sdist")
    if isinstance(sdist, dict) and sdist.get("hash"):
        out.append(sdist["hash"])
    for wheel in entry.get("wheels", []) or []:
        if isinstance(wheel, dict) and wheel.get("hash"):
            out.append(wheel["hash"])
    return out


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
        # A virtual/root project entry has source {virtual|editable}; not a dist.
        source = entry.get("source", {}) or {}
        if "virtual" in source or "editable" in source:
            continue
        packages.append(ResolvedPackage(
            ecosystem="PyPI",
            name=canonical,
            raw_name=raw_name,
            version=version,
            purl=PackageURL.for_package("pypi", canonical, ver_str),
            direct=False,
            confidence=VersionConfidence.LOCKFILE,
            hashes=_hashes(entry),
            depends_on=_edges(entry),
            source=str(path),
        ))
    return packages
