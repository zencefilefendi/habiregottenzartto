"""poetry.lock resolver — exact pins + transitive dependency edges + file hashes."""

from __future__ import annotations

import tomllib
from pathlib import Path

from ..core.model import ResolvedPackage, VersionConfidence
from ..core.purl import PackageURL, normalize_pypi_name
from ..core.version import InvalidVersion, Version


def _dep_names(dependencies) -> list[str]:
    """`[package.dependencies]` maps name -> constraint | list[constraint-table]."""
    names: list[str] = []
    if isinstance(dependencies, dict):
        names = list(dependencies.keys())
    return [normalize_pypi_name(n) for n in names]


def resolve(path: Path) -> list[ResolvedPackage]:
    data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))

    # File hashes: legacy layout is [metadata.files][name] -> [{file, hash}].
    meta_files = (data.get("metadata", {}) or {}).get("files", {}) or {}

    packages: list[ResolvedPackage] = []
    for entry in data.get("package", []):
        raw_name = entry.get("name", "")
        canonical = normalize_pypi_name(raw_name)
        ver_str = entry.get("version")
        try:
            version = Version(ver_str) if ver_str else None
        except InvalidVersion:
            version = None

        # hashes: per-package `files` (lock v2) or metadata.files (lock v1)
        files = entry.get("files") or meta_files.get(raw_name) or meta_files.get(canonical) or []
        hashes = [f.get("hash", "") for f in files if isinstance(f, dict) and f.get("hash")]

        packages.append(ResolvedPackage(
            ecosystem="PyPI",
            name=canonical,
            raw_name=raw_name,
            version=version,
            purl=PackageURL.for_package("pypi", canonical, ver_str),
            direct=False,   # poetry.lock doesn't declare roots; graph derives them
            confidence=VersionConfidence.LOCKFILE,
            hashes=hashes,
            depends_on=_dep_names(entry.get("dependencies", {})),
            source=str(path),
        ))
    return packages
