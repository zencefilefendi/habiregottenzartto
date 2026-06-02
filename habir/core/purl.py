"""
Package URL (PURL) — canonical, ecosystem-aware package identity.

A finding is only as trustworthy as the identifier it hangs on. Free-text
package names are ambiguous (``PyYAML`` == ``pyyaml`` == ``py-yaml``); PURL gives
every node in the dependency graph one canonical address so that resolution,
vulnerability matching and VEX statements all key off the same string.

Spec: https://github.com/package-url/purl-spec
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["PackageURL", "normalize_pypi_name"]

_PEP503 = re.compile(r"[-_.]+")


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalisation: lowercase, collapse runs of -_. into a single -."""
    return _PEP503.sub("-", name).strip("-").lower()


# Per-ecosystem canonicalisation. OSV/PURL ecosystems do not all share PyPI's
# rules, so we keep this dispatch explicit rather than guessing.
_NORMALIZERS = {
    "pypi": normalize_pypi_name,
    "npm": lambda n: n.lower(),
    "cargo": lambda n: n.lower(),
    "go": lambda n: n.lower(),
}


@dataclass(frozen=True, slots=True)
class PackageURL:
    type: str            # ecosystem, e.g. "pypi"
    name: str            # canonical name
    version: str | None = None
    namespace: str | None = None

    @classmethod
    def for_package(cls, ecosystem: str, name: str,
                    version: str | None = None) -> "PackageURL":
        eco = ecosystem.lower()
        norm = _NORMALIZERS.get(eco, lambda n: n)
        return cls(type=eco, name=norm(name), version=version)

    def with_version(self, version: str | None) -> "PackageURL":
        return PackageURL(self.type, self.name, version, self.namespace)

    @property
    def coordinate(self) -> str:
        """Identity without version — the join key for vulnerability lookup."""
        if self.namespace:
            return f"pkg:{self.type}/{self.namespace}/{self.name}"
        return f"pkg:{self.type}/{self.name}"

    def __str__(self) -> str:
        base = self.coordinate
        return f"{base}@{self.version}" if self.version else base
