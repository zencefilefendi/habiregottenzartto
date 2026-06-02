"""
requirements.txt resolver + a shared PEP 508-lite requirement parser.

Honesty over guessing: a ``requests==2.19.1`` line is a hard pin we trust; a
``requests>=2.0`` line is a *constraint* we will not silently resolve to a
concrete version offline. We surface it as CONSTRAINED so the risk engine can
discount any match instead of crying wolf on an assumed version.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..core.model import ResolvedPackage, VersionConfidence
from ..core.purl import PackageURL, normalize_pypi_name
from ..core.version import InvalidVersion, Version

# name [extras] specifiers ; marker
_REQ_RE = re.compile(
    r"""^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)
    (?:\s*\[(?P<extras>[^\]]*)\])?
    (?P<spec>(?:\s*(?:===|==|~=|!=|<=|>=|<|>)\s*[^;,\s]+\s*,?)*)
    (?:\s*;\s*(?P<marker>.+))?
    \s*$""",
    re.VERBOSE,
)

_PIN_RE = re.compile(r"==\s*([^=,;\s]+)")


@dataclass(slots=True)
class ParsedRequirement:
    name: str
    canonical: str
    specifier: str
    extras: list[str]
    marker: str | None
    hashes: list[str]

    def pinned_version(self) -> Version | None:
        m = _PIN_RE.search(self.specifier)
        if not m:
            return None
        token = m.group(1).strip()
        if token.endswith(".*"):       # wildcard pin is a constraint, not a pin
            return None
        try:
            return Version(token)
        except InvalidVersion:
            return None


def parse_requirement(text: str) -> ParsedRequirement | None:
    """Parse a single requirement expression (no surrounding hashes/options)."""
    text = text.strip()
    if not text or text.startswith("#"):
        return None
    if text.startswith("-") or "://" in text or text.startswith("."):
        return None  # options, VCS/URL installs, local paths — out of scope here
    m = _REQ_RE.match(text)
    if not m:
        return None
    name = m["name"]
    extras = [e.strip() for e in (m["extras"] or "").split(",") if e.strip()]
    return ParsedRequirement(
        name=name,
        canonical=normalize_pypi_name(name),
        specifier=(m["spec"] or "").strip(),
        extras=extras,
        marker=(m["marker"] or "").strip() or None,
        hashes=[],
    )


def _logical_lines(path: Path) -> list[tuple[str, list[str]]]:
    """Yield (requirement_text, hashes) handling backslash and --hash continuations."""
    out: list[tuple[str, list[str]]] = []
    raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
    buf = ""
    for line in raw:
        stripped = line.split(" #", 1)[0].rstrip() if not line.lstrip().startswith("#") else ""
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        buf += stripped
        if buf.strip():
            # split out --hash=... tokens that may share the logical line
            tokens = buf.replace("\\", " ").split()
            hashes = [t.split("=", 1)[1] for t in tokens if t.startswith("--hash=")]
            req_text = " ".join(t for t in tokens if not t.startswith("--"))
            out.append((req_text, hashes))
        buf = ""
    return out


def resolve(path: Path, *, _seen: set[Path] | None = None) -> list[ResolvedPackage]:
    """Resolve a requirements file (follows -r/--requirement includes)."""
    seen = _seen if _seen is not None else set()
    path = path.resolve()
    if path in seen:
        return []
    seen.add(path)

    packages: list[ResolvedPackage] = []
    for req_text, hashes in _logical_lines(path):
        low = req_text.lower()
        if low.startswith(("-r ", "--requirement ")):
            inc = req_text.split(None, 1)[1].strip()
            packages.extend(resolve((path.parent / inc), _seen=seen))
            continue
        parsed = parse_requirement(req_text)
        if parsed is None:
            continue

        version = parsed.pinned_version()
        if version is not None:
            confidence = VersionConfidence.LOCKFILE if hashes else VersionConfidence.PINNED
        else:
            confidence = VersionConfidence.CONSTRAINED

        packages.append(ResolvedPackage(
            ecosystem="PyPI",
            name=parsed.canonical,
            raw_name=parsed.name,
            version=version,
            purl=PackageURL.for_package("pypi", parsed.canonical,
                                        str(version) if version else None),
            direct=True,
            confidence=confidence,
            hashes=hashes,
            depends_on=[],
            source=str(path),
        ))
    return packages
