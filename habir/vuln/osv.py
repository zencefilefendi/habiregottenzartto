"""
OSV record parsing + the range-containment matcher.

The matcher implements the OSV schema "evaluation" semantics:
events on a number line, an ``introduced`` opens an affected interval, a
``fixed`` closes it exclusively, a ``last_affected`` closes it inclusively.
Versions are compared with our PEP 440 engine, so the ordering is exact rather
than lexical — the single most common source of false negatives in naive SCAs.
"""

from __future__ import annotations

from ..core.model import (Affected, AffectedRange, CVSS, ResolvedPackage,
                          Vulnerability)
from ..core.purl import normalize_pypi_name
from ..core.version import InvalidVersion, Version
from . import cvss as cvss_mod


# --------------------------------------------------------------------------- #
# Parsing: raw OSV JSON dict -> Vulnerability
# --------------------------------------------------------------------------- #
def _parse_severity(raw: dict) -> list[CVSS]:
    out: list[CVSS] = []
    for sev in raw.get("severity", []) or []:
        stype = sev.get("type", "")
        score = sev.get("score", "")
        if stype.startswith("CVSS_V3") and isinstance(score, str) and score.startswith("CVSS"):
            base = cvss_mod.base_score(score)
            out.append(CVSS(version="3.1", vector=score, base_score=base or 0.0))
        elif stype.startswith("CVSS_V4"):
            # v4 base requires the MacroVector table; record vector, score via db_specific.
            out.append(CVSS(version="4.0", vector=score if isinstance(score, str) else None,
                            base_score=0.0))
    # database_specific may carry a plain numeric severity as a fallback
    db = raw.get("database_specific", {}) or {}
    if not out and isinstance(db.get("cvss"), dict):
        sc = db["cvss"].get("score")
        if isinstance(sc, (int, float)):
            out.append(CVSS(version=str(db["cvss"].get("version", "3.1")),
                            vector=db["cvss"].get("vectorString"), base_score=float(sc)))
    return out


def _parse_affected(raw: dict) -> list[Affected]:
    out: list[Affected] = []
    for aff in raw.get("affected", []) or []:
        pkg = aff.get("package", {}) or {}
        eco = pkg.get("ecosystem", "")
        name = pkg.get("name", "")
        canonical = normalize_pypi_name(name) if eco.lower().startswith("pypi") else name.lower()
        ranges = [
            AffectedRange(type=r.get("type", "ECOSYSTEM"), events=r.get("events", []) or [])
            for r in aff.get("ranges", []) or []
        ]
        db = aff.get("database_specific", {}) or {}
        symbols = db.get("affected_functions") or db.get("symbols") or []
        out.append(Affected(
            ecosystem=eco, name=canonical, ranges=ranges,
            versions=aff.get("versions", []) or [],
            affected_symbols=list(symbols),
        ))
    return out


def parse_record(raw: dict) -> Vulnerability:
    fix_commits: list[str] = []
    for ref in raw.get("references", []) or []:
        url = ref.get("url", "")
        if "/commit/" in url or ref.get("type") == "FIX":
            fix_commits.append(url)
    return Vulnerability(
        id=raw.get("id", ""),
        aliases=raw.get("aliases", []) or [],
        summary=raw.get("summary", ""),
        details=raw.get("details", ""),
        severity=_parse_severity(raw),
        affected=_parse_affected(raw),
        references=raw.get("references", []) or [],
        published=raw.get("published"),
        modified=raw.get("modified"),
        withdrawn=raw.get("withdrawn"),
        fix_commits=fix_commits,
    )


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #
_EVENT_RANK = {"introduced": 0, "last_affected": 1, "fixed": 1}


def _event_version(value: str) -> Version | None:
    if value == "0":
        return Version("0")        # sentinel: -infinity (every version >= 0)
    try:
        return Version(value)
    except InvalidVersion:
        return None


def version_in_range(rng: AffectedRange, version: Version) -> bool:
    """Number-line walk over sorted events; True iff version is inside an
    open affected interval."""
    parsed: list[tuple[Version, int, str]] = []
    for event in rng.events:
        for kind, value in event.items():
            if kind == "limit":
                continue
            ver = _event_version(value)
            if ver is None:
                continue
            parsed.append((ver, _EVENT_RANK.get(kind, 1), kind))

    # Stable order: by version, then 'introduced' before close events at a tie.
    parsed.sort(key=lambda t: (t[0], t[1]))

    affected = False
    for ver, _rank, kind in parsed:
        if kind == "introduced":
            if version >= ver:
                affected = True
        elif kind == "fixed":
            if version >= ver:
                affected = False
        elif kind == "last_affected":
            if version > ver:
                affected = False
    return affected


def fixed_versions_for(affected: Affected) -> list[str]:
    out: list[str] = []
    for rng in affected.ranges:
        for event in rng.events:
            if "fixed" in event:
                out.append(event["fixed"])
    return out


def matches(vuln: Vulnerability, pkg: ResolvedPackage) -> tuple[bool, list[str], list[str]]:
    """Return (is_affected, fixed_versions, affected_symbols) for a package."""
    if pkg.version is None:
        return (False, [], [])      # never match without a concrete version
    if vuln.withdrawn:
        return (False, [], [])

    hit = False
    fixes: list[str] = []
    symbols: list[str] = []
    for aff in vuln.affected:
        if aff.ecosystem.lower() != pkg.ecosystem.lower():
            continue
        if aff.name != pkg.name:
            continue

        local_hit = False
        if aff.versions and str(pkg.version) in aff.versions:
            local_hit = True
        for rng in aff.ranges:
            if version_in_range(rng, pkg.version):
                local_hit = True
        if local_hit:
            hit = True
            fixes.extend(fixed_versions_for(aff))
            symbols.extend(aff.affected_symbols)

    # Only suggest fixes strictly greater than the installed version.
    upgrade_targets = sorted(
        {f for f in fixes if _safe_gt(f, pkg.version)},
        key=lambda s: Version(s),
    )
    return (hit, upgrade_targets, sorted(set(symbols)))


def _safe_gt(candidate: str, current: Version) -> bool:
    try:
        return Version(candidate) > current
    except InvalidVersion:
        return False
