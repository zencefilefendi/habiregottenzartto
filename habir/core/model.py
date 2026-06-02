"""
Shared domain model — the single vocabulary every layer speaks.

Design rule: a Finding must be able to *explain itself*. Every claim it makes
(this version, this match, this is reachable, this scored 81) hangs off an
EvidenceNode DAG so the verdict is auditable end-to-end, not a black box.
"""

from __future__ import annotations

import enum
import itertools
from dataclasses import dataclass, field

from .purl import PackageURL
from .version import Version


# --------------------------------------------------------------------------- #
# Confidence in the *resolved version* — the input determinism of the scan.
# This is the honest core of the tool: we never let a guessed version drive a
# loud verdict. Lockfile pins earn full confidence; bare imports earn little.
# --------------------------------------------------------------------------- #
class VersionConfidence(float, enum.Enum):
    LOCKFILE = 1.0      # exact pin from a lock file or `==` with hash
    PINNED = 0.9        # exact `==` pin without hash
    CONSTRAINED = 0.55  # a range constraint (>=, ~=, etc.) — version inferred
    IMPORTED = 0.3      # only observed as an import; version unknown/assumed


class Reachability(str, enum.Enum):
    REACHABLE = "reachable"        # vulnerable dist is imported by first-party code
    UNREACHABLE = "unreachable"    # present in graph but never imported
    UNKNOWN = "unknown"            # not enough signal (no source, dynamic import)


class RiskBand(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingKind(str, enum.Enum):
    VULNERABILITY = "vulnerability"     # known CVE/OSV match
    SUPPLY_CHAIN = "supply-chain"       # typosquat / behavioral / provenance


# --------------------------------------------------------------------------- #
# Resolved packages & graph
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class ResolvedPackage:
    ecosystem: str
    name: str                         # canonical (PEP 503) name
    raw_name: str                     # as written in the manifest
    version: Version | None
    purl: PackageURL
    direct: bool = False              # a top-level/declared dependency
    confidence: VersionConfidence = VersionConfidence.LOCKFILE
    hashes: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)   # canonical names
    source: str = ""                  # manifest path the package came from

    @property
    def coordinate(self) -> str:
        return self.purl.coordinate


@dataclass(slots=True)
class DependencyGraph:
    ecosystem: str
    packages: dict[str, ResolvedPackage] = field(default_factory=dict)  # by canonical name
    roots: set[str] = field(default_factory=set)                        # direct deps
    warnings: list[str] = field(default_factory=list)                   # resolution issues

    def add(self, pkg: ResolvedPackage) -> None:
        self.packages[pkg.name] = pkg
        if pkg.direct:
            self.roots.add(pkg.name)

    def __iter__(self):
        return iter(self.packages.values())

    def __len__(self) -> int:
        return len(self.packages)


# --------------------------------------------------------------------------- #
# Vulnerability records (OSV-shaped, ecosystem-agnostic)
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class CVSS:
    version: str           # "3.1", "4.0", ...
    vector: str | None
    base_score: float      # 0.0 - 10.0


@dataclass(slots=True)
class AffectedRange:
    type: str                      # ECOSYSTEM | SEMVER
    events: list[dict[str, str]]   # ordered {introduced|fixed|last_affected: version}


@dataclass(slots=True)
class Affected:
    ecosystem: str
    name: str                              # canonical
    ranges: list[AffectedRange] = field(default_factory=list)
    versions: list[str] = field(default_factory=list)
    affected_symbols: list[str] = field(default_factory=list)  # for reachability


@dataclass(slots=True)
class Vulnerability:
    id: str                                # canonical OSV id (e.g. GHSA-…, PYSEC-…)
    aliases: list[str] = field(default_factory=list)   # CVE-… etc.
    summary: str = ""
    details: str = ""
    severity: list[CVSS] = field(default_factory=list)
    affected: list[Affected] = field(default_factory=list)
    references: list[dict[str, str]] = field(default_factory=list)
    published: str | None = None
    modified: str | None = None
    withdrawn: str | None = None
    fix_commits: list[str] = field(default_factory=list)   # seeds the symbol-mining moat

    @property
    def cve(self) -> str | None:
        for a in itertools.chain([self.id], self.aliases):
            if a.upper().startswith("CVE-"):
                return a.upper()
        return None

    def best_cvss(self) -> CVSS | None:
        if not self.severity:
            return None
        # Prefer the highest declared version, then highest base score.
        return max(self.severity, key=lambda c: (c.version, c.base_score))


# --------------------------------------------------------------------------- #
# Enrichment, reachability, evidence, risk
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class Enrichment:
    epss: float | None = None              # 0..1 probability of exploitation (30d)
    epss_percentile: float | None = None
    kev: bool = False                      # CISA Known Exploited Vulnerabilities
    kev_date_added: str | None = None
    exploit_refs: list[str] = field(default_factory=list)
    enrichment_source: str = "none"        # "seed-illustrative" | "first.org" | ...


@dataclass(slots=True)
class ReachabilityResult:
    status: Reachability = Reachability.UNKNOWN
    imported_symbols: list[str] = field(default_factory=list)
    entry_paths: list[str] = field(default_factory=list)   # first-party files reaching it
    symbol_hit: bool = False               # an affected symbol is on a call path
    call_path: list[str] = field(default_factory=list)     # entrypoint → … → sink
    affected_fn_not_reached: bool = False  # package used, but vulnerable fn not called
    deep: bool = False                     # path confirmed through dependency internals
    proven_sink_unreachable: bool = False  # dep call graph proves the sink is unreached
    analysis: str = "package-level"        # package-level | function-level | cross-package


@dataclass(slots=True)
class EvidenceNode:
    kind: str          # e.g. "version", "match", "reachability", "enrichment", "risk"
    claim: str         # human-readable assertion
    source: str        # where the claim comes from (file, db, algorithm)
    confidence: float = 1.0
    children: list["EvidenceNode"] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "claim": self.claim,
            "source": self.source,
            "confidence": round(self.confidence, 4),
            "children": [c.to_dict() for c in self.children],
        }


@dataclass(slots=True)
class RiskScore:
    value: float                    # 0..100
    band: RiskBand
    raw_value: float                # score before confidence discount (nothing hidden)
    factors: dict[str, float] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    kind: FindingKind
    package: ResolvedPackage
    title: str
    vuln: Vulnerability | None = None
    fixed_versions: list[str] = field(default_factory=list)
    reachability: ReachabilityResult = field(default_factory=ReachabilityResult)
    enrichment: Enrichment = field(default_factory=Enrichment)
    risk: RiskScore | None = None
    evidence: EvidenceNode | None = None

    @property
    def identifier(self) -> str:
        return self.vuln.id if self.vuln else self.title


@dataclass(slots=True)
class ScanManifest:
    """Reproducibility record — a scan is replayable to this exact state."""
    tool: str
    tool_version: str
    generated_at: str               # UTC ISO-8601
    ecosystem: str
    target: str
    db_snapshot: dict[str, str | int]   # source, synced_at, content_hash, record_count
    inputs: list[dict[str, str]]        # {path, sha256}
    counts: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)   # non-fatal scan issues
