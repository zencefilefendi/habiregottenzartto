# Changelog

All notable changes to **habiregottenzartto** are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/); the project
adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-06-02

The first end-to-end release: a deterministic, reachability-aware supply-chain
intelligence engine with zero runtime dependencies.

### Added — core
- Self-contained **PEP 440** version engine (epochs, pre/post/dev, local versions).
- Canonical **PURL** identity with PEP 503 name normalization.
- **Lockfile-first resolvers**: `requirements.txt` (+hashes), `poetry.lock`,
  `Pipfile.lock`, `uv.lock`; transitive dependency graph with root inference.
- **OSV** range-matching with correct event-interval semantics, PEP 440 ordered.
- Self-contained **CVSS v3.x** base-score computation.
- Local-first **SQLite** vuln store with **EPSS** + **CISA KEV** enrichment and a
  content-hashed, reproducible snapshot.

### Added — analysis
- **Package-level reachability** via first-party import-graph closure.
- **Patch-diff symbol mining** (`habir mine`): unified-diff parser + AST line-span
  / git hunk-header extraction → automated CVE → affected-function mapping.
- **Function-level reachability**: conservative first-party call graph computing
  entrypoint → vulnerable-function paths, with honest degradation on dynamism.
- **Cross-package reachability** (`--deps-path`): descends into a dependency's own
  call graph to prove the public-entry → vulnerable-sink path (`REACH:DEEP`, with
  the full chain printed) or to refute it (`proven-safe` → VEX `not_affected`).
  Auto-detects a project `.venv` / `__pypackages__`; degrades honestly without sources.
- **Deterministic, explainable risk engine**
  (`severity × threat × exposure × confidence`) with a KEV risk-floor.
- **Supply-chain heuristics**: typosquat detection by bounded edit distance.

### Added — reporting & CLI
- Evidence-DAG, ANSI terminal table, structured JSON, **SARIF 2.1.0**, **OpenVEX**
  (reachability-driven `affected` / `not_affected`).
- `habir scan | db sync | db info | mine`; `--fail-on` CI gate; `--explain`.
- Reproducibility manifest (DB hash + input hashes + replay command).

### Engineering
- 71-test suite (incl. adversarial inputs + cross-package cases); zero-crash
  handling of malformed manifests/patches/DB rows; clean top-level CLI error
  channel (`HABIR_DEBUG` for tracebacks); ruff (E/F/W) + mypy config; CI matrix on
  Python 3.11–3.13; MIT licensed; PEP 561 typed (`py.typed`).

### Known limitations (by design, documented)
- CVSS v4.0 vectors are recorded but not yet scored (the MacroVector table is
  pending); such advisories fall back to the neutral severity path.
- Cross-package reachability uses a conservative *name-based* call graph
  (over-approximate forward, the safe direction). Type-aware data-flow taint
  (precise source→sink) is the v0.7 successor.
- Bundled EPSS values are an illustrative snapshot; KEV is intentionally empty.
  `habir db sync` is the seam for live production feeds.
