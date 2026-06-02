# habiregottenzartto

**Deterministic, reachability-aware supply-chain intelligence engine.**

[![CI](https://github.com/zencefilefendi/habiregottenzartto/actions/workflows/ci.yml/badge.svg)](https://github.com/zencefilefendi/habiregottenzartto/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Runtime deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen)
![Tests](https://img.shields.io/badge/tests-71%20passing-brightgreen)

Most dependency scanners answer *"do you have a package with a known CVE?"* and
hand you a wall of 2,000 findings. `habiregottenzartto` answers the question a
security engineer actually asks:

> *"Which of these vulnerabilities is in a version I really run, in code my
> program really reaches, that attackers are really exploiting — and prove it."*

It is **local-first**, **air-gap capable**, has **zero runtime dependencies**,
and every verdict carries a machine-checkable evidence chain.

---

## Why this exists (and how it leapfrogs CVE-matching)

CVE matching is a commodity (`pip-audit`, `osv-scanner`, Trivy all do it). The
frontier — what Snyk and Endor Labs charge enterprise money for — is **cutting
the noise** and **proving exploitability**. This engine ships that frontier in
v0.1:

| Capability | Commodity SCA | habiregottenzartto |
|---|---|---|
| Version source | often guesses from imports | **lockfile-first; never matches a guessed version** |
| Version comparison | lexical / library | **self-contained PEP 440 engine** (epochs, pre/post/dev, local) |
| Result | "you have CVE-X" | **risk = severity × threat-intel × reachability × confidence** |
| Noise control | none | **function-level reachability** → unreachable 9.8 becomes LOW |
| Affected-symbol data | hand-curated (vendor moat) | **auto-mined from fixing-commit patches** |
| Reachability precision | package presence | **call-graph path to the vulnerable function**, printed |
| Cross-package analysis | — | **descends into dependency internals** to prove/refute the sink path |
| Exploitability | — | **EPSS + KEV** enrichment, **OpenVEX** `not_affected` output |
| Threats without a CVE | missed | **typosquat / supply-chain heuristics** |
| "Why did you flag this?" | — | **evidence DAG** in the terminal |
| Reproducibility | — | **content-hashed DB snapshot**, replayable scans |

---

## Quickstart

```bash
# 1. build the local vulnerability DB from the bundled snapshot (offline)
python3 -m habir db sync

# 2. auto-mine affected functions from fixing-commit patches (the data moat)
python3 -m habir mine

# 3. scan a project (directory, lockfile, or requirements file)
python3 -m habir scan examples/demo-project --explain

# 4. emit machine formats for CI / downstream tools
python3 -m habir scan examples/demo-project --format sarif -o report.sarif
python3 -m habir scan examples/demo-project --format vex   -o vex.json
python3 -m habir scan . --fail-on high      # non-zero exit gates your pipeline
```

No network. No pip install required to try it — pure standard library
(`tomllib`, `ast`, `sqlite3`). Python ≥ 3.11.

---

## The demo, annotated

`examples/demo-project` pins old, genuinely-vulnerable versions. One scan shows
the whole thesis:

```
  RISK       PACKAGE              ADVISORY              REACHABILITY    THREAT-INTEL  FIX
  ──────────────────────────────────────────────────────────────────────────────────────
   71.3 HIGH pyyaml@5.1           GHSA-8q59-q68h-6hv4   REACH:SYM       EPSS 9.2%     5.4
   70.4 HIGH pyyaml@5.1           GHSA-6757-jp84-gxfx   REACH:SYM       EPSS 6.1%     5.3.1
   63.0 HIGH reqests@0.0.1        supply-chain          unreachable     —             —
   44.8 MEDI urllib3@1.24.1       GHSA-mh33-7rrq-662w   REACHABLE       EPSS 1.1%     1.24.2
   41.7 MEDI requests@2.19.1      GHSA-x84v-xcm2-53pg   reach:indirect  EPSS 2.8%     2.20.0
   21.0 LOW  jinja2@2.10          GHSA-462w-v97r-4m45   unreachable     EPSS 4.7%     2.10.1
```

- **`pyyaml`** — `REACH:SYM`. The call graph proves a path to the affected
  function and `--explain` prints it:
  `app.main:<toplevel> → app.main.run → app.config.load_config → pyyaml.full_load`.
  Symbol-confirmed exposure → ranked top.
- **`requests`** — `reach:indirect`. The code calls `requests.get`, but the
  vulnerable functions (`rebuild_auth` / `resolve_redirects`, **auto-mined from
  the fix commit**) are never on a call path. Honestly downgraded — it now ranks
  *below* `urllib3`, instead of being a loud, undifferentiated MEDIUM.
- **`urllib3`** — never imported directly, but `requests` depends on it →
  **transitively reachable** via graph closure (package-level, no symbol data).
- **`jinja2@2.10`** — a real **CVSS 9.8 RCE** (CVE-2019-10906), declared but
  **never imported** → discounted to **LOW** and emitted as `not_affected` in VEX.
- **`reqests`** — not a CVE at all: a **typosquat** of `requests`.

`--explain` prints the evidence DAG behind each number (version source, OSV range
match, the reachability call path, threat intel).

### Cross-package reachability — the same finding, sharpened by evidence

First-party analysis can prove you call `requests.get`, but not whether `get`
internally reaches the *vulnerable* function. Point `--deps-path` at the
dependency sources (a venv's `site-packages`, a vendored tree — auto-detected for
a project `.venv`) and the engine descends into the library's own call graph:

```
# first-party only          → requests is MEDIUM 41.7  "reach:indirect"
python3 -m habir scan examples/demo-project

# with dependency internals → requests is HIGH 69.4    "REACH:DEEP"
python3 -m habir scan examples/demo-project --deps-path examples/demo-project/vendor
```

The upgrade is backed by a proven end-to-end path, printed under `--explain`:

```
app.main:<toplevel> → app.main.run → app.main.fetch_json → requests.get
   ↘ requests internals → requests.request → requests.send → requests.resolve_redirects
```

The reverse also holds: if the dependency's call graph proves the public API you
use can **never** reach the vulnerable function, the finding becomes
`proven-safe` and is emitted as `not_affected` in VEX — a defensible suppression,
not a guess.

---

## Architecture

```
habir/
  core/      PEP 440 version engine · PURL identity · domain model     (correctness core)
  resolve/   lockfile-first resolvers (requirements/poetry/uv/pipfile) + dependency graph
  vuln/      OSV range-matcher · CVSS v3.x scorer · SQLite store · EPSS/KEV enrichment
  mine/      unified-diff parser · patch→symbol miner (the CVE→affected-function moat)
  analyze/   import-graph + call-graph + cross-package reachability · typosquat · risk
  report/    evidence DAG · terminal · JSON · SARIF 2.1.0 · OpenVEX · reproducibility manifest
  data/      bundled offline reference data (OSV seed, EPSS, KEV, patches, import-map)
```

Pipeline:

```
resolve (lockfile-first) → OSV range-match → EPSS/KEV enrich
   → package-level reachability → call-graph refinement (entrypoint → vulnerable fn)
   → cross-package descent (into dependency internals, when sources available)
   → supply-chain heuristics → deterministic risk
   → ranked, evidence-bearing findings + reproducibility manifest
```

Out of band: `habir mine` parses fixing-commit patches into a CVE → affected-
function map (AST line-spans when source is available, git hunk headers otherwise),
which the call graph then targets.

---

## The risk model (fully transparent)

```
severity = CVSS_base / 10                         (unknown → neutral 0.5)
threat   = max(EPSS, 0.9 if in CISA KEV)          actively-exploited floors high
exposure = reached 1.0 · imported .85 · indirect .6 · proven-safe .3 · unreachable .3
hazard   = severity × (0.7 + 0.3 × threat)
raw      = 100 × hazard × exposure                pre-confidence (always shown)
value    = raw × version_confidence               uncertain versions are discounted
```

`exposure` is where reachability pays off. A call-graph path to the vulnerable
function — first-party (`REACH:SYM`) or proven through dependency internals
(`REACH:DEEP`) — scores **1.0**. A package used but whose vulnerable function the
first-party graph never reaches is **0.6** (`indirect`). When the dependency's own
graph *proves* the sink is unreachable (`proven-safe`) it drops to **0.3**, on par
with a package that is never imported.

Guardrails: a **KEV** (actively exploited) finding never drops below **MEDIUM**,
so a real-world threat is surfaced even on an unreachable package. The
pre-confidence `raw` score is always reported — nothing is hidden by the
discount. Same inputs ⇒ identical output, byte for byte (verified by tests).

---

## Outputs

| Format | Use |
|---|---|
| `terminal` | humans; `--explain` adds the evidence DAG |
| `json` | the machine source of truth (findings + evidence + manifest) |
| `sarif` | GitHub Code Scanning / CI; risk, EPSS, KEV, reachability ride in properties |
| `vex` | OpenVEX attestation; reachability drives `affected` / `not_affected` |

---

## Determinism & reproducibility

Every scan records a **DB snapshot content-hash** plus SHA-256 of each input
manifest, and prints a `reproduce` command. A finding is replayable to the exact
database state it was produced against — the property that makes this usable for
audit and forensics, not just CI gating.

---

## Honesty about the bundled data

The shipped database is a small, **labeled seed** so the tool runs offline out
of the box:

- **OSV records** (`habir/data/seed/osv/`) — 5 *real* advisories with accurate
  version ranges and CVSS vectors.
- **EPSS** (`epss.csv`) — clearly marked **illustrative snapshot** values.
- **KEV** (`kev.json`) — **intentionally empty**. None of the demo CVEs are in
  the real CISA KEV catalog, and the tool will not falsely stamp a CVE as
  actively exploited. The KEV risk-floor logic is proven in
  `tests/test_risk.py` with synthetic fixtures.

`habir db sync` is the seam where a production mirror (full OSV export, live
FIRST.org EPSS, the real CISA KEV feed) replaces the seed. The engine is
identical; only the snapshot changes.

---

## Roadmap

This **0.1.0-beta** already ships the analysis layers usually gated behind
commercial tiers. The labels below describe *capabilities*, not package versions.

**Shipped**
- Lockfile-first resolution · OSV range-matching · EPSS/KEV · deterministic risk.
- Patch-diff symbol mining → automated CVE → affected-function DB (`habir mine`).
- Function-level (first-party) call-graph reachability.
- Cross-package reachability into dependency internals (`--deps-path` → `REACH:DEEP`
  / `proven-safe`).

**Planned**
- Live `db sync` from OSV / FIRST.org EPSS / CISA KEV mirrors; lockfile hash verification.
- Dependency-confusion + behavioral install-script analysis (Socket-class).
- Type-aware data-flow taint (precise source→sink) replacing the name-based graph; Rust core.
- Static × dynamic reachability (`sys.monitoring` / eBPF runtime confirmation).

### The data moat

Precise SCA is bottlenecked by the CVE → affected-symbol mapping, which Snyk and
Endor Labs curate by hand. `habir mine` derives it automatically and
deterministically from the fixing commit's diff — AST line-spans map the changed
lines to the innermost enclosing `def`/`class` (qualified `Class.method`), with a
git hunk-header fallback when no source checkout is available. In the demo, the
`requests` advisory ships with **no** hand-authored symbols; mining recovers
`rebuild_auth` / `resolve_redirects` from the patch, and the call graph then shows
they are never called — the full automated path from "raw CVE" to "honest verdict."

---

## Tests

```bash
python3 -m pytest -q          # 71 tests: version algebra, OSV boundaries, risk
                              # monotonicity, diff mining, call-graph + cross-package
                              # reachability, adversarial inputs, determinism
```

Every input path is hardened: malformed lock files, corrupt advisories, broken
patches and bad DB rows are reported as warnings, never crashes. The analyzer is
itself safe — it parses untrusted manifests and source with `tomllib` / `json` /
`ast.parse` only (no `eval`, `exec`, `pickle`, or `yaml.load`), so the tool that
audits your supply chain never becomes part of its attack surface.

## Design principles

**Determinism over guessing · Transparency over abstraction · Local-first.**
Every finding must explain itself, and the tool that audits your supply chain
adds nothing to it.
