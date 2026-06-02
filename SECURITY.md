# Security Policy

## Reporting a vulnerability

If you find a security issue in **habiregottenzartto** itself, please report it
privately rather than opening a public issue. Include a minimal reproduction and
the affected version (`habir --version`). You can expect an acknowledgement and a
remediation plan; coordinated disclosure is appreciated.

## The analyzer's own security posture

A tool that audits a supply chain must not enlarge it. By design:

- **Zero runtime dependencies** — nothing is pulled into the trust boundary it audits.
- **No code execution of analyzed inputs** — manifests and source are parsed with
  `tomllib` / `json` / `ast.parse` only. There is no `eval`, `exec`, `pickle`, or
  `yaml.load`; `ast.parse` builds a syntax tree and never runs the code.
- **Parameterised SQL** everywhere; the local store is a plain SQLite file.
- **No implicit network access at scan time** — the engine is local-first and
  air-gap capable. The only subprocess is an explicit, list-argument `git` call in
  the optional `mine --repo/--commit` mode (no shell, with a timeout).
- **Deterministic & reproducible** — every scan records a DB content-hash and the
  SHA-256 of each input, so results are replayable and auditable.

## Scope of findings

Severity is computed deterministically from CVSS × EPSS/KEV × reachability ×
version-confidence and is intended for prioritisation, not as a compliance
verdict. Bundled EPSS values are an illustrative snapshot and the KEV table is
intentionally empty until `habir db sync` ingests live feeds — see the README.
