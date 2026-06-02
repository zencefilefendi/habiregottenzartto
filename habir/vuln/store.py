"""
Local-first vulnerability store (SQLite).

Air-gap capable: the engine never reaches the network at scan time. A `db sync`
step ingests an OSV mirror + EPSS + KEV into SQLite and records a content hash,
so every scan is reproducible to an exact database snapshot — the property that
makes the tool usable for audit and forensics, not just CI gating.
"""

from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from ..core.model import Enrichment, Vulnerability
from ..core.purl import normalize_pypi_name
from . import osv

if TYPE_CHECKING:
    from ..mine.symbols import MineResult

DEFAULT_DB_PATH = Path.home() / ".habir" / "osv.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vulns (
    id        TEXT PRIMARY KEY,
    modified  TEXT,
    data      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS affects (
    vuln_id   TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_affects ON affects(ecosystem, name);
CREATE TABLE IF NOT EXISTS epss (
    cve        TEXT PRIMARY KEY,
    score      REAL,
    percentile REAL
);
CREATE TABLE IF NOT EXISTS kev (
    cve        TEXT PRIMARY KEY,
    date_added TEXT
);
CREATE TABLE IF NOT EXISTS mined_symbols (
    vuln_id   TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name      TEXT NOT NULL,
    symbol    TEXT NOT NULL,
    qualified TEXT,
    source    TEXT
);
CREATE INDEX IF NOT EXISTS idx_mined ON mined_symbols(vuln_id);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


class VulnStore:
    def __init__(self, path: Path = DEFAULT_DB_PATH) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # -- ingestion ------------------------------------------------------------
    def sync_from_seed(self, seed_dir: Path, *, source_label: str = "seed") -> dict:
        """Load OSV records + EPSS + KEV from a local directory."""
        seed_dir = Path(seed_dir)
        cur = self.conn.cursor()
        cur.execute("DELETE FROM vulns")
        cur.execute("DELETE FROM affects")
        cur.execute("DELETE FROM epss")
        cur.execute("DELETE FROM kev")
        cur.execute("DELETE FROM mined_symbols")   # re-mine after a fresh sync

        records: list[dict] = []
        skipped: list[str] = []
        osv_dir = seed_dir / "osv"
        if osv_dir.is_dir():
            for jf in sorted(osv_dir.glob("*.json")):
                try:
                    doc = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
                except (json.JSONDecodeError, OSError):
                    skipped.append(jf.name)
                    continue
                records.extend(doc if isinstance(doc, list) else [doc])

        digest = hashlib.sha256()
        for raw in sorted(records, key=lambda r: r.get("id", "")):
            vid = raw.get("id", "")
            if not vid:
                continue
            cur.execute("INSERT OR REPLACE INTO vulns(id, modified, data) VALUES (?,?,?)",
                        (vid, raw.get("modified"), json.dumps(raw, sort_keys=True)))
            for aff in raw.get("affected", []) or []:
                pkg = aff.get("package", {}) or {}
                eco = pkg.get("ecosystem", "")
                name = pkg.get("name", "")
                canon = (normalize_pypi_name(name)
                         if eco.lower().startswith("pypi") else name.lower())
                cur.execute("INSERT INTO affects(vuln_id, ecosystem, name) VALUES (?,?,?)",
                            (vid, eco, canon))
            digest.update(vid.encode())
            digest.update((raw.get("modified") or "").encode())

        epss_count = self._load_epss(cur, seed_dir / "epss.csv")
        kev_count = self._load_kev(cur, seed_dir / "kev.json")

        snapshot = {
            "source": source_label,
            "synced_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "content_hash": "sha256:" + digest.hexdigest()[:32],
            "record_count": len(records),
            "epss_count": epss_count,
            "kev_count": kev_count,
        }
        if skipped:
            snapshot["skipped_files"] = len(skipped)
        for k, v in snapshot.items():
            cur.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?,?)", (k, str(v)))
        self.conn.commit()
        return snapshot

    def _load_epss(self, cur, csv_path: Path) -> int:
        if not csv_path.exists():
            return 0
        count = 0
        with csv_path.open(encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(row for row in fh if not row.startswith("#"))
            for row in reader:
                cve = (row.get("cve") or row.get("CVE") or "").upper()
                if not cve:
                    continue
                try:
                    score = float(row.get("epss", 0) or 0)
                    pct = float(row.get("percentile", 0) or 0)
                except (TypeError, ValueError):
                    continue                     # skip a malformed row, keep going
                cur.execute("INSERT OR REPLACE INTO epss(cve, score, percentile) "
                            "VALUES (?,?,?)", (cve, score, pct))
                count += 1
        return count

    def _load_kev(self, cur, json_path: Path) -> int:
        if not json_path.exists():
            return 0
        try:
            doc = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            return 0
        count = 0
        for entry in doc.get("vulnerabilities", []) or []:
            cve = (entry.get("cveID") or "").upper()
            if not cve:
                continue
            cur.execute("INSERT OR REPLACE INTO kev(cve, date_added) VALUES (?,?)",
                        (cve, entry.get("dateAdded")))
            count += 1
        return count

    # -- query ----------------------------------------------------------------
    def lookup(self, ecosystem: str, name: str) -> list[Vulnerability]:
        rows = self.conn.execute(
            "SELECT DISTINCT v.data FROM affects a JOIN vulns v ON v.id = a.vuln_id "
            "WHERE a.ecosystem = ? COLLATE NOCASE AND a.name = ?",
            (ecosystem, name),
        ).fetchall()
        vulns = [osv.parse_record(json.loads(r["data"])) for r in rows]
        for vuln in vulns:
            self._merge_mined_symbols(vuln)
        return vulns

    def _merge_mined_symbols(self, vuln: Vulnerability) -> None:
        """Fold auto-mined affected functions into the matching Affected entries."""
        rows = self.conn.execute(
            "SELECT ecosystem, name, symbol FROM mined_symbols WHERE vuln_id = ?",
            (vuln.id,)).fetchall()
        if not rows:
            return
        by_pkg: dict[tuple[str, str], set[str]] = {}
        for r in rows:
            by_pkg.setdefault((r["ecosystem"].lower(), r["name"]), set()).add(r["symbol"])
        for aff in vuln.affected:
            extra = by_pkg.get((aff.ecosystem.lower(), aff.name))
            if not extra:
                continue
            existing = set(aff.affected_symbols)
            for sym in sorted(extra - existing):
                aff.affected_symbols.append(sym)

    def add_mined_symbols(self, vuln_id: str, ecosystem: str, name: str,
                          result: "MineResult", *, source: str = "mined") -> int:
        canon = (normalize_pypi_name(name)
                 if ecosystem.lower().startswith("pypi") else name.lower())
        pairs: set[tuple[str, str]] = set()
        for q in result.qualified:
            pairs.add((q.split(".")[-1], q))
        for s in result.short:
            pairs.add((s, s))
        cur = self.conn.cursor()
        cur.execute("DELETE FROM mined_symbols WHERE vuln_id = ? AND ecosystem = ? "
                    "AND name = ? AND source = ?", (vuln_id, ecosystem, canon, source))
        for short, qual in sorted(pairs):
            cur.execute("INSERT INTO mined_symbols(vuln_id, ecosystem, name, symbol, "
                        "qualified, source) VALUES (?,?,?,?,?,?)",
                        (vuln_id, ecosystem, canon, short, qual, source))
        self.conn.commit()
        return len(pairs)

    def mined_count(self) -> int:
        return self.conn.execute(
            "SELECT COUNT(DISTINCT vuln_id) c FROM mined_symbols").fetchone()["c"]

    def affected_packages(self, vuln_id: str) -> list[tuple[str, str]]:
        rows = self.conn.execute(
            "SELECT DISTINCT ecosystem, name FROM affects WHERE vuln_id = ?",
            (vuln_id,)).fetchall()
        return [(r["ecosystem"], r["name"]) for r in rows]

    def has_vuln(self, vuln_id: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM vulns WHERE id = ?", (vuln_id,)).fetchone() is not None

    def enrichment_for(self, vuln: Vulnerability) -> Enrichment:
        """Join EPSS + KEV using the vuln's CVE id (or any alias)."""
        candidates = [vuln.id] + list(vuln.aliases)
        cves = [c.upper() for c in candidates if c.upper().startswith("CVE-")]
        enr = Enrichment(enrichment_source="none")
        for cve in cves:
            row = self.conn.execute(
                "SELECT score, percentile FROM epss WHERE cve = ?", (cve,)).fetchone()
            if row:
                enr.epss = row["score"]
                enr.epss_percentile = row["percentile"]
                enr.enrichment_source = self._meta("source") or "seed"
            krow = self.conn.execute(
                "SELECT date_added FROM kev WHERE cve = ?", (cve,)).fetchone()
            if krow:
                enr.kev = True
                enr.kev_date_added = krow["date_added"]
        return enr

    def _meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def snapshot_info(self) -> dict[str, str | int]:
        rows = self.conn.execute("SELECT key, value FROM meta").fetchall()
        info: dict[str, str | int] = {r["key"]: r["value"] for r in rows}
        for numeric in ("record_count", "epss_count", "kev_count"):
            if numeric in info:
                try:
                    info[numeric] = int(info[numeric])  # type: ignore[arg-type]
                except (ValueError, TypeError):
                    pass
        return info

    def is_empty(self) -> bool:
        return self.conn.execute("SELECT COUNT(*) c FROM vulns").fetchone()["c"] == 0

    def close(self) -> None:
        self.conn.close()
