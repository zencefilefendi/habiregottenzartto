"""Human-facing terminal renderer — ranked, colored, with on-demand evidence."""

from __future__ import annotations

import os

from ..core.model import Finding, Reachability, RiskBand
from .. import __tool__, __version__

_RESET = "\033[0m"
_BAND_COLOR = {
    RiskBand.CRITICAL: "\033[1;97;41m",   # white on red
    RiskBand.HIGH: "\033[1;91m",
    RiskBand.MEDIUM: "\033[1;93m",
    RiskBand.LOW: "\033[1;94m",
    RiskBand.INFO: "\033[2;37m",
}
_DIM = "\033[2m"
_BOLD = "\033[1m"
_CYAN = "\033[96m"
_GREEN = "\033[92m"
_RED = "\033[91m"


def _supports_color() -> bool:
    return os.environ.get("NO_COLOR") is None and os.environ.get("TERM") != "dumb"


class _Painter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if self.enabled else text


def _reach_cell(f: Finding) -> tuple[str, str]:
    r = f.reachability
    if r.status == Reachability.REACHABLE:
        if r.dynamic:
            return ("REACH:DYN", _GREEN)
        if r.symbol_hit:
            return ("REACH:DEEP" if r.deep else "REACH:SYM", _GREEN)
        if r.proven_sink_unreachable:
            return ("proven-safe", _DIM)
        if r.affected_fn_not_reached:
            return ("reach:indirect", _DIM)
        return ("REACHABLE", _GREEN)
    if r.status == Reachability.UNREACHABLE:
        return ("unreachable", _DIM)
    return ("unknown", _DIM)


def _intel_cell(f: Finding) -> str:
    bits = []
    if f.enrichment.epss is not None:
        bits.append(f"EPSS {f.enrichment.epss*100:4.1f}%")
    if f.enrichment.kev:
        bits.append("KEV")
    return " ".join(bits) if bits else "—"


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def _pad(text: str, width: int) -> str:
    return _truncate(text, width).ljust(width)


def render(result, *, explain: bool = False, color: bool | None = None) -> str:
    paint = _Painter(_supports_color() if color is None else color)
    out: list[str] = []
    m = result.manifest

    out.append(paint(f"  {__tool__}", _BOLD) + paint(f"  v{__version__}", _DIM)
               + paint("  ·  deterministic supply-chain intelligence", _DIM))
    out.append(paint("  " + "─" * 78, _DIM))
    out.append(f"  target     {m.target}")
    out.append(f"  ecosystem  {m.ecosystem}    packages {m.counts.get('packages',0)}"
               f"  (direct {m.counts.get('direct',0)})")
    snap = m.db_snapshot
    out.append(paint(f"  vuln-db    {snap.get('source','?')} · {snap.get('content_hash','?')}"
                     f" · {snap.get('record_count','?')} records", _DIM))
    for warning in m.warnings:
        out.append(paint(f"  ⚠ {warning}", "\033[33m"))
    out.append("")

    # band summary
    bands: dict[RiskBand, int] = {}
    for f in result.findings:
        if f.risk:
            bands[f.risk.band] = bands.get(f.risk.band, 0) + 1
    summary = "  ".join(
        paint(f"{b.value} {bands.get(b,0)}", _BAND_COLOR[b])
        for b in (RiskBand.CRITICAL, RiskBand.HIGH, RiskBand.MEDIUM,
                  RiskBand.LOW, RiskBand.INFO)
    )
    out.append("  " + summary)
    out.append("")

    if not result.findings:
        out.append(paint("  ✓ no findings", _GREEN))
        return "\n".join(out)

    # header row
    out.append("  " + paint(
        f"{'RISK':<11}{'PACKAGE':<26}{'ADVISORY':<22}"
        f"{'REACHABILITY':<16}{'THREAT-INTEL':<16}{'FIX':<12}", _BOLD))
    out.append(paint("  " + "─" * 98, _DIM))

    for f in result.findings:
        band = f.risk.band if f.risk else RiskBand.INFO
        risk_txt = f"{f.risk.value:>5.1f} {band.value[:4]}" if f.risk else "  —"
        risk_cell = paint(_pad(risk_txt, 11), _BAND_COLOR[band])

        ver = str(f.package.version) if f.package.version else "?"
        pkg_cell = _pad(f"{f.package.name}@{ver}", 26)

        adv = f.vuln.id if f.vuln else f.kind.value
        adv_cell = _pad(adv, 22)

        reach_txt, reach_color = _reach_cell(f)
        reach_cell = paint(_pad(reach_txt, 16), reach_color)

        intel_cell = _pad(_intel_cell(f), 16)
        fix = f.fixed_versions[0] if f.fixed_versions else "—"
        fix_cell = paint(_pad(fix, 12), _GREEN if f.fixed_versions else _DIM)

        out.append(f"  {risk_cell}{pkg_cell}{adv_cell}{reach_cell}{intel_cell}{fix_cell}")

    out.append(paint("  " + "─" * 98, _DIM))

    if explain:
        out.append("")
        out.append(paint("  EVIDENCE", _BOLD))
        for f in result.findings:
            out.append("")
            head = f"{f.package.name}@{f.package.version}  →  {f.identifier}"
            out.append("  " + paint(head, _CYAN))
            if f.evidence:
                out.extend(_render_evidence(f.evidence, paint, indent=2))

    out.append("")
    out.append(paint(f"  generated  {m.generated_at}", _DIM))
    out.append(paint("  inputs     " +
                     ", ".join(os.path.basename(i['path']) for i in m.inputs), _DIM))
    repro = (f"  reproduce  habir scan {m.target} "
             f"--db-snapshot {m.db_snapshot.get('content_hash','')}")
    out.append(paint(repro, _DIM))
    return "\n".join(out)


def _render_evidence(node, paint, indent: int) -> list[str]:
    pad = "  " + "   " * indent
    glyph = {"risk": "◆", "version": "├─", "match": "├─", "reachability": "├─",
             "enrichment": "└─", "heuristic": "├─"}.get(node.kind, "•")
    conf = paint(f"[{node.confidence:.2f}]", _DIM)
    line = f"{pad}{glyph} {paint(node.kind, _CYAN)} {conf} {node.claim}"
    lines = [line, f"{pad}   {paint('source: ' + node.source, _DIM)}"]
    for child in node.children:
        lines.extend(_render_evidence(child, paint, indent + 1))
    return lines
