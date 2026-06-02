"""
habir — command-line entrypoint.

    habir scan <target> [--format terminal|json|sarif|vex] [--explain]
                        [--fail-on critical|high|medium|low] [--min-risk N]
    habir db sync [--seed DIR]
    habir db info
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __tool__, __version__
from .core.model import RiskBand
from .data import seed_dir
from .engine import scan
from .report import FORMATTERS
from .report import terminal
from .vuln import VulnStore, DEFAULT_DB_PATH

_BAND_ORDER = [RiskBand.INFO, RiskBand.LOW, RiskBand.MEDIUM, RiskBand.HIGH,
               RiskBand.CRITICAL]


def _mine_patches_dir(store: VulnStore, patch_dir: Path, *,
                      source_root: Path | None = None, source: str = "seed-patch",
                      verbose: bool = False) -> tuple[int, int]:
    """Mine every <advisory-id>.patch in a directory into the store."""
    from . import mine as mine_mod
    advisories = symbols = 0
    if not patch_dir.is_dir():
        return (0, 0)
    for patch in sorted(patch_dir.glob("*.patch")) + sorted(patch_dir.glob("*.diff")):
        advisory = patch.stem
        if not store.has_vuln(advisory):
            if verbose:
                sys.stderr.write(f"  skip {advisory}: not in vuln-db\n")
            continue
        result = mine_mod.mine_patch_file(patch, source_root)
        if result.is_empty():
            if verbose:
                sys.stderr.write(f"  warn {advisory}: no symbols extracted\n")
            continue
        for eco, name in store.affected_packages(advisory):
            symbols += store.add_mined_symbols(advisory, eco, name, result, source=source)
        advisories += 1
        if verbose:
            print(f"  {advisory:24} [{','.join(result.method)}] → {result.short}")
    return (advisories, symbols)


def _open_store(db_path: str | None, *, auto_seed: bool) -> VulnStore:
    store = VulnStore(Path(db_path) if db_path else DEFAULT_DB_PATH)
    if store.is_empty() and auto_seed:
        sys.stderr.write(f"{__tool__}: local vuln-db empty — seeding from bundled "
                         f"snapshot + mining patches (run `habir db sync` to refresh)\n")
        store.sync_from_seed(seed_dir(), source_label="bundled-seed")
        _mine_patches_dir(store, seed_dir() / "patches")
    return store


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.exists():
        sys.stderr.write(f"{__tool__}: target not found: {target}\n")
        return 2

    store = _open_store(args.db, auto_seed=True)
    deps_roots = [Path(d) for d in (args.deps_path or [])]
    result = scan(target, store, deps_roots=deps_roots)

    if args.min_risk:
        result.findings = [f for f in result.findings
                           if f.risk and f.risk.value >= args.min_risk]

    renderer = FORMATTERS[args.format]
    if args.format == "terminal":
        text = terminal.render(result, explain=args.explain,
                               color=None if not args.no_color else False)
    else:
        text = renderer(result)

    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        sys.stderr.write(f"{__tool__}: wrote {args.format} report → {args.output}\n")
    else:
        print(text)

    store.close()
    return _exit_code(result, args.fail_on)


def _exit_code(result, fail_on: str | None) -> int:
    if not fail_on:
        return 0
    threshold = RiskBand(fail_on.upper())
    tindex = _BAND_ORDER.index(threshold)
    for f in result.findings:
        if f.risk and _BAND_ORDER.index(f.risk.band) >= tindex:
            return 1
    return 0


def cmd_db_sync(args: argparse.Namespace) -> int:
    src = Path(args.seed) if args.seed else seed_dir()
    store = VulnStore(Path(args.db) if args.db else DEFAULT_DB_PATH)
    label = "seed" if args.seed else "bundled-seed"
    snap = store.sync_from_seed(src, source_label=label)
    store.close()
    print(f"{__tool__}: synced vuln-db from {src}")
    for k, v in snap.items():
        print(f"  {k:14} {v}")
    return 0


def cmd_mine(args: argparse.Namespace) -> int:
    from . import mine as mine_mod
    store = VulnStore(Path(args.db) if args.db else DEFAULT_DB_PATH)
    if store.is_empty():
        sys.stderr.write(f"{__tool__}: vuln-db empty — run `habir db sync` first\n")
        return 2

    if args.repo and args.commit and args.advisory:
        result = mine_mod.mine_repo(Path(args.repo), args.commit)
        symbols = 0
        for eco, name in store.affected_packages(args.advisory):
            symbols += store.add_mined_symbols(args.advisory, eco, name, result,
                                               source=f"git:{args.commit[:12]}")
        store.close()
        print(f"{__tool__}: mined {args.advisory} from {args.repo}@{args.commit[:12]} "
              f"[{', '.join(result.method) or 'none'}] → {result.short}")
        return 0

    if args.repo or args.commit or args.advisory:
        sys.stderr.write(f"{__tool__}: git mode needs all of --repo, --commit, --advisory\n")
        return 2

    src_root = Path(args.source_root) if args.source_root else None
    patch_dir = Path(args.patches) if args.patches else (seed_dir() / "patches")
    if not patch_dir.is_dir():
        sys.stderr.write(f"{__tool__}: no patch directory at {patch_dir}\n")
        return 2
    advisories, symbols = _mine_patches_dir(store, patch_dir, source_root=src_root,
                                            verbose=True)
    store.close()
    print(f"{__tool__}: mined {symbols} symbols across {advisories} advisories")
    return 0


def cmd_db_info(args: argparse.Namespace) -> int:
    store = VulnStore(Path(args.db) if args.db else DEFAULT_DB_PATH)
    if store.is_empty():
        print(f"{__tool__}: vuln-db is empty — run `habir db sync`")
        return 0
    for k, v in store.snapshot_info().items():
        print(f"  {k:14} {v}")
    print(f"  {'mined_advisories':14} {store.mined_count()}")
    store.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="habir",
        description=f"{__tool__} v{__version__} — deterministic, reachability-aware "
                    "supply-chain intelligence engine.")
    p.add_argument("--version", action="version", version=f"{__tool__} {__version__}")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan a project or manifest")
    s.add_argument("target", help="directory, lock file, or requirements file")
    s.add_argument("--format", choices=list(FORMATTERS), default="terminal")
    s.add_argument("--explain", action="store_true", help="print the evidence DAG")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                   help="exit non-zero if a finding meets/exceeds this band (CI gate)")
    s.add_argument("--min-risk", type=float, default=0.0,
                   help="suppress findings below this risk score")
    s.add_argument("--deps-path", action="append", metavar="DIR",
                   help="dependency source root for cross-package reachability "
                        "(repeatable; venv site-packages / vendor auto-detected)")
    s.add_argument("--output", "-o", help="write report to a file instead of stdout")
    s.add_argument("--db", help=f"vuln-db path (default {DEFAULT_DB_PATH})")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(func=cmd_scan)

    db = sub.add_parser("db", help="manage the local vulnerability database")
    dbsub = db.add_subparsers(dest="db_command", required=True)
    sync = dbsub.add_parser("sync", help="(re)build the local DB from a seed/mirror")
    sync.add_argument("--seed", help="seed directory (default: bundled snapshot)")
    sync.add_argument("--db", help=f"vuln-db path (default {DEFAULT_DB_PATH})")
    sync.set_defaults(func=cmd_db_sync)
    info = dbsub.add_parser("info", help="show the current DB snapshot")
    info.add_argument("--db", help=f"vuln-db path (default {DEFAULT_DB_PATH})")
    info.set_defaults(func=cmd_db_info)

    mine = sub.add_parser("mine", help="auto-extract affected functions from fix patches")
    mine.add_argument("--patches", help="directory of <advisory-id>.patch files")
    mine.add_argument("--source-root",
                      help="optional source checkout enabling precise AST mining")
    mine.add_argument("--repo", help="local git clone to mine from")
    mine.add_argument("--commit", help="fixing commit SHA (with --repo)")
    mine.add_argument("--advisory", help="advisory id the commit fixes (with --repo)")
    mine.add_argument("--db", help=f"vuln-db path (default {DEFAULT_DB_PATH})")
    mine.set_defaults(func=cmd_mine)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        return 130
    except BrokenPipeError:
        return 0
    except Exception as exc:  # noqa: BLE001 - top-level guard for a clean CLI
        if os.environ.get("HABIR_DEBUG"):
            raise
        sys.stderr.write(f"{__tool__}: error: {type(exc).__name__}: {exc}\n"
                         f"  (set HABIR_DEBUG=1 for a full traceback)\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
