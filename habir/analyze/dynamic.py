"""
Dynamic Analysis integration.
Parses the runtime trace file and maps it to reachability results.
"""

from __future__ import annotations

import json
from pathlib import Path
from ..core.model import ReachabilityResult

def load_trace(trace_path: Path) -> dict[str, set[str]]:
    """Load a dynamic trace file into a dictionary of module -> set(functions)."""
    if not trace_path.exists():
        return {}

    try:
        data = json.loads(trace_path.read_text(encoding="utf-8", errors="replace"))
        return {mod: set(funcs) for mod, funcs in data.items()}
    except json.JSONDecodeError:
        return {}

def refine_with_trace(
    base: ReachabilityResult,
    dist: str,
    affected_symbols: list[str],
    trace: dict[str, set[str]]
) -> ReachabilityResult:
    """Combine existing reachability with empirical runtime evidence."""
    if not trace:
        return base

    out = ReachabilityResult(
        status=base.status,
        imported_symbols=list(base.imported_symbols),
        entry_paths=list(base.entry_paths),
        analysis=(
            "dynamic-trace"
            if base.analysis in ("package-level", "function-level", "cross-package")
            else base.analysis
        ),
        symbol_hit=base.symbol_hit,
        call_path=list(base.call_path),
        affected_fn_not_reached=base.affected_fn_not_reached,
        deep=base.deep,
        proven_sink_unreachable=base.proven_sink_unreachable,
    )

    # Check if the vulnerable package was reached dynamically
    # Note: package name `requests` vs module name `requests` or `requests.models`
    # We look for any trace module starting with the distribution's canonical name
    # or the actual affected symbol (which is fully qualified like
    # `requests.models.PreparedRequest`)

    hit = False
    reached_vulnerable_symbols = []

    for symbol in affected_symbols:
        # Symbol might be `requests.models.PreparedRequest.prepare`
        parts = symbol.split(".")
        if len(parts) > 1:
            mod = ".".join(parts[:-1])
            func = parts[-1]
            if mod in trace and func in trace[mod]:
                hit = True
                reached_vulnerable_symbols.append(symbol)

    if hit:
        out.status = out.status  # Maintain REACHABLE
        out.symbol_hit = True
        out.analysis = "dynamic-trace"
        out.dynamic = True
        out.affected_fn_not_reached = False
        out.call_path = [f"RUNTIME CONFIRMED: {s}" for s in reached_vulnerable_symbols]

    return out
