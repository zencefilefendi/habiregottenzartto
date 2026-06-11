"""
Dynamic Reachability Tracer.

Intercepts execution of a Python script or module to record precisely which
functions are called at runtime. This provides cryptographic proof of
reachability (REACH:DYN).
"""

from __future__ import annotations

import json
import os
import sys
import runpy
from pathlib import Path
from typing import Any

# Global set of executed (module, function) pairs.
_reached: set[tuple[str, str]] = set()

def _trace_calls(frame: Any, event: str, arg: Any) -> Any:
    """sys.settrace callback to record function calls."""
    if event != "call":
        return None

    code = frame.f_code
    func_name = code.co_name
    # Ignore internal/magic methods to keep overhead low
    if func_name.startswith("<") and func_name != "<module>":
        return None

    # Resolve module name
    module_name = frame.f_globals.get("__name__", "")

    if module_name:
        _reached.add((module_name, func_name))

    return None

def start_trace() -> None:
    """Activate the tracer."""
    sys.settrace(_trace_calls)

def stop_trace() -> None:
    """Deactivate the tracer."""
    sys.settrace(None)

def save_trace(output_path: Path) -> None:
    """Save the recorded execution trace to a file."""
    # Group by module for compact storage
    trace_data: dict[str, list[str]] = {}
    for mod, func in _reached:
        if mod not in trace_data:
            trace_data[mod] = []
        trace_data[mod].append(func)

    # Sort for deterministic output
    for mod in trace_data:
        trace_data[mod].sort()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(trace_data, indent=2), encoding="utf-8")
    print(
        f"\n[habir] Dynamic trace saved to {output_path} ({len(_reached)} functions recorded)",
        file=sys.stderr,
    )

def run_traced(args: list[str], output_path: Path) -> int:
    """Run a module or script under the tracer."""
    if not args:
        print(
            "Error: No command to trace. Usage: habir trace [-m module | script.py] [args...]",
            file=sys.stderr,
        )
        return 1

    # Emulate python's standard execution (-m or script)
    is_module = False
    if args[0] == "-m":
        if len(args) < 2:
            print("Error: -m requires a module name.", file=sys.stderr)
            return 1
        is_module = True
        target = args[1]
        sys.argv = args[1:]
    else:
        target = args[0]
        sys.argv = args

    # Inject current directory into sys.path like python does
    sys.path.insert(0, os.path.abspath(os.getcwd() if is_module else os.path.dirname(target)))

    start_trace()
    try:
        if is_module:
            runpy.run_module(target, run_name="__main__", alter_sys=True)
        else:
            runpy.run_path(target, run_name="__main__")
    except Exception as e:
        # Ignore SystemExit so we still save the trace on normal exit (like pytest does)
        if not isinstance(e, SystemExit):
            print(f"\n[habir] Trace target raised an exception: {e}", file=sys.stderr)
            raise
    finally:
        stop_trace()
        save_trace(output_path)

    return 0
