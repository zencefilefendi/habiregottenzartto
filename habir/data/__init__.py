"""Loaders for bundled, offline reference data (not the vuln DB)."""

from __future__ import annotations

import functools
import json
from pathlib import Path

_SEED = Path(__file__).parent / "seed"


@functools.lru_cache(maxsize=1)
def top_packages() -> list[str]:
    """Popular PyPI names — the reference set for typosquat distance checks."""
    f = _SEED / "top-pypi-packages.txt"
    if not f.exists():
        return []
    return [ln.strip().lower() for ln in f.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.startswith("#")]


@functools.lru_cache(maxsize=1)
def import_map() -> dict[str, str]:
    """Map a top-level import name to its canonical PyPI distribution name.

    Reachability needs this because `import yaml` ships from `PyYAML`, `import cv2`
    from `opencv-python`, etc. Unmapped names fall back to name==dist.
    """
    f = _SEED / "import-map.json"
    if not f.exists():
        return {}
    return {k.lower(): v.lower() for k, v in json.loads(f.read_text(encoding="utf-8")).items()}


def seed_dir() -> Path:
    return _SEED
