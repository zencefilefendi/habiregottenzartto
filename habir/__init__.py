"""
habiregottenzartto — a deterministic, reachability-aware supply-chain
intelligence engine.

Principles: determinism over guessing · transparency over abstraction ·
local-first & air-gap capable. Every verdict carries its evidence.
"""

__version__ = "0.1.0"
__tool__ = "habiregottenzartto"

from .core.version import Version, InvalidVersion  # noqa: E402,F401
from .core.purl import PackageURL  # noqa: E402,F401
