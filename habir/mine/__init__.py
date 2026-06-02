"""
Patch-diff symbol mining — the automated CVE → affected-function pipeline.

Offline-first: operate on a directory of mirrored ``<advisory-id>.patch`` files
(optionally with a local source checkout for AST precision). A ``--repo/--commit``
git mode is available when a local clone exists, using ``git show`` to obtain both
the patch and the post-image source.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from .diff import parse_unified_diff
from .symbols import MineResult, mine_patch, symbols_from_hunk_headers, symbols_from_source

__all__ = ["MineResult", "mine_patch", "mine_patch_file", "mine_repo",
           "parse_unified_diff", "symbols_from_source", "symbols_from_hunk_headers"]


def _source_provider_from_root(source_root: Path | None):
    if source_root is None:
        return None
    root = Path(source_root)

    def provider(path: str) -> str | None:
        # Try the path as-is and with common leading dirs stripped (a/, src/, lib/).
        for candidate in (path, *(_strip_lead(path))):
            fp = root / candidate
            if fp.is_file():
                return fp.read_text(encoding="utf-8", errors="replace")
        return None

    return provider


def _strip_lead(path: str):
    parts = path.split("/")
    for i in range(1, len(parts)):
        yield "/".join(parts[i:])


def mine_patch_file(patch_path: Path, source_root: Path | None = None) -> MineResult:
    text = Path(patch_path).read_text(encoding="utf-8", errors="replace")
    return mine_patch(text, _source_provider_from_root(source_root))


# --------------------------------------------------------------------------- #
# git mode (optional; degrades gracefully without git or a repo)
# --------------------------------------------------------------------------- #
def _git(repo: Path, *args: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(["git", "-C", str(repo), *args],
                              capture_output=True, text=True, timeout=30)
        return proc.returncode, proc.stdout
    except (FileNotFoundError, subprocess.SubprocessError):
        return 1, ""


def mine_repo(repo: Path, commit: str) -> MineResult:
    repo = Path(repo)

    def provider(path: str) -> str | None:
        code, out = _git(repo, "show", f"{commit}:{path}")
        return out if code == 0 else None

    code, patch = _git(repo, "show", "--format=", "--no-color", commit)
    if code != 0 or not patch.strip():
        return MineResult()
    return mine_patch(patch, provider)
