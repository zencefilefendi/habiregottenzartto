"""
Unified-diff parser — the front end of the symbol-mining moat.

Given a fixing commit's patch, we need to know *exactly which lines changed* in
which files, with correct pre-image and post-image line numbers, so the symbol
resolver can map those lines back to the functions that were patched. Pure
stdlib, deterministic, no git binary required.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = ["FileDiff", "Hunk", "parse_unified_diff"]

_HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))?"
    r" \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?P<section>.*)$"
)


@dataclass(slots=True)
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    section: str                       # text after the second @@ (git xfuncname context)
    added: list[tuple[int, str]] = field(default_factory=list)    # (new_lineno, text)
    removed: list[tuple[int, str]] = field(default_factory=list)  # (old_lineno, text)


@dataclass(slots=True)
class FileDiff:
    old_path: str | None
    new_path: str | None
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def is_python(self) -> bool:
        p = self.new_path or self.old_path or ""
        return p.endswith(".py")

    def changed_new_lines(self) -> set[int]:
        return {ln for h in self.hunks for ln, _ in h.added}

    def changed_old_lines(self) -> set[int]:
        return {ln for h in self.hunks for ln, _ in h.removed}

    def section_headers(self) -> list[str]:
        return [h.section.strip() for h in self.hunks if h.section.strip()]


def _strip_prefix(path: str) -> str | None:
    path = path.strip()
    if path in ("/dev/null", ""):
        return None
    # drop the a/ or b/ git prefix
    if path[:2] in ("a/", "b/"):
        return path[2:]
    return path


def parse_unified_diff(text: str) -> list[FileDiff]:
    files: list[FileDiff] = []
    current: FileDiff | None = None
    hunk: Hunk | None = None
    old_lineno = new_lineno = 0

    for raw in text.splitlines():
        if raw.startswith("diff --git"):
            current = FileDiff(old_path=None, new_path=None)
            files.append(current)
            hunk = None
            continue

        if raw.startswith("--- "):
            if current is None:
                current = FileDiff(old_path=None, new_path=None)
                files.append(current)
            current.old_path = _strip_prefix(raw[4:])
            hunk = None
            continue

        if raw.startswith("+++ "):
            if current is not None:
                current.new_path = _strip_prefix(raw[4:])
            hunk = None
            continue

        m = _HUNK_RE.match(raw)
        if m and current is not None:
            hunk = Hunk(
                old_start=int(m["old_start"]),
                old_count=int(m["old_count"] or 1),
                new_start=int(m["new_start"]),
                new_count=int(m["new_count"] or 1),
                section=m["section"],
            )
            current.hunks.append(hunk)
            old_lineno = hunk.old_start
            new_lineno = hunk.new_start
            continue

        if hunk is None:
            continue

        tag, body = (raw[:1], raw[1:]) if raw else (" ", "")
        if tag == "+":
            hunk.added.append((new_lineno, body))
            new_lineno += 1
        elif tag == "-":
            hunk.removed.append((old_lineno, body))
            old_lineno += 1
        elif tag == "\\":          # "\ No newline at end of file"
            continue
        else:                      # context line advances both sides
            old_lineno += 1
            new_lineno += 1

    return files
