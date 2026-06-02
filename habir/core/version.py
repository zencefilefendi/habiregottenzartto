"""
PEP 440 version engine — self-contained, zero-dependency, deterministic.

Why we re-implement instead of leaning on `packaging`:
  * Air-gap / supply-chain integrity: the SCA tool must not itself pull a
    third-party parser into the trust boundary it is auditing.
  * Determinism is a product promise. A pinned, audited comparator with our
    own test vectors is more defensible than an external version that can drift.

The comparison key faithfully reproduces PEP 440 ordering semantics:
    epoch  <  release  <  pre  <  post  <  dev  <  local
with the subtle rules that a bare dev-release sorts *before* a pre-release,
a release with no pre-release sorts *after* its pre-releases, and trailing
zeros in the release segment are insignificant.
"""

from __future__ import annotations

import re
from functools import total_ordering
from typing import Iterable

__all__ = ["Version", "InvalidVersion", "parse"]


class InvalidVersion(ValueError):
    """Raised when a string is not a valid PEP 440 version."""


# --- ordering sentinels --------------------------------------------------------
class _Infinity:
    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return "Infinity"

    def __lt__(self, other: object) -> bool:
        return False

    def __le__(self, other: object) -> bool:
        return isinstance(other, _Infinity)

    def __gt__(self, other: object) -> bool:
        return not isinstance(other, _Infinity)

    def __ge__(self, other: object) -> bool:
        return True

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Infinity)

    def __hash__(self) -> int:
        return hash(repr(self))


class _NegativeInfinity:
    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return "-Infinity"

    def __lt__(self, other: object) -> bool:
        return not isinstance(other, _NegativeInfinity)

    def __le__(self, other: object) -> bool:
        return True

    def __gt__(self, other: object) -> bool:
        return False

    def __ge__(self, other: object) -> bool:
        return isinstance(other, _NegativeInfinity)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _NegativeInfinity)

    def __hash__(self) -> int:
        return hash(repr(self))


Infinity = _Infinity()
NegativeInfinity = _NegativeInfinity()


# --- grammar -------------------------------------------------------------------
# Adapted from the canonical PEP 440 regular expression.
_VERSION_PATTERN = r"""
    v?
    (?:
        (?:(?P<epoch>[0-9]+)!)?                           # epoch
        (?P<release>[0-9]+(?:\.[0-9]+)*)                  # release
        (?P<pre>                                          # pre-release
            [-_\.]?
            (?P<pre_l>alpha|beta|preview|pre|a|b|c|rc)
            [-_\.]?
            (?P<pre_n>[0-9]+)?
        )?
        (?P<post>                                         # post-release
            (?:-(?P<post_n1>[0-9]+))
            |
            (?:[-_\.]?(?P<post_l>post|rev|r)[-_\.]?(?P<post_n2>[0-9]+)?)
        )?
        (?P<dev>                                          # dev-release
            [-_\.]?
            (?P<dev_l>dev)
            [-_\.]?
            (?P<dev_n>[0-9]+)?
        )?
    )
    (?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?       # local version
"""

_VERSION_RE = re.compile(
    r"^\s*" + _VERSION_PATTERN + r"\s*$",
    re.VERBOSE | re.IGNORECASE,
)

_LOCAL_SEP = re.compile(r"[._-]")

# Normalise the many spellings PyPI tolerates into the canonical pre-release tag.
_PRE_ALIASES = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}
_POST_ALIASES = {"rev": "post", "r": "post"}


def _parse_letter_number(letter: str | None, number: str | None,
                         aliases: dict[str, str]) -> tuple[str, int] | None:
    if letter is None:
        # Implicit post-release form like "1.0-1".
        if number is None:
            return None
        return ("post", int(number))
    letter = letter.lower()
    letter = aliases.get(letter, letter)
    return (letter, int(number) if number is not None else 0)


def _parse_local(local: str | None) -> tuple[object, ...] | None:
    if local is None:
        return None
    parts: list[object] = []
    for seg in _LOCAL_SEP.split(local):
        parts.append(int(seg) if seg.isdigit() else seg.lower())
    return tuple(parts)


@total_ordering
class Version:
    """An immutable, comparable PEP 440 version."""

    __slots__ = ("_raw", "epoch", "release", "pre", "post", "dev", "local", "_key")

    def __init__(self, version: str) -> None:
        match = _VERSION_RE.match(version)
        if match is None:
            raise InvalidVersion(f"invalid PEP 440 version: {version!r}")

        self._raw = version
        self.epoch: int = int(match["epoch"]) if match["epoch"] else 0
        self.release: tuple[int, ...] = tuple(int(p) for p in match["release"].split("."))

        self.pre = _parse_letter_number(match["pre_l"], match["pre_n"], _PRE_ALIASES) \
            if match["pre"] else None

        post_letter = match["post_l"]
        post_number = match["post_n1"] if match["post_n1"] is not None else match["post_n2"]
        self.post = _parse_letter_number(post_letter, post_number, _POST_ALIASES) \
            if match["post"] else None

        self.dev = ("dev", int(match["dev_n"]) if match["dev_n"] is not None else 0) \
            if match["dev"] else None

        self.local = _parse_local(match["local"])
        self._key = _cmpkey(self.epoch, self.release, self.pre, self.post,
                            self.dev, self.local)

    # -- predicates ------------------------------------------------------------
    @property
    def is_prerelease(self) -> bool:
        return self.dev is not None or self.pre is not None

    @property
    def is_postrelease(self) -> bool:
        return self.post is not None

    @property
    def base_version(self) -> str:
        """epoch + release only — used for fuzzy public-version comparison."""
        prefix = f"{self.epoch}!" if self.epoch else ""
        return prefix + ".".join(str(x) for x in self.release)

    # -- dunder ----------------------------------------------------------------
    def __str__(self) -> str:
        return self._raw

    def __repr__(self) -> str:
        return f"Version('{self._raw}')"

    def __hash__(self) -> int:
        return hash(self._key)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            try:
                other = Version(other)
            except InvalidVersion:
                return NotImplemented
        if not isinstance(other, Version):
            return NotImplemented
        return self._key == other._key

    def __lt__(self, other: object) -> bool:
        if isinstance(other, str):
            other = Version(other)
        if not isinstance(other, Version):
            return NotImplemented
        return self._key < other._key


def _cmpkey(epoch: int, release: tuple[int, ...],
            pre: tuple[str, int] | None, post: tuple[str, int] | None,
            dev: tuple[str, int] | None, local: tuple[object, ...] | None):
    # Trailing zeros in the release segment are not significant for ordering.
    trimmed = tuple(
        reversed(list(_drop_leading(reversed(release), lambda x: x == 0)))
    )

    if pre is None and post is None and dev is not None:
        _pre: object = NegativeInfinity     # a bare dev release sorts first
    elif pre is None:
        _pre = Infinity                     # final/post release sorts after pre
    else:
        _pre = pre

    _post: object = NegativeInfinity if post is None else post
    _dev: object = Infinity if dev is None else dev

    if local is None:
        _local: object = NegativeInfinity
    else:
        # Numeric local segments outrank alpha; encode each per PEP 440.
        _local = tuple(
            (i, "") if isinstance(i, int) else (NegativeInfinity, i) for i in local
        )

    return (epoch, trimmed, _pre, _post, _dev, _local)


def _drop_leading(seq: Iterable[int], pred):
    seq = list(seq)
    i = 0
    while i < len(seq) and pred(seq[i]):
        i += 1
    return seq[i:]


def parse(version: str) -> Version:
    return Version(version)
