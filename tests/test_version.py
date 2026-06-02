import pytest

from habir.core.version import InvalidVersion, Version as V


def test_canonical_ordering_is_monotonic():
    order = ["1.0.dev0", "1.0a1.dev1", "1.0a1", "1.0b1", "1.0rc1", "1.0",
             "1.0.post1", "1.0.1", "1.1", "2.0", "1!0.1"]
    vs = [V(s) for s in order]
    assert all(vs[i] < vs[i + 1] for i in range(len(vs) - 1))


@pytest.mark.parametrize("a,b", [
    ("1.0", "1.0.0"), ("1.0.0", "1.0"), ("1.0BETA2", "1.0b2"),
    ("1.0-1", "1.0.post1"), ("1.0c1", "1.0rc1"), ("1!1.0", "1!1.0.0"),
])
def test_equivalence(a, b):
    assert V(a) == V(b)


@pytest.mark.parametrize("a,b", [
    ("1.0a1", "1.0"), ("1.0", "1.0.post1"), ("1.0.dev1", "1.0a1"),
    ("2.19.1", "2.20.0"), ("5.1", "5.3.1"), ("1.0", "1.0+local"),
    ("1.0", "2!0.1"),
])
def test_strict_less_than(a, b):
    assert V(a) < V(b)
    assert V(b) > V(a)


def test_predicates():
    assert V("1.0a1").is_prerelease
    assert V("1.0.dev0").is_prerelease
    assert not V("1.0").is_prerelease
    assert V("1.0.post1").is_postrelease
    assert V("1!2.3.4").base_version == "1!2.3.4"


def test_invalid_raises():
    for bad in ["", "not-a-version", "1.0.0.0.x", "??"]:
        with pytest.raises(InvalidVersion):
            V(bad)
