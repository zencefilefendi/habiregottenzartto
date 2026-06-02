import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from habir import mine as mine_mod       # noqa: E402
from habir.data import seed_dir          # noqa: E402
from habir.vuln import VulnStore         # noqa: E402

DEMO = ROOT / "examples" / "demo-project"


def _mine_bundled(store: VulnStore) -> None:
    patch_dir = seed_dir() / "patches"
    for patch in sorted(patch_dir.glob("*.patch")):
        advisory = patch.stem
        if not store.has_vuln(advisory):
            continue
        result = mine_mod.mine_patch_file(patch)
        for eco, name in store.affected_packages(advisory):
            store.add_mined_symbols(advisory, eco, name, result, source="test")


@pytest.fixture(scope="session")
def store(tmp_path_factory):
    db = tmp_path_factory.mktemp("db") / "osv.db"
    s = VulnStore(db)
    s.sync_from_seed(seed_dir(), source_label="test-seed")
    _mine_bundled(s)
    yield s
    s.close()


@pytest.fixture
def demo_dir() -> Path:
    return DEMO
