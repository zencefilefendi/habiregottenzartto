"""Patch-diff symbol mining: parser, AST + hunk-header extraction, store merge."""

from habir.mine import mine_patch
from habir.mine.diff import parse_unified_diff
from habir.mine.symbols import symbols_from_hunk_headers, symbols_from_source

_PATCH = """\
diff --git a/pkg/mod.py b/pkg/mod.py
index 111..222 100644
--- a/pkg/mod.py
+++ b/pkg/mod.py
@@ -10,7 +10,8 @@ def vulnerable(self, x):
     a = 1
-    return danger(x)
+    check(x)
+    return danger(x)
@@ -40,6 +41,8 @@ class Loader:
     def safe(self):
+        guard()
         return ok
"""


def test_diff_parser_tracks_paths_and_lines():
    files = parse_unified_diff(_PATCH)
    assert len(files) == 1
    fd = files[0]
    assert fd.new_path == "pkg/mod.py" and fd.is_python
    # added lines recorded with new-image line numbers
    assert fd.changed_new_lines()  # non-empty
    assert "def vulnerable(self, x):" in fd.section_headers()[0]


def test_hunk_header_symbol_extraction():
    fd = parse_unified_diff(_PATCH)[0]
    syms = symbols_from_hunk_headers(fd)
    assert "vulnerable" in syms
    assert "Loader" in syms


def test_ast_symbol_extraction_is_qualified():
    source = (
        "class Loader:\n"
        "    def safe(self):\n"
        "        guard()\n"            # line 3
        "        return ok\n"
        "def free():\n"
        "    return danger()\n"        # line 6
    )
    assert symbols_from_source(source, {3}) == {"Loader.safe"}
    assert symbols_from_source(source, {6}) == {"free"}


def test_mine_patch_hunk_header_mode():
    result = mine_patch(_PATCH)              # no source provider → hunk headers
    assert "hunk-header" in result.method
    assert "vulnerable" in result.short


def test_mine_patch_ast_mode_prefers_source():
    # post-image source: the changed line (2) lives inside real_target
    source = "def real_target():\n    x = 2\n    return 1\n"
    patch = ("diff --git a/m.py b/m.py\n--- a/m.py\n+++ b/m.py\n"
             "@@ -1,2 +1,3 @@ def wrong_header():\n"
             " def real_target():\n+    x = 2\n     return 1\n")
    # When source is available, AST line-spans win over the (wrong) hunk header.
    result = mine_patch(patch, source_provider=lambda p: source)
    assert "ast" in result.method
    assert "real_target" in result.short
    assert "wrong_header" not in result.short


def test_store_merges_mined_symbols(store):
    # The requests advisory ships with NO hand-authored symbols; mining fills it.
    vulns = store.lookup("PyPI", "requests")
    advisory = next(v for v in vulns if v.id == "GHSA-x84v-xcm2-53pg")
    symbols = {s for aff in advisory.affected for s in aff.affected_symbols}
    assert {"rebuild_auth", "resolve_redirects"} <= symbols
