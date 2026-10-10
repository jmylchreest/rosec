#!/usr/bin/env python3
"""Offline regression tests for the upstream change detector."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("proton_upstream", ROOT / "contrib/check-proton-upstream.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
A, B, C = "a" * 40, "b" * 40, "c" * 40


def tree(entries, truncated=False):
    return {"truncated": truncated, "tree": [
        {"path": path, "type": "blob", "sha": sha} for path, sha in entries.items()
    ]}


class UpstreamTests(unittest.TestCase):
    def test_current_provenance_pins_parse(self):
        pins = checker.read_pins((ROOT / "rosec-protonpass/UPSTREAM.txt").read_text())
        self.assertEqual(set(pins), set(checker.SCOPES))
        for tag, sha in pins.values():
            self.assertTrue(tag)
            self.assertEqual(checker.checked_sha(sha), sha)

    def test_missing_duplicate_or_invalid_pin_fails(self):
        text = (ROOT / "rosec-protonpass/UPSTREAM.txt").read_text()
        for broken in ("", text + text, text.replace("Commit:", "Unknown:")):
            with self.assertRaises(ValueError):
                checker.read_pins(broken)

    def test_scope_boundaries_and_added_removed_changed(self):
        before = checker.scoped_tree(tree({"src/key.rs": A, "src/old.rs": A,
                                          "src-other/unrelated.rs": A}), ("src",))
        after = checker.scoped_tree(tree({"src/key.rs": B, "src/new.rs": B,
                                         "docs/readme.md": B}), ("src",))
        self.assertEqual(checker.changes(before, after), [
            ("src/key.rs", "changed"), ("src/new.rs", "added"), ("src/old.rs", "removed")])

    def test_unrelated_changes_do_not_alert(self):
        before = checker.scoped_tree(tree({"src/key.rs": A, "README.md": A}), ("src",))
        after = checker.scoped_tree(tree({"src/key.rs": A, "README.md": B}), ("src",))
        self.assertEqual(checker.changes(before, after), [])

    def test_incomplete_or_missing_baseline_is_not_success(self):
        for payload in (tree({"src/key.rs": A}, True), {}, [], tree({"src/key.rs": "bad"})):
            with self.assertRaises(ValueError):
                checker.scoped_tree(payload, ("src",))
        with self.assertRaises(ValueError):
            checker.changes({}, {})
        self.assertEqual(checker.changes({"src/key.rs": A}, {}), [("src/key.rs", "removed")])

    def test_report_uses_pinned_and_snapshot_tree(self):
        def fetch(repo, endpoint):
            return {f"commits/{A}": {"commit": {"tree": {"sha": A}}},
                    "commits?per_page=1": [{"sha": C, "commit": {"tree": {"sha": B}}}],
                    f"git/trees/{A}?recursive=1": tree({"src/key.rs": A}),
                    f"git/trees/{B}?recursive=1": tree({"src/key.rs": B})}[endpoint]
        with patch.dict(checker.SCOPES, {"example/repo": ("src",)}, clear=True):
            drift, report = checker.check({"example/repo": ("1.0.0", A)}, fetch)
        self.assertTrue(drift)
        self.assertIn(f"compare/{A}...{C}", report)
        self.assertIn("changed: `src/key.rs`", report)
        with patch.dict(checker.SCOPES, {"example/repo": ("src", "missing")}, clear=True):
            with self.assertRaises(ValueError):
                checker.check({"example/repo": ("1.0.0", A)}, fetch)

    def test_cli_exit_codes_summary_and_redacted_errors(self):
        for result, code in (((False, "unchanged"), 0), ((True, "review"), 1),
                             (OSError("private diagnostic"), 2)):
            with tempfile.TemporaryDirectory() as directory:
                summary = Path(directory) / "summary"
                with patch.object(sys, "argv", ["check", "--summary", str(summary)]), \
                     patch.object(checker, "check", side_effect=result if isinstance(result, Exception) else None,
                                  return_value=result), contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(checker.main(), code)
                self.assertIn(summary.read_text().strip(), out.getvalue())
                self.assertNotIn("private diagnostic", out.getvalue())


if __name__ == "__main__":
    unittest.main()
