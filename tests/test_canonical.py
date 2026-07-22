"""Unit tests for skillscan_core.canonical (coding spec M1, §5.2 - INV-6/INV-7)."""

from __future__ import annotations

import unittest

from skillscan_core import EngineMetadata
from skillscan_core.canonical import cache_key, content_hash, toolchain_digest


class TestContentHash(unittest.TestCase):
    def test_order_independent(self) -> None:
        files_a = [("a.py", 0o644, b"x"), ("b.py", 0o644, b"y")]
        files_b = [("b.py", 0o644, b"y"), ("a.py", 0o644, b"x")]
        self.assertEqual(content_hash(files_a), content_hash(files_b))

    def test_mode_sensitive(self) -> None:
        h1 = content_hash([("a.py", 0o644, b"x")])
        h2 = content_hash([("a.py", 0o755, b"x")])
        self.assertNotEqual(h1, h2)

    def test_raw_bytes_sensitive(self) -> None:
        h1 = content_hash([("a.py", 0o644, b"x\n")])
        h2 = content_hash([("a.py", 0o644, b"x\r\n")])
        self.assertNotEqual(h1, h2)

    def test_rejects_absolute_path(self) -> None:
        with self.assertRaises(ValueError):
            content_hash([("/etc/passwd", 0o644, b"x")])

    def test_rejects_dotdot_segment(self) -> None:
        with self.assertRaises(ValueError):
            content_hash([("../escape.py", 0o644, b"x")])

    def test_rejects_dot_segment(self) -> None:
        with self.assertRaises(ValueError):
            content_hash([("a/./b.py", 0o644, b"x")])

    def test_rejects_empty_segment(self) -> None:
        with self.assertRaises(ValueError):
            content_hash([("a//b.py", 0o644, b"x")])

    def test_rejects_drive_letter(self) -> None:
        with self.assertRaises(ValueError):
            content_hash([("C:/windows.py", 0o644, b"x")])

    # INV-6 regression (2026-07-06 spec-compliance audit): a '..'/'.' segment
    # hidden behind a backslash (no literal '/' at all) must be rejected the
    # same way a forward-slash equivalent already is - the deployment target
    # is POSIX, where '\' has no separator meaning to the OS, but archive/tar
    # member names and engine adapters may still treat it as one.
    def test_rejects_dotdot_segment_hidden_behind_backslash(self) -> None:
        with self.assertRaises(ValueError):
            content_hash([("..\\..\\etc\\passwd", 0o644, b"x")])

    def test_rejects_dot_segment_hidden_behind_backslash(self) -> None:
        with self.assertRaises(ValueError):
            content_hash([("scripts\\.\\run.py", 0o644, b"x")])

    def test_rejects_mixed_slash_and_backslash_traversal(self) -> None:
        with self.assertRaises(ValueError):
            content_hash([("scripts/..\\..\\secret.py", 0o644, b"x")])

    def test_allows_literal_backslash_character_in_a_real_filename(self) -> None:
        # A literal backslash inside a single path segment is a legal POSIX
        # filename character, not a traversal attempt - must NOT be rejected
        # just because it contains '\'.
        h = content_hash([("scripts/weird\\name.py", 0o644, b"x")])
        self.assertIsInstance(h, str)

    def test_rejects_nul_byte(self) -> None:
        with self.assertRaises(ValueError):
            content_hash([("a\x00.py", 0o644, b"x")])

    def test_rejects_empty_file_set(self) -> None:
        with self.assertRaises(ValueError):
            content_hash([])

    def test_rejects_duplicate_after_nfc_normalization(self) -> None:
        composed = "caf\u00e9.py"  # single precomposed codepoint U+00E9
        decomposed = "cafe\u0301.py"  # 'e' + combining acute U+0301 -> same NFC form
        self.assertNotEqual(composed, decomposed)  # sanity: genuinely different raw strings
        with self.assertRaises(ValueError):
            content_hash([(composed, 0o644, b"x"), (decomposed, 0o644, b"y")])

    def test_deterministic(self) -> None:
        files = [("a.py", 0o644, b"x")]
        self.assertEqual(content_hash(files), content_hash(files))


class TestToolchainDigest(unittest.TestCase):
    def _engine(self, version: str = "1.0.0") -> EngineMetadata:
        return EngineMetadata(
            name="eng", version=version, ruleset_digest="d1", capabilities=frozenset()
        )

    def test_changes_on_engine_version_bump(self) -> None:
        d1 = toolchain_digest([self._engine("1.0.0")], "policy-v1")
        d2 = toolchain_digest([self._engine("1.0.1")], "policy-v1")
        self.assertNotEqual(d1, d2)

    def test_changes_on_policy_version_bump(self) -> None:
        d1 = toolchain_digest([self._engine()], "policy-v1")
        d2 = toolchain_digest([self._engine()], "policy-v2")
        self.assertNotEqual(d1, d2)

    def test_changes_on_prompt_version_bump(self) -> None:
        d1 = toolchain_digest([self._engine()], "policy-v1", prompt_version="p1")
        d2 = toolchain_digest([self._engine()], "policy-v1", prompt_version="p2")
        self.assertNotEqual(d1, d2)

    def test_order_independent(self) -> None:
        e1 = self._engine("1.0.0")
        e2 = EngineMetadata(
            name="other", version="2.0.0", ruleset_digest="d2", capabilities=frozenset()
        )
        self.assertEqual(toolchain_digest([e1, e2], "p"), toolchain_digest([e2, e1], "p"))


class TestCacheKey(unittest.TestCase):
    def test_changes_with_content_hash(self) -> None:
        self.assertNotEqual(cache_key("h1", "t1"), cache_key("h2", "t1"))

    def test_changes_with_toolchain_digest(self) -> None:
        self.assertNotEqual(cache_key("h1", "t1"), cache_key("h1", "t2"))

    def test_deterministic(self) -> None:
        self.assertEqual(cache_key("h1", "t1"), cache_key("h1", "t1"))


if __name__ == "__main__":
    unittest.main()
