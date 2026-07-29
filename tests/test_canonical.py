"""Unit tests for skillscan_core.canonical (coding spec M1, §5.2 - INV-6/INV-7)."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from skillscan_core import EngineMetadata
from skillscan_core.canonical import cache_key, content_hash, toolchain_digest

_REPO_ROOT = Path(__file__).resolve().parent.parent


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


class TestEveryCallSitePassesTheCachePolicyVersion(unittest.TestCase):
    """INV-7, milestone C Tasks 5 and 11: `toolchain_digest`'s policy term must
    be `GatePolicy.cache_policy_version`, never any other attribute of the
    policy.

    Task 5 wrote this as a BLOCKLIST of one - "not `.version`" - because
    `.version` was the only wrong answer that existed. The two spellings differ
    only when the policy carries something the bare version does not name,
    which is the case nobody exercises by accident: a call site that kept
    passing `.version` would look correct in every test and every review, and
    would misbehave only on the day someone first edited a weight or a
    threshold, serving that scan the cache entry of the old policy.

    Task 11 turned it into an ALLOWLIST of one - the argument must be spelled
    `cache_policy_version` - because binding the whole policy makes several
    more attributes plausible-looking and equally wrong (`.policy_version`, a
    future `.semantics_digest`, `.adjudication_semantics()`), and a blocklist
    says nothing about a name nobody thought of. This also fixes the case the
    Task 5 form silently allowed: `toolchain_digest(engines, policy.name)`.

    DISCOVERS the call sites by walking the source rather than listing them.
    `ScanRuntime.current_toolchain_digest` exists precisely because this
    expression had already been duplicated once (see its docstring); a hardcoded
    list of the two known sites did not notice the third, which this walk found
    (`gateway/router.py`).
    """

    _SCANNED_DIRS = ("apps", "services", "libs", "scripts")
    _REQUIRED_TERM = "cache_policy_version"

    def _call_sites(self) -> list[tuple[str, ast.expr]]:
        """(location, the policy-term argument node) for every real
        `toolchain_digest(...)` call in the tree."""
        sites: list[tuple[str, ast.expr]] = []
        for top in self._SCANNED_DIRS:
            for path in sorted((_REPO_ROOT / top).rglob("*.py")):
                if "vendor" in path.parts or "__pycache__" in path.parts:
                    continue
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue
                    func = node.func
                    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                    if not name.endswith("toolchain_digest") or name.startswith("current_"):
                        continue
                    # arg 1 is `policy_version`. Also accept the keyword form,
                    # which the positional-only walk used to skip entirely.
                    arg: ast.expr | None = node.args[1] if len(node.args) > 1 else None
                    if arg is None:
                        arg = next(
                            (kw.value for kw in node.keywords if kw.arg == "policy_version"), None
                        )
                    if arg is None:
                        continue
                    sites.append((f"{path.relative_to(_REPO_ROOT)}:{node.lineno} {name}()", arg))
        return sites

    def _offending_call_sites(self) -> list[str]:
        offenders: list[str] = []
        for location, arg in self._call_sites():
            # A literal (test fixture) is fine. Reading ANY attribute other
            # than cache_policy_version off a policy object is the bug.
            if isinstance(arg, ast.Attribute) and arg.attr != self._REQUIRED_TERM:
                offenders.append(f"{location} passes .{arg.attr}")
        return offenders

    def test_no_call_site_passes_anything_but_the_cache_policy_version(self) -> None:
        offenders = self._offending_call_sites()
        self.assertEqual(
            offenders,
            [],
            "toolchain_digest's policy term must be GatePolicy.cache_policy_version "
            "(INV-7: the policy's thresholds and weights change the persisted verdict "
            f"and score without changing .version). Offending call sites: {offenders}",
        )

    def test_the_production_call_sites_are_actually_found(self) -> None:
        # Guards the guard: `offenders == []` also passes when the walk matches
        # NOTHING (an import alias, a keyword argument, a refactor to a
        # wrapper). Task 5's version of this only parsed a synthetic string,
        # which would not have noticed the walk going blind against the real
        # tree. Assert the real call sites are seen and are all the right form.
        located = {location.split(" ")[0].split(":")[0] for location, _ in self._call_sites()}
        for expected in (
            "apps/monolith/modules/orchestration/service.py",
            "apps/monolith/modules/gateway/runtime.py",
            "apps/monolith/modules/gateway/router.py",
        ):
            self.assertIn(expected, located)
        attribute_args = [arg for _, arg in self._call_sites() if isinstance(arg, ast.Attribute)]
        self.assertTrue(attribute_args, "the walk found no attribute-form policy term at all")
        for arg in attribute_args:
            self.assertEqual(arg.attr, self._REQUIRED_TERM)

    def test_the_scan_would_actually_catch_one(self) -> None:
        source = "compute_toolchain_digest(metadatas, policy.version)\n"
        tree = ast.parse(source)
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        arg = call.args[1]  # type: ignore[attr-defined]
        self.assertIsInstance(arg, ast.Attribute)
        self.assertNotEqual(arg.attr, self._REQUIRED_TERM)


class TestCacheKey(unittest.TestCase):
    def test_changes_with_content_hash(self) -> None:
        self.assertNotEqual(cache_key("h1", "t1"), cache_key("h2", "t1"))

    def test_changes_with_toolchain_digest(self) -> None:
        self.assertNotEqual(cache_key("h1", "t1"), cache_key("h1", "t2"))

    def test_deterministic(self) -> None:
        self.assertEqual(cache_key("h1", "t1"), cache_key("h1", "t1"))


if __name__ == "__main__":
    unittest.main()
