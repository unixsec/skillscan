"""Tests for `common.skill_package` - locating a Skill package's one
authoritative SKILL.md.

WHY (2026-07-27, milestone D final review, F-5): three call sites each spelled
this as `path == "SKILL.md"`, which is wrong for `tar czf skill.tgz my-skill/`
- the conventional way to pack a directory. `normalizer._canonicalize_member_
path` only strips `.` segments, never a leading directory, so a wrapped
package read as "no manifest": a false `perm.undeclared_permissions` finding
AND `skill_version.declared_perms` silently recorded as None for a package
that declares its permissions correctly.

The security property that must NOT regress in the process: a SKILL.md nested
inside the package (`examples/SKILL.md`) must never count as the manifest. The
Agent reads exactly one, and letting a bundled example satisfy the check is a
false negative - a genuinely undeclared package reading as declared - which is
worse than the false positive being fixed.
"""

from __future__ import annotations

import unittest

from common.skill_package import package_root_prefix, root_skill_md_path


class TestPackageRootPrefix(unittest.TestCase):
    def test_a_flat_package_has_no_prefix(self) -> None:
        self.assertEqual(package_root_prefix(["SKILL.md", "scripts/run.sh"]), "")

    def test_a_single_shared_wrapper_is_the_prefix(self) -> None:
        self.assertEqual(
            package_root_prefix(["my-skill/SKILL.md", "my-skill/scripts/run.sh"]), "my-skill/"
        )

    def test_a_real_member_at_the_top_level_means_there_is_no_wrapper(self) -> None:
        self.assertEqual(package_root_prefix(["skill.py", "my-skill/SKILL.md"]), "")

    def test_stray_packaging_metadata_at_the_root_does_not_defeat_the_wrapper(self) -> None:
        """VM re-review, F-5 residual: `tar czf skill.tgz LICENSE my-skill/` is
        an ordinary shape, and a single stray root member used to collapse the
        prefix back to `""` and reinstate the original false positive."""
        for stray in ("LICENSE", "LICENSE.txt", "README.md", ".gitignore", "NOTICE"):
            with self.subTest(stray=stray):
                self.assertEqual(
                    package_root_prefix([stray, "my-skill/SKILL.md", "my-skill/scripts/run.sh"]),
                    "my-skill/",
                )

    def test_a_structural_directory_is_never_a_wrapper(self) -> None:
        """VM regression (2026-07-28): a single-member archive has exactly one
        top-level directory, so it is shape-identical to a wrapped package -
        `{examples/SKILL.md}` was stripped and its bundled example accepted as
        the manifest. That is a false NEGATIVE (it suppresses a real
        `perm.undeclared_permissions`), i.e. worse than the false positive F-5
        set out to fix. The disambiguating signal cannot come from the path
        shape; it comes from the name: the format's own structural directories
        (SRS glossary + FR-PAR-010) can never BE the package."""
        for structural in ("examples", "scripts", "references", "assets", "docs", "hooks"):
            with self.subTest(directory=structural):
                self.assertEqual(package_root_prefix([f"{structural}/SKILL.md"]), "")
                self.assertEqual(
                    package_root_prefix([f"{structural}/SKILL.md", f"{structural}/run.sh"]), ""
                )

    def test_a_skill_named_wrapper_is_still_a_wrapper(self) -> None:
        """The structural-name rule must not swallow the case F-5 exists for."""
        self.assertEqual(package_root_prefix(["my-skill/SKILL.md"]), "my-skill/")

    def test_two_top_level_directories_are_not_a_wrapper(self) -> None:
        self.assertEqual(package_root_prefix(["examples/SKILL.md", "scripts/run.sh"]), "")

    def test_only_one_level_is_ever_stripped(self) -> None:
        """A doubly wrapped archive keeps the inner level, so it reads as "no
        root manifest" (one extra finding, the safe direction) rather than
        risking the false negative below."""
        self.assertEqual(package_root_prefix(["a/b/SKILL.md", "a/b/scripts/run.sh"]), "a/")

    def test_greedy_stripping_would_accept_a_manifest_inside_scripts(self) -> None:
        """The reason stripping stops at one level: this package shares a
        top-level directory at BOTH levels, so a greedy strip would treat
        `scripts/SKILL.md` as the package manifest - a file the Agent would
        never read as a permission declaration."""
        paths = ["my-skill/scripts/SKILL.md", "my-skill/scripts/run.sh"]
        self.assertEqual(package_root_prefix(paths), "my-skill/")
        self.assertNotIn(root_skill_md_path(paths), paths)

    def test_an_empty_package_has_no_prefix(self) -> None:
        self.assertEqual(package_root_prefix([]), "")


class TestRootSkillMdPath(unittest.TestCase):
    def test_flat_package(self) -> None:
        self.assertEqual(root_skill_md_path(["SKILL.md", "scripts/run.sh"]), "SKILL.md")

    def test_wrapped_package(self) -> None:
        self.assertEqual(
            root_skill_md_path(["my-skill/SKILL.md", "my-skill/scripts/run.sh"]),
            "my-skill/SKILL.md",
        )

    def test_a_nested_example_is_never_the_root(self) -> None:
        """The property `skill_permissions` depends on: a bundled example must
        not be picked up as the manifest."""
        paths = ["examples/SKILL.md", "scripts/run.sh"]
        self.assertEqual(root_skill_md_path(paths), "SKILL.md")
        self.assertNotIn(root_skill_md_path(paths), paths)

    def test_a_nested_example_inside_a_wrapper_is_never_the_root(self) -> None:
        paths = ["my-skill/examples/SKILL.md", "my-skill/scripts/run.sh"]
        self.assertEqual(root_skill_md_path(paths), "my-skill/SKILL.md")
        self.assertNotIn(root_skill_md_path(paths), paths)

    def test_a_lone_bundled_example_is_never_the_root_manifest(self) -> None:
        """The exact VM regression, at the level the three call sites use:
        `_parse_skill_name([("examples/SKILL.md", ...)])` must stay None, and
        `skill_permissions` must still report the undeclared package."""
        paths = ["examples/SKILL.md"]
        self.assertEqual(root_skill_md_path(paths), "SKILL.md")
        self.assertNotIn(root_skill_md_path(paths), paths)

    def test_the_path_is_returned_even_when_no_such_member_exists(self) -> None:
        """Callers report "no root manifest" against this path, so it has to be
        a real, nameable path rather than None."""
        self.assertEqual(root_skill_md_path(["my-skill/scripts/run.sh"]), "my-skill/SKILL.md")

    def test_an_iterator_argument_is_not_consumed_before_use(self) -> None:
        """Two of the three call sites pass a generator over their own file
        tuples - a helper that iterated it twice would silently see an empty
        package the second time."""
        paths = iter(["my-skill/SKILL.md", "my-skill/scripts/run.sh"])
        self.assertEqual(root_skill_md_path(paths), "my-skill/SKILL.md")


class TestThePropertyThatActuallyMatters(unittest.TestCase):
    """The helper is only interesting through its security-relevant consumer.
    Driving the real detector here - in the KERNEL suite, which runs locally -
    is deliberate: every existing test of this behaviour lives in
    `apps/monolith/tests/`, which is VM-only, so the `{examples/SKILL.md}`
    regression could not surface until a full VM run. `skill_permissions.scan`
    needs no DB or Redis, so there is no reason for that to be true."""

    _DECLARED = b"---\nname: s\nallowed-tools: [Read]\n---\n"
    _SCRIPT = b"#!/bin/sh\necho hi\n"

    def _rule_ids(self, files: dict[str, bytes]) -> set[str]:
        from engine_runner.detectors.skill_permissions import scan

        return {f.rule_id for f in scan(files)}

    def test_a_lone_bundled_example_does_not_suppress_the_undeclared_finding(self) -> None:
        files = {"examples/SKILL.md": self._DECLARED, "examples/scripts/run.sh": self._SCRIPT}
        self.assertIn("perm.undeclared_permissions", self._rule_ids(files))

    def test_a_directory_wrapped_declaration_is_still_honoured(self) -> None:
        files = {"my-skill/SKILL.md": self._DECLARED, "my-skill/scripts/run.sh": self._SCRIPT}
        self.assertEqual(self._rule_ids(files), set())

    def test_a_stray_license_beside_the_wrapper_does_not_reinstate_the_false_positive(
        self,
    ) -> None:
        files = {
            "LICENSE": b"MIT\n",
            "my-skill/SKILL.md": self._DECLARED,
            "my-skill/scripts/run.sh": self._SCRIPT,
        }
        self.assertEqual(self._rule_ids(files), set())
