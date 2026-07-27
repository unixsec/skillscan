"""Tests for the SKILL.md permission-declaration detector (Cat-5 PERM-*,
FR-PAR-013, FR-DET-050). All payloads are inert scanned-content bytes."""

from __future__ import annotations

import time

import pytest
from engine_runner.detectors.skill_permissions import SkillPermissionsDetector, scan
from skillscan_core import EngineStatus


def _rule_ids(files: dict[str, bytes]) -> set[str]:
    return {f.rule_id for f in scan(files)}


def _skill(body: str) -> dict[str, bytes]:
    return {"SKILL.md": body.encode("utf-8")}


class TestCleanDeclarations:
    def test_a_narrow_read_only_skill_produces_no_findings(self) -> None:
        assert scan(_skill("---\nname: s\nallowed-tools: [Read, Grep]\n---\n")) == ()

    def test_a_skill_without_scripts_and_without_perms_is_not_flagged(self) -> None:
        assert scan(_skill("---\nname: s\n---\n# doc only\n")) == ()


class TestDangerousCombination:
    def test_bash_plus_network_tool_is_flagged(self) -> None:
        files = _skill("---\nname: s\nallowed-tools: [Bash, WebFetch]\n---\n")
        assert "perm.dangerous_tool_combination" in _rule_ids(files)

    def test_bash_alone_is_not_the_combination_rule(self) -> None:
        files = _skill("---\nname: s\nallowed-tools: [Bash]\n---\n")
        assert "perm.dangerous_tool_combination" not in _rule_ids(files)


class TestUnrestrictedBash:
    def test_bare_bash_is_flagged(self) -> None:
        assert "perm.unrestricted_bash" in _rule_ids(
            _skill("---\nname: s\nallowed-tools: [Bash]\n---\n")
        )

    def test_scoped_bash_is_not_flagged(self) -> None:
        assert "perm.unrestricted_bash" not in _rule_ids(
            _skill("---\nname: s\nallowed-tools: ['Bash(git status)']\n---\n")
        )


class TestUndeclaredPermissions:
    def test_scripts_without_any_declaration_is_flagged(self) -> None:
        files = _skill("---\nname: s\n---\n")
        files["scripts/run.sh"] = b"#!/bin/sh\necho hi\n"
        assert "perm.undeclared_permissions" in _rule_ids(files)

    def test_scripts_with_a_declaration_is_not_flagged(self) -> None:
        files = _skill("---\nname: s\nallowed-tools: [Read]\n---\n")
        files["scripts/run.sh"] = b"#!/bin/sh\necho hi\n"
        assert "perm.undeclared_permissions" not in _rule_ids(files)


class TestRootPathOnly:
    """2026-07-27: the Agent only ever reads the package-ROOT SKILL.md as its
    permission declaration - a SKILL.md nested elsewhere (e.g. a bundled
    example) must never satisfy this detector's "permissions declared" check.
    Matching by basename-anywhere here would be a false negative (a real
    undeclared-scripts package reads as declared), which is worse than the
    false positive mcp_config.py's basename-anywhere matcher risks - that
    asymmetry is deliberate, see skill_permissions.py's `scan()` docstring."""

    def test_a_fully_declared_non_root_skill_md_does_not_suppress_the_finding(
        self,
    ) -> None:
        files = {
            "examples/SKILL.md": b"---\nname: s\nallowed-tools: [Read]\n---\n",
            "scripts/run.sh": b"#!/bin/sh\necho hi\n",
        }
        assert "perm.undeclared_permissions" in _rule_ids(files)

    def test_a_root_skill_md_still_behaves_as_before_regression_guard(self) -> None:
        files = _skill("---\nname: s\nallowed-tools: [Read]\n---\n")
        files["scripts/run.sh"] = b"#!/bin/sh\necho hi\n"
        assert "perm.undeclared_permissions" not in _rule_ids(files)


class TestDirectoryWrappedPackaging:
    """2026-07-27 (final review, F-5): `tar czf skill.tgz my-skill/` - the
    conventional way to pack a directory - puts every member under a
    `my-skill/` wrapper, and `normalizer._canonicalize_member_path` only
    strips `.` segments, never a leading directory. Matching the literal
    string "SKILL.md" therefore concluded "no manifest" for a package that
    declares its permissions perfectly well, emitting a false
    `perm.undeclared_permissions`. The flat/root form of the SAME package
    produced no finding, which is what made this invisible: every test here
    used the flat form.

    The fix must not become basename-anywhere matching - see
    `TestRootPathOnly` above, which still has to hold.
    """

    _DECLARED = b"---\nname: s\nallowed-tools: [Read]\n---\n"
    _UNDECLARED = b"---\nname: s\n---\n"
    _SCRIPT = b"#!/bin/sh\necho hi\n"

    def test_a_wrapped_package_that_declares_permissions_is_not_flagged(self) -> None:
        files = {"my-skill/SKILL.md": self._DECLARED, "my-skill/scripts/run.sh": self._SCRIPT}
        assert scan(files) == ()

    def test_a_wrapped_package_that_declares_nothing_is_still_flagged(self) -> None:
        files = {"my-skill/SKILL.md": self._UNDECLARED, "my-skill/scripts/run.sh": self._SCRIPT}
        assert "perm.undeclared_permissions" in _rule_ids(files)

    def test_a_wrapped_packages_declaration_is_actually_read(self) -> None:
        """Not just "no undeclared finding" - the wrapped manifest must drive
        the real rules too, or the fix would only be suppressing a symptom."""
        files = {"my-skill/SKILL.md": b"---\nname: s\nallowed-tools: [Bash, WebFetch]\n---\n"}
        assert _rule_ids(files) == {"perm.dangerous_tool_combination", "perm.unrestricted_bash"}

    def test_an_example_inside_the_wrapper_does_not_satisfy_the_check(self) -> None:
        """The `TestRootPathOnly` property, restated for the wrapped shape: a
        nested example is still not the manifest."""
        files = {
            "my-skill/examples/SKILL.md": self._DECLARED,
            "my-skill/scripts/run.sh": self._SCRIPT,
        }
        assert "perm.undeclared_permissions" in _rule_ids(files)

    def test_the_root_manifest_wins_over_a_nested_one(self) -> None:
        files = {
            "my-skill/SKILL.md": b"---\nname: s\nallowed-tools: [Bash, WebFetch]\n---\n",
            "my-skill/examples/SKILL.md": self._DECLARED,
        }
        assert "perm.dangerous_tool_combination" in _rule_ids(files)

    def test_two_top_level_directories_are_not_a_wrapper(self) -> None:
        """Nothing is stripped unless ALL members share one top-level
        directory, so `examples/SKILL.md` alongside `scripts/` is still not a
        root manifest."""
        files = {"examples/SKILL.md": self._DECLARED, "scripts/run.sh": self._SCRIPT}
        assert "perm.undeclared_permissions" in _rule_ids(files)

    def test_the_reported_path_names_the_real_root(self) -> None:
        files = {"my-skill/SKILL.md": self._UNDECLARED, "my-skill/scripts/run.sh": self._SCRIPT}
        finding = next(f for f in scan(files) if f.rule_id == "perm.undeclared_permissions")
        assert finding.file_path == "my-skill/SKILL.md"


class TestMalformedInputNeverRaises:
    """This detector is in required_engines - an uncaught exception blocks
    every scan that trips it."""

    @pytest.mark.parametrize(
        "body",
        [
            "---\nname: [unclosed\n---\n",
            "---\n",
            "",
            "---\n- a list not a mapping\n---\n",
            "---\nallowed-tools: not-a-list\n---\n",
            "---\nallowed-tools: [1, 2, {nested: obj}]\n---\n",
        ],
    )
    def test_malformed_frontmatter_never_raises(self, body: str) -> None:
        scan(_skill(body))  # must not raise

    def test_binary_skill_md_never_raises(self) -> None:
        scan({"SKILL.md": b"\x00\x01\xff\xfe"})

    def test_control_character_after_frontmatter_delimiter_never_raises(self) -> None:
        """2026-07-27 review finding (Critical): the payload above
        (b"\\x00\\x01\\xff\\xfe") does NOT start with b"---", so
        `parse_frontmatter` early-returns at its `startswith` check and never
        reaches `NoAliasSafeLoader` construction - that test proves early-exit
        works, not that the loader path itself never raises. This payload
        starts with "---" and is otherwise valid UTF-8, so it actually reaches
        loader construction, where PyYAML's `Reader.__init__` (called from
        the loader's MRO) raises `yaml.reader.ReaderError` for a disallowed
        control character BEFORE `get_single_data()` is ever called - a path
        that was outside `parse_frontmatter`'s try/except at the time this
        test was written. `scan()` is inside `required_engines`; an uncaught
        exception here fails the whole scan closed."""
        scan(_skill("---\nname: x\n\x01\n---\n"))  # must not raise

    def test_alias_bomb_is_refused_not_expanded(self) -> None:
        payload = (
            "---\n"
            "a: &a ['x','x','x','x','x','x','x','x','x']\n"
            "b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
            "c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n"
            "d: [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n"
            "---\n"
        )
        started = time.monotonic()
        scan(_skill(payload))
        assert time.monotonic() - started < 5.0


class TestCatalogIds:
    """2026-07-27 (Task 8 SAD coverage-matrix review): these four rules had no
    test_item_id assertions at all - Task 7 hardened test_item_id mapping
    elsewhere in the codebase but never audited this detector (a scoping gap
    in that task's brief, not this detector's own oversight). Two of the four
    original mappings were the same class of defect Task 7 exists to remove:
    syntactically valid but semantically mismatched catalog ids. Corrected
    against 企业Skill安全评估测试维度清单.xlsx - see `skill_permissions.py`'s
    own `_TEST_ITEM_IDS` comment for the full per-rule justification.
    """

    def test_dangerous_combination_maps_to_perm_05(self) -> None:
        # was PERM-03 ("沙箱逃逸"/sandbox escape) - unrelated; declaring both
        # an execution and a network tool is PERM-05's "过度授权"
        # (over-provisioning beyond what the function actually needs).
        files = _skill("---\nname: s\nallowed-tools: [Bash, WebFetch]\n---\n")
        findings = scan(files)
        match = next(f for f in findings if f.rule_id == "perm.dangerous_tool_combination")
        assert match.test_item_id == "PERM-05"

    def test_unrestricted_bash_maps_to_perm_05(self) -> None:
        # was PERM-01 ("权限提升"/privilege escalation - missing authz checks,
        # setuid/chmod+x) - an unscoped Bash grant is a permission REQUEST
        # wider than needed, not a privilege-escalation mechanism; PERM-05
        # ("超出功能实际所需") is the precise fit.
        files = _skill("---\nname: s\nallowed-tools: [Bash]\n---\n")
        findings = scan(files)
        match = next(f for f in findings if f.rule_id == "perm.unrestricted_bash")
        assert match.test_item_id == "PERM-05"

    def test_undeclared_permissions_maps_to_perm_04(self) -> None:
        # unchanged - exact match ("权限manifest缺失").
        files = _skill("---\nname: s\n---\n")
        files["scripts/run.sh"] = b"#!/bin/sh\necho hi\n"
        findings = scan(files)
        match = next(f for f in findings if f.rule_id == "perm.undeclared_permissions")
        assert match.test_item_id == "PERM-04"

    def test_malformed_frontmatter_maps_to_perm_04(self) -> None:
        # unchanged - unparseable has the same practical effect as no
        # declaration at all (nothing to review), and PERM-04 is the on-point
        # item for this detector's whole domain.
        files = _skill("---\nname: [unclosed\n---\n")
        files["scripts/run.sh"] = b"#!/bin/sh\necho hi\n"
        findings = scan(files)
        match = next(f for f in findings if f.rule_id == "perm.malformed_frontmatter")
        assert match.test_item_id == "PERM-04"


class TestEngineProtocol:
    def test_is_zero_arg_constructible(self) -> None:
        engine = SkillPermissionsDetector()
        assert engine.metadata.name == "inhouse-skill-permissions"
        assert engine.metadata.requires_network is False

    def test_expired_deadline_reports_timeout(self) -> None:
        result = SkillPermissionsDetector().analyze(
            _skill("---\nname: s\n---\n"), deadline=time.time() - 3600
        )
        assert result.status is EngineStatus.TIMEOUT
