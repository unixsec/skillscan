"""Tests for claims/groups -> role resolution (coding spec §11.2, FR-SSO-031)
and `group_role_map.yaml` loading (coding spec §16.3, INV-17)."""

from __future__ import annotations

from pathlib import Path

import pytest

from monolith.modules.gateway.auth.rbac import (
    DEFAULT_ROLE,
    GroupRoleMapLoadError,
    load_group_role_map,
    resolve_roles,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REAL_GROUP_ROLE_MAP_PATH = _REPO_ROOT / "policies" / "rbac" / "group_role_map.yaml"

GROUP_ROLE_MAP = {
    "skillscan-admins": "admin",
    "skillscan-approvers": "approver",
    "skillscan-auditors": "auditor",
}


class TestResolveRoles:
    def test_no_groups_yields_default_role_only(self) -> None:
        assert resolve_roles(frozenset(), GROUP_ROLE_MAP) == frozenset({DEFAULT_ROLE})

    def test_unknown_group_yields_default_role_only(self) -> None:
        roles = resolve_roles(frozenset({"some-unrelated-group"}), GROUP_ROLE_MAP)
        assert roles == frozenset({DEFAULT_ROLE})

    def test_mapped_group_elevates_role(self) -> None:
        roles = resolve_roles(frozenset({"skillscan-approvers"}), GROUP_ROLE_MAP)
        assert roles == frozenset({DEFAULT_ROLE, "approver"})

    def test_multiple_mapped_groups_grant_multiple_roles(self) -> None:
        roles = resolve_roles(frozenset({"skillscan-admins", "skillscan-auditors"}), GROUP_ROLE_MAP)
        assert roles == frozenset({DEFAULT_ROLE, "admin", "auditor"})

    def test_map_entry_naming_an_unrecognized_role_is_ignored(self) -> None:
        bad_map = {"skillscan-superusers": "superuser"}  # typo/future config mistake
        roles = resolve_roles(frozenset({"skillscan-superusers"}), bad_map)
        assert roles == frozenset({DEFAULT_ROLE})

    def test_empty_group_role_map_still_yields_default(self) -> None:
        roles = resolve_roles(frozenset({"skillscan-admins"}), {})
        assert roles == frozenset({DEFAULT_ROLE})


class TestLoadGroupRoleMap:
    def test_real_shipped_file_loads(self) -> None:
        mapping = load_group_role_map(_REAL_GROUP_ROLE_MAP_PATH)
        assert mapping["skillscan-admins"] == "admin"
        assert mapping["skillscan-approvers"] == "approver"
        assert mapping["skillscan-auditors"] == "auditor"

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(GroupRoleMapLoadError, match="cannot read"):
            load_group_role_map(tmp_path / "does-not-exist.yaml")

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("group_role_map: [unterminated\n")
        with pytest.raises(GroupRoleMapLoadError, match="not valid YAML"):
            load_group_role_map(bad)

    def test_missing_top_level_key_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("something_else: {}\n")
        with pytest.raises(GroupRoleMapLoadError, match="group_role_map"):
            load_group_role_map(bad)

    def test_non_string_value_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("group_role_map:\n  skillscan-admins: 123\n")
        with pytest.raises(GroupRoleMapLoadError, match="must map strings to strings"):
            load_group_role_map(bad)

    def test_unknown_role_name_raises(self, tmp_path: Path) -> None:
        # SECURITY: fail loudly at startup on an obvious config typo, rather
        # than silently resolving to "no role granted" at request time.
        bad = tmp_path / "bad.yaml"
        bad.write_text("group_role_map:\n  skillscan-admins: supervisor\n")
        with pytest.raises(GroupRoleMapLoadError, match="unknown role"):
            load_group_role_map(bad)

    def test_valid_custom_file_loads_correctly(self, tmp_path: Path) -> None:
        good = tmp_path / "good.yaml"
        good.write_text("group_role_map:\n  my-group: approver\n")
        assert load_group_role_map(good) == {"my-group": "approver"}
