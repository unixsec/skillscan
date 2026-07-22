"""Claims/groups -> role resolution (coding spec §11.2, FR-SSO-030/031/032).

SECURITY: deny-by-default - unmapped IdP groups contribute nothing; every
authenticated subject always resolves to at least `submitter`, and elevation to
`approver`/`admin`/`auditor` requires an explicit, config-as-code group match.
Nothing here trusts a client-supplied role; roles are always re-derived from
IdP-asserted groups on every request.
"""

from __future__ import annotations

from pathlib import Path

import yaml

DEFAULT_ROLE = "submitter"
KNOWN_ROLES = frozenset({"submitter", "approver", "admin", "auditor"})


def resolve_roles(groups: frozenset[str], group_role_map: dict[str, str]) -> frozenset[str]:
    """Map IdP-asserted groups to roles via `policies/rbac/group_role_map.yaml`.

    SECURITY (FR-SSO-031): an entry in `group_role_map` that names a role outside
    `KNOWN_ROLES` (e.g. a typo, or a future config mistake) is ignored rather
    than granted - fail-closed on unrecognized configuration, not fail-open.
    """
    roles = {DEFAULT_ROLE}
    for group in groups:
        role = group_role_map.get(group)
        if role in KNOWN_ROLES:
            roles.add(role)
    return frozenset(roles)


class GroupRoleMapLoadError(ValueError):
    pass


def load_group_role_map(yaml_path: Path) -> dict[str, str]:
    """coding spec §16.3 (INV-17): "无任何环节出现明文默认口令" - this file
    carries no credentials at all, only a group-name-to-role-name mapping.
    Fail-closed parsing, same posture as gate.policy.load_gate_policy: a
    malformed file must crash startup, never silently resolve to an empty
    (or worse, wrong) mapping."""
    try:
        text = yaml_path.read_text()
    except OSError as exc:
        raise GroupRoleMapLoadError(f"cannot read group_role_map file {yaml_path}: {exc}") from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise GroupRoleMapLoadError(
            f"group_role_map file {yaml_path} is not valid YAML: {exc}"
        ) from exc
    if not isinstance(raw, dict) or "group_role_map" not in raw:
        raise GroupRoleMapLoadError(
            f"group_role_map file {yaml_path} must contain a top-level 'group_role_map' mapping"
        )
    mapping = raw["group_role_map"]
    if not isinstance(mapping, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in mapping.items()
    ):
        raise GroupRoleMapLoadError(
            f"group_role_map file {yaml_path}: 'group_role_map' must map strings to strings"
        )
    # SECURITY: fail-closed on a config mistake - a role name outside
    # KNOWN_ROLES here is almost certainly a typo, and resolve_roles() would
    # silently ignore it at request time (deny-by-default) - better to catch
    # it loudly at startup than have an intended admin group quietly grant
    # nothing.
    for group, role in mapping.items():
        if role not in KNOWN_ROLES:
            raise GroupRoleMapLoadError(
                f"group_role_map file {yaml_path}: group {group!r} maps to unknown role "
                f"{role!r}, expected one of {sorted(KNOWN_ROLES)}"
            )
    return dict(mapping)
