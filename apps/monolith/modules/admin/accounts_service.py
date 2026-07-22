"""Local account + IdP group-role-map management (2026-07-14, item #13).

SECURITY: every mutation here writes an `AuditIntentInsertOnly` row in the
SAME transaction as the business-data change (INV-12, mirroring inventory.
service's `_record_transition`/`set_baseline`) - never logged separately,
never logged after the fact. Payloads never include `password_hash` or a
plaintext password - only who/what/when (coding spec INV-17 posture: no
secret material in an audit trail meant to be readable by auditors).

Accounts are disabled, never deleted (status='disabled') - same revoke-not-
delete posture as gate.service's allowlist and admin.breakglass, so "who had
this account and when" survives in local_account itself, not just the audit
log.
"""

from __future__ import annotations

import datetime
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .local_auth import hash_password
from .models import AuditIntentInsertOnly, GroupRoleMappingRow, LocalAccountRow

_MIN_PASSWORD_LENGTH = 12
_ACCOUNT_STATUSES = frozenset({"active", "disabled"})


class AdminAccountError(ValueError):
    pass


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


def _validate_role(role: str, *, known_roles: frozenset[str]) -> None:
    if role not in known_roles:
        raise AdminAccountError(f"unknown role {role!r} - must be one of {sorted(known_roles)}")


def _validate_password(password: str) -> None:
    # SECURITY: admin-set (not self-service), so this is a floor, not a full
    # complexity policy - long enough that a scrypt-hashed brute force is
    # impractical, same rationale as this module's existing lockout/timing
    # defenses in local_auth.py.
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise AdminAccountError(f"password must be at least {_MIN_PASSWORD_LENGTH} characters")


async def list_accounts(session: AsyncSession) -> Sequence[LocalAccountRow]:
    result = await session.execute(select(LocalAccountRow).order_by(LocalAccountRow.username.asc()))
    return result.scalars().all()


async def create_account(
    session: AsyncSession,
    *,
    username: str,
    role: str,
    initial_password: str,
    created_by: str,
    known_roles: frozenset[str],
) -> LocalAccountRow:
    if not username.strip():
        raise AdminAccountError("username must not be empty")
    _validate_role(role, known_roles=known_roles)
    _validate_password(initial_password)
    existing = await session.execute(
        select(LocalAccountRow.id).where(LocalAccountRow.username == username)
    )
    if existing.scalar_one_or_none() is not None:
        raise AdminAccountError(f"username {username!r} is already taken")

    now = _naive_utcnow()
    row = LocalAccountRow(
        username=username,
        password_hash=hash_password(initial_password),
        role=role,
        status="active",
        created_by=created_by,
        created_at=now,
        updated_at=now,
    )
    session.add(row)
    session.add(
        AuditIntentInsertOnly(
            operator=created_by,
            action="local_account_created",
            payload={"username": username, "role": role},
        )
    )
    await session.flush()
    return row


async def _get_account_or_raise(session: AsyncSession, account_id: int) -> LocalAccountRow:
    row = await session.get(LocalAccountRow, account_id)
    if row is None:
        raise AdminAccountError(f"no local account with id={account_id}")
    return row


async def set_account_role_status(
    session: AsyncSession,
    *,
    account_id: int,
    role: str | None,
    status: str | None,
    actor: str,
    known_roles: frozenset[str],
) -> LocalAccountRow:
    if role is None and status is None:
        raise AdminAccountError("at least one of role/status must be provided")
    if status is not None and status not in _ACCOUNT_STATUSES:
        raise AdminAccountError(
            f"unknown status {status!r} - must be one of {sorted(_ACCOUNT_STATUSES)}"
        )
    row = await _get_account_or_raise(session, account_id)
    demoting_admin = role is not None and role != "admin"
    disabling = status is not None and status != "active"
    if row.role == "admin" and row.status == "active" and (demoting_admin or disabling):
        # SECURITY: without this, an operator can demote/disable the only
        # active admin account through the normal admin API - on a
        # deployment where local auth is the sole working login path (see
        # docs/superpowers/plans/2026-07-11-web-console-redesign-STATUS.md's
        # break-glass activation deadlock), that's a permanent lockout with
        # no way back in short of direct DB surgery.
        other_active_admins = await session.execute(
            select(func.count())
            .select_from(LocalAccountRow)
            .where(
                LocalAccountRow.role == "admin",
                LocalAccountRow.status == "active",
                LocalAccountRow.id != account_id,
            )
        )
        if other_active_admins.scalar_one() == 0:
            raise AdminAccountError(
                "cannot demote or disable the last active admin account - "
                "create or promote another admin account first"
            )
    changes: dict[str, dict[str, str]] = {}
    if role is not None and role != row.role:
        _validate_role(role, known_roles=known_roles)
        changes["role"] = {"from": row.role, "to": role}
        row.role = role
    if status is not None and status != row.status:
        changes["status"] = {"from": row.status, "to": status}
        row.status = status
    if not changes:
        return row  # SECURITY: a no-op PATCH writes no audit row - nothing actually changed.
    row.updated_at = _naive_utcnow()
    session.add(
        AuditIntentInsertOnly(
            operator=actor,
            action="local_account_updated",
            payload={"account_id": account_id, "username": row.username, "changes": changes},
        )
    )
    await session.flush()
    return row


async def reset_password(
    session: AsyncSession, *, account_id: int, new_password: str, actor: str
) -> None:
    _validate_password(new_password)
    row = await _get_account_or_raise(session, account_id)
    row.password_hash = hash_password(new_password)
    row.updated_at = _naive_utcnow()
    session.add(
        AuditIntentInsertOnly(
            operator=actor,
            action="local_account_password_reset",
            payload={"account_id": account_id, "username": row.username},
        )
    )
    await session.flush()


async def list_group_role_mapping(session: AsyncSession) -> Sequence[GroupRoleMappingRow]:
    result = await session.execute(
        select(GroupRoleMappingRow).order_by(GroupRoleMappingRow.group_name.asc())
    )
    return result.scalars().all()


async def upsert_group_role_mapping(
    session: AsyncSession,
    *,
    group_name: str,
    role: str,
    actor: str,
    known_roles: frozenset[str],
) -> GroupRoleMappingRow:
    if not group_name.strip():
        raise AdminAccountError("group_name must not be empty")
    _validate_role(role, known_roles=known_roles)
    now = _naive_utcnow()
    existing = await session.get(GroupRoleMappingRow, group_name)
    previous_role = existing.role if existing else None
    if existing is None:
        row = GroupRoleMappingRow(
            group_name=group_name, role=role, updated_by=actor, updated_at=now
        )
        session.add(row)
    else:
        existing.role = role
        existing.updated_by = actor
        existing.updated_at = now
        row = existing
    session.add(
        AuditIntentInsertOnly(
            operator=actor,
            action="group_role_map_updated",
            payload={"group_name": group_name, "from_role": previous_role, "to_role": role},
        )
    )
    await session.flush()
    return row


async def delete_group_role_mapping(session: AsyncSession, *, group_name: str, actor: str) -> None:
    row = await session.get(GroupRoleMappingRow, group_name)
    if row is None:
        raise AdminAccountError(f"no group_role_mapping for group {group_name!r}")
    previous_role = row.role
    await session.delete(row)
    session.add(
        AuditIntentInsertOnly(
            operator=actor,
            action="group_role_map_removed",
            payload={"group_name": group_name, "from_role": previous_role},
        )
    )
    await session.flush()
