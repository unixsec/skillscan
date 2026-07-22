"""Tests for `admin.accounts_service` (2026-07-14, item #13) against real
local MySQL/Redis. Every mutation's audit_intent row is verified via
`audit_sessionmaker` (svc_admin can only INSERT into audit_intent, never
SELECT it back - policies/grants/manifest.yaml), same cross-module grant-
isolation pattern test_inventory_service.py already established for
`transition_skill`'s own audit write.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError

from monolith.modules.admin.accounts_service import (
    AdminAccountError,
    create_account,
    delete_group_role_mapping,
    list_accounts,
    list_group_role_mapping,
    reset_password,
    set_account_role_status,
    upsert_group_role_mapping,
)
from monolith.modules.admin.local_auth import verify_password
from monolith.modules.admin.models import AuditIntentInsertOnly
from monolith.modules.audit.models import AuditIntent
from monolith.modules.gateway.auth.rbac import KNOWN_ROLES
from monolith.tests.conftest import SessionmakerFixture

_PASSWORD = "correct horse battery staple"


def _username() -> str:
    return f"acct-{uuid.uuid4().hex[:12]}"


class TestCreateAccount:
    @pytest.mark.asyncio
    async def test_valid_create_persists_and_returns_row(
        self, admin_sessionmaker: SessionmakerFixture
    ) -> None:
        username = _username()
        async with admin_sessionmaker() as session, session.begin():
            row = await create_account(
                session,
                username=username,
                role="submitter",
                initial_password=_PASSWORD,
                created_by="admin-alice",
                known_roles=KNOWN_ROLES,
            )
        assert row.id is not None
        assert row.username == username
        assert row.role == "submitter"
        assert row.status == "active"
        assert row.password_hash != _PASSWORD  # never stored in plaintext

    @pytest.mark.asyncio
    async def test_duplicate_username_rejected(
        self, admin_sessionmaker: SessionmakerFixture
    ) -> None:
        username = _username()
        async with admin_sessionmaker() as session, session.begin():
            await create_account(
                session,
                username=username,
                role="submitter",
                initial_password=_PASSWORD,
                created_by="admin-alice",
                known_roles=KNOWN_ROLES,
            )
        with pytest.raises(AdminAccountError, match="already taken"):
            async with admin_sessionmaker() as session, session.begin():
                await create_account(
                    session,
                    username=username,
                    role="approver",
                    initial_password=_PASSWORD,
                    created_by="admin-alice",
                    known_roles=KNOWN_ROLES,
                )

    @pytest.mark.asyncio
    async def test_unknown_role_rejected(self, admin_sessionmaker: SessionmakerFixture) -> None:
        with pytest.raises(AdminAccountError, match="unknown role"):
            async with admin_sessionmaker() as session, session.begin():
                await create_account(
                    session,
                    username=_username(),
                    role="superuser",
                    initial_password=_PASSWORD,
                    created_by="admin-alice",
                    known_roles=KNOWN_ROLES,
                )

    @pytest.mark.asyncio
    async def test_short_password_rejected(self, admin_sessionmaker: SessionmakerFixture) -> None:
        with pytest.raises(AdminAccountError, match="at least"):
            async with admin_sessionmaker() as session, session.begin():
                await create_account(
                    session,
                    username=_username(),
                    role="submitter",
                    initial_password="short1",
                    created_by="admin-alice",
                    known_roles=KNOWN_ROLES,
                )

    @pytest.mark.asyncio
    async def test_writes_audit_intent_without_password(
        self,
        admin_sessionmaker: SessionmakerFixture,
        audit_sessionmaker: SessionmakerFixture,
    ) -> None:
        username = _username()
        async with admin_sessionmaker() as session, session.begin():
            await create_account(
                session,
                username=username,
                role="approver",
                initial_password=_PASSWORD,
                created_by="admin-alice",
                known_roles=KNOWN_ROLES,
            )
        async with audit_sessionmaker() as session:
            result = await session.execute(
                select(AuditIntent).where(AuditIntent.action == "local_account_created")
            )
            intents = [r for r in result.scalars().all() if r.payload.get("username") == username]
        assert len(intents) == 1
        assert intents[0].payload["role"] == "approver"
        assert "password" not in intents[0].payload
        assert "initial_password" not in intents[0].payload

    @pytest.mark.asyncio
    async def test_admin_session_cannot_read_audit_intent_back(
        self, admin_sessionmaker: SessionmakerFixture
    ) -> None:
        # SECURITY: proves the INSERT-only grant is real at the DB layer, not
        # just app-layer convention (mirrors test_inventory_service.py's own
        # negative test for the same cross-module seam).
        with pytest.raises(DBAPIError):
            async with admin_sessionmaker() as session:
                await session.execute(select(AuditIntentInsertOnly))


class TestListAccounts:
    @pytest.mark.asyncio
    async def test_includes_newly_created_account(
        self, admin_sessionmaker: SessionmakerFixture
    ) -> None:
        username = _username()
        async with admin_sessionmaker() as session, session.begin():
            await create_account(
                session,
                username=username,
                role="auditor",
                initial_password=_PASSWORD,
                created_by="admin-alice",
                known_roles=KNOWN_ROLES,
            )
        async with admin_sessionmaker() as session:
            rows = await list_accounts(session)
        assert any(r.username == username and r.role == "auditor" for r in rows)


class TestSetAccountRoleStatus:
    @pytest.mark.asyncio
    async def test_role_change_persists(self, admin_sessionmaker: SessionmakerFixture) -> None:
        async with admin_sessionmaker() as session, session.begin():
            created = await create_account(
                session,
                username=_username(),
                role="submitter",
                initial_password=_PASSWORD,
                created_by="admin-alice",
                known_roles=KNOWN_ROLES,
            )
        async with admin_sessionmaker() as session, session.begin():
            updated = await set_account_role_status(
                session,
                account_id=created.id,
                role="approver",
                status=None,
                actor="admin-bob",
                known_roles=KNOWN_ROLES,
            )
        assert updated.role == "approver"

    @pytest.mark.asyncio
    async def test_disable_then_reenable(self, admin_sessionmaker: SessionmakerFixture) -> None:
        async with admin_sessionmaker() as session, session.begin():
            created = await create_account(
                session,
                username=_username(),
                role="submitter",
                initial_password=_PASSWORD,
                created_by="admin-alice",
                known_roles=KNOWN_ROLES,
            )
        async with admin_sessionmaker() as session, session.begin():
            disabled = await set_account_role_status(
                session,
                account_id=created.id,
                role=None,
                status="disabled",
                actor="admin-bob",
                known_roles=KNOWN_ROLES,
            )
        assert disabled.status == "disabled"
        async with admin_sessionmaker() as session, session.begin():
            reenabled = await set_account_role_status(
                session,
                account_id=created.id,
                role=None,
                status="active",
                actor="admin-bob",
                known_roles=KNOWN_ROLES,
            )
        assert reenabled.status == "active"

    @pytest.mark.asyncio
    async def test_unknown_status_rejected(self, admin_sessionmaker: SessionmakerFixture) -> None:
        async with admin_sessionmaker() as session, session.begin():
            created = await create_account(
                session,
                username=_username(),
                role="submitter",
                initial_password=_PASSWORD,
                created_by="admin-alice",
                known_roles=KNOWN_ROLES,
            )
        with pytest.raises(AdminAccountError, match="unknown status"):
            async with admin_sessionmaker() as session, session.begin():
                await set_account_role_status(
                    session,
                    account_id=created.id,
                    role=None,
                    status="deleted",
                    actor="admin-bob",
                    known_roles=KNOWN_ROLES,
                )

    @pytest.mark.asyncio
    async def test_unknown_account_id_rejected(
        self, admin_sessionmaker: SessionmakerFixture
    ) -> None:
        with pytest.raises(AdminAccountError, match="no local account"):
            async with admin_sessionmaker() as session, session.begin():
                await set_account_role_status(
                    session,
                    account_id=999_999_999,
                    role="admin",
                    status=None,
                    actor="admin-bob",
                    known_roles=KNOWN_ROLES,
                )

    @pytest.mark.asyncio
    async def test_neither_role_nor_status_rejected(
        self, admin_sessionmaker: SessionmakerFixture
    ) -> None:
        async with admin_sessionmaker() as session, session.begin():
            created = await create_account(
                session,
                username=_username(),
                role="submitter",
                initial_password=_PASSWORD,
                created_by="admin-alice",
                known_roles=KNOWN_ROLES,
            )
        with pytest.raises(AdminAccountError, match="at least one"):
            async with admin_sessionmaker() as session, session.begin():
                await set_account_role_status(
                    session,
                    account_id=created.id,
                    role=None,
                    status=None,
                    actor="admin-bob",
                    known_roles=KNOWN_ROLES,
                )

    @pytest.mark.asyncio
    async def test_no_actual_change_writes_no_audit_row(
        self,
        admin_sessionmaker: SessionmakerFixture,
        audit_sessionmaker: SessionmakerFixture,
    ) -> None:
        async with admin_sessionmaker() as session, session.begin():
            created = await create_account(
                session,
                username=_username(),
                role="submitter",
                initial_password=_PASSWORD,
                created_by="admin-alice",
                known_roles=KNOWN_ROLES,
            )
        # role="submitter" is already current - a genuine no-op.
        async with admin_sessionmaker() as session, session.begin():
            await set_account_role_status(
                session,
                account_id=created.id,
                role="submitter",
                status="active",
                actor="admin-bob",
                known_roles=KNOWN_ROLES,
            )
        async with audit_sessionmaker() as session:
            result = await session.execute(
                select(AuditIntent).where(AuditIntent.action == "local_account_updated")
            )
            intents = [
                r for r in result.scalars().all() if r.payload.get("account_id") == created.id
            ]
        assert intents == []


class TestResetPassword:
    @pytest.mark.asyncio
    async def test_new_password_verifies_old_does_not(
        self, admin_sessionmaker: SessionmakerFixture
    ) -> None:
        async with admin_sessionmaker() as session, session.begin():
            created = await create_account(
                session,
                username=_username(),
                role="submitter",
                initial_password=_PASSWORD,
                created_by="admin-alice",
                known_roles=KNOWN_ROLES,
            )
        new_password = "a totally different long passphrase"
        async with admin_sessionmaker() as session, session.begin():
            await reset_password(
                session, account_id=created.id, new_password=new_password, actor="admin-bob"
            )
        async with admin_sessionmaker() as session:
            rows = await list_accounts(session)
        row = next(r for r in rows if r.id == created.id)
        assert verify_password(new_password, row.password_hash) is True
        assert verify_password(_PASSWORD, row.password_hash) is False

    @pytest.mark.asyncio
    async def test_short_password_rejected(self, admin_sessionmaker: SessionmakerFixture) -> None:
        async with admin_sessionmaker() as session, session.begin():
            created = await create_account(
                session,
                username=_username(),
                role="submitter",
                initial_password=_PASSWORD,
                created_by="admin-alice",
                known_roles=KNOWN_ROLES,
            )
        with pytest.raises(AdminAccountError, match="at least"):
            async with admin_sessionmaker() as session, session.begin():
                await reset_password(
                    session, account_id=created.id, new_password="short", actor="admin-bob"
                )


class TestGroupRoleMapping:
    @pytest.mark.asyncio
    async def test_upsert_creates_then_updates(
        self, admin_sessionmaker: SessionmakerFixture
    ) -> None:
        group = f"group-{uuid.uuid4().hex[:12]}"
        async with admin_sessionmaker() as session, session.begin():
            created = await upsert_group_role_mapping(
                session,
                group_name=group,
                role="approver",
                actor="admin-alice",
                known_roles=KNOWN_ROLES,
            )
        assert created.role == "approver"
        async with admin_sessionmaker() as session, session.begin():
            updated = await upsert_group_role_mapping(
                session, group_name=group, role="admin", actor="admin-bob", known_roles=KNOWN_ROLES
            )
        assert updated.role == "admin"
        async with admin_sessionmaker() as session:
            rows = await list_group_role_mapping(session)
        matches = [r for r in rows if r.group_name == group]
        assert len(matches) == 1
        assert matches[0].role == "admin"

    @pytest.mark.asyncio
    async def test_unknown_role_rejected(self, admin_sessionmaker: SessionmakerFixture) -> None:
        with pytest.raises(AdminAccountError, match="unknown role"):
            async with admin_sessionmaker() as session, session.begin():
                await upsert_group_role_mapping(
                    session,
                    group_name=f"group-{uuid.uuid4().hex[:12]}",
                    role="superuser",
                    actor="admin-alice",
                    known_roles=KNOWN_ROLES,
                )

    @pytest.mark.asyncio
    async def test_delete_removes_mapping(self, admin_sessionmaker: SessionmakerFixture) -> None:
        group = f"group-{uuid.uuid4().hex[:12]}"
        async with admin_sessionmaker() as session, session.begin():
            await upsert_group_role_mapping(
                session,
                group_name=group,
                role="submitter",
                actor="admin-alice",
                known_roles=KNOWN_ROLES,
            )
        async with admin_sessionmaker() as session, session.begin():
            await delete_group_role_mapping(session, group_name=group, actor="admin-bob")
        async with admin_sessionmaker() as session:
            rows = await list_group_role_mapping(session)
        assert not any(r.group_name == group for r in rows)

    @pytest.mark.asyncio
    async def test_delete_unknown_group_rejected(
        self, admin_sessionmaker: SessionmakerFixture
    ) -> None:
        with pytest.raises(AdminAccountError, match="no group_role_mapping"):
            async with admin_sessionmaker() as session, session.begin():
                await delete_group_role_mapping(
                    session, group_name=f"nonexistent-{uuid.uuid4().hex[:12]}", actor="admin-bob"
                )

    @pytest.mark.asyncio
    async def test_writes_audit_intent_with_from_and_to_role(
        self,
        admin_sessionmaker: SessionmakerFixture,
        audit_sessionmaker: SessionmakerFixture,
    ) -> None:
        group = f"group-{uuid.uuid4().hex[:12]}"
        async with admin_sessionmaker() as session, session.begin():
            await upsert_group_role_mapping(
                session,
                group_name=group,
                role="submitter",
                actor="admin-alice",
                known_roles=KNOWN_ROLES,
            )
        async with admin_sessionmaker() as session, session.begin():
            await upsert_group_role_mapping(
                session, group_name=group, role="admin", actor="admin-bob", known_roles=KNOWN_ROLES
            )
        async with audit_sessionmaker() as session:
            result = await session.execute(
                select(AuditIntent)
                .where(AuditIntent.action == "group_role_map_updated")
                .order_by(AuditIntent.id.asc())
            )
            intents = [r for r in result.scalars().all() if r.payload.get("group_name") == group]
        assert len(intents) == 2
        assert intents[0].payload["from_role"] is None
        assert intents[0].payload["to_role"] == "submitter"
        assert intents[1].payload["from_role"] == "submitter"
        assert intents[1].payload["to_role"] == "admin"
