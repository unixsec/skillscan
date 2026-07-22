"""Tests for `admin.local_auth` (2026-07-13 addition, coding spec INV-17
extension) against the real local Redis instance - no mocking, mirrors
test_breakglass.py's structure and isolation-fixture pattern.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from monolith.modules.admin.local_auth import (
    LocalAccount,
    LocalAuthError,
    StaticLocalAccountStore,
    authenticate_local,
    create_local_session,
    hash_password,
    load_local_accounts_from_json,
    resolve_local_session,
    verify_password,
)

_KNOWN_ROLES = frozenset({"submitter", "approver", "admin", "auditor"})


@pytest_asyncio.fixture(autouse=True)
async def _clean_local_auth_redis_state() -> AsyncIterator[None]:
    """Same rationale as test_breakglass.py's analogous fixture: local_auth's
    Redis keys (fail-counters, sessions) are fixed/global, not per-test-
    namespaced, and `redis_client` (conftest.py) is a single shared DB with
    no flush between tests."""
    client: aioredis.Redis = aioredis.Redis.from_url("redis://localhost:6379/0")
    try:

        async def _clear() -> None:
            keys = [k async for k in client.scan_iter(match="skillscan:admin:local:*")]
            if keys:
                await client.delete(*keys)

        await _clear()
        yield
        await _clear()
    finally:
        await client.aclose()


def _account(
    username: str = "alice", password: str = "correct horse battery staple", role: str = "admin"
) -> tuple[LocalAccount, str]:
    return LocalAccount(
        username=username, password_hash=hash_password(password), role=role
    ), password


class TestHashAndVerifyPassword:
    def test_correct_password_verifies(self) -> None:
        h = hash_password("s3cret!")
        assert verify_password("s3cret!", h) is True

    def test_wrong_password_rejected(self) -> None:
        h = hash_password("s3cret!")
        assert verify_password("wrong", h) is False

    def test_hash_is_never_plaintext(self) -> None:
        # SECURITY (INV-17): the stored hash must not equal or contain the
        # plaintext password verbatim.
        h = hash_password("s3cret!")
        assert "s3cret!" not in h

    def test_two_hashes_of_same_password_differ(self) -> None:
        # SECURITY: random salt per call - equal passwords must not produce
        # equal hashes (defends against rainbow-table/duplicate-hash leakage).
        h1 = hash_password("s3cret!")
        h2 = hash_password("s3cret!")
        assert h1 != h2
        assert verify_password("s3cret!", h1) is True
        assert verify_password("s3cret!", h2) is True

    def test_malformed_hash_rejected_not_crashed(self) -> None:
        assert verify_password("anything", "not-a-real-hash") is False
        assert verify_password("anything", "scrypt$onlyonepart") is False


class TestLoadLocalAccountsFromJson:
    def test_valid_json_loads(self) -> None:
        h = hash_password("pw")
        accounts = load_local_accounts_from_json(
            f'[{{"username": "a", "password_hash": "{h}", "role": "admin"}}]',
            known_roles=_KNOWN_ROLES,
        )
        assert accounts == (LocalAccount(username="a", password_hash=h, role="admin"),)

    def test_invalid_json_raises(self) -> None:
        with pytest.raises(LocalAuthError, match="not valid JSON"):
            load_local_accounts_from_json("{not json", known_roles=_KNOWN_ROLES)

    def test_non_array_raises(self) -> None:
        with pytest.raises(LocalAuthError, match="must be a JSON array"):
            load_local_accounts_from_json("{}", known_roles=_KNOWN_ROLES)

    def test_unknown_role_rejected(self) -> None:
        # SECURITY (mirrors rbac.load_group_role_map's KNOWN_ROLES check):
        # fail-closed on a config mistake/typo, never silently ignored.
        h = hash_password("pw")
        with pytest.raises(LocalAuthError, match="unknown role"):
            load_local_accounts_from_json(
                f'[{{"username": "a", "password_hash": "{h}", "role": "superuser"}}]',
                known_roles=_KNOWN_ROLES,
            )

    def test_duplicate_username_rejected(self) -> None:
        h = hash_password("pw")
        with pytest.raises(LocalAuthError, match="duplicate"):
            load_local_accounts_from_json(
                f'[{{"username": "a", "password_hash": "{h}", "role": "admin"}}, '
                f'{{"username": "a", "password_hash": "{h}", "role": "auditor"}}]',
                known_roles=_KNOWN_ROLES,
            )

    def test_missing_field_rejected(self) -> None:
        with pytest.raises(LocalAuthError, match="username"):
            load_local_accounts_from_json('[{"role": "admin"}]', known_roles=_KNOWN_ROLES)


class TestAuthenticateLocal:
    @pytest.mark.asyncio
    async def test_correct_credentials_succeed(self, redis_client: aioredis.Redis) -> None:
        account, password = _account()
        store = StaticLocalAccountStore((account,))
        result = await authenticate_local(redis_client, store, username="alice", password=password)
        assert result == account

    @pytest.mark.asyncio
    async def test_wrong_password_rejected(self, redis_client: aioredis.Redis) -> None:
        account, _password = _account()
        store = StaticLocalAccountStore((account,))
        result = await authenticate_local(redis_client, store, username="alice", password="wrong")
        assert result is None

    @pytest.mark.asyncio
    async def test_unknown_username_rejected(self, redis_client: aioredis.Redis) -> None:
        account, password = _account()
        store = StaticLocalAccountStore((account,))
        result = await authenticate_local(redis_client, store, username="nobody", password=password)
        assert result is None

    @pytest.mark.asyncio
    async def test_role_carried_through_on_success(self, redis_client: aioredis.Redis) -> None:
        account, password = _account(role="auditor")
        store = StaticLocalAccountStore((account,))
        result = await authenticate_local(redis_client, store, username="alice", password=password)
        assert result is not None
        assert result.role == "auditor"

    @pytest.mark.asyncio
    async def test_lockout_after_threshold_failures(self, redis_client: aioredis.Redis) -> None:
        # SECURITY: 5 wrong attempts must lock the account out for the
        # lockout window, even on a subsequent CORRECT password.
        account, password = _account()
        store = StaticLocalAccountStore((account,))
        for _ in range(5):
            result = await authenticate_local(
                redis_client, store, username="alice", password="wrong"
            )
            assert result is None
        # 6th attempt, this time with the CORRECT password - must still fail,
        # proving lockout (not just repeated wrong-password rejection).
        result = await authenticate_local(redis_client, store, username="alice", password=password)
        assert result is None

    @pytest.mark.asyncio
    async def test_successful_login_resets_failure_counter(
        self, redis_client: aioredis.Redis
    ) -> None:
        account, password = _account()
        store = StaticLocalAccountStore((account,))
        for _ in range(3):
            await authenticate_local(redis_client, store, username="alice", password="wrong")
        result = await authenticate_local(redis_client, store, username="alice", password=password)
        assert result == account
        # Failure counter must be cleared - 3 more wrong attempts (would have
        # been 6 total, past the threshold, if the counter hadn't reset)
        # still leave room for one more before lockout.
        for _ in range(3):
            r = await authenticate_local(redis_client, store, username="alice", password="wrong")
            assert r is None
        result_again = await authenticate_local(
            redis_client, store, username="alice", password=password
        )
        assert result_again == account

    @pytest.mark.asyncio
    async def test_concurrent_attempts_all_resolve_independently(
        self, redis_client: aioredis.Redis
    ) -> None:
        # Unlike break-glass's single-use arming, local accounts are a
        # standing credential - concurrent correct logins must ALL succeed
        # (no single-use semantics here), proving authenticate_local has no
        # unintended one-shot consumption behavior.
        account, password = _account()
        store = StaticLocalAccountStore((account,))

        async def _attempt() -> LocalAccount | None:
            return await authenticate_local(
                redis_client, store, username="alice", password=password
            )

        results = await asyncio.gather(_attempt(), _attempt(), _attempt())
        assert all(r == account for r in results)


class TestLocalSession:
    @pytest.mark.asyncio
    async def test_created_session_resolves_to_same_subject_and_role(
        self, redis_client: aioredis.Redis
    ) -> None:
        token = await create_local_session(redis_client, subject="alice", role="approver")
        resolved = await resolve_local_session(redis_client, token)
        assert resolved == ("alice", "approver")

    @pytest.mark.asyncio
    async def test_unknown_token_resolves_to_none(self, redis_client: aioredis.Redis) -> None:
        resolved = await resolve_local_session(redis_client, f"nonexistent-{uuid.uuid4().hex}")
        assert resolved is None

    @pytest.mark.asyncio
    async def test_sessions_for_different_roles_are_independent(
        self, redis_client: aioredis.Redis
    ) -> None:
        # SECURITY: unlike break-glass (always "admin"), local sessions carry
        # whatever role the authenticated account has - each of the four
        # roles must round-trip correctly and independently.
        for role in ("admin", "approver", "auditor", "submitter"):
            token = await create_local_session(redis_client, subject=f"user-{role}", role=role)
            resolved = await resolve_local_session(redis_client, token)
            assert resolved == (f"user-{role}", role)
