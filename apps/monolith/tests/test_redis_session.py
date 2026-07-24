"""Tests for the shared redis_session store (coding spec §16.3).

Runs against the real Redis fixture (conftest.redis_client), not a mock -
this project's standing policy is to test session/state logic against real
infrastructure. The most important assertion here is the security one: the
stored Redis KEY must be sha256(token), never the raw token.
"""

from __future__ import annotations

import hashlib
import uuid

import pytest
import redis.asyncio as aioredis

from monolith.modules.gateway.auth import redis_session

_PREFIX = "skillscan:test:redis_session:"


class TestRoundTrip:
    @pytest.mark.asyncio
    async def test_string_payload_round_trips(self, redis_client: aioredis.Redis) -> None:
        token = await redis_session.create_session(
            redis_client, key_prefix=_PREFIX, ttl_s=60, payload="alice"
        )
        assert (
            await redis_session.resolve_session(redis_client, key_prefix=_PREFIX, token=token)
            == "alice"
        )

    @pytest.mark.asyncio
    async def test_dict_payload_round_trips(self, redis_client: aioredis.Redis) -> None:
        token = await redis_session.create_session(
            redis_client,
            key_prefix=_PREFIX,
            ttl_s=60,
            payload={"subject": "bob", "roles": ["approver", "admin"]},
        )
        assert await redis_session.resolve_session(
            redis_client, key_prefix=_PREFIX, token=token
        ) == {"subject": "bob", "roles": ["approver", "admin"]}

    @pytest.mark.asyncio
    async def test_unknown_token_resolves_to_none(self, redis_client: aioredis.Redis) -> None:
        assert (
            await redis_session.resolve_session(
                redis_client, key_prefix=_PREFIX, token=f"nope-{uuid.uuid4().hex}"
            )
            is None
        )

    @pytest.mark.asyncio
    async def test_tokens_are_unique_per_creation(self, redis_client: aioredis.Redis) -> None:
        tokens = {
            await redis_session.create_session(
                redis_client, key_prefix=_PREFIX, ttl_s=60, payload="x"
            )
            for _ in range(20)
        }
        assert len(tokens) == 20


class TestStorageKeyIsHashedNotRawToken:
    """SECURITY: the whole point of this module over the three implementations
    it replaced. A session token is a bearer credential; storing it verbatim
    as a Redis key exposed live sessions to anyone who could read Redis
    (snapshot, SCAN/KEYS, slow-query log). The stored key must be
    sha256(token)."""

    @pytest.mark.asyncio
    async def test_raw_token_is_never_a_redis_key(self, redis_client: aioredis.Redis) -> None:
        token = await redis_session.create_session(
            redis_client, key_prefix=_PREFIX, ttl_s=60, payload="alice"
        )

        # The raw-token key the OLD implementations used must NOT exist.
        assert await redis_client.get(f"{_PREFIX}{token}") is None

        # The hashed key MUST exist and hold the payload.
        hashed_key = f"{_PREFIX}{hashlib.sha256(token.encode()).hexdigest()}"
        assert await redis_client.get(hashed_key) is not None

    @pytest.mark.asyncio
    async def test_no_stored_key_contains_the_raw_token(self, redis_client: aioredis.Redis) -> None:
        token = await redis_session.create_session(
            redis_client, key_prefix=_PREFIX, ttl_s=60, payload="alice"
        )
        # Scan every key under our prefix; none may contain the raw token
        # substring. (Belt-and-suspenders over the exact-key check above.)
        async for key in redis_client.scan_iter(match=f"{_PREFIX}*"):
            key_str = key.decode() if isinstance(key, bytes) else key
            assert token not in key_str


class TestFailClosed:
    @pytest.mark.asyncio
    async def test_corrupt_record_resolves_to_none(self, redis_client: aioredis.Redis) -> None:
        # Write a non-JSON value directly at the hashed key a token maps to,
        # then confirm resolution treats it as missing rather than trusting it.
        token = f"corrupt-{uuid.uuid4().hex}"
        hashed_key = f"{_PREFIX}{hashlib.sha256(token.encode()).hexdigest()}"
        await redis_client.set(hashed_key, b"\xff not json \x00", ex=60)
        assert (
            await redis_session.resolve_session(redis_client, key_prefix=_PREFIX, token=token)
            is None
        )


class TestDeleteSession:
    @pytest.mark.asyncio
    async def test_deleted_session_no_longer_resolves(self, redis_client: aioredis.Redis) -> None:
        token = await redis_session.create_session(
            redis_client, key_prefix=_PREFIX, ttl_s=60, payload="alice"
        )
        await redis_session.delete_session(redis_client, key_prefix=_PREFIX, token=token)
        assert (
            await redis_session.resolve_session(redis_client, key_prefix=_PREFIX, token=token)
            is None
        )

    @pytest.mark.asyncio
    async def test_deleting_an_unknown_token_does_not_raise(
        self, redis_client: aioredis.Redis
    ) -> None:
        # Logout must be idempotent - a session that's already gone (expired,
        # or a double-click) is not an error.
        await redis_session.delete_session(
            redis_client, key_prefix=_PREFIX, token=f"nope-{uuid.uuid4().hex}"
        )
