"""Tests for `marketplace_api.ratelimit` (里程碑 B' Task 5, spec §6.3) against
the real local Redis instance - no mocking, mirrors test_local_auth.py's
structure and isolation-fixture pattern.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from monolith.modules.marketplace_api.ratelimit import check_rate_limit


@pytest_asyncio.fixture(autouse=True)
async def _clean_marketplace_rate_redis_state() -> AsyncIterator[None]:
    """Same rationale as test_local_auth.py's analogous fixture: ratelimit's
    Redis keys are fixed (per service account), not per-test-namespaced, and
    `redis_client` (conftest.py) is a single shared DB with no flush between
    tests."""
    client: aioredis.Redis = aioredis.Redis.from_url("redis://localhost:6379/0")
    try:

        async def _clear() -> None:
            keys = [k async for k in client.scan_iter(match="skillscan:mkt:rate:*")]
            if keys:
                await client.delete(*keys)

        await _clear()
        yield
        await _clear()
    finally:
        await client.aclose()


class TestCheckRateLimit:
    @pytest.mark.asyncio
    async def test_within_limit_returns_none(self, redis_client: aioredis.Redis) -> None:
        for _ in range(3):
            result = await check_rate_limit(redis_client, service_account="mkt-a", limit_per_min=3)
            assert result is None

    @pytest.mark.asyncio
    async def test_exceeding_limit_returns_positive_retry_after(
        self, redis_client: aioredis.Redis
    ) -> None:
        for _ in range(3):
            result = await check_rate_limit(redis_client, service_account="mkt-b", limit_per_min=3)
            assert result is None
        # 4th call, past the limit - must be rejected with a positive
        # Retry-After hint, not silently allowed.
        result = await check_rate_limit(redis_client, service_account="mkt-b", limit_per_min=3)
        assert result is not None
        assert result > 0

    @pytest.mark.asyncio
    async def test_further_calls_after_limit_stay_rejected(
        self, redis_client: aioredis.Redis
    ) -> None:
        for _ in range(3):
            await check_rate_limit(redis_client, service_account="mkt-c", limit_per_min=3)
        first_reject = await check_rate_limit(
            redis_client, service_account="mkt-c", limit_per_min=3
        )
        second_reject = await check_rate_limit(
            redis_client, service_account="mkt-c", limit_per_min=3
        )
        assert first_reject is not None
        assert second_reject is not None

    @pytest.mark.asyncio
    async def test_different_service_accounts_are_independent(
        self, redis_client: aioredis.Redis
    ) -> None:
        # SECURITY (spec §6.3): one marketplace exhausting its own budget must
        # not affect another service account's budget.
        for _ in range(3):
            result = await check_rate_limit(redis_client, service_account="mkt-d", limit_per_min=3)
            assert result is None
        # mkt-d is now over budget - mkt-e must still be allowed.
        exhausted = await check_rate_limit(redis_client, service_account="mkt-d", limit_per_min=3)
        assert exhausted is not None
        fresh = await check_rate_limit(redis_client, service_account="mkt-e", limit_per_min=3)
        assert fresh is None
