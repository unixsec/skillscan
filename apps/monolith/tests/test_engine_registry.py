"""Tests for `admin.engine_registry` (coding spec §9 Admin·Engines, INV-1)
against the real local Redis instance.
"""

from __future__ import annotations

import uuid

import pytest
import redis.asyncio as aioredis
from skillscan_core import EngineCapability, EngineMetadata

from monolith.modules.admin.engine_registry import (
    EngineDisableError,
    filter_enabled_engines,
    is_disableable,
    list_disabled_engines,
    set_engine_enabled,
)


def _metadata(name: str) -> EngineMetadata:
    return EngineMetadata(
        name=name,
        version="1.0",
        ruleset_digest="d",
        capabilities=frozenset({EngineCapability.STATIC}),
    )


class TestIsDisableable:
    def test_required_engine_is_not_disableable(self) -> None:
        assert (
            is_disableable("static-keyword", required_names=frozenset({"static-keyword"})) is False
        )

    def test_non_required_engine_is_disableable(self) -> None:
        assert is_disableable("bandit", required_names=frozenset({"static-keyword"})) is True


class TestSetEngineEnabled:
    @pytest.mark.asyncio
    async def test_disabling_a_required_engine_raises(self, redis_client: aioredis.Redis) -> None:
        name = f"floor-{uuid.uuid4().hex[:8]}"
        with pytest.raises(EngineDisableError, match="cannot be disabled"):
            await set_engine_enabled(
                redis_client, name, enabled=False, required_names=frozenset({name})
            )

    @pytest.mark.asyncio
    async def test_disabling_a_non_required_engine_succeeds(
        self, redis_client: aioredis.Redis
    ) -> None:
        name = f"bandit-{uuid.uuid4().hex[:8]}"
        await set_engine_enabled(redis_client, name, enabled=False, required_names=frozenset())
        disabled = await list_disabled_engines(redis_client)
        assert name in disabled

    @pytest.mark.asyncio
    async def test_re_enabling_removes_it_from_the_disabled_set(
        self, redis_client: aioredis.Redis
    ) -> None:
        name = f"bandit-{uuid.uuid4().hex[:8]}"
        await set_engine_enabled(redis_client, name, enabled=False, required_names=frozenset())
        await set_engine_enabled(redis_client, name, enabled=True, required_names=frozenset())
        disabled = await list_disabled_engines(redis_client)
        assert name not in disabled

    @pytest.mark.asyncio
    async def test_a_required_engine_can_still_be_explicitly_re_enabled_as_a_no_op(
        self, redis_client: aioredis.Redis
    ) -> None:
        # enabled=True never goes through the disableability check at all -
        # only disabling is restricted.
        name = f"floor-{uuid.uuid4().hex[:8]}"
        await set_engine_enabled(redis_client, name, enabled=True, required_names=frozenset({name}))
        disabled = await list_disabled_engines(redis_client)
        assert name not in disabled


class TestFilterEnabledEngines:
    @pytest.mark.asyncio
    async def test_disabled_engine_excluded_from_filtered_list(
        self, redis_client: aioredis.Redis
    ) -> None:
        keep = _metadata(f"keep-{uuid.uuid4().hex[:8]}")
        drop = _metadata(f"drop-{uuid.uuid4().hex[:8]}")
        await set_engine_enabled(redis_client, drop.name, enabled=False, required_names=frozenset())

        result = await filter_enabled_engines(redis_client, [keep, drop])
        assert [m.name for m in result] == [keep.name]

    @pytest.mark.asyncio
    async def test_no_disabled_engines_returns_everything(
        self, redis_client: aioredis.Redis
    ) -> None:
        a = _metadata(f"a-{uuid.uuid4().hex[:8]}")
        b = _metadata(f"b-{uuid.uuid4().hex[:8]}")
        result = await filter_enabled_engines(redis_client, [a, b])
        assert {m.name for m in result} == {a.name, b.name}
