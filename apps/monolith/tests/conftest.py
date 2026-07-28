"""Shared pytest fixtures for M3+ tests: real local MySQL (per-module least-
privilege users, policies/grants/manifest.yaml) + real local Redis + a
LocalFilesystemBlobStore under tmp_path.

SECURITY: these fixtures intentionally use the SAME per-module credentials
production would use (never a shared root/admin connection) - a test that
tried to write another module's table is rejected by MySQL itself, exactly as
in production (see test_grant_isolation.py). Requires the local dev services
from docs/USER_GUIDE.md (MySQL 8 with policies/grants/manifest.yaml applied,
Redis) to be running; these fixtures do not start/stop them.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from common.blobstore import LocalFilesystemBlobStore
from common.db import make_engine, make_session_factory
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

_LOCAL_DEV_PASSWORD = "local-dev-only-not-a-secret"

# Shared annotation for the `*_sessionmaker` fixtures below - tests importing
# this avoid repeating `async_sessionmaker[AsyncSession]` at every call site.
SessionmakerFixture = async_sessionmaker[AsyncSession]


def _dsn(user: str) -> str:
    return f"mysql+aiomysql://{user}:{_LOCAL_DEV_PASSWORD}@localhost/skillscan"


async def _make_module_sessionmaker(user: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(_dsn(user))
    try:
        yield make_session_factory(engine)
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def orchestration_sessionmaker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    async for sm in _make_module_sessionmaker("svc_orchestration"):
        yield sm


@pytest_asyncio.fixture
async def gate_sessionmaker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    async for sm in _make_module_sessionmaker("svc_gate"):
        yield sm


@pytest_asyncio.fixture
async def audit_sessionmaker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    async for sm in _make_module_sessionmaker("svc_audit"):
        yield sm


@pytest_asyncio.fixture
async def relay_sessionmaker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    async for sm in _make_module_sessionmaker("svc_relay"):
        yield sm


@pytest_asyncio.fixture
async def reeval_sessionmaker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    async for sm in _make_module_sessionmaker("svc_reeval"):
        yield sm


@pytest_asyncio.fixture
async def inventory_sessionmaker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    async for sm in _make_module_sessionmaker("svc_inventory"):
        yield sm


@pytest_asyncio.fixture
async def intel_sessionmaker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    async for sm in _make_module_sessionmaker("svc_intel"):
        yield sm


@pytest_asyncio.fixture
async def reporting_sessionmaker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    async for sm in _make_module_sessionmaker("svc_reporting"):
        yield sm


@pytest_asyncio.fixture
async def admin_sessionmaker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    async for sm in _make_module_sessionmaker("svc_admin"):
        yield sm


@pytest_asyncio.fixture
async def marketplace_sessionmaker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    async for sm in _make_module_sessionmaker("svc_marketplace"):
        yield sm


@pytest_asyncio.fixture
async def redis_client() -> AsyncIterator[aioredis.Redis]:
    client: aioredis.Redis = aioredis.Redis.from_url("redis://localhost:6379/0")
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
def blobstore(tmp_path: Path) -> LocalFilesystemBlobStore:
    return LocalFilesystemBlobStore(tmp_path / "blobstore")


@pytest.fixture
def unique_consumer() -> str:
    return f"test-{uuid.uuid4()}"
