"""Tests for `GET /.well-known/jwks.json`, `/healthz`, `/readyz` (coding spec
§9) - deliberately public/unauthenticated, real ScanRuntime.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from common.blobstore import LocalFilesystemBlobStore
from fastapi import FastAPI
from skillscan_core import GatePolicy, StaticKeywordEngine, Verdict

from monolith.main import create_app
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.tests.conftest import SessionmakerFixture

_ENGINE = StaticKeywordEngine()


@pytest.fixture
def app(
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
) -> FastAPI:
    scan_runtime = ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=orchestration_sessionmaker,
        gate_session_factory=gate_sessionmaker,
        policy=GatePolicy(
            version=f"test-infra-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
    )
    return create_app(scan_runtime=scan_runtime)


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


class TestJwks:
    @pytest.mark.asyncio
    async def test_returns_public_key_with_no_auth(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        response = await client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        keys = response.json()["keys"]
        assert len(keys) == 1
        assert keys[0]["kty"] == "RSA"
        assert keys[0]["alg"] == "RS256"


class TestHealthz:
    @pytest.mark.asyncio
    async def test_always_ok(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestReadyz:
    @pytest.mark.asyncio
    async def test_ready_when_dependencies_healthy(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        response = await client.get("/readyz")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["checks"]["redis"] is True
        assert body["checks"]["orchestration_db"] is True

    @pytest.mark.asyncio
    async def test_not_ready_when_redis_unreachable(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # SECURITY: fail-closed - point at a port nothing is listening on
        # rather than mocking, so this is a REAL connection failure.
        broken_redis: aioredis.Redis = aioredis.Redis.from_url("redis://localhost:1")
        app.state.scan.redis = broken_redis
        try:
            response = await client.get("/readyz")
            assert response.status_code == 503
            assert response.json()["checks"]["redis"] is False
        finally:
            await broken_redis.aclose()
