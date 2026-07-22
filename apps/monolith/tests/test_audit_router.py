"""Tests for `GET /v1/audit` (coding spec §9) - real local MySQL/Redis via a
real ScanRuntime; auth faked via FastAPI dependency override.
"""

from __future__ import annotations

import datetime
import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from common.blobstore import LocalFilesystemBlobStore
from fastapi import FastAPI
from skillscan_core import GatePolicy, StaticKeywordEngine, TrustTier, Verdict

from monolith.main import create_app
from monolith.modules.audit.models import AuditEntry
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.auth.dependencies import get_session_context
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.tests.conftest import SessionmakerFixture

_ENGINE = StaticKeywordEngine()


def _session(subject: str, roles: frozenset[str]) -> SessionContext:
    return SessionContext(
        subject=subject,
        roles=roles,
        scopes=frozenset(),
        tier=TrustTier.INTERNAL,
        token_exp=9999999999.0,
    )


@pytest.fixture
def app(
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    audit_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
) -> FastAPI:
    scan_runtime = ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=orchestration_sessionmaker,
        gate_session_factory=gate_sessionmaker,
        policy=GatePolicy(
            version=f"test-audit-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
        audit_session_factory=audit_sessionmaker,
    )
    return create_app(scan_runtime=scan_runtime)


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


def _as(app_instance: FastAPI, subject: str, roles: frozenset[str]) -> None:
    app_instance.dependency_overrides[get_session_context] = lambda: _session(subject, roles)


class TestGetAuditLog:
    @pytest.mark.asyncio
    async def test_auditor_can_read_and_gets_a_valid_chain(
        self, app: FastAPI, client: httpx.AsyncClient, audit_sessionmaker: SessionmakerFixture
    ) -> None:
        marker = f"op-{uuid.uuid4().hex[:12]}"
        async with audit_sessionmaker() as session, session.begin():
            session.add(
                AuditEntry(
                    prev_hash="0" * 64,
                    entry_hash=f"dummy-{uuid.uuid4().hex}",
                    operator=marker,
                    action="test_action",
                    payload={"note": "seeded"},
                    chained_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )
        _as(app, "auditor-alice", frozenset({"auditor"}))
        response = await client.get("/v1/audit")
        assert response.status_code == 200
        body = response.json()
        assert "chain_valid" in body
        matching = [e for e in body["entries"] if e["operator"] == marker]
        assert len(matching) == 1
        assert matching[0]["action"] == "test_action"

    @pytest.mark.asyncio
    async def test_non_auditor_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "carol", frozenset({"approver"}))
        response = await client.get("/v1/audit")
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_limit_is_bounded(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "auditor-alice", frozenset({"auditor"}))
        response = await client.get("/v1/audit", params={"limit": 999999})
        assert response.status_code == 200
        assert len(response.json()["entries"]) <= 500
