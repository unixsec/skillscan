"""Tests for `GET/POST /v1/reviews*` (coding spec §9) - real local MySQL/
Redis via a real ScanRuntime; auth faked via FastAPI dependency override.
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
from monolith.modules.gate.models import VerdictRow
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.auth.dependencies import get_session_context
from monolith.modules.gateway.auth.middleware import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
)
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.orchestration.models import ScanJob
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


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


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
            version=f"test-reviews-{uuid.uuid4().hex[:8]}",
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


def _as(app_instance: FastAPI, subject: str, roles: frozenset[str]) -> None:
    app_instance.dependency_overrides[get_session_context] = lambda: _session(subject, roles)


def _csrf_headers_and_cookies(client_instance: httpx.AsyncClient) -> dict[str, str]:
    client_instance.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
    client_instance.cookies.set(CSRF_COOKIE_NAME, "test-csrf-token")
    return {CSRF_HEADER_NAME: "test-csrf-token"}


async def _seed_review_scan(
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    *,
    scan_id: str,
    submitter: str,
) -> None:
    content_hash = uuid.uuid4().hex + uuid.uuid4().hex
    async with orchestration_sessionmaker() as session, session.begin():
        session.add(
            ScanJob(
                scan_id=scan_id,
                content_hash=content_hash,
                toolchain_digest="digest-v1",
                cache_key=f"cache-{uuid.uuid4().hex}",
                state="scored",
                submitter=submitter,
                created_at=_naive_utcnow(),
            )
        )
    async with gate_sessionmaker() as session, session.begin():
        session.add(
            VerdictRow(
                scan_id=scan_id,
                content_hash=content_hash,
                verdict="REVIEW",
                policy_version="v1",
                jti=str(uuid.uuid4()),
                jws_signature="original-sig",
                effective_severity=2,
                reasons=["automated: ambiguous"],
                issued_at=_naive_utcnow(),
            )
        )


class TestListReviews:
    @pytest.mark.asyncio
    async def test_approver_can_list_pending_reviews(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )
        _as(app, "approver-carol", frozenset({"approver"}))
        response = await client.get("/v1/reviews")
        assert response.status_code == 200
        assert any(s["scan_id"] == scan_id for s in response.json()["scans"])

    @pytest.mark.asyncio
    async def test_submitter_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "bob", frozenset({"submitter"}))
        response = await client.get("/v1/reviews")
        assert response.status_code == 403


class TestDecideReview:
    @pytest.mark.asyncio
    async def test_approver_can_approve(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )
        _as(app, "approver-carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/reviews/{scan_id}",
            json={"decision": "approve", "reason": "looks fine"},
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["verdict"] == "PASS"

    @pytest.mark.asyncio
    async def test_reviewer_same_as_submitter_is_403(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )
        _as(app, "dev-dave", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/reviews/{scan_id}", json={"decision": "approve"}, headers=headers
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_unknown_scan_is_404(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "approver-carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/reviews/{uuid.uuid4()}", json={"decision": "approve"}, headers=headers
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_invalid_decision_is_400(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )
        _as(app, "approver-carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/reviews/{scan_id}", json={"decision": "maybe"}, headers=headers
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_missing_csrf_is_403(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )
        _as(app, "approver-carol", frozenset({"approver"}))
        client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
        response = await client.post(f"/v1/reviews/{scan_id}", json={"decision": "approve"})
        assert response.status_code == 403
