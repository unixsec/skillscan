"""Tests for `GET/POST /v1/allowlist`, `DELETE /v1/allowlist/{id}` (coding
spec §9, INV-8) - real local MySQL/Redis via a real ScanRuntime; auth faked
via FastAPI dependency override.
"""

from __future__ import annotations

import time
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
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.auth.dependencies import get_session_context
from monolith.modules.gateway.auth.middleware import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
)
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.tests.conftest import SessionmakerFixture

_ENGINE = StaticKeywordEngine()
_HARD_GATE_RULE = "pii.credit_card"


def _session(subject: str, roles: frozenset[str]) -> SessionContext:
    return SessionContext(
        subject=subject,
        roles=roles,
        scopes=frozenset(),
        tier=TrustTier.INTERNAL,
        token_exp=9999999999.0,
        is_machine=False,  # a console/reviewer session is a person
    )


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
            version=f"test-allowlist-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset({_HARD_GATE_RULE}),
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


def _grant_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "scope_type": "skill_id",
        "scope_value": "skill-123",
        "rule_id": f"rule-{uuid.uuid4().hex[:12]}",
        "expires_at": time.time() + 3600,
        "requested_by": "dev-dave",
        "reason": "false positive",
    }
    body.update(overrides)
    return body


class TestCreateAllowlistEntry:
    @pytest.mark.asyncio
    async def test_approver_can_grant_non_hard_gate_exemption(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as(app, "approver-carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post("/v1/allowlist", json=_grant_body(), headers=headers)
        assert response.status_code == 201
        body = response.json()
        assert body["approved_by"] == "approver-carol"
        assert body["requested_by"] == "dev-dave"

    @pytest.mark.asyncio
    async def test_approver_cannot_grant_hard_gate_exemption(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as(app, "approver-carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/allowlist", json=_grant_body(rule_id=_HARD_GATE_RULE), headers=headers
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_can_grant_hard_gate_exemption(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/allowlist", json=_grant_body(rule_id=_HARD_GATE_RULE), headers=headers
        )
        assert response.status_code == 201

    @pytest.mark.asyncio
    async def test_self_approval_is_400(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        # four-eyes: approved_by (the caller) must differ from requested_by
        _as(app, "dev-dave", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/allowlist", json=_grant_body(requested_by="dev-dave"), headers=headers
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_submitter_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "bob", frozenset({"submitter"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post("/v1/allowlist", json=_grant_body(), headers=headers)
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_missing_csrf_is_403(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "approver-carol", frozenset({"approver"}))
        client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
        response = await client.post("/v1/allowlist", json=_grant_body())
        assert response.status_code == 403


class TestListAllowlist:
    @pytest.mark.asyncio
    async def test_lists_the_entry_just_granted(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        rule_id = f"rule-{uuid.uuid4().hex[:12]}"
        await client.post("/v1/allowlist", json=_grant_body(rule_id=rule_id), headers=headers)

        response = await client.get("/v1/allowlist")
        assert response.status_code == 200
        matching = [e for e in response.json()["entries"] if e["rule_id"] == rule_id]
        assert len(matching) == 1

    @pytest.mark.asyncio
    async def test_listed_entries_include_id_for_revocation(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # SECURITY/BUG: the list response must carry an `id` - otherwise
        # nothing (UI or API caller) can ever target DELETE /v1/allowlist/{id}
        # for a specific entry (caught while wiring the frontend's Allowlist
        # page against this exact endpoint).
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        rule_id = f"rule-{uuid.uuid4().hex[:12]}"
        create_response = await client.post(
            "/v1/allowlist", json=_grant_body(rule_id=rule_id), headers=headers
        )
        created_id = create_response.json()["id"]

        list_response = await client.get("/v1/allowlist")
        matching = [e for e in list_response.json()["entries"] if e["rule_id"] == rule_id]
        assert matching[0]["id"] == created_id


class TestDeleteAllowlistEntry:
    @pytest.mark.asyncio
    async def test_admin_can_revoke(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        create_response = await client.post("/v1/allowlist", json=_grant_body(), headers=headers)
        allowlist_id = create_response.json()["id"]

        delete_response = await client.delete(f"/v1/allowlist/{allowlist_id}", headers=headers)
        assert delete_response.status_code == 200

        list_response = await client.get("/v1/allowlist")
        assert all(e["rule_id"] != allowlist_id for e in list_response.json()["entries"])

    @pytest.mark.asyncio
    async def test_approver_cannot_revoke(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        create_response = await client.post("/v1/allowlist", json=_grant_body(), headers=headers)
        allowlist_id = create_response.json()["id"]

        _as(app, "approver-carol", frozenset({"approver"}))
        response = await client.delete(f"/v1/allowlist/{allowlist_id}", headers=headers)
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_unknown_id_is_404(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.delete(f"/v1/allowlist/{uuid.uuid4()}", headers=headers)
        assert response.status_code == 404
