"""Tests for `GET/POST /v1/inventory*` (coding spec §9/§16.2) - real local
MySQL/Redis via a real ScanRuntime; auth faked via FastAPI dependency
override, matching test_admin_router.py's established pattern.
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
from monolith.modules.inventory.service import register_skill_version, transition_skill
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
    inventory_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
) -> FastAPI:
    scan_runtime = ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=orchestration_sessionmaker,
        gate_session_factory=gate_sessionmaker,
        policy=GatePolicy(
            version=f"test-inv-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
        inventory_session_factory=inventory_sessionmaker,
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


async def _seed_skill(inventory_sessionmaker: SessionmakerFixture, *, skill_id: str) -> None:
    # NOTE: content_hash is skill_version's PRIMARY KEY - must be unique per
    # call, not a shared constant, or a second seeded skill in the same test
    # run collides on it (a real IntegrityError caught by actually running
    # this against MySQL, not assumed correct from reading the code).
    async with inventory_sessionmaker() as session, session.begin():
        await register_skill_version(
            session,
            skill_id=skill_id,
            source="test-suite",
            trust_tier="public",
            content_hash=uuid.uuid4().hex + uuid.uuid4().hex,
            toolchain_digest="digest-v1",
            declared_perms=None,
            operator="tester",
        )


class TestListInventory:
    @pytest.mark.asyncio
    async def test_approver_can_list(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "carol", frozenset({"approver"}))
        response = await client.get("/v1/inventory")
        assert response.status_code == 200
        matching = [s for s in response.json()["skills"] if s["skill_id"] == skill_id]
        assert len(matching) == 1
        assert matching[0]["state"] == "submitted"

    @pytest.mark.asyncio
    async def test_submitter_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "dave", frozenset({"submitter"}))
        response = await client.get("/v1/inventory")
        assert response.status_code == 403


class TestGetInventoryItem:
    @pytest.mark.asyncio
    async def test_returns_versions_and_state(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "carol", frozenset({"auditor"}))
        response = await client.get(f"/v1/inventory/{skill_id}")
        assert response.status_code == 200
        body = response.json()
        assert body["state"] == "submitted"
        assert len(body["versions"]) == 1
        assert body["baseline"] is None

    @pytest.mark.asyncio
    async def test_unknown_skill_is_404(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "carol", frozenset({"auditor"}))
        response = await client.get(f"/v1/inventory/nonexistent-{uuid.uuid4().hex}")
        assert response.status_code == 404


class TestQuarantineSkill:
    @pytest.mark.asyncio
    async def test_admin_can_quarantine_a_published_skill(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        # submitted -> scanning -> published (valid transition path)
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="scan started",
                actor="system",
            )
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="published",
                reason="passed gate",
                actor="system",
            )

        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/quarantine",
            json={"reason": "drift detected"},
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["state"] == "quarantined"

    @pytest.mark.asyncio
    async def test_invalid_transition_is_409(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)  # state: submitted
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        # submitted -> quarantined is not a valid transition
        response = await client.post(
            f"/v1/inventory/{skill_id}/quarantine", json={"reason": "x"}, headers=headers
        )
        assert response.status_code == 409

    @pytest.mark.asyncio
    async def test_non_admin_denied(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/quarantine", json={"reason": "x"}, headers=headers
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_unknown_skill_is_404(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/nonexistent-{uuid.uuid4().hex}/quarantine",
            json={"reason": "x"},
            headers=headers,
        )
        assert response.status_code == 404


class TestRetireSkill:
    @pytest.mark.asyncio
    async def test_admin_can_retire(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="scan started",
                actor="system",
            )
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/retire", json={"reason": "obsolete"}, headers=headers
        )
        assert response.status_code == 200
        assert response.json()["state"] == "retired"


class TestSetBaseline:
    # SECURITY (regression, was BUG): `inventory.service.set_baseline` had NO
    # HTTP-reachable caller anywhere - none of the mounted routers called it -
    # so a drift-detection baseline could never be established in any real
    # deployment, and worker.py's rug-pull auto-quarantine logic (SUPPLY-06)
    # could never fire. `POST /v1/inventory/{skill_id}/baseline` is the fix.

    @pytest.mark.asyncio
    async def test_admin_can_set_baseline_and_it_is_persisted(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)

        response = await client.post(
            f"/v1/inventory/{skill_id}/baseline",
            json={"content_hash": content_hash},
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json() == {"skill_id": skill_id, "content_hash": content_hash}

        # Confirms the baseline was actually persisted (not just a 200 with
        # no real write) - readable back via the existing GET, the same
        # place `TestGetInventoryItem` already asserts `baseline` shape.
        get_response = await client.get(f"/v1/inventory/{skill_id}")
        assert get_response.status_code == 200
        baseline = get_response.json()["baseline"]
        assert baseline is not None
        assert baseline["content_hash"] == content_hash

    @pytest.mark.asyncio
    async def test_set_baseline_replaces_existing_baseline(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        first_hash = uuid.uuid4().hex + uuid.uuid4().hex
        second_hash = uuid.uuid4().hex + uuid.uuid4().hex
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)

        await client.post(
            f"/v1/inventory/{skill_id}/baseline",
            json={"content_hash": first_hash},
            headers=headers,
        )
        response = await client.post(
            f"/v1/inventory/{skill_id}/baseline",
            json={"content_hash": second_hash},
            headers=headers,
        )
        assert response.status_code == 200

        get_response = await client.get(f"/v1/inventory/{skill_id}")
        assert get_response.json()["baseline"]["content_hash"] == second_hash

    @pytest.mark.asyncio
    async def test_non_admin_denied(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/baseline",
            json={"content_hash": uuid.uuid4().hex + uuid.uuid4().hex},
            headers=headers,
        )
        assert response.status_code == 403

        # Confirms the denial was real, not just a misleading status code -
        # no baseline row actually got written.
        _as(app, "admin-alice", frozenset({"admin"}))
        get_response = await client.get(f"/v1/inventory/{skill_id}")
        assert get_response.json()["baseline"] is None

    @pytest.mark.asyncio
    async def test_unknown_skill_is_404(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/nonexistent-{uuid.uuid4().hex}/baseline",
            json={"content_hash": uuid.uuid4().hex + uuid.uuid4().hex},
            headers=headers,
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_missing_csrf_is_403(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "admin-alice", frozenset({"admin"}))
        # SECURITY: deliberately no _csrf_headers_and_cookies() call - this is
        # a state-changing endpoint (coding spec §16.1 INV-16) and must be
        # CSRF-gated like every sibling write endpoint in this router.
        client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
        response = await client.post(
            f"/v1/inventory/{skill_id}/baseline",
            json={"content_hash": uuid.uuid4().hex + uuid.uuid4().hex},
        )
        assert response.status_code == 403
