"""Tests for `GET/POST /v1/admin/intel*` (coding spec §9, SEC-UPD-010) - real
local MySQL/Redis via a real ScanRuntime; auth faked via FastAPI dependency
override.
"""

from __future__ import annotations

import base64
import json
import uuid
from collections.abc import AsyncIterator, Mapping
from unittest.mock import patch

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from common.blobstore import LocalFilesystemBlobStore
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256
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


def _sign(private_key: rsa.RSAPrivateKey, claim: Mapping[str, object]) -> str:
    claim_bytes = json.dumps(claim, sort_keys=True, separators=(",", ":")).encode()
    signature = private_key.sign(
        claim_bytes,
        padding.PSS(mgf=padding.MGF1(SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        SHA256(),
    )
    return base64.b64encode(signature).decode()


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
def trusted_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def app(
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    intel_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
    trusted_key: rsa.RSAPrivateKey,
) -> FastAPI:
    scan_runtime = ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=orchestration_sessionmaker,
        gate_session_factory=gate_sessionmaker,
        policy=GatePolicy(
            version=f"test-intel-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
        intel_session_factory=intel_sessionmaker,
        trusted_intel_public_keys=(trusted_key.public_key(),),
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


class TestGetIntelStatus:
    @pytest.mark.asyncio
    async def test_admin_can_read_status(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        response = await client.get("/v1/admin/intel")
        assert response.status_code == 200
        assert "sources" in response.json()

    @pytest.mark.asyncio
    async def test_non_admin_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "carol", frozenset({"approver"}))
        response = await client.get("/v1/admin/intel")
        assert response.status_code == 403


class TestImportIntelPackage:
    @pytest.mark.asyncio
    async def test_valid_signed_package_is_applied(
        self, app: FastAPI, client: httpx.AsyncClient, trusted_key: rsa.RSAPrivateKey
    ) -> None:
        md5_hash = f"{uuid.uuid4().hex}{uuid.uuid4().hex}"[:32]
        claim = {"iocs": [{"ioc_type": "md5", "ioc_value": md5_hash}]}
        package: dict[str, object] = dict(claim)
        package["signature"] = _sign(trusted_key, claim)

        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/admin/intel/import",
            files={"package": ("package.json", json.dumps(package).encode(), "application/json")},
            headers=headers,
        )
        assert response.status_code == 201
        assert response.json()["indicators_applied"] == 1

    @pytest.mark.asyncio
    async def test_untrusted_signature_rejected(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        claim = {"iocs": [{"ioc_type": "domain", "ioc_value": "evil.example.com"}]}
        package: dict[str, object] = dict(claim)
        package["signature"] = _sign(attacker_key, claim)

        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/admin/intel/import",
            files={"package": ("package.json", json.dumps(package).encode(), "application/json")},
            headers=headers,
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_non_admin_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/admin/intel/import",
            files={"package": ("package.json", b"{}", "application/json")},
            headers=headers,
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_missing_csrf_is_403(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
        response = await client.post(
            "/v1/admin/intel/import",
            files={"package": ("package.json", b"{}", "application/json")},
        )
        assert response.status_code == 403


class TestSyncIntelFromInternalSource:
    """coding spec §11.4 "内网情报系统同步" - sync_from_internal_source was
    implemented and unit-tested (test_intel_sync.py) but never had a live
    caller until this route; these tests cover the router wiring specifically
    (env-configured endpoint, session handling, CSRF, role, fail-closed
    error mapping), not sync_from_internal_source's own logic."""

    @pytest.mark.asyncio
    async def test_admin_can_trigger_sync(
        self, app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SKILLSCAN_INTEL_SYNC_ENDPOINT_URL", "http://localhost:9/intel-feed")
        md5_hash = f"{uuid.uuid4().hex}{uuid.uuid4().hex}"[:32]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=[{"ioc_type": "md5", "ioc_value": md5_hash}])

        mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        with patch("monolith.modules.intel.router.httpx.AsyncClient", return_value=mock_client):
            response = await client.post("/v1/admin/intel/sync", headers=headers)
        assert response.status_code == 201
        body = response.json()
        assert body["indicators_applied"] == 1
        assert body["source"] == "http://localhost:9/intel-feed"

    @pytest.mark.asyncio
    async def test_not_configured_is_500(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post("/v1/admin/intel/sync", headers=headers)
        assert response.status_code == 500

    @pytest.mark.asyncio
    async def test_non_internal_endpoint_is_400(
        self, app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # SECURITY (INV-14): require_internal_endpoint must fail this closed
        # even though it's server-side config, not caller input - a
        # misconfigured public endpoint must never be silently honored.
        monkeypatch.setenv("SKILLSCAN_INTEL_SYNC_ENDPOINT_URL", "https://example.com/feed")
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post("/v1/admin/intel/sync", headers=headers)
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_non_admin_denied(
        self, app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SKILLSCAN_INTEL_SYNC_ENDPOINT_URL", "http://localhost:9/intel-feed")
        _as(app, "carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post("/v1/admin/intel/sync", headers=headers)
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_missing_csrf_is_403(
        self, app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SKILLSCAN_INTEL_SYNC_ENDPOINT_URL", "http://localhost:9/intel-feed")
        _as(app, "admin-alice", frozenset({"admin"}))
        client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
        response = await client.post("/v1/admin/intel/sync")
        assert response.status_code == 403
