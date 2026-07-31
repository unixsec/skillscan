"""End-to-end: a marketplace calling `/v1/market` with username/password.

Unlike test_marketplace_router.py, authentication here is NOT faked - there is
no `dependency_overrides[get_session_context]`. The request carries a real
`Authorization: Basic` header and runs the production path
`get_session_context -> authenticate_basic_service_account -> SessionContext`,
against real local MySQL/Redis.

That is the whole point: the unit tests in test_m2m_basic_auth.py prove the
credential check itself, and this file proves the wiring around it - that the
header reaches that check, that the resulting identity satisfies the market
endpoints' scope requirements, and that it is still refused by the console.
"""

from __future__ import annotations

import base64
import io
import tarfile
import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from common.blobstore import LocalFilesystemBlobStore
from common.config import SessionSettings
from common.password import hash_password
from fastapi import FastAPI
from skillscan_core import GatePolicy, StaticKeywordEngine, TrustTier, Verdict

from monolith.main import create_app
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.auth.dependencies import AuthRuntime
from monolith.modules.gateway.auth.m2m import M2MGrant
from monolith.modules.gateway.auth.session import IntrospectionCache
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.tests.conftest import SessionmakerFixture

_ENGINE = StaticKeywordEngine()
_PASSWORD = "correct horse battery staple"


def _account() -> str:
    """Fresh per test: the rate-limit and lockout counters are keyed on the
    service account in a SHARED Redis with a 60s/15min window."""
    return f"mkt-basic-{uuid.uuid4().hex[:10]}"


def _auth(account: str, password: str = _PASSWORD) -> dict[str, str]:
    raw = base64.b64encode(f"{account}:{password}".encode()).decode()
    return {"Authorization": f"Basic {raw}"}


def _package() -> bytes:
    """Unique bytes per submission - submit_scan is single-flight on content."""
    payload = f"print({uuid.uuid4().hex!r})\n".encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name="skill.py")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


@pytest_asyncio.fixture(autouse=True)
async def _clean_redis_state() -> AsyncIterator[None]:
    client: aioredis.Redis = aioredis.Redis.from_url("redis://localhost:6379/0")
    try:

        async def _clear() -> None:
            for pattern in ("skillscan:mkt:rate:*", "skillscan:m2m:basic:*"):
                keys = [k async for k in client.scan_iter(match=pattern)]
                if keys:
                    await client.delete(*keys)

        await _clear()
        yield
        await _clear()
    finally:
        await client.aclose()


def _build_app(
    *,
    account: str,
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    inventory_sessionmaker: SessionmakerFixture,
    marketplace_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
) -> FastAPI:
    scan_runtime = ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=orchestration_sessionmaker,
        gate_session_factory=gate_sessionmaker,
        inventory_session_factory=inventory_sessionmaker,
        policy=GatePolicy(
            version=f"test-basic-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
        marketplace_session_factory=marketplace_sessionmaker,
        marketplace_rate_limit_per_min=120,
    )
    auth_runtime = AuthRuntime(
        # Loopback, and never actually contacted: the Basic path does no
        # introspection at all. It is here because SessionSettings requires an
        # internal endpoint to construct (INV-14).
        settings=SessionSettings(
            introspection_endpoint="http://127.0.0.1:9/introspect",
            introspection_client_id="gateway",
            introspection_client_secret="unused-on-the-basic-path",
        ),
        http_client=httpx.AsyncClient(),
        cache=IntrospectionCache(ttl_s=30),
        group_role_map={},
        allowed_m2m_service_accounts=frozenset({account}),
        m2m_grants={
            account: M2MGrant(scopes=frozenset({"scan:submit", "scan:read"}), tier=TrustTier.PUBLIC)
        },
        m2m_basic_accounts={account: hash_password(_PASSWORD)},
        m2m_basic_redis=redis_client,
    )
    return create_app(auth_runtime=auth_runtime, scan_runtime=scan_runtime)


class TestMarketplaceOverBasicAuth:
    @pytest.mark.asyncio
    async def test_submit_then_poll_round_trip(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        inventory_sessionmaker: SessionmakerFixture,
        marketplace_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        """The whole reason this path exists: submit a package and read the
        answer back, with nothing but a username and a password."""
        account = _account()
        app = _build_app(
            account=account,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            inventory_sessionmaker=inventory_sessionmaker,
            marketplace_sessionmaker=marketplace_sessionmaker,
            redis_client=redis_client,
            blobstore=blobstore,
        )
        skill_id = f"@basic/{uuid.uuid4().hex[:10]}"
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            submitted = await client.post(
                "/v1/market/scans",
                files={"package": ("skill.tar", _package(), "application/x-tar")},
                data={"skill_id": skill_id},
                headers=_auth(account),
            )
            assert submitted.status_code == 202, submitted.text

            polled = await client.get(f"/v1/market/skills/{skill_id}", headers=_auth(account))
            assert polled.status_code == 200, polled.text
            body = polled.json()

        # The three facts the marketplace integration is FOR. Asserted as
        # presence, not value: no engine has run yet in this test, so the honest
        # answer is `is_safe: false / not_yet_scanned` - what matters here is
        # that the contract's fields cross the HTTP boundary under this identity.
        assert body["skill_id"] == skill_id
        assert body["is_safe"] is False
        assert body["unsafe_reason"] == "not_yet_scanned"
        assert "score" in body
        assert "findings" in body
        assert "summary" in body

    @pytest.mark.asyncio
    async def test_wrong_password_is_refused(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        inventory_sessionmaker: SessionmakerFixture,
        marketplace_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        account = _account()
        app = _build_app(
            account=account,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            inventory_sessionmaker=inventory_sessionmaker,
            marketplace_sessionmaker=marketplace_sessionmaker,
            redis_client=redis_client,
            blobstore=blobstore,
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get(
                "/v1/market/skills/@basic/whatever",
                headers=_auth(account, "not-the-password"),
            )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_password_identity_is_still_refused_by_the_console(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        inventory_sessionmaker: SessionmakerFixture,
        marketplace_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        """SECURITY (milestone B' C1): adding a password path must not open a
        door around the marketplace projection.

        The console's `GET /v1/scans/{scan_id}` returns the RAW internal shape
        (`snippet_hash`, `provenance`, `required_ok`) that
        `marketplace_api.views` exists to withhold. `require_human_role` refuses
        machine identities, and this identity is one - so the projection stays
        the only door, exactly as it is for the token-authenticated paths.
        """
        account = _account()
        app = _build_app(
            account=account,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            inventory_sessionmaker=inventory_sessionmaker,
            marketplace_sessionmaker=marketplace_sessionmaker,
            redis_client=redis_client,
            blobstore=blobstore,
        )
        skill_id = f"@basic/{uuid.uuid4().hex[:10]}"
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            submitted = await client.post(
                "/v1/market/scans",
                files={"package": ("skill.tar", _package(), "application/x-tar")},
                data={"skill_id": skill_id},
                headers=_auth(account),
            )
            assert submitted.status_code == 202, submitted.text
            scan_id = submitted.json()["scan_id"]

            # Same credentials, same scan it just submitted - the CONSOLE route.
            console = await client.get(f"/v1/scans/{scan_id}", headers=_auth(account))

        assert console.status_code == 403, console.text
