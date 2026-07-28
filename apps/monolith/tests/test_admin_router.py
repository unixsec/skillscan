"""Tests for `POST/GET /v1/admin/*` (coding spec §9/§16.1) - real local
MySQL/Redis via a real ScanRuntime; only auth is faked via FastAPI dependency
override, matching test_router.py's established pattern.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator

import httpx
import pyotp
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from common.blobstore import LocalFilesystemBlobStore
from fastapi import FastAPI
from skillscan_core import GatePolicy, StaticKeywordEngine, TrustTier, Verdict
from sqlalchemy import select

from monolith.main import create_app
from monolith.modules.admin.breakglass import deactivate_breakglass
from monolith.modules.audit.models import AuditIntent
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.auth.dependencies import get_session_context
from monolith.modules.gateway.auth.middleware import (
    BREAKGLASS_SESSION_COOKIE_NAME,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
)
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
            version=f"test-admin-{uuid.uuid4().hex[:8]}",
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


class _FakeBreakGlassCredentials:
    """Test double for `BreakGlassCredentialPort` - no live Vault is authorized
    for this automated suite (same policy as `test_gate_signer.py`'s fake
    hvac Transit client); this stands in for `VaultBreakGlassCredentialPort`,
    which has its own dedicated tests against a fake hvac KV v2 client in
    `test_breakglass_vault.py`."""

    def __init__(self, *, credential: str, totp_secret: str) -> None:
        self._credential = credential
        self._totp_secret = totp_secret

    async def fetch_credential(self) -> str:
        return self._credential

    async def fetch_totp_secret(self) -> str:
        return self._totp_secret


_BREAKGLASS_CREDENTIAL = "breakglass-test-credential"
_BREAKGLASS_TOTP_SECRET = pyotp.random_base32()


@pytest.fixture
def breakglass_app(
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
            version=f"test-admin-bg-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
        breakglass_enabled=True,
        breakglass_credentials=_FakeBreakGlassCredentials(
            credential=_BREAKGLASS_CREDENTIAL, totp_secret=_BREAKGLASS_TOTP_SECRET
        ),
    )
    return create_app(scan_runtime=scan_runtime)


@pytest_asyncio.fixture
async def breakglass_client(breakglass_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=breakglass_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


def _as_admin(app: FastAPI) -> None:
    app.dependency_overrides[get_session_context] = lambda: _session(
        "admin-alice", frozenset({"admin"})
    )


def _as_submitter(app: FastAPI) -> None:
    app.dependency_overrides[get_session_context] = lambda: _session(
        "bob", frozenset({"submitter"})
    )


def _csrf_headers_and_cookies(client: httpx.AsyncClient) -> dict[str, str]:
    # NOTE: also sets the SESSION cookie (any value - get_session_context is
    # dependency-overridden in these tests, so its validity is never checked)
    # so require_csrf actually treats this as a cookie-authenticated request
    # needing CSRF, matching a real BFF/browser request's shape - otherwise
    # every "success" test below would silently take the CSRF-exempt bearer
    # path and never really exercise CSRF validation at all.
    client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
    client.cookies.set(CSRF_COOKIE_NAME, "test-csrf-token")
    return {CSRF_HEADER_NAME: "test-csrf-token"}


class TestListEngines:
    @pytest.mark.asyncio
    async def test_admin_can_list_engines(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as_admin(app)
        response = await client.get("/v1/admin/engines")
        assert response.status_code == 200
        engines = response.json()["engines"]
        assert any(e["name"] == _ENGINE.metadata.name and e["required"] for e in engines)

    @pytest.mark.asyncio
    async def test_non_admin_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as_submitter(app)
        response = await client.get("/v1/admin/engines")
        assert response.status_code == 403


class TestSetEngineEnabled:
    @pytest.mark.asyncio
    async def test_disabling_required_floor_engine_is_409(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        response = await client.patch(
            f"/v1/admin/engines/{_ENGINE.metadata.name}",
            json={"enabled": False},
            headers=headers,
        )
        assert response.status_code == 409

    @pytest.mark.asyncio
    async def test_disabling_non_required_engine_succeeds(
        self, app: FastAPI, client: httpx.AsyncClient, redis_client: aioredis.Redis
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        # A real, known sandbox engine name (services/engine_runner/
        # sandbox_engines.py's SANDBOX_ENGINE_NAMES) - the endpoint now
        # rejects unknown names with 404 (test_disabling_unknown_engine_name_
        # is_404 below), so a made-up name can no longer stand in here.
        name = "bandit"
        try:
            response = await client.patch(
                f"/v1/admin/engines/{name}", json={"enabled": False}, headers=headers
            )
            assert response.status_code == 200
            assert response.json()["enabled"] is False
        finally:
            await redis_client.srem("skillscan:admin:disabled_engines", name)  # type: ignore[misc]

    @pytest.mark.asyncio
    async def test_disabling_unknown_engine_name_is_404(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        name = f"not-a-real-engine-{uuid.uuid4().hex[:8]}"
        response = await client.patch(
            f"/v1/admin/engines/{name}", json={"enabled": False}, headers=headers
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_disabling_engine_writes_audit_intent(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        audit_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
    ) -> None:
        # SECURITY (coding spec §16.1: "admin 高危操作...经审计"): admin has no
        # DB user of its own (policies/grants/manifest.yaml) - verifying the
        # row actually landed requires svc_audit's own (SELECT-capable)
        # session, same pattern as test_policy_workflow.py's equivalent test.
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        name = "bandit"
        try:
            # audit_intent is append-only (no delete grant, by design - see
            # feedback_setup_grants_additive_masks_violations) and this exact
            # engine name is also used by a sibling test in this class, so a
            # full-suite run can carry a pre-existing row for the same
            # action/name. Snapshot ids beforehand and only assert on rows
            # this PATCH call actually created, instead of an unscoped count.
            async with audit_sessionmaker() as session:
                result = await session.execute(
                    select(AuditIntent).where(AuditIntent.action == "engine_enabled_changed")
                )
                pre_existing_ids = {
                    row.id for row in result.scalars().all() if row.payload.get("name") == name
                }

            response = await client.patch(
                f"/v1/admin/engines/{name}", json={"enabled": False}, headers=headers
            )
            assert response.status_code == 200

            async with audit_sessionmaker() as session:
                result = await session.execute(
                    select(AuditIntent).where(AuditIntent.action == "engine_enabled_changed")
                )
                intents = [
                    row
                    for row in result.scalars().all()
                    if row.payload.get("name") == name and row.id not in pre_existing_ids
                ]
            assert len(intents) == 1
            assert intents[0].operator == "admin-alice"
            assert intents[0].payload["enabled"] is False
        finally:
            await redis_client.srem("skillscan:admin:disabled_engines", name)  # type: ignore[misc]

    @pytest.mark.asyncio
    async def test_missing_csrf_token_is_403(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as_admin(app)
        # NOTE: `require_csrf` decides cookie- vs bearer-authenticated purely
        # from the SESSION cookie's presence on the raw request - independent
        # of `get_session_context`'s dependency override above, which only
        # fakes the RESULT of auth, not the request shape. A real BFF/browser
        # request always carries this cookie, so set one here too (any value -
        # its validity is what the override bypasses, not its presence).
        client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
        response = await client.patch(
            f"/v1/admin/engines/bandit-{uuid.uuid4().hex[:8]}", json={"enabled": False}
        )
        assert response.status_code == 403


class TestPolicyEndpoints:
    @pytest.mark.asyncio
    async def test_get_policy_returns_active_policy_and_empty_pending(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        response = await client.get("/v1/admin/policy")
        assert response.status_code == 200
        body = response.json()
        assert "active_policy" in body
        assert body["active_policy"]["required_engines"] == [_ENGINE.metadata.name]

    @pytest.mark.asyncio
    async def test_propose_non_hard_gate_change_is_auto_approved(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/admin/policy",
            json={"policy_yaml": f'version: "v-{uuid.uuid4().hex[:8]}"\nrequired_engines: []\n'},
            headers=headers,
        )
        assert response.status_code == 201
        assert response.json()["status"] == "approved"

    @pytest.mark.asyncio
    async def test_propose_hard_gate_change_then_appears_in_pending(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        yaml_body = (
            f'version: "v-{uuid.uuid4().hex[:8]}"\n'
            "required_engines: []\n"
            "hard_gate_rules:\n  - pii.credit_card\n"
        )
        propose_response = await client.post(
            "/v1/admin/policy", json={"policy_yaml": yaml_body}, headers=headers
        )
        assert propose_response.status_code == 201
        assert propose_response.json()["status"] == "pending"

        get_response = await client.get("/v1/admin/policy")
        pending_ids = [p["id"] for p in get_response.json()["pending_proposals"]]
        assert propose_response.json()["id"] in pending_ids

    @pytest.mark.asyncio
    async def test_invalid_policy_yaml_is_400(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/admin/policy", json={"policy_yaml": "not valid: [policy"}, headers=headers
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_self_approval_of_own_proposal_is_403(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        yaml_body = (
            f'version: "v-{uuid.uuid4().hex[:8]}"\n'
            "required_engines: []\n"
            "hard_gate_rules:\n  - pii.credit_card\n"
        )
        propose_response = await client.post(
            "/v1/admin/policy", json={"policy_yaml": yaml_body}, headers=headers
        )
        proposal_id = propose_response.json()["id"]

        # same admin ("admin-alice") tries to approve their own proposal
        approve_response = await client.post(
            f"/v1/admin/policy/{proposal_id}/approve", headers=headers
        )
        assert approve_response.status_code == 403

    @pytest.mark.asyncio
    async def test_different_admin_can_approve(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        yaml_body = (
            f'version: "v-{uuid.uuid4().hex[:8]}"\n'
            "required_engines: []\n"
            "hard_gate_rules:\n  - pii.credit_card\n"
        )
        propose_response = await client.post(
            "/v1/admin/policy", json={"policy_yaml": yaml_body}, headers=headers
        )
        proposal_id = propose_response.json()["id"]

        app.dependency_overrides[get_session_context] = lambda: _session(
            "admin-carol", frozenset({"admin"})
        )
        approve_response = await client.post(
            f"/v1/admin/policy/{proposal_id}/approve", headers=headers
        )
        assert approve_response.status_code == 200
        assert approve_response.json()["status"] == "approved"
        assert approve_response.json()["approved_by"] == "admin-carol"

    @pytest.mark.asyncio
    async def test_approving_nonexistent_proposal_is_404(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        response = await client.post("/v1/admin/policy/999999999/approve", headers=headers)
        assert response.status_code == 404


class TestListUsers:
    @pytest.mark.asyncio
    async def test_admin_can_view_group_role_map(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        response = await client.get("/v1/admin/users")
        assert response.status_code == 200
        assert "group_role_map" in response.json()

    @pytest.mark.asyncio
    async def test_non_admin_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as_submitter(app)
        response = await client.get("/v1/admin/users")
        assert response.status_code == 403


class TestBreakGlassDisabledByDefault:
    """The plain `app` fixture builds a `ScanRuntime` with no break-glass
    kwargs, so `breakglass_enabled` is False by default (coding spec §16.3:
    disabled-by-default is the mandatory posture) - every break-glass route
    must fail closed to 404, never expose whether it's merely unconfigured
    vs. something more specific."""

    @pytest.mark.asyncio
    async def test_status_reports_disabled(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as_admin(app)
        response = await client.get("/v1/admin/breakglass")
        assert response.status_code == 200
        assert response.json() == {"enabled": False, "armed": False}

    @pytest.mark.asyncio
    async def test_activate_is_404(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "admin-bob", "totp_code": "000000"},
            headers=headers,
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_login_is_404(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        response = await client.post(
            "/v1/admin/breakglass/login", json={"credential": "x", "totp_code": "000000"}
        )
        assert response.status_code == 404


class TestBreakGlassEnabled:
    @pytest_asyncio.fixture(autouse=True)
    async def _reset_armed_state(self, redis_client: aioredis.Redis) -> AsyncIterator[None]:
        # SECURITY-adjacent test hygiene: the armed/used state lives in
        # module-level Redis keys shared across every test in this class (and
        # test_breakglass.py) - reset to "not armed" before each test so an
        # earlier test's leftover activation can never make a later
        # "not-yet-activated" assertion pass (or fail) for the wrong reason.
        await deactivate_breakglass(redis_client)
        yield

    @pytest.mark.asyncio
    async def test_status_reports_enabled_and_not_armed(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        _as_admin(breakglass_app)
        response = await breakglass_client.get("/v1/admin/breakglass")
        assert response.status_code == 200
        assert response.json() == {"enabled": True, "armed": False}

    @pytest.mark.asyncio
    async def test_activate_requires_two_different_people(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        _as_admin(breakglass_app)  # session.subject == "admin-alice"
        headers = _csrf_headers_and_cookies(breakglass_client)
        code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "admin-alice", "totp_code": code},
            headers=headers,
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_activate_with_wrong_totp_is_403(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        _as_admin(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "admin-bob", "totp_code": "000000"},
            headers=headers,
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_activate_requires_csrf(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        _as_admin(breakglass_app)
        # NOTE (see TestSetEngineEnabled.test_missing_csrf_token_is_403): require_csrf
        # decides cookie- vs. bearer-authenticated purely from the SESSION cookie's
        # presence on the raw request, independent of the get_session_context
        # override above - set it here too so this reads as a BFF/browser request
        # that genuinely needs CSRF, not one silently exempted as bearer-like.
        breakglass_client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
        code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "admin-bob", "totp_code": code},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_activate_requires_admin_role(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        _as_submitter(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "admin-bob", "totp_code": code},
            headers=headers,
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_activate_succeeds_and_status_then_reports_armed(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        _as_admin(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        # SECURITY (BUG 2 fix): `second_activator` must now be a real, known
        # admin identity - this app builds its AuthRuntime from the REAL
        # policies/rbac/group_role_map.yaml (no auth_runtime override passed
        # to create_app in this fixture), so "skillscan-admins" (that file's
        # actual admin-mapped group name) is what the router's
        # known_admin_subjects allowlist actually contains - an arbitrary
        # name like the old "admin-bob" no longer passes.
        activate_response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "skillscan-admins", "totp_code": code},
            headers=headers,
        )
        assert activate_response.status_code == 200
        assert activate_response.json()["activated_by"] == ["admin-alice", "skillscan-admins"]

        status_response = await breakglass_client.get("/v1/admin/breakglass")
        assert status_response.json() == {"enabled": True, "armed": True}

    @pytest.mark.asyncio
    async def test_login_without_activation_fails(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        login_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        response = await breakglass_client.post(
            "/v1/admin/breakglass/login",
            json={"credential": _BREAKGLASS_CREDENTIAL, "totp_code": login_code},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_login_succeeds_after_activation_and_sets_cookies(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        _as_admin(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        activate_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "skillscan-admins", "totp_code": activate_code},
            headers=headers,
        )

        # SECURITY: login is deliberately NOT gated by get_session_context/
        # require_csrf - it authenticates purely via credential+TOTP, so no
        # `_as_admin`/session override is needed (or meaningful) here.
        login_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        login_response = await breakglass_client.post(
            "/v1/admin/breakglass/login",
            json={"credential": _BREAKGLASS_CREDENTIAL, "totp_code": login_code},
        )
        assert login_response.status_code == 200
        assert BREAKGLASS_SESSION_COOKIE_NAME in login_response.cookies
        assert CSRF_COOKIE_NAME in login_response.cookies

    @pytest.mark.asyncio
    async def test_authenticated_write_request_without_csrf_token_is_403(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        # SECURITY/BUG (caught by real browser testing, not by any test that
        # fakes the session via a dependency override - see require_csrf's
        # own module docstring for the full story): a REAL break-glass
        # session (established here via an actual login, not an override)
        # must still require CSRF on a subsequent state-changing request -
        # proves the fix holds through the full stack, not just at the
        # require_csrf unit level (test_dependencies.py covers that half).
        _as_admin(breakglass_app)
        activate_headers = _csrf_headers_and_cookies(breakglass_client)
        activate_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "skillscan-admins", "totp_code": activate_code},
            headers=activate_headers,
        )
        login_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        login_response = await breakglass_client.post(
            "/v1/admin/breakglass/login",
            json={"credential": _BREAKGLASS_CREDENTIAL, "totp_code": login_code},
        )
        assert login_response.status_code == 200

        # NOTE: no _as_admin override here and no CSRF header - this is now a
        # REAL break-glass session (cookies persisted on breakglass_client by
        # httpx across requests), not a faked one, and it deliberately omits
        # the CSRF header despite having a valid session + CSRF cookie.
        del breakglass_app.dependency_overrides[get_session_context]
        response = await breakglass_client.patch(
            f"/v1/admin/engines/bandit-{uuid.uuid4().hex[:8]}", json={"enabled": False}
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_login_with_wrong_credential_fails(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        _as_admin(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        activate_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "skillscan-admins", "totp_code": activate_code},
            headers=headers,
        )
        login_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        response = await breakglass_client.post(
            "/v1/admin/breakglass/login",
            json={"credential": "wrong-credential", "totp_code": login_code},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_second_login_after_use_fails(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        # SECURITY (INV-17 "用后即禁"): the arming is single-use - a second
        # login attempt must fail even though it's well within the TTL and
        # supplies fully correct credential+TOTP.
        _as_admin(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        activate_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "skillscan-admins", "totp_code": activate_code},
            headers=headers,
        )
        first_login_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        first = await breakglass_client.post(
            "/v1/admin/breakglass/login",
            json={"credential": _BREAKGLASS_CREDENTIAL, "totp_code": first_login_code},
        )
        assert first.status_code == 200

        second_login_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        second = await breakglass_client.post(
            "/v1/admin/breakglass/login",
            json={"credential": _BREAKGLASS_CREDENTIAL, "totp_code": second_login_code},
        )
        assert second.status_code == 401

    @pytest.mark.asyncio
    async def test_concurrent_logins_against_same_activation_only_one_succeeds(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        # SECURITY (BUG 1 regression, full HTTP stack): the same TOCTOU race
        # test_breakglass.py exercises at the pure-function level, proven
        # through the REAL router/HTTP layer this time - two concurrent login
        # POSTs against the same armed activation, both with fully correct
        # credential+TOTP, must not both return 200.
        _as_admin(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        activate_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "skillscan-admins", "totp_code": activate_code},
            headers=headers,
        )
        login_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()

        async def _attempt() -> httpx.Response:
            return await breakglass_client.post(
                "/v1/admin/breakglass/login",
                json={"credential": _BREAKGLASS_CREDENTIAL, "totp_code": login_code},
            )

        responses = await asyncio.gather(_attempt(), _attempt())
        status_codes = sorted(r.status_code for r in responses)
        assert status_codes == [200, 401]

    @pytest.mark.asyncio
    async def test_activate_rejects_unknown_second_activator(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        # SECURITY (BUG 2 regression, full HTTP stack): an arbitrary string
        # that is NOT a real, known admin identity must be rejected - the
        # core "four-eyes was not real" fix.
        _as_admin(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "totally-made-up-name", "totp_code": code},
            headers=headers,
        )
        assert response.status_code == 403
        assert "real, known admin" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_activate_rejects_second_activator_equal_to_caller(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        # SECURITY (BUG 2 regression, full HTTP stack): `second_activator`
        # naming the CALLER's own identity must be rejected even though
        # `session.subject` ("admin-alice") textually differs from the
        # existing "same string twice" check's field name - this is the
        # router-level explicit guard, independent of the pure function's
        # own activator_a == activator_b check.
        _as_admin(breakglass_app)  # session.subject == "admin-alice"
        headers = _csrf_headers_and_cookies(breakglass_client)
        code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "admin-alice", "totp_code": code},
            headers=headers,
        )
        assert response.status_code == 403
        assert "other than the caller" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_activate_while_already_armed_is_rejected_not_clobbered(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        # SECURITY (BUG 3 regression, full HTTP stack): re-activating on top
        # of an existing armed-and-unused activation must fail (403), not
        # silently succeed and clobber the pending one.
        _as_admin(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        first_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        first_response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "skillscan-admins", "totp_code": first_code},
            headers=headers,
        )
        assert first_response.status_code == 200

        second_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        second_response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "skillscan-admins", "totp_code": second_code},
            headers=headers,
        )
        assert second_response.status_code == 403
        assert "already armed" in second_response.json()["detail"]

        status_response = await breakglass_client.get("/v1/admin/breakglass")
        assert status_response.json() == {"enabled": True, "armed": True}
