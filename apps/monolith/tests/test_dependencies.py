"""Tests for the `require_role`/`get_session_context` FastAPI dependency wiring
(coding spec §11.2 key interfaces). Exercised against a minimal standalone test
app since the real app assembly is M3's `apps/monolith/main.py`."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx
from common.config import SessionSettings
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from monolith.modules.gateway.auth.dependencies import AuthRuntime, require_csrf, require_role
from monolith.modules.gateway.auth.middleware import (
    BREAKGLASS_SESSION_COOKIE_NAME,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
)
from monolith.modules.gateway.auth.session import IntrospectionCache, SessionContext

GROUP_ROLE_MAP = {"skillscan-approvers": "approver"}


def _build_app(handler: Callable[[httpx.Request], httpx.Response]) -> FastAPI:
    app = FastAPI()

    # NOTE: `require_role(...)` is hoisted into a variable so `Depends(...)`
    # below wraps a plain reference, not a nested call - ruff's B008 (no
    # function calls in argument defaults) otherwise flags this even though
    # it's the standard, required FastAPI dependency-injection pattern.
    _any_authenticated = require_role()
    _approver_or_admin = require_role("approver", "admin")

    @app.get("/submit-only")
    def submit_only(session: SessionContext = Depends(_any_authenticated)) -> dict[str, Any]:
        return {"subject": session.subject}

    @app.get("/approver-only")
    def approver_only(session: SessionContext = Depends(_approver_or_admin)) -> dict[str, Any]:
        return {"subject": session.subject, "roles": sorted(session.roles)}

    @app.post("/mutate", dependencies=[Depends(require_csrf)])
    def mutate(session: SessionContext = Depends(_any_authenticated)) -> dict[str, Any]:
        return {"subject": session.subject}

    settings = SessionSettings(
        introspection_endpoint="https://localhost/introspect",
        introspection_client_id="gateway",
        introspection_client_secret="secret",
    )
    app.state.auth = AuthRuntime(
        settings=settings,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        cache=IntrospectionCache(ttl_s=30),
        group_role_map=GROUP_ROLE_MAP,
        allowed_m2m_service_accounts=frozenset({"ci-runner"}),
    )
    return app


def _active_submitter(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"active": True, "sub": "alice", "exp": time.time() + 300})


def _active_approver(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "active": True,
            "sub": "bob",
            "exp": time.time() + 300,
            "groups": ["skillscan-approvers"],
        },
    )


def _inactive(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"active": False})


class TestRequireRoleViaCookie:
    def test_no_cookie_is_401(self) -> None:
        client = TestClient(_build_app(_active_submitter))
        response = client.get("/submit-only")
        assert response.status_code == 401

    def test_valid_cookie_grants_access_to_any_authenticated_route(self) -> None:
        client = TestClient(_build_app(_active_submitter))
        client.cookies.set(SESSION_COOKIE_NAME, "a-valid-opaque-token")
        response = client.get("/submit-only")
        assert response.status_code == 200
        assert response.json()["subject"] == "alice"

    def test_inactive_session_is_401(self) -> None:
        client = TestClient(_build_app(_inactive))
        client.cookies.set(SESSION_COOKIE_NAME, "a-revoked-token")
        response = client.get("/submit-only")
        assert response.status_code == 401

    def test_submitter_denied_approver_only_route(self) -> None:
        client = TestClient(_build_app(_active_submitter))
        client.cookies.set(SESSION_COOKIE_NAME, "a-valid-opaque-token")
        response = client.get("/approver-only")
        assert response.status_code == 403

    def test_approver_granted_approver_only_route(self) -> None:
        client = TestClient(_build_app(_active_approver))
        client.cookies.set(SESSION_COOKIE_NAME, "a-valid-opaque-token")
        response = client.get("/approver-only")
        assert response.status_code == 200
        assert "approver" in response.json()["roles"]

    def test_401_response_does_not_leak_internal_reason(self) -> None:
        client = TestClient(_build_app(_inactive))
        client.cookies.set(SESSION_COOKIE_NAME, "a-revoked-token")
        response = client.get("/submit-only")
        assert response.status_code == 401
        # SECURITY (FR-API-060): generic detail only, no internal exception text.
        assert "SessionError" not in response.text
        assert "not active" not in response.text


class TestRequireRoleViaBearerM2M:
    def test_bearer_token_authenticates_as_m2m(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"active": True, "client_id": "ci-runner", "exp": time.time() + 60}
            )

        client = TestClient(_build_app(handler))
        response = client.get("/submit-only", headers={"Authorization": "Bearer m2m-token"})
        assert response.status_code == 200
        assert response.json()["subject"] == "ci-runner"

    def test_bearer_token_for_non_allowlisted_service_is_401(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"active": True, "client_id": "rogue-service", "exp": time.time() + 60}
            )

        client = TestClient(_build_app(handler))
        response = client.get("/submit-only", headers={"Authorization": "Bearer m2m-token"})
        assert response.status_code == 401

    def test_bearer_m2m_denied_approver_only_route(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"active": True, "client_id": "ci-runner", "exp": time.time() + 60}
            )

        client = TestClient(_build_app(handler))
        response = client.get("/approver-only", headers={"Authorization": "Bearer m2m-token"})
        assert response.status_code == 403


class TestRequireCsrf:
    def test_cookie_session_without_csrf_token_is_403(self) -> None:
        client = TestClient(_build_app(_active_submitter))
        client.cookies.set(SESSION_COOKIE_NAME, "a-valid-opaque-token")
        response = client.post("/mutate")
        assert response.status_code == 403

    def test_cookie_session_with_matching_csrf_token_succeeds(self) -> None:
        client = TestClient(_build_app(_active_submitter))
        client.cookies.set(SESSION_COOKIE_NAME, "a-valid-opaque-token")
        client.cookies.set(CSRF_COOKIE_NAME, "matching-token")
        response = client.post("/mutate", headers={CSRF_HEADER_NAME: "matching-token"})
        assert response.status_code == 200

    def test_cookie_session_with_mismatched_csrf_token_is_403(self) -> None:
        client = TestClient(_build_app(_active_submitter))
        client.cookies.set(SESSION_COOKIE_NAME, "a-valid-opaque-token")
        client.cookies.set(CSRF_COOKIE_NAME, "the-real-token")
        response = client.post("/mutate", headers={CSRF_HEADER_NAME: "a-forged-token"})
        assert response.status_code == 403

    def test_breakglass_session_without_csrf_token_is_403(self) -> None:
        # SECURITY/BUG (caught by real browser testing against a running
        # server, not by any test that fakes the session via a dependency
        # override - see require_csrf's own module docstring): a break-glass
        # session cookie must be recognized as cookie-authenticated too, not
        # silently treated as bearer-like and exempted from CSRF. (The
        # matching-token "succeeds" counterpart needs a real resolvable
        # break-glass session - see test_admin_router.py's
        # TestBreakGlassEnabled class, which has that infrastructure.)
        client = TestClient(_build_app(_active_submitter))
        client.cookies.set(BREAKGLASS_SESSION_COOKIE_NAME, "a-breakglass-session-token")
        response = client.post("/mutate")
        assert response.status_code == 403

    def test_bearer_m2m_request_is_exempt_from_csrf(self) -> None:
        # SECURITY: a forged cross-origin request can never attach a custom
        # Authorization: Bearer header, so bearer-authenticated (M2M/API)
        # calls need no CSRF token at all - only cookie-authenticated ones do.
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"active": True, "client_id": "ci-runner", "exp": time.time() + 60}
            )

        client = TestClient(_build_app(handler))
        response = client.post("/mutate", headers={"Authorization": "Bearer m2m-token"})
        assert response.status_code == 200


class TestCsrfCoversEverySessionCookie:
    """SECURITY REGRESSION LOCK for the enumeration-rot bug class.

    require_csrf no longer hand-enumerates cookie names; it consults the single
    `SESSION_COOKIE_NAMES` registry. These tests fail if that registry ever
    drifts from the actually-declared session cookie constants, or if any
    registered cookie stops triggering CSRF - the two ways the old copied
    enumeration silently rotted (a new cookie-authenticated session type added
    without CSRF coverage = fail-OPEN, which already happened once to
    break-glass; docs/stories/BACKLOG.md's S8 note).
    """

    def test_registry_matches_all_declared_session_cookie_constants(self) -> None:
        # Discover every session-cookie constant the middleware declares, so
        # ADDING a new one without also adding it to SESSION_COOKIE_NAMES is
        # caught here rather than shipping as a silent CSRF exemption. Matches
        # both the primary `SESSION_COOKIE_NAME` and the `XXX_SESSION_COOKIE_NAME`
        # variants; deliberately excludes the CSRF cookie (not a session
        # credential) and the `SESSION_COOKIE_NAMES` registry set itself.
        from monolith.modules.gateway.auth import middleware

        declared = {
            getattr(middleware, name)
            for name in dir(middleware)
            if name.endswith("SESSION_COOKIE_NAME") and isinstance(getattr(middleware, name), str)
        }
        assert declared == set(middleware.SESSION_COOKIE_NAMES), (
            "SESSION_COOKIE_NAMES has drifted from the declared session-cookie "
            "constants - a session cookie is missing from the CSRF registry (fail-open) "
            "or a stale name lingers in it"
        )

    def test_every_registered_cookie_triggers_csrf_without_a_token(self) -> None:
        # Each cookie in the registry, on its own, must make a state-changing
        # request require CSRF (403 when no token is presented). This is the
        # behavioral half: registry membership must actually enforce, not just
        # match a constant.
        from monolith.modules.gateway.auth.middleware import SESSION_COOKIE_NAMES

        for cookie_name in SESSION_COOKIE_NAMES:
            client = TestClient(_build_app(_active_submitter))
            client.cookies.set(cookie_name, "some-session-token")
            response = client.post("/mutate")
            assert response.status_code == 403, (
                f"a request bearing {cookie_name!r} was NOT subjected to CSRF - "
                f"this cookie is exempt (fail-open)"
            )
