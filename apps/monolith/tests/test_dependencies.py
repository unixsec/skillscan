"""Tests for the `require_role`/`get_session_context` FastAPI dependency wiring
(coding spec §11.2 key interfaces). Exercised against a minimal standalone test
app since the real app assembly is M3's `apps/monolith/main.py`."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx
from common.config import SessionSettings
from common.errors import ERROR_CODE_HEADER
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.responses import Response as StarletteResponse

from monolith.modules.admin.breakglass import BREAKGLASS_SESSION_TTL_S
from monolith.modules.gateway.auth.dependencies import (
    AuthRuntime,
    require_csrf,
    require_human_role,
    require_role,
)
from monolith.modules.gateway.auth.middleware import (
    BREAKGLASS_SESSION_COOKIE_NAME,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
    set_csrf_cookie,
    set_session_cookie,
)
from monolith.modules.gateway.auth.session import IntrospectionCache, SessionContext

GROUP_ROLE_MAP = {"skillscan-approvers": "approver"}
# The TTL every non-break-glass login uses (login_router's OIDC/SAML paths and
# local_auth.LOCAL_SESSION_TTL_S all default to a workday).
_EIGHT_HOURS_S = 28800


def _build_app(handler: Callable[[httpx.Request], httpx.Response]) -> FastAPI:
    app = FastAPI()

    # NOTE: `require_role(...)` is hoisted into a variable so `Depends(...)`
    # below wraps a plain reference, not a nested call - ruff's B008 (no
    # function calls in argument defaults) otherwise flags this even though
    # it's the standard, required FastAPI dependency-injection pattern.
    _any_authenticated = require_role()
    _approver_or_admin = require_role("approver", "admin")
    _humans_only = require_human_role()

    @app.get("/submit-only")
    def submit_only(session: SessionContext = Depends(_any_authenticated)) -> dict[str, Any]:
        return {"subject": session.subject}

    @app.get("/console-only")
    def console_only(session: SessionContext = Depends(_humans_only)) -> dict[str, Any]:
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


class TestRequireHumanRole:
    """SECURITY (milestone B' C1): the console surface refuses machine identities.

    The bug this locks down: `require_role()` with no arguments accepts ANY
    authenticated session, and an M2M identity carries `roles={"submitter"}` -
    so the same bearer token that submits through `/v1/market/scans` also read
    the console's internal scan shape. `require_human_role()` judges the KIND of
    identity, which is why these tests go through the REAL m2m authentication
    path (a bearer token + introspection) rather than a hand-built
    SessionContext: the flag has to survive the actual authentication code, not
    just exist on the dataclass.
    """

    @staticmethod
    def _m2m_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"active": True, "client_id": "ci-runner", "exp": time.time() + 60}
        )

    def test_a_machine_identity_is_403_even_though_it_is_authenticated(self) -> None:
        client = TestClient(_build_app(self._m2m_handler))
        response = client.get("/console-only", headers={"Authorization": "Bearer m2m-token"})
        assert response.status_code == 403

    def test_the_same_machine_identity_still_passes_plain_require_role(self) -> None:
        # The contrast that makes the test above mean something: this identity is
        # fully authenticated and role-satisfying. It is refused on the console
        # for what it IS, not for lacking authentication or a role.
        client = TestClient(_build_app(self._m2m_handler))
        assert (
            client.get("/submit-only", headers={"Authorization": "Bearer m2m-token"}).status_code
            == 200
        )

    def test_403_not_404_and_the_reason_is_actionable(self) -> None:
        # SECURITY/OPERABILITY: object-level authz answers 404 elsewhere to hide
        # whether someone else's object exists. Nothing is hidden here - the
        # endpoint exists and the token is valid - so a 404 would only leave an
        # integrator hunting a scan that never disappeared.
        client = TestClient(_build_app(self._m2m_handler))
        response = client.get("/console-only", headers={"Authorization": "Bearer m2m-token"})
        assert response.status_code == 403
        assert "/v1/market" in response.json()["detail"]

    def test_a_human_cookie_session_is_unaffected(self) -> None:
        client = TestClient(_build_app(_active_submitter))
        client.cookies.set(SESSION_COOKIE_NAME, "a-valid-opaque-token")
        response = client.get("/console-only")
        assert response.status_code == 200
        assert response.json()["subject"] == "alice"

    def test_an_unauthenticated_request_is_still_401_not_403(self) -> None:
        # Order matters: authentication fail-closes first, so an anonymous
        # caller must not be told "you are a machine".
        client = TestClient(_build_app(_active_submitter))
        assert client.get("/console-only").status_code == 401


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
    break-glass and was caught only by real browser testing).
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


class TestBreakGlassLoginDoesNotStrandAnExistingSession:
    """SECURITY REGRESSION (2026-07-29), reproduced before it was fixed.

    `csrf_token` is a single shared cookie name across all four login paths.
    While each login stamped it with its own session's TTL, a 900s break-glass
    login overwrote the CSRF cookie of an 8h OIDC/SAML/local session with a
    15-minute one. After those 15 minutes the surviving 8h session's GETs still
    worked (CSRF only guards state-changing methods) and every write returned
    403 - a console the user can browse but cannot save anything in, with
    nothing pointing at the cause.

    This drives a REAL cookie jar (`http.cookiejar` via httpx, the same
    Set-Cookie parsing and Max-Age expiry a browser applies) over the two
    Set-Cookie sets the two logins emit, then makes the request the user would
    make afterwards. Before the fix the CSRF cookie is simply gone from the jar
    and the write is a 403.

    The break-glass/OIDC pair is the combination exercised end-to-end here
    because the OIDC session cookie is the one this standalone app can resolve
    (the Redis-backed types need infrastructure). The OTHER pairs are covered
    structurally rather than combinatorially: `set_csrf_cookie` no longer takes
    a TTL argument at all, so a login path that missed the fix would not
    type-check, and test_middleware.py's TestCsrfCookieOutlivesEverySessionType
    asserts the one lifetime covers every declared session TTL.
    """

    @staticmethod
    def _login_set_cookie_headers(
        *, session_cookie_name: str, session_ttl_s: int, csrf_value: str
    ) -> list[str]:
        """The Set-Cookie headers a login handler emits: its session cookie
        with its own TTL, plus the shared CSRF cookie."""
        response = StarletteResponse()
        set_session_cookie(
            response,
            name=session_cookie_name,
            value=f"{session_cookie_name}-token",
            max_age_s=session_ttl_s,
        )
        set_csrf_cookie(response, csrf_value)
        return [v.decode() for k, v in response.raw_headers if k == b"set-cookie"]

    def test_writes_still_work_after_the_break_glass_session_expires(self) -> None:
        jar = httpx.Cookies()
        origin = httpx.Request("POST", "https://console.example/login")
        for headers in (
            # 1. the ordinary 8h login
            self._login_set_cookie_headers(
                session_cookie_name=SESSION_COOKIE_NAME,
                session_ttl_s=_EIGHT_HOURS_S,
                csrf_value="csrf-from-the-8h-login",
            ),
            # 2. a 900s break-glass login in the same browser, overwriting the
            #    shared csrf_token cookie
            self._login_set_cookie_headers(
                session_cookie_name=BREAKGLASS_SESSION_COOKIE_NAME,
                session_ttl_s=BREAKGLASS_SESSION_TTL_S,
                csrf_value="csrf-from-the-break-glass-login",
            ),
        ):
            jar.extract_cookies(
                httpx.Response(200, headers=[("set-cookie", h) for h in headers], request=origin)
            )

        # Fifteen minutes later, as the browser would have it: real
        # http.cookiejar expiry, not a reimplementation of it.
        later = int(time.time()) + BREAKGLASS_SESSION_TTL_S + 1
        surviving = {
            c.name: c.value for c in jar.jar if c.value is not None and not c.is_expired(later)
        }
        assert BREAKGLASS_SESSION_COOKIE_NAME not in surviving  # the emergency session is over
        assert SESSION_COOKIE_NAME in surviving  # the 8h one is not
        assert CSRF_COOKIE_NAME in surviving, (
            "the break-glass login's short TTL expired the shared csrf_token cookie out "
            "from under a session that is still live - its writes will 403 while its "
            "reads keep working"
        )

        client = TestClient(_build_app(_active_submitter))
        for name, value in surviving.items():
            client.cookies.set(name, value)

        # Reads never broke - that asymmetry is what made this so hard to see.
        assert client.get("/submit-only").status_code == 200
        # The write is the point.
        write = client.post("/mutate", headers={CSRF_HEADER_NAME: surviving[CSRF_COOKIE_NAME]})
        assert write.status_code == 200, (
            "a live 8h session cannot write after an unrelated break-glass session expired"
        )


class TestMachineReadableErrorCode:
    """CONTRACT LOCK: every auth error answers with a stable machine-readable
    code in ERROR_CODE_HEADER, so a program never has to branch on the
    human-readable `detail`.

    web/src/api/client.ts must tell an expired-session 403 (bounce the user to
    /login) apart from a permission 403 (a live session being refused - logging
    that user out over a role problem would be a bug). Before this, the only
    signal was the exact `detail` literal "CSRF validation failed": any
    rewording, translation or punctuation change on this side would have taken
    that branch dark with nothing turning red. These tests are the backend half
    of the pin; `web/src/api/client.test.ts` holds the frontend half, and the
    two literals must stay identical.
    """

    def test_csrf_failure_carries_the_csrf_validation_failed_code(self) -> None:
        client = TestClient(_build_app(_active_submitter))
        client.cookies.set(SESSION_COOKIE_NAME, "a-valid-opaque-token")
        response = client.post("/mutate")
        assert response.status_code == 403
        # The literal, spelled out rather than imported from common.errors:
        # importing the constant would let a rename pass silently on both
        # sides at once, which is the whole failure mode being pinned. This
        # string is duplicated on purpose in web/src/api/client.ts.
        assert response.headers[ERROR_CODE_HEADER] == "csrf_validation_failed"

    def test_the_human_detail_is_still_present_and_still_human(self) -> None:
        # The code is ADDED alongside the human message, not a replacement for
        # it - an operator reading a log or a curl output still gets a sentence.
        client = TestClient(_build_app(_active_submitter))
        client.cookies.set(SESSION_COOKIE_NAME, "a-valid-opaque-token")
        response = client.post("/mutate")
        assert response.json()["detail"] == "CSRF validation failed"

    def test_a_permission_403_carries_a_DIFFERENT_code(self) -> None:
        # The discrimination that matters: a role refusal is a 403 too, and the
        # frontend must not read it as "your session died". Different code, so
        # matching the code can never conflate them.
        client = TestClient(_build_app(_active_submitter))
        client.cookies.set(SESSION_COOKIE_NAME, "a-valid-opaque-token")
        response = client.get("/approver-only")
        assert response.status_code == 403
        assert response.headers[ERROR_CODE_HEADER] == "forbidden"
        assert response.headers[ERROR_CODE_HEADER] != "csrf_validation_failed"

    def test_a_machine_identity_refusal_carries_the_permission_code_too(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"active": True, "client_id": "ci-runner", "exp": time.time() + 60}
            )

        client = TestClient(_build_app(handler))
        response = client.get("/console-only", headers={"Authorization": "Bearer m2m-token"})
        assert response.status_code == 403
        assert response.headers[ERROR_CODE_HEADER] == "forbidden"

    def test_authentication_failure_carries_the_authentication_required_code(self) -> None:
        client = TestClient(_build_app(_active_submitter))
        response = client.get("/submit-only")
        assert response.status_code == 401
        assert response.headers[ERROR_CODE_HEADER] == "authentication_required"
