"""Tests for CSRF protection and security headers (coding spec §11.2, §16.1 INV-16)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse, Response
from starlette.responses import Response as StarletteResponse

from monolith.modules.gateway.auth.middleware import (
    CSRF_COOKIE_MAX_AGE_S,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    CsrfError,
    SecurityHeadersMiddleware,
    SessionTtlTooLongError,
    enforce_csrf,
    generate_csrf_token,
    session_ttl_from_env,
    set_csrf_cookie,
    set_session_cookie,
    verify_csrf,
)


class TestCookieSecurityFlagsAreConfigurable:
    """Regression: over local HTTP dev, the production-default Secure +
    SameSite=Strict cookies are silently dropped/withheld by the browser
    (session 'vanishes on leaving the page'). The flags must default to the
    strict production values but be relaxable via env for local HTTP dev."""

    def test_defaults_are_secure_and_strict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SKILLSCAN_COOKIE_SECURE", raising=False)
        monkeypatch.delenv("SKILLSCAN_COOKIE_SAMESITE", raising=False)
        resp = StarletteResponse()
        set_session_cookie(resp, name="skillscan_session", value="x", max_age_s=900)
        set_csrf_cookie(resp, "tok")
        headers = [v.decode() for k, v in resp.raw_headers if k == b"set-cookie"]
        assert all("Secure" in h for h in headers)
        assert all("samesite=strict" in h.lower() for h in headers)

    def test_dev_override_relaxes_secure_and_samesite(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SKILLSCAN_COOKIE_SECURE", "false")
        monkeypatch.setenv("SKILLSCAN_COOKIE_SAMESITE", "lax")
        resp = StarletteResponse()
        set_session_cookie(resp, name="skillscan_session", value="x", max_age_s=900)
        set_csrf_cookie(resp, "tok")
        headers = [v.decode() for k, v in resp.raw_headers if k == b"set-cookie"]
        assert all("Secure" not in h for h in headers)  # dropped over HTTP dev
        assert all("samesite=lax" in h.lower() for h in headers)


class TestCsrfCookieOutlivesEverySessionType:
    """SECURITY REGRESSION LOCK (2026-07-29): there are four session cookie
    names but only ONE `csrf_token` name, so every login overwrites the
    previous one's CSRF cookie. While each login stamped that cookie with its
    OWN session's TTL, a 900s break-glass login on top of an 8h session left
    the 8h session with a CSRF cookie that died in 15 minutes - after which its
    reads still worked and every write returned 403, with nothing telling the
    user why.

    The invariant: a readable CSRF cookie must exist for as long as ANY session
    cookie may. Since every login writes both cookies in one response, that
    reduces to CSRF_COOKIE_MAX_AGE_S >= every session TTL.
    """

    def test_an_over_long_env_ttl_is_refused_at_import(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SECURITY REGRESSION LOCK (2026-07-29, milestones E+F review): the
        ceiling has to be ENFORCED, not merely discovered.

        The discovery test below reads `LOCAL_SESSION_TTL_S` and
        `BREAKGLASS_SESSION_TTL_S`, and both used to be
        `int(os.environ.get(...))` evaluated at import - so it read exactly
        what the code read, and under CI defaults could only ever compare
        604800 against 28800 and 900. `SKILLSCAN_LOCAL_SESSION_TTL_S=1209600`
        reintroduced the break-glass bug a0a0ba5 fixed with the suite fully
        green. A guard asserted against the constant the implementation itself
        reads is not a guard; the same tautology shape this project has been
        bitten by before.

        So this exercises an OVER-LONG value, which is the input that has to
        fail, rather than the default, which cannot. `session_ttl_from_env` is
        what both call sites now use, so testing it here is testing the code
        path - not a parallel reimplementation of it.
        """
        monkeypatch.setenv("SKILLSCAN_TEST_TTL_S", str(CSRF_COOKIE_MAX_AGE_S + 1))
        with pytest.raises(SessionTtlTooLongError) as excinfo:
            session_ttl_from_env("SKILLSCAN_TEST_TTL_S", 900)
        # The message has to name the variable and both numbers - this fires at
        # startup, and "invalid configuration" with no operand is not actionable.
        assert "SKILLSCAN_TEST_TTL_S" in str(excinfo.value)
        assert str(CSRF_COOKIE_MAX_AGE_S) in str(excinfo.value)

        # Exactly at the ceiling is fine; one second over is not (above).
        monkeypatch.setenv("SKILLSCAN_TEST_TTL_S", str(CSRF_COOKIE_MAX_AGE_S))
        assert session_ttl_from_env("SKILLSCAN_TEST_TTL_S", 900) == CSRF_COOKIE_MAX_AGE_S
        # An over-long DEFAULT is refused too - a future session type whose
        # hardcoded default outlives the cookie must not pass just because
        # nobody set the env var.
        monkeypatch.delenv("SKILLSCAN_TEST_TTL_S", raising=False)
        assert session_ttl_from_env("SKILLSCAN_TEST_TTL_S", 900) == 900
        with pytest.raises(SessionTtlTooLongError):
            session_ttl_from_env("SKILLSCAN_TEST_TTL_S", CSRF_COOKIE_MAX_AGE_S + 1)
        # Garbage fails loudly rather than crashing with a bare ValueError at
        # import, or - worse - being coerced to something plausible.
        monkeypatch.setenv("SKILLSCAN_TEST_TTL_S", "forever")
        with pytest.raises(SessionTtlTooLongError):
            session_ttl_from_env("SKILLSCAN_TEST_TTL_S", 900)

    def test_both_env_driven_session_ttls_go_through_the_checked_reader(self) -> None:
        """The enforcement above is worth nothing if a call site quietly goes
        back to a raw `int(os.environ.get(...))`. Both env-driven TTLs must be
        produced by `session_ttl_from_env`, asserted against the SOURCE rather
        than the value - a value assertion would pass for a hardcoded 28800
        that no longer reads the environment at all."""
        import inspect

        from monolith.modules.admin import breakglass, local_auth

        for module, attr in (
            (local_auth, "LOCAL_SESSION_TTL_S"),
            (breakglass, "BREAKGLASS_SESSION_TTL_S"),
        ):
            source = inspect.getsource(module)
            assignment = next(line for line in source.splitlines() if line.startswith(f"{attr} = "))
            assert "session_ttl_from_env(" in assignment, (
                f"{module.__name__}.{attr} bypasses the checked reader: {assignment!r} - "
                f"an env override there is enforced by nothing"
            )

    def test_csrf_cookie_lifetime_covers_every_declared_session_ttl(self) -> None:
        # Discovered, not listed: a fifth session type declaring its own
        # *_SESSION_TTL_S longer than the CSRF cookie's lifetime fails here
        # instead of shipping as "writes 403 after a while". This is the same
        # shape as test_dependencies.py's SESSION_COOKIE_NAMES registry lock -
        # the cookie NAMES and the cookie LIFETIMES are two ways the same
        # assumption ("all session types are the same thing") rots.
        from monolith.modules.admin import breakglass, local_auth
        from monolith.modules.gateway.auth import login_router, saml

        discovered: dict[str, int] = {}
        for module in (breakglass, local_auth, saml, login_router):
            for name in dir(module):
                if not name.endswith(("SESSION_TTL_S", "SESSION_COOKIE_TTL_S")):
                    continue
                value = getattr(module, name)
                if isinstance(value, int):
                    discovered[f"{module.__name__}.{name}"] = value

        # The discovery itself must not silently find nothing: break-glass,
        # local, SAML and OIDC are the four session types that exist today.
        assert len(discovered) >= 4, f"session TTL discovery found only {discovered}"
        for name, ttl_s in discovered.items():
            assert CSRF_COOKIE_MAX_AGE_S >= ttl_s, (
                f"{name}={ttl_s}s outlives the CSRF cookie ({CSRF_COOKIE_MAX_AGE_S}s) - "
                f"that session's writes will start failing with a bare 403 once the "
                f"shared csrf_token cookie expires, while its reads keep working"
            )

    def test_the_cookie_carries_that_lifetime_and_not_the_callers(self) -> None:
        # set_csrf_cookie deliberately takes no max_age argument at all, so no
        # login path can stamp its own session's TTL onto the shared cookie.
        resp = StarletteResponse()
        set_csrf_cookie(resp, "tok")
        header = next(
            v.decode() for k, v in resp.raw_headers if k == b"set-cookie" and b"csrf_token" in v
        )
        assert f"Max-Age={CSRF_COOKIE_MAX_AGE_S}" in header

    def test_a_short_login_cannot_shorten_a_long_sessions_csrf_cookie(self) -> None:
        # Two logins in a row, second one short-lived, both writing the shared
        # cookie name: the surviving lifetime must still be the long one.
        first = StarletteResponse()
        set_csrf_cookie(first, "csrf-from-the-8h-login")
        second = StarletteResponse()
        set_csrf_cookie(second, "csrf-from-the-900s-login")

        def max_age(resp: StarletteResponse) -> int:
            header = next(v.decode() for k, v in resp.raw_headers if k == b"set-cookie")
            return int(header.split("Max-Age=")[1].split(";")[0])

        assert max_age(second) == max_age(first)


class TestVerifyCsrf:
    def test_matching_tokens_pass(self) -> None:
        token = generate_csrf_token()
        assert verify_csrf(token, token) is True

    def test_mismatched_tokens_fail(self) -> None:
        assert verify_csrf(generate_csrf_token(), generate_csrf_token()) is False

    def test_missing_cookie_fails(self) -> None:
        assert verify_csrf(None, "some-header-value") is False

    def test_missing_header_fails(self) -> None:
        assert verify_csrf("some-cookie-value", None) is False

    def test_tokens_are_unpredictable(self) -> None:
        assert generate_csrf_token() != generate_csrf_token()


def _build_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/safe")
    def safe_endpoint() -> dict[str, Any]:
        return {"ok": True}

    @app.post("/change-state")
    def unsafe_endpoint(_csrf: None = Depends(enforce_csrf)) -> dict[str, Any]:
        return {"ok": True}

    @app.exception_handler(CsrfError)
    def _handle_csrf_error(request: Request, exc: Exception) -> Response:
        return JSONResponse(status_code=403, content={"detail": "csrf token missing or invalid"})

    return app


class TestSecurityHeadersMiddleware:
    def test_headers_present_on_every_response(self) -> None:
        client = TestClient(_build_app())
        response = client.get("/safe")
        assert response.status_code == 200
        csp = response.headers["content-security-policy"]
        assert "default-src 'self'" in csp
        assert "unsafe-inline" not in csp
        assert "unsafe-eval" not in csp
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "max-age=" in response.headers["strict-transport-security"]


class TestEnforceCsrfIntegration:
    def test_get_request_never_checked(self) -> None:
        client = TestClient(_build_app())
        response = client.get("/safe")
        assert response.status_code == 200

    def test_post_without_csrf_cookie_or_header_rejected(self) -> None:
        client = TestClient(_build_app())
        response = client.post("/change-state")
        assert response.status_code == 403

    def test_post_with_mismatched_csrf_rejected(self) -> None:
        client = TestClient(_build_app())
        client.cookies.set(CSRF_COOKIE_NAME, "cookie-value")
        headers = {CSRF_HEADER_NAME: "different-header-value"}
        response = client.post("/change-state", headers=headers)
        assert response.status_code == 403

    def test_post_with_matching_csrf_accepted(self) -> None:
        client = TestClient(_build_app())
        token = generate_csrf_token()
        client.cookies.set(CSRF_COOKIE_NAME, token)
        response = client.post("/change-state", headers={CSRF_HEADER_NAME: token})
        assert response.status_code == 200

    def test_cross_origin_attacker_cannot_forge_matching_pair(self) -> None:
        # SECURITY: simulates the actual threat model - an attacker's page can
        # make the victim's browser send the victim's csrf cookie (auto-attached),
        # but the attacker cannot read that cookie's value cross-origin, so they
        # cannot also set a matching X-CSRF-Token header. We model "attacker
        # doesn't know the value" by using a token that was never set as the cookie.
        client = TestClient(_build_app())
        client.cookies.set(CSRF_COOKIE_NAME, generate_csrf_token())
        forged_header_guess = generate_csrf_token()
        response = client.post("/change-state", headers={CSRF_HEADER_NAME: forged_header_guess})
        assert response.status_code == 403
