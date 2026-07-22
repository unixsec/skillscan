"""Tests for CSRF protection and security headers (coding spec §11.2, §16.1 INV-16)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse, Response
from starlette.responses import Response as StarletteResponse

from monolith.modules.gateway.auth.middleware import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    CsrfError,
    SecurityHeadersMiddleware,
    enforce_csrf,
    generate_csrf_token,
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
        set_csrf_cookie(resp, "tok", max_age_s=900)
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
        set_csrf_cookie(resp, "tok", max_age_s=900)
        headers = [v.decode() for k, v in resp.raw_headers if k == b"set-cookie"]
        assert all("Secure" not in h for h in headers)  # dropped over HTTP dev
        assert all("samesite=lax" in h.lower() for h in headers)


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
