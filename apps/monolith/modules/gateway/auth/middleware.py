"""Security headers, CSRF protection, and cookie hardening (coding spec §11.2,
§16.1 INV-16).

SECURITY:
- CSRF uses the double-submit-cookie pattern: a non-HttpOnly `csrf_token` cookie
  (readable by same-origin JS, unlike the session cookie) must be echoed back
  in the `X-CSRF-Token` header on every state-changing request. A cross-origin
  attacker's browser will auto-attach the victim's cookies to a forged request,
  but cannot read the cookie's value to also set the matching header - so the
  comparison failing is what blocks the forgery, not any secrecy of the token.
- Security headers follow INV-16: no `unsafe-inline`/`unsafe-eval` in CSP, no
  external asset sources, clickjacking denied via X-Frame-Options.
"""

from __future__ import annotations

import os
import secrets
from typing import Literal, cast

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "x-csrf-token"
SESSION_COOKIE_NAME = "skillscan_session"
# SECURITY (§16.3): a SEPARATE cookie from SESSION_COOKIE_NAME - break-glass
# sessions are resolved via Redis (gateway.auth.dependencies), never via IdP
# introspection, and must never be confused with a normal session cookie.
BREAKGLASS_SESSION_COOKIE_NAME = "skillscan_breakglass_session"
# SECURITY (2026-07-06 login-callback fix): SAML sessions are ALSO
# Redis-backed (see saml.py's create_saml_session - SAML has no
# introspection-endpoint equivalent to check against, unlike OIDC's
# access_token), so this needs its own cookie name for the same reason
# BREAKGLASS_SESSION_COOKIE_NAME does - and, just as critically, every
# "is this a cookie-authenticated request" check in this codebase (see
# require_csrf below) must recognize ALL THREE cookie names, not just the
# ones that existed when that check was written - this is the exact bug class
# a real browser-testing pass already found and fixed once for break-glass
# (docs/stories/BACKLOG.md's S8 status note) - don't reintroduce it here.
SAML_SESSION_COOKIE_NAME = "skillscan_saml_session"
# SECURITY (2026-07-13 local-auth addition): a FOURTH cookie-authenticated
# session type, same "own distinct cookie name" reasoning as the three above.
LOCAL_SESSION_COOKIE_NAME = "skillscan_local_session"

# SECURITY (single source of truth): EVERY cookie name that authenticates a
# request. `require_csrf` (gateway.auth.dependencies) and any other "is this a
# cookie-authenticated request?" check MUST enumerate this set, never a
# hand-copied subset. Adding a new cookie-authenticated session type is a
# one-line addition HERE, and CSRF protection then covers it automatically.
#
# This exact enumeration silently rotting - a new session cookie added without
# updating the CSRF check, leaving that session type exempt from CSRF entirely
# (fail-OPEN) - is the bug class that already bit break-glass once
# (docs/stories/BACKLOG.md's S8 status note). Centralizing it here is what
# stops the check and the cookie list from drifting apart again.
SESSION_COOKIE_NAMES: frozenset[str] = frozenset(
    {
        SESSION_COOKIE_NAME,
        BREAKGLASS_SESSION_COOKIE_NAME,
        SAML_SESSION_COOKIE_NAME,
        LOCAL_SESSION_COOKIE_NAME,
    }
)


def request_has_session_cookie(request: Request) -> bool:
    """True if the request carries ANY cookie-authenticated session (see
    SESSION_COOKIE_NAMES). SECURITY: this is the authoritative "should CSRF
    apply?" predicate - a request with no session cookie is a bearer/API
    caller that cannot be CSRF-forged (no ambient credential a browser would
    auto-attach), so CSRF does not apply; a request WITH one must pass CSRF."""
    return any(name in request.cookies for name in SESSION_COOKIE_NAMES)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def verify_csrf(cookie_token: str | None, header_token: str | None) -> bool:
    if not cookie_token or not header_token:
        return False
    return secrets.compare_digest(cookie_token, header_token)


def _cookie_secure() -> bool:
    # SECURITY (INV-16): defaults to Secure=True (production is always HTTPS).
    # ONLY the local HTTP dev launcher (scripts/dev/run_local.py) sets this
    # false - a Secure cookie is silently dropped by the browser over plain
    # http:// on any origin that isn't localhost/127.0.0.1, which shows up as
    # "the session is lost the moment I leave/reload the page". Never in prod.
    return os.environ.get("SKILLSCAN_COOKIE_SECURE", "true").lower() != "false"


def _cookie_samesite() -> Literal["strict", "lax", "none"]:
    # SECURITY (INV-16): defaults to Strict. Dev can relax to Lax so the session
    # cookie still accompanies a top-level navigation BACK to the app from an
    # external page (Strict withholds it there, logging the user out). Lax stays
    # CSRF-safe here because state-changing requests are separately protected by
    # the double-submit CSRF token, not by SameSite alone.
    value = os.environ.get("SKILLSCAN_COOKIE_SAMESITE", "strict").lower()
    if value in ("strict", "lax", "none"):
        return cast("Literal['strict', 'lax', 'none']", value)
    return "strict"


def set_session_cookie(response: Response, *, name: str, value: str, max_age_s: int) -> None:
    # SECURITY (INV-16): session cookie is always HttpOnly (no token in JS);
    # Secure + SameSite default to the strict production values and are relaxed
    # only by an explicit local-HTTP-dev env override (see helpers above).
    response.set_cookie(
        key=name,
        value=value,
        max_age=max_age_s,
        httponly=True,
        secure=_cookie_secure(),
        samesite=_cookie_samesite(),
    )


def set_csrf_cookie(response: Response, token: str, *, max_age_s: int) -> None:
    # SECURITY: deliberately NOT HttpOnly - the frontend must be able to read
    # this value to echo it back in X-CSRF-Token. It carries no authentication
    # power on its own. Secure/SameSite follow the same env-driven policy as the
    # session cookie so both survive (or don't) together.
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        max_age=max_age_s,
        httponly=False,
        secure=_cookie_secure(),
        samesite=_cookie_samesite(),
    )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """SECURITY (INV-16): strict CSP (no inline/eval, no external sources),
    clickjacking denial, MIME-sniffing denial, HSTS."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response


class CsrfError(Exception):
    """SECURITY: callers must treat this as fail-closed (403)."""


def enforce_csrf(request: Request) -> None:
    if request.method in _SAFE_METHODS:
        return
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    header_token = request.headers.get(CSRF_HEADER_NAME)
    if not verify_csrf(cookie_token, header_token):
        raise CsrfError("missing or mismatched CSRF token")
