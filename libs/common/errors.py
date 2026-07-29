"""Unified error contract - never leak internal details across an API boundary
(FR-API-060, coding spec §8 cross-cutting concerns)."""

from __future__ import annotations

# The response header carrying `ApiError.code` to programmatic callers.
#
# CONTRACT (2026-07-29): `detail` is written for a human to read and may be
# reworded, punctuated, capitalized or translated at any time; `code` is a
# stable identifier a program may branch on and must NOT change without
# treating it as an API break. The frontend's session-expiry handling
# (web/src/api/client.ts) previously discriminated an expired-session 403
# from a permission 403 by comparing `detail` to the exact literal
# "CSRF validation failed" - any rewording on this side would have taken
# that branch dark with nothing turning red. Codes exist precisely so an
# interface consumed by a program is not contracted on text written for
# people.
#
# Delivered as a HEADER rather than a body field deliberately: FastAPI's
# default HTTPException handler copies `exc.headers` onto the response, so
# the code travels with the exception itself and reaches the wire in EVERY
# app assembly - including the minimal standalone test apps - instead of
# depending on an app-level exception handler that a differently-wired app
# could silently lack. Same-origin only (CSP `connect-src 'self'`), so no
# Access-Control-Expose-Headers is needed.
ERROR_CODE_HEADER = "X-Error-Code"


class ApiError(Exception):
    """Base for every error that can reach an external response.

    SECURITY: `detail` is what the caller sees - never put stack traces, internal
    paths, SQL, or raw exception text in it. `internal_detail` is for logs only
    and must never be serialized into a response body.

    `code` is the machine-readable half of the same answer - see
    ERROR_CODE_HEADER above for why callers must branch on it, never on
    `detail`.
    """

    def __init__(
        self, status_code: int, code: str, detail: str, internal_detail: str | None = None
    ) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.code = code
        self.detail = detail
        self.internal_detail = internal_detail


class AuthenticationError(ApiError):
    def __init__(
        self, detail: str = "authentication required", internal_detail: str | None = None
    ) -> None:
        super().__init__(401, "authentication_required", detail, internal_detail)


class AuthorizationError(ApiError):
    def __init__(self, detail: str = "forbidden", internal_detail: str | None = None) -> None:
        super().__init__(403, "forbidden", detail, internal_detail)


class CsrfValidationError(ApiError):
    """A state-changing cookie-authenticated request whose double-submit CSRF
    token is missing or mismatched (gateway.auth.dependencies.require_csrf).

    Its own code, NOT AuthorizationError's generic "forbidden": to the browser
    this is "your session can no longer write, go re-authenticate", whereas
    every other 403 is "this live session may not do that" - and the frontend
    has to tell those apart to decide between bouncing to /login and rendering
    an inline refusal. `csrf_validation_failed` is the value web/src/api/client.ts
    matches; both sides pin it with a test.
    """

    def __init__(self, internal_detail: str | None = None) -> None:
        super().__init__(403, "csrf_validation_failed", "CSRF validation failed", internal_detail)


class ValidationError(ApiError):
    def __init__(self, detail: str, internal_detail: str | None = None) -> None:
        super().__init__(400, "invalid_request", detail, internal_detail)
