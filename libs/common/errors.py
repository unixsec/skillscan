"""Unified error contract - never leak internal details across an API boundary
(FR-API-060, coding spec §8 cross-cutting concerns)."""

from __future__ import annotations


class ApiError(Exception):
    """Base for every error that can reach an external response.

    SECURITY: `detail` is what the caller sees - never put stack traces, internal
    paths, SQL, or raw exception text in it. `internal_detail` is for logs only
    and must never be serialized into a response body.
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


class ValidationError(ApiError):
    def __init__(self, detail: str, internal_detail: str | None = None) -> None:
        super().__init__(400, "invalid_request", detail, internal_detail)
