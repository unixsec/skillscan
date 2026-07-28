"""FastAPI dependency wiring for authentication (coding spec §11.2: `authenticate`
+ `require_role` key interfaces).

SECURITY: this is the only place that decides WHERE in the request a token
comes from (session cookie for BFF web calls, `Authorization: Bearer` for
direct API/M2M callers) - `session.authenticate`/`m2m.authenticate_*` never see
a raw Request, only the token string this layer extracts. The actual FastAPI
app/router assembly is M3's `apps/monolith/main.py`; this module defines the
dependency `require_role()` that M3's routers will use, and is tested here
against a minimal standalone test app.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable

import httpx
import redis.asyncio as aioredis
from common.config import SessionSettings
from common.errors import AuthenticationError, AuthorizationError
from fastapi import Depends, HTTPException, Request
from skillscan_core import TrustTier

from .m2m import M2MError, M2MGrant, authenticate_client_credentials
from .middleware import (
    BREAKGLASS_SESSION_COOKIE_NAME,
    LOCAL_SESSION_COOKIE_NAME,
    SAML_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    CsrfError,
    enforce_csrf,
    request_has_session_cookie,
)
from .session import IntrospectionCache, SessionContext, SessionError, authenticate


class AuthRuntime:
    """Bundles what `get_session_context` needs, attached to `app.state.auth`
    once at startup."""

    def __init__(
        self,
        *,
        settings: SessionSettings,
        http_client: httpx.AsyncClient,
        cache: IntrospectionCache,
        group_role_map: dict[str, str],
        allowed_m2m_service_accounts: frozenset[str] = frozenset(),
        m2m_grants: dict[str, M2MGrant] | None = None,
        breakglass_redis: aioredis.Redis | None = None,
        saml_redis: aioredis.Redis | None = None,
        local_redis: aioredis.Redis | None = None,
    ) -> None:
        self.settings = settings
        self.http_client = http_client
        self.cache = cache
        self.group_role_map = group_role_map
        self.allowed_m2m_service_accounts = allowed_m2m_service_accounts
        # SECURITY (2026-07-28, 里程碑 B'): per-service-account scope/tier
        # grants (see m2m.M2MGrant/resolve_grant) - None defaults to {} so
        # every unconfigured caller falls through to DEFAULT_M2M_GRANT
        # (scan:submit only, PUBLIC tier), never a wider grant.
        self.m2m_grants: dict[str, M2MGrant] = m2m_grants if m2m_grants is not None else {}
        # SECURITY (§16.3): None by default - break-glass session resolution
        # is only even ATTEMPTED when this is wired up (main.py), keeping
        # every other caller (most tests included) unaffected.
        self.breakglass_redis = breakglass_redis
        # SECURITY (2026-07-06 login-callback fix): same "only attempted when
        # wired up" posture as breakglass_redis above - None by default, so
        # every existing test/caller that never touches SAML login is
        # completely unaffected.
        self.saml_redis = saml_redis
        # SECURITY (2026-07-13 local-auth addition): same "only attempted when
        # wired up" posture as breakglass_redis/saml_redis above.
        self.local_redis = local_redis


def _extract_bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization")
    if header and header.lower().startswith("bearer "):
        return header[len("bearer ") :].strip()
    return None


def _as_http_exception(err: AuthenticationError | AuthorizationError) -> HTTPException:
    # SECURITY (FR-API-060): `err.detail` is the caller-safe message; the real
    # reason (`err.internal_detail`) is logged by the raising code, never
    # forwarded into the response.
    return HTTPException(status_code=err.status_code, detail=err.detail)


async def _resolve_breakglass_session_context(
    request: Request, runtime: AuthRuntime
) -> SessionContext | None:
    """SECURITY (§16.3): break-glass sessions can never be verified via IdP
    introspection (the IdP being unreachable is the whole premise) - this
    checks a SEPARATE, Redis-backed, opaque session instead. Returns None
    (never raises) on anything short of a fully valid, unexpired token, so
    the caller falls through to normal bearer/cookie auth rather than hard-
    failing on a merely stale/absent break-glass cookie."""
    if runtime.breakglass_redis is None:
        return None
    token = request.cookies.get(BREAKGLASS_SESSION_COOKIE_NAME)
    if token is None:
        return None
    # NOTE: deliberately a local import - gateway.auth is this codebase's
    # foundational auth layer; admin is a higher-level feature module, and
    # keeping this the ONE inverted edge (rather than a top-level import)
    # makes that layering choice visible at the call site instead of quietly
    # baked into this file's module-level dependency graph.
    from monolith.modules.admin.breakglass import resolve_breakglass_session

    subject = await resolve_breakglass_session(runtime.breakglass_redis, token)
    if subject is None:
        return None
    # SECURITY: a break-glass session is ALWAYS exactly the "admin" role -
    # that is the entire point of this emergency path, never anything else.
    return SessionContext(
        subject=subject,
        roles=frozenset({"admin"}),
        scopes=frozenset(),
        tier=TrustTier.INTERNAL,
        token_exp=time.time() + 1,  # re-validated against Redis on every request anyway
        is_machine=False,  # break-glass is an operator with a cookie, not a service account
    )


async def _resolve_saml_session_context(
    request: Request, runtime: AuthRuntime
) -> SessionContext | None:
    """SECURITY (2026-07-06 login-callback fix): SAML has no opaque-token +
    introspection-endpoint equivalent to re-verify against on every request
    (unlike OIDC, whose session cookie carries the IdP's own access_token -
    see oidc.py's OidcIdentity.access_token) - a validated assertion is a
    one-time identity assertion, full stop. Session state after a successful
    SAML login is therefore Redis-backed, exactly the same shape break-glass
    already uses for its own (necessarily IdP-independent) session type - see
    saml.py's create_saml_session/resolve_saml_session. Returns None (never
    raises) on anything short of a fully valid, unexpired token, so the
    caller falls through to normal bearer/cookie auth rather than hard-
    failing on a merely stale/absent SAML session cookie."""
    if runtime.saml_redis is None:
        return None
    token = request.cookies.get(SAML_SESSION_COOKIE_NAME)
    if token is None:
        return None
    from .saml import resolve_saml_session

    resolved = await resolve_saml_session(runtime.saml_redis, token)
    if resolved is None:
        return None
    subject, roles = resolved
    return SessionContext(
        subject=subject,
        roles=roles,
        scopes=frozenset(),
        tier=TrustTier.INTERNAL,
        token_exp=time.time() + 1,  # re-validated against Redis on every request anyway
        is_machine=False,  # a validated SAML assertion is a person
    )


async def _resolve_local_session_context(
    request: Request, runtime: AuthRuntime
) -> SessionContext | None:
    """SECURITY (2026-07-13 local-auth addition): mirrors
    _resolve_saml_session_context exactly - a Redis-backed opaque session,
    its own cookie name, multi-role (unlike break-glass's hardcoded "admin").
    Returns None (never raises) on anything short of a fully valid,
    unexpired token, so the caller falls through to normal bearer/cookie auth
    rather than hard-failing on a merely stale/absent local-session cookie."""
    if runtime.local_redis is None:
        return None
    token = request.cookies.get(LOCAL_SESSION_COOKIE_NAME)
    if token is None:
        return None
    from monolith.modules.admin.local_auth import resolve_local_session

    resolved = await resolve_local_session(runtime.local_redis, token)
    if resolved is None:
        return None
    subject, role = resolved
    return SessionContext(
        subject=subject,
        roles=frozenset({role}),
        scopes=frozenset(),
        tier=TrustTier.INTERNAL,
        token_exp=time.time() + 1,  # re-validated against Redis on every request anyway
        is_machine=False,  # a local account is a person's login
    )


async def get_session_context(request: Request) -> SessionContext:
    """SECURITY: the single entry point every protected route depends on
    (directly or via `require_role`). Any failure fail-closes to 401."""
    runtime: AuthRuntime = request.app.state.auth
    breakglass_session = await _resolve_breakglass_session_context(request, runtime)
    if breakglass_session is not None:
        return breakglass_session
    saml_session = await _resolve_saml_session_context(request, runtime)
    if saml_session is not None:
        return saml_session
    local_session = await _resolve_local_session_context(request, runtime)
    if local_session is not None:
        return local_session
    bearer = _extract_bearer_token(request)
    try:
        if bearer is not None:
            return await authenticate_client_credentials(
                bearer,
                settings=runtime.settings,
                http_client=runtime.http_client,
                cache=runtime.cache,
                allowed_service_accounts=runtime.allowed_m2m_service_accounts,
                grants=runtime.m2m_grants,
            )
        cookie_token = request.cookies.get(SESSION_COOKIE_NAME)
        return await authenticate(
            cookie_token,
            settings=runtime.settings,
            http_client=runtime.http_client,
            cache=runtime.cache,
            group_role_map=runtime.group_role_map,
        )
    except (SessionError, M2MError) as exc:
        raise _as_http_exception(AuthenticationError(internal_detail=str(exc))) from exc


def require_role(*roles: str) -> Callable[..., Awaitable[SessionContext]]:
    """SECURITY: `require_role()` with no args just requires *any* authenticated
    session; `require_role("approver", "admin")` requires at least one match.
    Role checking happens strictly after `get_session_context` has already
    fail-closed on any authentication failure - never checked independently."""

    async def _dependency(
        session: SessionContext = Depends(get_session_context),
    ) -> SessionContext:
        if roles and not session.has_role(*roles):
            raise _as_http_exception(
                AuthorizationError(internal_detail=f"requires one of {roles}, has {session.roles}")
            )
        return session

    return _dependency


def require_human_role(*roles: str) -> Callable[..., Awaitable[SessionContext]]:
    """`require_role(*roles)` plus a refusal of machine identities.

    SECURITY (2026-07-28, milestone B' C1): this is what the CONSOLE surface
    depends on. `require_role()` with no arguments means "any authenticated
    session", and an M2M identity carries `roles={"submitter"}` (m2m.M2M_ROLES)
    and is the legitimate submitter of the scans it submitted itself - so it
    satisfied both the role check and the object-level ownership check, and
    could read `GET /v1/scans/{scan_id}` with the very same bearer token it used
    to submit through `POST /v1/market/scans`. That response is the raw internal
    shape: `snippet_hash`, `provenance`, `required_ok`, `hard_gate_hits`, the
    exact four things the marketplace projection exists to withhold (spec §5.3).
    A whole anti-corruption layer that the other side can simply walk around is
    decoration.

    403, deliberately NOT the 404 that object-level authz uses elsewhere in this
    codebase: 404 exists there to hide whether someone else's scan_id exists.
    Nothing is being hidden here - the endpoint exists, the identity is valid,
    and it is the KIND of identity that is refused. A 404 would turn a
    correctly-enforced boundary into a debugging guessing game for the
    integrator, who would reasonably conclude their own scan had vanished.

    Machine callers are not losing access to anything: `/v1/market/scans` +
    `/v1/market/scans/{scan_id}` is the surface built for them, and it serves
    the same scans through the projection.
    """
    role_dependency = require_role(*roles)

    async def _dependency(
        session: SessionContext = Depends(role_dependency),
    ) -> SessionContext:
        if session.is_machine:
            raise _as_http_exception(
                AuthorizationError(
                    detail=(
                        "this endpoint is not available to machine identities; "
                        "use the /v1/market endpoints"
                    ),
                    internal_detail=f"machine identity {session.subject!r} on a console endpoint",
                )
            )
        return session

    return _dependency


async def require_csrf(request: Request) -> None:
    """SECURITY (coding spec §16.1 INV-16): state-changing requests must carry
    a valid double-submit CSRF token. Only applies to cookie-authenticated
    (BFF/browser) requests - a forged cross-origin request can never attach a
    custom `Authorization: Bearer` header, so M2M/API bearer-token callers
    (coding spec §9: "OAuth2 client-credentials/mTLS 机器") are exempt, same
    as CSRF protection's own threat model everywhere it's used. Depend on
    this ALONGSIDE `require_role(...)` (order doesn't matter - both must
    pass), not instead of it.

    SECURITY (single source of truth): which cookies count as
    "cookie-authenticated" is decided by `request_has_session_cookie` against
    the `SESSION_COOKIE_NAMES` registry in middleware.py - NOT by a per-cookie
    enumeration copied into this function. That copied enumeration is exactly
    what silently rotted before: break-glass sessions were once left out of it
    and were thereby exempted from CSRF entirely (fail-OPEN) until real browser
    testing caught it (docs/stories/BACKLOG.md's S8 status note). Adding a new
    cookie-authenticated session type now updates one registry and this check
    follows automatically - the two can no longer drift apart.
    """
    if not request_has_session_cookie(request):
        # No session cookie -> bearer/API caller, not CSRF-forgeable. Exempt.
        return
    try:
        enforce_csrf(request)
    except CsrfError as exc:
        raise HTTPException(status_code=403, detail="CSRF validation failed") from exc
