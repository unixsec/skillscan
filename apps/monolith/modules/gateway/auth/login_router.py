"""Real OIDC/SAML login-callback routes (coding spec §11.2, §9 BFF session
paragraph) - fixes the most-repeatedly-flagged gap in this codebase: M2 built
and thoroughly tested the actual verification logic (oidc.py/saml.py), but no
router ever completed a real login handshake and called set_session_cookie -
only break-glass's login endpoint did. Every endpoint in this API was, in
practice, only reachable via a break-glass-derived admin session.

SECURITY: this router is intentionally OPTIONAL/best-effort at the app-wiring
level - every handler 404s cleanly if its settings aren't configured on
`app.state` (same "not configured" posture as admin.router's break-glass
login), so including this router costs nothing in a deployment that hasn't
set up OIDC/SAML yet.

SECURITY: no `require_csrf` on any handler here - every one of them is, by
definition, PRE-session (the login-start endpoints have no session yet; the
callback/ACS endpoints are what CREATES the session, so there is nothing for
require_csrf's cookie-presence check to find yet either). Don't add it.

EXCEPTION: `/logout` below is POST-session (a state-changing request from an
already-authenticated caller), so it DOES depend on `require_csrf` - the
"don't add it" guidance above is about the pre-session handlers, not this one.
"""

from __future__ import annotations

import json
from typing import Any

import redis.asyncio as aioredis
from common.config import OidcSettings, SamlSettings
from common.log import get_logger
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from starlette.datastructures import FormData

from monolith.modules.admin.breakglass import revoke_breakglass_session
from monolith.modules.admin.local_auth import revoke_local_session

from .dependencies import require_csrf, require_role
from .middleware import (
    BREAKGLASS_SESSION_COOKIE_NAME,
    LOCAL_SESSION_COOKIE_NAME,
    SAML_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    clear_all_session_cookies,
    generate_csrf_token,
    set_csrf_cookie,
    set_session_cookie,
)
from .oidc import AuthorizationRequestState, OidcError, begin_authorization, complete_authorization
from .rbac import resolve_roles
from .saml import (
    SamlError,
    SamlRequestTracker,
    build_request_data,
    create_saml_session,
    process_saml_response,
    revoke_saml_session,
)
from .saml import (
    begin_authorization as saml_begin_authorization,
)

router = APIRouter(prefix="/v1/auth")
_logger = get_logger("skillscan.gateway.auth.login")
_authenticated = require_role()  # any resolved role - logging out needs no specific one

# SECURITY: access_token TTL bound (coding spec §9/§13, ≤600s) governs how
# long session.authenticate() will keep re-accepting this token via
# introspection - the session cookie itself just needs to outlive that,
# giving the browser something to keep sending; the REAL expiry enforcement
# is introspection's own `exp` check on every request, not this cookie TTL.
_OIDC_SESSION_COOKIE_TTL_S = 28800  # 8h, matches SAML_SESSION_TTL_S's workday scope
_OIDC_STATE_KEY_PREFIX = "skillscan:auth:oidc:state:"
_OIDC_STATE_TTL_S = 300  # SECURITY: bound how long an outstanding authorization request stays valid


def _get_redis(request: Request) -> aioredis.Redis:
    # SECURITY: reuses the SAME app-wide Redis connection ScanRuntime already
    # holds (scan_runtime.redis) - not a second, independent connection - same
    # reasoning main.py already documents for why break-glass session state
    # lives there instead of a dedicated connection.
    scan_runtime: Any = request.app.state.scan
    redis: aioredis.Redis = scan_runtime.redis
    return redis


def _get_oidc_settings(request: Request) -> OidcSettings | None:
    return getattr(request.app.state, "oidc_settings", None)


def _get_saml_settings(request: Request) -> SamlSettings | None:
    return getattr(request.app.state, "saml_settings", None)


def _get_group_role_map(request: Request) -> dict[str, str]:
    auth_runtime: Any = request.app.state.auth
    group_role_map: dict[str, str] = auth_runtime.group_role_map
    return group_role_map


def _get_saml_tracker(request: Request) -> SamlRequestTracker:
    # SECURITY: one tracker instance per app.state, NOT constructed fresh per
    # request - a fresh-per-request tracker could never later `consume()` an
    # ID it `register()`-ed on a different request. saml.py's own docstring
    # already documents this as in-memory/single-process for now (M3 should
    # Redis-back it, same limitation SamlRequestTracker had before this fix -
    # not something this change is trying to also solve).
    tracker = getattr(request.app.state, "saml_request_tracker", None)
    if tracker is None:
        tracker = SamlRequestTracker()
        request.app.state.saml_request_tracker = tracker
    return tracker


@router.get("/oidc/login")
async def oidc_login(request: Request) -> RedirectResponse:
    settings = _get_oidc_settings(request)
    if settings is None:
        raise HTTPException(status_code=404, detail="OIDC login is not configured")

    redirect_url, auth_state = begin_authorization(settings)
    # Keep the request state server-side (Redis, so it survives the redirect
    # round-trip and works across replicas) keyed by its own `.state` field;
    # the browser only ever sees the opaque `state` query param
    # begin_authorization already embedded in `redirect_url` itself.
    redis = _get_redis(request)
    payload = json.dumps(
        {
            "state": auth_state.state,
            "nonce": auth_state.nonce,
            "code_verifier": auth_state.code_verifier,
            "redirect_uri": auth_state.redirect_uri,
        }
    )
    await redis.set(f"{_OIDC_STATE_KEY_PREFIX}{auth_state.state}", payload, ex=_OIDC_STATE_TTL_S)
    return RedirectResponse(redirect_url, status_code=302)


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request, response: Response, code: str = Query(...), state: str = Query(...)
) -> dict[str, str]:
    settings = _get_oidc_settings(request)
    if settings is None:
        raise HTTPException(status_code=404, detail="OIDC login is not configured")

    redis = _get_redis(request)
    key = f"{_OIDC_STATE_KEY_PREFIX}{state}"
    raw = await redis.get(key)
    if raw is None:
        raise HTTPException(status_code=401, detail="unknown or expired OIDC authorization state")
    # SECURITY: one-time use, same replay defense as SAML's request-id
    # tracker and break-glass's single-use arming - consume before doing
    # anything else with it.
    await redis.delete(key)
    stored_raw = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
    stored = AuthorizationRequestState(
        state=stored_raw["state"],
        nonce=stored_raw["nonce"],
        code_verifier=stored_raw["code_verifier"],
        redirect_uri=stored_raw["redirect_uri"],
        created_at=0.0,  # not used by complete_authorization; TTL already enforced by Redis above
    )

    try:
        identity = await complete_authorization(
            settings=settings,
            http_client=request.app.state.auth.http_client,
            stored=stored,
            received_state=state,
            received_redirect_uri=stored.redirect_uri,
            code=code,
        )
    except OidcError as exc:
        raise HTTPException(status_code=401, detail="OIDC login failed") from exc

    groups = frozenset(identity.claims.get("groups") or ())
    roles = resolve_roles(groups, _get_group_role_map(request))
    _logger.info(
        "OIDC login succeeded",
        extra={"context": {"subject": identity.subject, "roles": sorted(roles)}},
    )

    # SECURITY: the session cookie carries the IdP's own opaque access_token
    # (see OidcIdentity.access_token's docstring) - session.authenticate()
    # re-introspects THIS value against settings.introspection_endpoint on
    # every subsequent request; nothing is minted or stored server-side here,
    # unlike break-glass/SAML's Redis-backed sessions, because OIDC already
    # has a real "ask the IdP" mechanism to lean on.
    set_session_cookie(
        response,
        name=SESSION_COOKIE_NAME,
        value=identity.access_token,
        max_age_s=_OIDC_SESSION_COOKIE_TTL_S,
    )
    csrf_token = generate_csrf_token()
    set_csrf_cookie(response, csrf_token, max_age_s=_OIDC_SESSION_COOKIE_TTL_S)
    return {"status": "ok", "subject": identity.subject}


@router.get("/saml/login")
async def saml_login(request: Request) -> RedirectResponse:
    settings = _get_saml_settings(request)
    if settings is None:
        raise HTTPException(status_code=404, detail="SAML login is not configured")

    redirect_url, request_id = saml_begin_authorization(
        settings,
        http_host=request.url.hostname or "localhost",
        script_name=request.url.path,
        https=request.url.scheme == "https",
    )
    _get_saml_tracker(request).register(request_id)
    return RedirectResponse(redirect_url, status_code=302)


@router.post("/saml/acs")
async def saml_acs(request: Request, response: Response) -> dict[str, str]:
    """Assertion Consumer Service - the conventional SAML endpoint name the
    IdP POSTs the SAMLResponse back to."""
    settings = _get_saml_settings(request)
    if settings is None:
        raise HTTPException(status_code=404, detail="SAML login is not configured")

    form: FormData = await request.form()
    saml_response_b64 = form.get("SAMLResponse")
    request_id = form.get("InResponseTo") or request.query_params.get("RequestID")
    if not isinstance(saml_response_b64, str) or not isinstance(request_id, str) or not request_id:
        raise HTTPException(status_code=400, detail="missing SAMLResponse or request correlation")

    request_data = build_request_data(
        http_host=request.url.hostname or "localhost",
        script_name=request.url.path,
        https=request.url.scheme == "https",
        saml_response_b64=saml_response_b64,
    )
    try:
        identity = process_saml_response(
            settings,
            request_data,
            tracker=_get_saml_tracker(request),
            expected_request_id=request_id,
        )
    except SamlError as exc:
        raise HTTPException(status_code=401, detail="SAML login failed") from exc

    groups = frozenset(identity.attributes.get("groups") or ())
    roles = resolve_roles(groups, _get_group_role_map(request))
    _logger.info(
        "SAML login succeeded",
        extra={"context": {"subject": identity.name_id, "roles": sorted(roles)}},
    )

    redis = _get_redis(request)
    session_token = await create_saml_session(redis, subject=identity.name_id, roles=roles)
    set_session_cookie(
        response,
        name=SAML_SESSION_COOKIE_NAME,
        value=session_token,
        max_age_s=28800,  # matches saml.py's SAML_SESSION_TTL_S
    )
    csrf_token = generate_csrf_token()
    set_csrf_cookie(response, csrf_token, max_age_s=28800)
    return {"status": "ok", "subject": identity.name_id}


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    _session: Any = Depends(_authenticated),
    _csrf: None = Depends(require_csrf),
) -> dict[str, str]:
    """Ends whichever cookie-authenticated session the caller currently has
    (break-glass/SAML/local are Redis-backed - revoked immediately below;
    OIDC's session cookie IS the IdP's own opaque access_token, not a
    redis_session record, so there is nothing to revoke server-side for it -
    clearing the cookie is the whole story there) and clears every session +
    CSRF cookie regardless of which one was actually present.
    """
    redis = _get_redis(request)
    if (token := request.cookies.get(LOCAL_SESSION_COOKIE_NAME)) is not None:
        await revoke_local_session(redis, token)
    if (token := request.cookies.get(BREAKGLASS_SESSION_COOKIE_NAME)) is not None:
        await revoke_breakglass_session(redis, token)
    if (token := request.cookies.get(SAML_SESSION_COOKIE_NAME)) is not None:
        await revoke_saml_session(redis, token)
    clear_all_session_cookies(response)
    return {"status": "logged_out"}
