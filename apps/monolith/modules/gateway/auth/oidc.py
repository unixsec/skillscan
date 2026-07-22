"""OIDC Relying Party - Authorization Code Flow + PKCE (coding spec §11.2).

SECURITY: authlib's JWS algorithm registry includes "none" and symmetric (HS*)
algorithms alongside RS*/ES* - every decode call here explicitly restricts
`algorithms` to the asymmetric algorithm the IdP actually signs with. Never use
`authlib.jose.jwt` (the module-level default) directly.

SECURITY: authlib's JWTClaims only validates a claim if an option is explicitly
supplied for it (verified against authlib 1.4.1 source: `_validate_claim_value`
returns immediately when no option is registered for that claim name, and
`validate_exp` only checks expiry if `exp` happens to be present in the payload).
This means iss/aud/exp/nonce/sub MUST all be passed as essential `claims_options`
below - omitting any of them means authlib silently skips checking it at all.

This module owns PKCE/state/nonce generation+validation and redirect_uri
allowlisting - that's request-flow orchestration a library can't do for you.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlencode

import httpx
from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from common.config import OidcSettings
from common.log import get_logger

logger = get_logger(__name__)

# SECURITY: explicit allowlist; extend deliberately, never widen to include "none"/"HS*"
_ID_TOKEN_ALGORITHMS = ("RS256",)


class OidcError(Exception):
    """Any OIDC validation failure. SECURITY: callers must treat this as fail-closed (401)."""


@dataclass(frozen=True, slots=True)
class AuthorizationRequestState:
    """Server-side state for one in-flight authorization request.

    SECURITY: state/nonce/code_verifier must be looked up server-side by a
    session-bound key and compared - never trust a client-supplied copy of any
    of these as authoritative on its own.
    """

    state: str
    nonce: str
    code_verifier: str
    redirect_uri: str
    created_at: float


@dataclass(frozen=True, slots=True)
class OidcIdentity:
    subject: str
    issuer: str
    claims: dict[str, Any]
    # SECURITY (2026-07-06 login-callback fix): the id_token (validated above)
    # asserts identity ONCE at login time; it is not the opaque, re-introspectable
    # token gateway.auth.session.authenticate()/introspect_token() expect for
    # EVERY subsequent request (coding spec §11.2's "opaque token + OAuth2
    # introspection" model). `access_token` is that opaque token - default ""
    # because validate_id_token() (below) constructs OidcIdentity directly and
    # has no network access to a token response at all (deliberately, so it
    # stays testable against crafted id_tokens alone); complete_authorization()
    # is the only caller with a real token response, and attaches the real
    # value via dataclasses.replace() before returning.
    access_token: str = ""


def begin_authorization(settings: OidcSettings) -> tuple[str, AuthorizationRequestState]:
    """Build the redirect URL for the authorization endpoint and the request
    state that must be persisted server-side (e.g. in a short-lived server
    session) keyed by `state`."""
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = create_s256_code_challenge(code_verifier)
    redirect_uri = settings.redirect_uri_allowlist[0]

    params = {
        "response_type": "code",
        "client_id": settings.client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(settings.scopes),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",  # SECURITY: S256 only - "plain" is never offered
    }
    url = f"{settings.authorization_endpoint}?{urlencode(params)}"
    return url, AuthorizationRequestState(
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
        created_at=time.time(),
    )


def _build_claims_options(*, issuer: str, client_id: str, nonce: str) -> dict[str, Any]:
    # SECURITY: every claim we care about must be listed here with essential=True -
    # authlib does not validate a claim unless it's configured (see module docstring).
    return {
        "iss": {"essential": True, "value": issuer},
        "aud": {"essential": True, "value": client_id},
        "exp": {"essential": True},
        "sub": {"essential": True},
        "nonce": {"essential": True, "value": nonce},
    }


async def _fetch_jwks(http_client: httpx.AsyncClient, jwks_uri: str) -> dict[str, Any]:
    response = await http_client.get(jwks_uri)
    response.raise_for_status()
    jwks: Any = response.json()
    if not isinstance(jwks, dict) or "keys" not in jwks:
        raise OidcError("jwks endpoint returned an unexpected shape")
    return jwks


def validate_id_token(
    id_token: str, jwks: dict[str, Any], *, issuer: str, client_id: str, nonce: str
) -> OidcIdentity:
    """Pure validation entry point (no I/O) - kept separate from the network
    calls in `complete_authorization` so it can be tested directly against
    crafted tokens without mocking HTTP."""
    validator = JsonWebToken(algorithms=list(_ID_TOKEN_ALGORITHMS))
    claims_options = _build_claims_options(issuer=issuer, client_id=client_id, nonce=nonce)
    try:
        claims = validator.decode(id_token, key=jwks, claims_options=claims_options)
        claims.validate()
    except JoseError as exc:
        logger.info("id_token rejected", extra={"context": {"reason": type(exc).__name__}})
        raise OidcError(f"id_token validation failed: {exc}") from exc

    # SECURITY: mix-up defense - re-assert the issuer we validated against is
    # exactly the configured one (belt-and-suspenders on top of the essential
    # claims_options check above, in case a future refactor loosens it).
    if claims.get("iss") != issuer:
        raise OidcError("issuer mismatch (mix-up defense)")

    return OidcIdentity(subject=claims["sub"], issuer=claims["iss"], claims=dict(claims))


async def complete_authorization(
    *,
    settings: OidcSettings,
    http_client: httpx.AsyncClient,
    stored: AuthorizationRequestState,
    received_state: str,
    received_redirect_uri: str,
    code: str,
) -> OidcIdentity:
    # SECURITY: CSRF - state must match exactly what was generated for this flow.
    if not secrets.compare_digest(received_state, stored.state):
        raise OidcError("state mismatch")
    # SECURITY: redirect_uri exact allowlist match, never prefix/pattern matching.
    if received_redirect_uri not in settings.redirect_uri_allowlist:
        raise OidcError("redirect_uri not in allowlist")

    token_response = await http_client.post(
        settings.token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": stored.redirect_uri,
            # SECURITY: PKCE - proves this client started the flow.
            "code_verifier": stored.code_verifier,
            "client_id": settings.client_id,
            "client_secret": settings.client_secret,
        },
    )
    token_response.raise_for_status()
    payload = token_response.json()
    id_token = payload.get("id_token")
    if not id_token:
        raise OidcError("token response has no id_token")
    # SECURITY: access_token is a REQUIRED field of a spec-compliant OAuth2
    # token response (RFC 6749 §5.1) - a compliant IdP always sends one, and
    # this is the value the login callback needs to hand session.authenticate()
    # for every later request. Treat a missing one as a rejection, the same
    # fail-closed posture as a missing id_token above, rather than minting a
    # session that can never actually pass introspection afterward.
    access_token = payload.get("access_token")
    if not access_token:
        raise OidcError("token response has no access_token")

    jwks = await _fetch_jwks(http_client, settings.jwks_uri)
    identity = validate_id_token(
        id_token, jwks, issuer=settings.issuer, client_id=settings.client_id, nonce=stored.nonce
    )
    return replace(identity, access_token=access_token)
