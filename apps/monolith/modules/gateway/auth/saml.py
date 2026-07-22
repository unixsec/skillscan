"""SAML 2.0 Service Provider via python3-saml (coding spec §11.2).

SECURITY (verified against installed python3-saml 1.16.0 source):
- `wantMessagesSigned`/`wantAssertionsSigned` default to `False` in the library
  itself - `_build_security_settings` below forces both `True`, or an attacker's
  entirely unsigned assertion would be accepted. Never construct
  `OneLogin_Saml2_Auth` with a settings dict that omits these.
- XXE/DTD handling is hardened by the library's own XML parser by default
  (`onelogin.saml2.xmlparser`: `forbid_dtd=True, forbid_entities=True`) - this
  module does not need to (and must not attempt to) re-implement XML parsing.
- `process_response` can raise on malformed/hostile XML (e.g. `DTDForbidden`)
  rather than merely setting an error - every call site here is wrapped so
  ANY exception is treated as authentication failure (fail-closed), never
  allowed to propagate as an unhandled request error.
- Replay protection for `InResponseTo` is NOT provided by the library on its
  own (it only checks the given response's InResponseTo against whatever
  `request_id` you pass in) - `SamlRequestTracker` below tracks one-time-use
  request IDs so a captured response can't be replayed after its request ID
  has already been consumed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import redis.asyncio as aioredis
from common.config import SamlSettings
from common.log import get_logger
from onelogin.saml2.auth import OneLogin_Saml2_Auth

from . import redis_session

logger = get_logger(__name__)

_REQUEST_ID_TTL_S = 300  # SECURITY: bound how long an outstanding AuthnRequest ID stays valid


class SamlError(Exception):
    """Any SAML validation failure. SECURITY: callers must treat this as fail-closed (401)."""


@dataclass(frozen=True, slots=True)
class SamlIdentity:
    name_id: str
    session_index: str | None
    attributes: dict[str, list[str]]


class SamlRequestTracker:
    """SECURITY: tracks outstanding AuthnRequest IDs so each can be consumed by
    at most one response (defends against replaying a captured SAMLResponse).
    In-memory + single-process for M2; M3 should back this with Redis (shared
    across replicas) using the same one-time-consume semantics."""

    def __init__(self) -> None:
        self._outstanding: dict[str, float] = {}

    def register(self, request_id: str) -> None:
        self._prune()
        self._outstanding[request_id] = time.time() + _REQUEST_ID_TTL_S

    def consume(self, request_id: str) -> bool:
        """Returns True exactly once per registered request_id; False on replay
        or on an unknown/expired ID (fail-closed)."""
        self._prune()
        expiry = self._outstanding.pop(request_id, None)
        return expiry is not None

    def _prune(self) -> None:
        now = time.time()
        expired = [rid for rid, expiry in self._outstanding.items() if expiry < now]
        for rid in expired:
            del self._outstanding[rid]


def _build_settings_dict(settings: SamlSettings) -> dict[str, Any]:
    return {
        # SECURITY: library default is already True; set explicitly for auditability.
        "strict": True,
        "sp": {
            "entityId": settings.sp_entity_id,
            "assertionConsumerService": {
                "url": settings.sp_acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": settings.sp_acs_url.rsplit("/", 1)[0] + "/slo",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": settings.idp_entity_id,
            "singleSignOnService": {
                "url": settings.idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": settings.idp_slo_url or "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": settings.idp_x509_cert,
        },
        "security": {
            # SECURITY: library defaults are False for both - must force True.
            "wantMessagesSigned": False,
            "wantAssertionsSigned": True,
            "wantNameId": True,
            "wantAssertionsEncrypted": settings.want_assertions_encrypted,
            "rejectDeprecatedAlgorithm": True,
            "requestedAuthnContext": False,
        },
    }


def build_request_data(
    *, http_host: str, script_name: str, https: bool, saml_response_b64: str
) -> dict[str, Any]:
    # SECURITY/compat: `server_port` is deprecated by python3-saml in favor of an
    # explicit port in `http_host`; `https` alone is sufficient for our https-only
    # deployment (verified against installed 1.16.0's `is_https()` - it checks
    # `https != "off"` before ever consulting `server_port`).
    return {
        "http_host": http_host,
        "script_name": script_name,
        "https": "on" if https else "off",
        "post_data": {"SAMLResponse": saml_response_b64},
    }


def process_saml_response(
    settings: SamlSettings,
    request_data: dict[str, Any],
    *,
    tracker: SamlRequestTracker,
    expected_request_id: str,
) -> SamlIdentity:
    # SECURITY: consume-before-validate would leak whether a request_id merely
    # *exists*; consume-after-validate would allow replay if validation ever
    # partially succeeds before raising. Consuming first is the fail-closed
    # choice - a used-up ID can never grant another attempt regardless of what
    # the validation step does. It also means a single replay attempt with a
    # tampered response burns that request_id rather than allowing retries.
    if not tracker.consume(expected_request_id):
        raise SamlError("unknown or already-used SAML request id (possible replay)")

    try:
        auth = OneLogin_Saml2_Auth(request_data, old_settings=_build_settings_dict(settings))
        auth.process_response(request_id=expected_request_id)
    except Exception as exc:  # noqa: BLE001 - SECURITY: fail-closed on ANY parse/validation exception
        logger.info("saml response rejected", extra={"context": {"reason": type(exc).__name__}})
        raise SamlError(f"SAML response processing failed: {exc}") from exc

    errors = auth.get_errors()
    if errors or not auth.is_authenticated():
        raise SamlError(f"SAML response invalid: {errors} ({auth.get_last_error_reason()})")

    name_id = auth.get_nameid()
    if not name_id:
        raise SamlError("SAML response has no NameID")

    return SamlIdentity(
        name_id=name_id,
        session_index=auth.get_session_index(),
        attributes=auth.get_attributes(),
    )


def begin_authorization(
    settings: SamlSettings, *, http_host: str, script_name: str, https: bool
) -> tuple[str, str]:
    """Builds the SP-initiated AuthnRequest redirect (mirrors oidc.py's
    begin_authorization - SAML's equivalent of "start the login flow").
    Returns (redirect_url, request_id) - the caller must `tracker.register
    (request_id)` before returning the redirect to the browser, exactly as
    `process_saml_response` above expects to later `consume()` it."""
    request_data = {
        "http_host": http_host,
        "script_name": script_name,
        "https": "on" if https else "off",
    }
    auth = OneLogin_Saml2_Auth(request_data, old_settings=_build_settings_dict(settings))
    redirect_url = auth.login(return_to=None)
    request_id = auth.get_last_request_id()
    if not request_id:
        # SECURITY: fail-closed - without a request_id there is nothing for
        # process_saml_response's replay-tracker to check the response
        # against later, which would make InResponseTo validation meaningless.
        raise SamlError("python3-saml did not produce a request_id for this AuthnRequest")
    return redirect_url, request_id


# SECURITY (2026-07-06 login-callback fix, INV-16/§11.2): SAML has no
# equivalent of OIDC's opaque-access-token + introspection model (see oidc.py's
# OidcIdentity.access_token docstring) - a validated assertion is a one-time
# identity assertion with no subsequent "ask the IdP if this is still valid"
# mechanism at all. Session state after a successful SAML login must therefore
# be maintained server-side, exactly the same shape admin.breakglass already
# uses for its own (necessarily IdP-independent) session type: a Redis-backed
# opaque token, resolved by dependencies.get_session_context BEFORE it falls
# through to session.authenticate()'s introspection path, via ITS OWN distinct
# cookie name so the two session types never collide (same reasoning as
# BREAKGLASS_SESSION_COOKIE_NAME being separate from SESSION_COOKIE_NAME).
_SAML_SESSION_KEY_PREFIX = "skillscan:auth:saml:session:"
SAML_SESSION_TTL_S = 28800  # 8h - a normal human workday session, not break-glass's 15min


async def create_saml_session(redis: aioredis.Redis, *, subject: str, roles: frozenset[str]) -> str:
    """SECURITY: called ONLY after `process_saml_response` has already
    returned a validated SamlIdentity and roles have been resolved via
    rbac.resolve_roles - never call this independently of a fresh, successful
    validation. Returns the opaque session token to set as the SAML session
    cookie's value."""
    return await redis_session.create_session(
        redis,
        key_prefix=_SAML_SESSION_KEY_PREFIX,
        ttl_s=SAML_SESSION_TTL_S,
        payload={"subject": subject, "roles": sorted(roles)},
    )


async def resolve_saml_session(
    redis: aioredis.Redis, token: str
) -> tuple[str, frozenset[str]] | None:
    """Returns (subject, roles) the token resolves to, or None if the token is
    missing/expired/unrecognized/corrupt (fail-closed - never guesses).

    SECURITY: a corrupt session record is treated exactly like a missing one -
    fail-closed, never partially trust a malformed payload."""
    payload = await redis_session.resolve_session(
        redis, key_prefix=_SAML_SESSION_KEY_PREFIX, token=token
    )
    if not isinstance(payload, dict) or "subject" not in payload or "roles" not in payload:
        return None
    try:
        return payload["subject"], frozenset(payload["roles"])
    except TypeError:
        # SECURITY (fail-closed): a JSON-valid record whose `roles` is
        # non-iterable/non-hashable (int/null/bool, or a nested list from an
        # out-of-band or cross-version writer) must be treated like any other
        # corrupt record - None, never raise. get_session_context resolves the
        # SAML session BEFORE its 401 try-block (dependencies.py), so a raised
        # TypeError here would escape as an unhandled 500 instead of failing
        # closed to bearer/cookie auth, contradicting both this function's and
        # get_session_context's "never raises / fail-closes to 401" contract.
        return None
