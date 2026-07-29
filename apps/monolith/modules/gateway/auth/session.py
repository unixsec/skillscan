"""Opaque token + OAuth2 introspection (RFC 7662) session validation
(coding spec §11.2, FR-SES).

SECURITY:
- Interactive access tokens are opaque references; every request is verified
  against the IdP's introspection endpoint, never decoded/trusted locally.
- Introspection results are cached briefly (<=30s, FR-SES-040) keyed by
  `sha256(token)` - never the raw token - so a cache dump doesn't expose live
  bearer tokens, and the cache window is the hard upper bound on how long a
  revoked token can still appear valid.
- Introspection endpoint failure is fail-closed (FR-SES-050): no fallback to a
  stale cache entry past its TTL, no "assume valid" default.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any

import httpx
from common.config import SessionSettings
from common.log import get_logger
from skillscan_core import TrustTier

from .rbac import resolve_roles

logger = get_logger(__name__)


class SessionError(Exception):
    """Any session validation failure. SECURITY: callers must treat this as fail-closed (401)."""


class IntrospectionUnavailableError(SessionError):
    """The introspection CALL itself failed - the IdP was unreachable, returned
    a non-2xx, or answered with something that is not a JSON object.

    SECURITY: a subclass, not a separate exception, so every existing
    `except SessionError` handler keeps fail-closing exactly as before - the
    distinction is additive and cannot change any authorization outcome
    (Task 13, 2026-07-29).

    It exists so `introspection_failures_total` (coding spec §11.7) can count
    the condition the spec's own acceptance test names - "introspection 故障→
    fail-closed 拒" - WITHOUT counting the ordinary rejections that share the
    same 401: an expired token, a revoked token, `active: false`, a missing
    `sub`. Those are the system working; this is the system unable to ask.
    Merging them would produce a counter that rises steadily on a healthy
    deployment (every lapsed browser session) and so could never alert on an
    IdP outage, which is the only thing it is for. The type is raised here,
    at the one place that performs the introspection I/O, and counted in
    `dependencies.get_session_context`, the one place that can reach the
    metrics registry."""


@dataclass(frozen=True, slots=True)
class SessionContext:
    """SECURITY: `is_machine` is the KIND of identity, not its permission list.

    It exists so the console surface (`gateway/router.py`) can refuse machine
    identities outright. Before it, `require_role()` with no arguments meant
    "any authenticated session", and an M2M caller carries `roles={"submitter"}`
    and is the submitter of its own scans - so it passed both the role check and
    the object-level ownership check and could read the console's
    `GET /v1/scans/{scan_id}`, whose body is the raw internal shape
    (`snippet_hash`, `provenance`, `required_ok`, `hard_gate_hits` - the four
    things `marketplace_api.views` deliberately withholds). The projection was
    the door the marketplace was EXPECTED to use, not the only door it could.

    Deliberately NOT expressed as "requires scope X": a scope allowlist is one
    added scope away from silently reopening that hole, and scopes describe what
    an identity may do, whereas the question here is what an identity IS. There
    is no default value for the same reason - a new session type must state its
    kind rather than inherit "human" by omission, and a test fixture that fakes
    an M2M session must say so or it is not testing the machine path at all.
    """

    subject: str
    roles: frozenset[str]
    scopes: frozenset[str]
    tier: TrustTier
    token_exp: float
    is_machine: bool

    def has_role(self, *roles: str) -> bool:
        return bool(self.roles.intersection(roles))


class IntrospectionCache:
    """SECURITY: in-memory, single-process for M2. M3 should back this with
    Redis (shared across replicas) using the same sha256(token)-keyed,
    TTL-bounded semantics - never store the raw token as a cache key."""

    def __init__(self, ttl_s: int) -> None:
        self._ttl_s = ttl_s
        self._entries: dict[str, tuple[dict[str, Any], float]] = {}

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def get(self, token: str) -> dict[str, Any] | None:
        entry = self._entries.get(self._key(token))
        if entry is None:
            return None
        payload, cached_at = entry
        if time.time() - cached_at > self._ttl_s:
            del self._entries[self._key(token)]
            return None
        return payload

    def put(self, token: str, payload: dict[str, Any]) -> None:
        self._entries[self._key(token)] = (payload, time.time())


async def introspect_token(
    token: str,
    *,
    settings: SessionSettings,
    http_client: httpx.AsyncClient,
    cache: IntrospectionCache,
) -> dict[str, Any]:
    cached = cache.get(token)
    if cached is not None:
        return cached
    try:
        response = await http_client.post(
            settings.introspection_endpoint,
            data={"token": token},
            auth=(settings.introspection_client_id, settings.introspection_client_secret),
        )
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        # SECURITY (FR-SES-050): introspection outage -> fail-closed, never serve
        # a stale/assumed-valid result.
        logger.info(
            "introspection endpoint failure", extra={"context": {"error": type(exc).__name__}}
        )
        raise IntrospectionUnavailableError(f"introspection endpoint unavailable: {exc}") from exc
    if not isinstance(payload, dict):
        # Also an introspection failure, not a token verdict: the IdP answered
        # with something we cannot interpret, so we never learned anything
        # about this token at all.
        raise IntrospectionUnavailableError("introspection response was not a JSON object")
    cache.put(token, payload)
    return payload


def _resolve_trust_tier(payload: dict[str, Any]) -> TrustTier:
    # SECURITY: default to the strictest-scoped human/internal-session tier;
    # only an explicit, valid claim from the IdP can widen it. An unrecognized
    # value fails closed to INTERNAL rather than silently picking PUBLIC.
    raw = payload.get("trust_tier")
    if raw in (TrustTier.INTERNAL, TrustTier.PARTNER, TrustTier.PUBLIC):
        return TrustTier(raw)
    return TrustTier.INTERNAL


async def authenticate(
    token: str | None,
    *,
    settings: SessionSettings,
    http_client: httpx.AsyncClient,
    cache: IntrospectionCache,
    group_role_map: dict[str, str],
) -> SessionContext:
    """SECURITY: the single entry point every request must go through. Any
    failure raises SessionError - callers map that to 401, never to a partial
    or default-permissive SessionContext."""
    if not token:
        raise SessionError("no token provided")

    payload = await introspect_token(token, settings=settings, http_client=http_client, cache=cache)

    if not payload.get("active"):
        raise SessionError("token is not active (expired, revoked, or invalid)")

    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        raise SessionError("introspection response missing numeric exp")
    if time.time() >= exp:
        raise SessionError("token expired per introspection exp")

    subject = payload.get("sub")
    if not subject:
        raise SessionError("introspection response missing sub")

    groups = frozenset(payload.get("groups") or ())
    roles = resolve_roles(groups, group_role_map)
    scope_str = payload.get("scope") or ""
    scopes = frozenset(scope_str.split()) if scope_str else frozenset()

    return SessionContext(
        subject=subject,
        roles=roles,
        scopes=scopes,
        tier=_resolve_trust_tier(payload),
        token_exp=float(exp),
        # An interactive OIDC session is a person behind a browser/CLI, not a
        # service account - `m2m.py` is the only module that builds machine
        # sessions.
        is_machine=False,
    )
