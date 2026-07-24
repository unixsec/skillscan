"""Shared opaque-token Redis session store (coding spec §16.3).

Three cookie-authenticated session types - break-glass, SAML, and local-account
login - each independently hand-rolled the SAME create/resolve pair over Redis:
mint `secrets.token_urlsafe(32)`, store a JSON (or bare-string) payload under a
per-type key prefix with a TTL, then read it back fail-closed. This module is
the single implementation they now share.

SECURITY:
- The Redis KEY is `sha256(token)`, never the raw token. This matches the
  posture `session.py`'s IntrospectionCache already documented and enforced
  ("never store the raw token as a cache key") - the three session
  implementations this replaces did NOT follow it: they interpolated the raw
  session token straight into the Redis key. A session token IS a bearer
  credential (holding it is enough to impersonate the user), so a Redis
  snapshot, a `SCAN`/`KEYS` sweep, or slow-query logging previously exposed
  live sessions directly. Hashing the key means the stored key is useless to
  an attacker who reads Redis but doesn't already hold the token.
- The token returned to the caller (to set as the cookie value) is still the
  raw high-entropy token - only the storage key is hashed. Resolution hashes
  the presented token the same way, so this is transparent to callers.
- Resolution is fail-closed: a missing, expired, or corrupt record resolves to
  None and is never partially trusted (mirrors the prior implementations and
  session.py's own posture).
"""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any

import redis.asyncio as aioredis

_TOKEN_BYTES = 32


def _storage_key(prefix: str, token: str) -> str:
    """SECURITY: the Redis key is `<prefix><sha256(token)>`, never the raw
    token. See module docstring."""
    return f"{prefix}{hashlib.sha256(token.encode()).hexdigest()}"


async def create_session(
    redis: aioredis.Redis, *, key_prefix: str, ttl_s: int, payload: Any
) -> str:
    """Mint an opaque session token, store `payload` under `sha256(token)` with
    a `ttl_s` expiry, and return the raw token for the caller to set as a cookie
    value.

    `payload` may be any JSON-serializable value - a bare string (break-glass
    stores just its subject), or a dict (SAML/local store subject+roles/role).
    It is always persisted as JSON so resolution has one uniform decode path.

    SECURITY: callers must only invoke this AFTER a fresh successful
    authentication for the corresponding session type - it mints trust, it does
    not verify it.
    """
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    await redis.set(_storage_key(key_prefix, token), json.dumps(payload), ex=ttl_s)
    return token


async def delete_session(redis: aioredis.Redis, *, key_prefix: str, token: str) -> None:
    """Revoke a session immediately (logout) by deleting its Redis record.

    Idempotent: deleting an already-missing/expired/unknown token is a no-op,
    not an error - a logout call should never fail just because the session
    it's trying to end is already gone.
    """
    await redis.delete(_storage_key(key_prefix, token))


async def resolve_session(redis: aioredis.Redis, *, key_prefix: str, token: str) -> Any | None:
    """Return the payload the token resolves to, or None if the token is
    missing/expired/unrecognized/corrupt.

    SECURITY: fail-closed. A record that fails to JSON-decode is treated exactly
    like a missing one - never partially trusted.
    """
    raw = await redis.get(_storage_key(key_prefix, token))
    if raw is None:
        return None
    try:
        return json.loads(raw.decode() if isinstance(raw, bytes) else raw)
    except (ValueError, TypeError):
        return None
