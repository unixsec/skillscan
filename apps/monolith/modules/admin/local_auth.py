"""Local username/password admin authentication - additive alongside
break-glass (admin.breakglass) and OIDC/SAML, for enterprise deployments that
need a standing credential-based login path independent of both an IdP and
break-glass's emergency four-eyes flow.

SECURITY:
- Coding spec INV-17 ("无任何环节出现明文默认口令"): passwords are never
  stored or compared in plaintext, and there is no default/bootstrap account -
  every account's password hash comes from SKILLSCAN_LOCAL_ACCOUNTS_JSON,
  populated by the deployer, same "env-sourced, never hardcoded" posture as
  every other credential in this codebase.
- Hashed with scrypt (stdlib `hashlib.scrypt`, N=2**14/r=8/p=1 - OWASP's
  minimum recommended scrypt parameters as of this writing) with a random
  16-byte salt per account, compared in constant time.
- Failed attempts are rate-limited per-username via Redis (5 failures / 15min
  lockout) - checked BEFORE the deliberately-slow scrypt hash is computed,
  both to fail fast and so the lockout check itself isn't a timing oracle.
- An unknown username still costs one scrypt verification against a fixed
  dummy hash, so response timing can't distinguish "no such account" from
  "wrong password" - same one-generic-failure-reason posture
  breakglass.authenticate_breakglass documents for the same reason.
- Sessions are Redis-backed opaque tokens on their own cookie name
  (LOCAL_SESSION_COOKIE_NAME, gateway.auth.middleware), following the exact
  pattern admin.breakglass/gateway.auth.saml already established - see
  gateway.auth.dependencies._resolve_local_session_context. Multi-role
  (mirrors saml.create_saml_session), unlike break-glass which is hardcoded
  to "admin" - local accounts are meant to cover all four roles for
  environments with no IdP.
- Disabled by default (SKILLSCAN_LOCAL_AUTH_ENABLED=false) - same posture as
  break-glass (INV-17).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

import redis.asyncio as aioredis
from common.log import get_logger
from common.password import DUMMY_HASH

# Explicit re-export (`X as X`): mypy's strict mode treats a plain
# `from ... import X` as private, and these two are part of THIS module's public
# surface - admin routes, tests and operator runbooks all import
# `hash_password` from here. Moving where they are defined must not move where
# they are imported from.
from common.password import hash_password as hash_password
from common.password import verify_password as verify_password
from common.redis_window_counter import incr_in_window, read_in_window
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from monolith.modules.gateway.auth import redis_session
from monolith.modules.gateway.auth.middleware import session_ttl_from_env

from .models import LocalAccountRow

logger = get_logger(__name__)


class LocalAuthError(Exception):
    """Any local-auth configuration failure. Fail-closed: callers must treat
    this as startup-fatal, never silently falling back to no accounts."""


@dataclass(frozen=True, slots=True)
class LocalAccount:
    username: str
    password_hash: str  # format: "scrypt$<salt_hex>$<digest_hex>"
    role: str


# 2026-07-31: the scrypt primitives moved to `common.password` so the M2M
# username/password path can share them (see that module for why they cannot
# simply be imported from here). Re-exported rather than relocated-and-renamed:
# `hash_password` is what operators are told to run to mint a password hash, and
# it is imported from this module by admin routes, tests and prior runbooks.
_DUMMY_HASH = DUMMY_HASH


class LocalAccountStore(Protocol):
    async def fetch_accounts(self) -> tuple[LocalAccount, ...]: ...


class StaticLocalAccountStore:
    """Accounts loaded once at startup from SKILLSCAN_LOCAL_ACCOUNTS_JSON.

    2026-07-14 (item #13): now used ONLY as the first-boot bootstrap seed
    (main.py's `_seed_admin_tables_if_empty` writes these into `local_account`
    the first time the table is empty) - the live authentication path uses
    `DbLocalAccountStore` below, so an admin can add/disable/reset accounts at
    runtime without a redeploy. Kept as a distinct class (rather than folded
    into the seeding function) because it's still exactly what an empty/fresh
    deployment needs before any admin account exists to log in and create one.
    """

    def __init__(self, accounts: tuple[LocalAccount, ...]) -> None:
        self._accounts = accounts

    async def fetch_accounts(self) -> tuple[LocalAccount, ...]:
        return self._accounts


class DbLocalAccountStore:
    """Accounts read live from `local_account` (status='active' only) - the
    runtime counterpart to StaticLocalAccountStore. A disabled account simply
    stops being returned here (authenticate_local then reports the same
    generic "no such account" failure it would for an unknown username -
    disabling never gets a distinguishable error message)."""

    def __init__(self, session_factory: Callable[[], AsyncSession]) -> None:
        self._session_factory = session_factory

    async def fetch_accounts(self) -> tuple[LocalAccount, ...]:
        async with self._session_factory() as session:
            result = await session.execute(
                select(LocalAccountRow).where(LocalAccountRow.status == "active")
            )
            rows = result.scalars().all()
        return tuple(
            LocalAccount(username=r.username, password_hash=r.password_hash, role=r.role)
            for r in rows
        )


def load_local_accounts_from_json(
    raw_json: str, *, known_roles: frozenset[str]
) -> tuple[LocalAccount, ...]:
    """SECURITY: fail-closed parsing, same posture as
    rbac.load_group_role_map - a malformed config or a role outside
    `known_roles` must crash startup, never silently resolve to an empty or
    partially-wrong account list."""
    try:
        raw = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise LocalAuthError(f"SKILLSCAN_LOCAL_ACCOUNTS_JSON is not valid JSON: {exc}") from exc
    if not isinstance(raw, list):
        raise LocalAuthError("SKILLSCAN_LOCAL_ACCOUNTS_JSON must be a JSON array")
    accounts: list[LocalAccount] = []
    seen_usernames: set[str] = set()
    for entry in raw:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("username"), str)
            or not isinstance(entry.get("password_hash"), str)
            or not isinstance(entry.get("role"), str)
        ):
            raise LocalAuthError(
                "each SKILLSCAN_LOCAL_ACCOUNTS_JSON entry must have string "
                "'username', 'password_hash', and 'role' fields"
            )
        if entry["role"] not in known_roles:
            raise LocalAuthError(
                f"local account {entry['username']!r} has unknown role {entry['role']!r} "
                f"(must be one of {sorted(known_roles)})"
            )
        if entry["username"] in seen_usernames:
            raise LocalAuthError(f"duplicate local account username {entry['username']!r}")
        seen_usernames.add(entry["username"])
        accounts.append(
            LocalAccount(
                username=entry["username"], password_hash=entry["password_hash"], role=entry["role"]
            )
        )
    return tuple(accounts)


_FAIL_KEY_PREFIX = "skillscan:admin:local:failcount:"
_LOCKOUT_THRESHOLD = 5
_LOCKOUT_WINDOW_S = 900  # 15 min


async def _is_locked_out(redis: aioredis.Redis, username: str) -> bool:
    # Reads through the shared primitive rather than a plain GET because THIS is
    # the path that has to repair a stranded counter: it returns before
    # `_record_failure` ever runs, so if the read does not re-arm a missing
    # expiry, nothing on the authentication path does and the lockout becomes
    # permanent (correct password included). See common.redis_window_counter.
    count, _ttl = await read_in_window(
        redis, f"{_FAIL_KEY_PREFIX}{username}", window_s=_LOCKOUT_WINDOW_S
    )
    return count >= _LOCKOUT_THRESHOLD


async def _record_failure(redis: aioredis.Redis, username: str) -> None:
    # 2026-07-31: was `INCR` then a conditional `EXPIRE` - two round-trips, so a
    # drop between them stranded the counter with no expiry and locked the
    # account out forever.
    await incr_in_window(redis, f"{_FAIL_KEY_PREFIX}{username}", window_s=_LOCKOUT_WINDOW_S)


async def _clear_failures(redis: aioredis.Redis, username: str) -> None:
    await redis.delete(f"{_FAIL_KEY_PREFIX}{username}")


async def authenticate_local(
    redis: aioredis.Redis,
    store: LocalAccountStore,
    *,
    username: str,
    password: str,
) -> LocalAccount | None:
    """Returns the matched account on success, else None uniformly for
    "unknown username", "locked out", and "wrong password" - never
    distinguished, same one-generic-failure-reason posture
    breakglass.authenticate_breakglass uses (an attacker must not be able to
    enumerate valid usernames from the response)."""
    if await _is_locked_out(redis, username):
        return None
    accounts = await store.fetch_accounts()
    match = next((a for a in accounts if a.username == username), None)
    if match is None:
        verify_password(password, _DUMMY_HASH)
        await _record_failure(redis, username)
        return None
    if not verify_password(password, match.password_hash):
        await _record_failure(redis, username)
        return None
    await _clear_failures(redis, username)
    return match


_SESSION_KEY_PREFIX = "skillscan:admin:local:session:"
# SECURITY: a normal human workday session (8h), unlike break-glass's
# deliberately punishing 15min emergency window - this is meant to be the
# standing day-to-day admin login path, not a limited emergency escape hatch.
# SECURITY: validated against the shared CSRF cookie's lifetime AT IMPORT (see
# `session_ttl_from_env`) - a misconfiguration is refused loudly here rather
# than shipping as "reads work, every write 403s after a while". The plain
# `int(os.environ.get(...))` this replaces could not be caught by any test,
# because the test that was supposed to enforce the ceiling read this very
# attribute.
LOCAL_SESSION_TTL_S = session_ttl_from_env("SKILLSCAN_LOCAL_SESSION_TTL_S", 28800)


async def create_local_session(redis: aioredis.Redis, *, subject: str, role: str) -> str:
    """SECURITY: called ONLY after `authenticate_local` has already returned a
    matched account - never call this independently of a fresh, successful
    authentication.

    Backed by the shared redis_session store (sha256(token) key - see that
    module's docstring)."""
    return await redis_session.create_session(
        redis,
        key_prefix=_SESSION_KEY_PREFIX,
        ttl_s=LOCAL_SESSION_TTL_S,
        payload={"subject": subject, "role": role},
    )


async def resolve_local_session(redis: aioredis.Redis, token: str) -> tuple[str, str] | None:
    """Returns (subject, role) the token resolves to, or None if
    missing/expired/unrecognized/corrupt (fail-closed - never guesses)."""
    payload = await redis_session.resolve_session(
        redis, key_prefix=_SESSION_KEY_PREFIX, token=token
    )
    if not isinstance(payload, dict) or "subject" not in payload or "role" not in payload:
        return None
    return payload["subject"], payload["role"]


async def revoke_local_session(redis: aioredis.Redis, token: str) -> None:
    """Logout: end this local-account session immediately rather than letting
    it ride out its TTL."""
    await redis_session.delete_session(redis, key_prefix=_SESSION_KEY_PREFIX, token=token)
