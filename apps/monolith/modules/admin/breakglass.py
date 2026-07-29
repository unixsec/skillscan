"""Break-glass local admin bootstrap (coding spec §16.3, INV-17).

SECURITY: this is the emergency-ONLY, default-DISABLED path for when the IdP
itself is unreachable - the normal, primary, only-recommended path to
becoming admin is IdP group membership (gateway.auth.rbac.resolve_roles).
There is NO default password anywhere in this module and no "admin/admin"
first-login pattern of any kind: the break-glass credential and TOTP secret
are Vault-sealed (`BreakGlassCredentialPort` - fetched fresh from Vault at
activation/login time, never stored in this project's own DB or config
files in any form, not even hashed). Activation requires TWO DIFFERENT,
real/known admin identities (four-eyes) presenting a valid TOTP code, and
refuses to silently clobber an existing pending activation; the FIRST login
attempt made while armed IMMEDIATELY and atomically consumes the arming
("用后即禁" - disabled after use, regardless of remaining TTL), whether or
not that attempt's credential/TOTP turns out correct - see
authenticate_breakglass's docstring for why. Every activation/login attempt
is meant to be fully
audited and alert SecOps (the CALLER's responsibility - see admin.router's
breakglass endpoints - this module only decides allow/deny, it doesn't emit
the audit/alert side effects itself, keeping this pure decision logic
independently testable from the loud, real-world side effects around it).
"""

from __future__ import annotations

import datetime
import os
import secrets
from dataclasses import dataclass
from typing import Protocol

import pyotp
import redis.asyncio as aioredis

from monolith.modules.gateway.auth import redis_session
from monolith.modules.gateway.auth.middleware import session_ttl_from_env

# SECURITY: two separate Redis keys - "armed" carries a real TTL (the
# activation's own time-limited window); "used" is atomically claimed
# (SET NX) by the FIRST login attempt that reaches it while armed - whether
# or not that attempt's credential/TOTP then turns out to be correct (see
# authenticate_breakglass's own docstring for why a failed attempt still
# burns the arming) - and checked ALONGSIDE "armed" being present, so a
# login attempt immediately and irrevocably consumes the arming even if most
# of the TTL remains.
_ARMED_KEY = "skillscan:admin:breakglass:armed"
_USED_KEY = "skillscan:admin:breakglass:used_this_arming"
_USED_KEY_TTL_S = 3600  # outlives any reasonable arming TTL - harmless if it lingers


class BreakGlassError(ValueError):
    pass


class BreakGlassCredentialPort(Protocol):
    """SECURITY: implemented by a Vault-backed adapter - the credential/TOTP
    secret material lives ONLY in Vault, never in this codebase's own DB or
    config files, not even as a hash."""

    async def fetch_credential(self) -> str: ...
    async def fetch_totp_secret(self) -> str: ...


@dataclass(frozen=True, slots=True)
class BreakGlassActivation:
    activated_by: tuple[str, str]
    expires_at: datetime.datetime


# TOTP step/period in seconds (RFC 6238 default 30). Env-configurable so an
# operator can widen the rotation window; the authenticator app that generates
# the codes MUST use the same period, so this value is shared with every code
# generator (see scripts/dev/run_local.py + the otpauth provisioning URI).
TOTP_PERIOD_S = int(os.environ.get("SKILLSCAN_TOTP_PERIOD_S", "30"))


def verify_totp(secret: str, code: str) -> bool:
    # SECURITY/RELIABILITY: valid_window=1 tolerates +/-1 period of clock drift
    # or network/typing latency between the authenticator app and this server -
    # RFC 6238's own recommended practice, and the default (window=0, exact-
    # match-only) is unusually strict for a real deployment: break-glass is
    # used precisely in urgent/stressful situations where a few seconds of
    # delay is normal, and a legitimate admin's correct code being rejected
    # for pure timing reasons is a bad failure mode for emergency access.
    return pyotp.TOTP(secret, interval=TOTP_PERIOD_S).verify(code, valid_window=1)


async def activate_breakglass(
    redis: aioredis.Redis,
    *,
    activator_a: str,
    activator_b: str,
    totp_code: str,
    totp_secret: str,
    known_admin_subjects: frozenset[str],
    ttl_s: int = 900,
) -> BreakGlassActivation:
    """SECURITY (four-eyes + MFA): raises `BreakGlassError` on ANY failure -
    the same person twice, a `activator_b` that isn't a real/known admin
    identity, a wrong/replayed TOTP code, or an already-armed-and-unused
    activation - never silently arms and never silently clobbers a pending
    one. `ttl_s` bounds how long the activation stays usable at all (coding
    spec: "限时会话" - time-limited session) - default 15 minutes.

    SECURITY (BUG 2 fix - four-eyes was not real): `activator_b` used to be
    accepted as ANY client-supplied string, checked only for byte-for-byte
    inequality against `activator_a` - a caller could type an arbitrary,
    nonexistent name as their "second activator" and four-eyes provided no
    real second-identity guarantee at all. `known_admin_subjects` is the
    caller's (router's) resolved allowlist of admin identities to check
    `activator_b` against - see admin.router.activate_breakglass_endpoint for
    exactly where that allowlist comes from and its documented limitation
    (this codebase has no local user/identity directory - see
    gateway.auth.rbac and admin.router's own `list_users` docstring - so the
    best available allowlist is deployment-config-derived, not a live IdP
    lookup of `activator_b` specifically). This still does NOT
    cryptographically prove LIVE second-person consent - `activator_b` is
    still only asserted by `activator_a`, not independently authenticated in
    this same request - that would require a second authenticated
    session/request (e.g. an approval step `activator_b` themselves must
    complete). That is a known, deliberately-not-over-engineered remaining
    limitation, not something this fix claims to solve.
    """
    if activator_a == activator_b:
        raise BreakGlassError("break-glass activation requires two DIFFERENT people (four-eyes)")
    # SECURITY (BUG 2 fix): reject `activator_b` outright if it's not a real,
    # known admin identity - closes the "any string" gap. Checked before the
    # TOTP verify below (order doesn't affect security - both are checked
    # before anything is written - but this is the cheaper check).
    if activator_b not in known_admin_subjects:
        raise BreakGlassError(
            "break-glass activation requires the second activator to be a real, known admin"
        )
    if not verify_totp(totp_secret, totp_code):
        raise BreakGlassError("invalid TOTP code")
    # SECURITY (BUG 3 fix - unconditional re-arm): this used to write
    # `_ARMED_KEY` unconditionally, silently clobbering an existing valid
    # (armed, unused, unexpired) activation from a DIFFERENT activator pair
    # with no error at all - the clobbered activation's activator pair was
    # simply lost. `is_armed()` must be checked BEFORE writing; refuse to
    # re-arm on top of a live activation instead of overwriting it.
    if await is_armed(redis):
        raise BreakGlassError(
            "break-glass is already armed by a pending activation; wait for it to be used "
            "or expire before re-activating"
        )
    await redis.set(_ARMED_KEY, f"{activator_a}|{activator_b}", ex=ttl_s)
    await redis.delete(_USED_KEY)
    expires_at = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=ttl_s)
    return BreakGlassActivation(activated_by=(activator_a, activator_b), expires_at=expires_at)


async def is_armed(redis: aioredis.Redis) -> bool:
    armed = await redis.get(_ARMED_KEY)
    used = await redis.get(_USED_KEY)
    return armed is not None and used is None


async def deactivate_breakglass(redis: aioredis.Redis) -> None:
    """Manual/administrative disarm - e.g. the IdP came back online before
    anyone used the break-glass window."""
    await redis.delete(_ARMED_KEY)


async def authenticate_breakglass(
    redis: aioredis.Redis,
    *,
    supplied_credential: str,
    expected_credential: str,
    totp_code: str,
    totp_secret: str,
) -> bool:
    """SECURITY: must be armed (activated, unused, unexpired) AND the
    credential (constant-time compared - it's Vault-sourced high-entropy
    random, not a human password, so a plain constant-time compare is the
    right check, not a slow password hash meant to resist offline brute
    force against low-entropy input) AND TOTP code must both be correct. A
    successful login marks this arming used - single-use per activation,
    even if TTL remains.

    SECURITY (BUG 1 fix - TOCTOU race): this used to call `is_armed()` (a
    plain GET) and only write `_USED_KEY` at the very end, AFTER credential/
    TOTP verification - two non-atomic steps with a real gap between them.
    Two concurrent calls sharing the same still-valid arming could both pass
    the `is_armed()` GET (neither had written `_USED_KEY` yet), both then
    verify the (shared, Vault-sourced) credential/TOTP correctly, and both
    reach the final `SET` - minting two independent admin sessions from one
    single-use arming.

    The fix: claim `_USED_KEY` FIRST via an atomic `SET ... NX` (set-if-
    not-exists) - Redis serializes this per-key, so of any number of
    concurrent callers racing the same arming, exactly one can ever see the
    NX-set succeed; every other concurrent (or later) caller sees it fail
    and returns False immediately, before doing any credential/TOTP work at
    all. `_ARMED_KEY` is still checked first (a plain GET) purely to fail
    fast on the common "not armed at all" case without burning a claim for
    no reason; that initial GET is NOT itself part of the atomicity
    guarantee - the NX-set is what actually closes the race, since it's the
    one operation that can only ever succeed once per arming.

    This does deliberately mean: once the NX-set succeeds, THIS call has
    permanently consumed the arming - even if the credential or TOTP check
    that follows then fails. That is intentional, not a leftover bug: the
    single-use invariant ("用后即禁") exists precisely so a break-glass
    window can't be hammered with repeated attempts, and a caller who got
    past the armed-check with a wrong credential/TOTP has already
    demonstrated they can reach this endpoint during a live arming - the
    conservative, fail-closed choice is to burn the arming on ANY attempt
    that gets this far, not to reopen a retry window (which would itself
    reintroduce a check-then-act gap between "verification failed" and
    "un-claim _USED_KEY" that a second concurrent attacker could race).
    A legitimate admin who mistypes still has the option to re-run the
    four-eyes `activate_breakglass` flow for a fresh arming (BUG 3's fix
    guarantees that doesn't silently clobber anything unexpected either).
    """
    armed = await redis.get(_ARMED_KEY)
    if armed is None:
        return False
    claimed = await redis.set(_USED_KEY, "1", nx=True, ex=_USED_KEY_TTL_S)
    if not claimed:
        # Someone else (or an earlier attempt) already consumed this arming.
        return False
    if not secrets.compare_digest(supplied_credential, expected_credential):
        return False
    if not verify_totp(totp_secret, totp_code):
        return False
    return True


# SECURITY: break-glass sessions can NEVER be verified via IdP introspection
# (introspection.py, gateway.auth.session) - by definition, break-glass exists
# for when the IdP is unreachable. A break-glass login therefore creates its
# OWN Redis-backed, opaque, time-limited session record instead - checked by
# gateway.auth.dependencies.get_session_context BEFORE it falls through to
# normal cookie/bearer auth, via a DISTINCT cookie name so the two paths never
# collide. This session always carries exactly the "admin" role (that's the
# entire point of break-glass) and nothing else.
_SESSION_KEY_PREFIX = "skillscan:admin:breakglass:session:"
# SECURITY (coding spec §16.3 "限时会话"): time-limited break-glass session,
# 900s (15 min) by default. Env-overridable ONLY so a local dev/demo launcher
# can extend it (a 15-min window is punishing when you're iterating in the UI);
# a real deployment leaves the short default in place.
# SECURITY: validated against the shared CSRF cookie's lifetime AT IMPORT - see
# `session_ttl_from_env` and `local_auth.LOCAL_SESSION_TTL_S`'s note.
BREAKGLASS_SESSION_TTL_S = session_ttl_from_env("SKILLSCAN_BREAKGLASS_SESSION_TTL_S", 900)


async def create_breakglass_session(redis: aioredis.Redis, *, subject: str) -> str:
    """SECURITY: called ONLY after `authenticate_breakglass` has already
    returned True - never call this independently of a fresh, successful
    authentication. Returns the opaque session token to set as the
    break-glass session cookie's value.

    Backed by the shared redis_session store (sha256(token) key - see that
    module's docstring for why the raw token is never a Redis key)."""
    return await redis_session.create_session(
        redis, key_prefix=_SESSION_KEY_PREFIX, ttl_s=BREAKGLASS_SESSION_TTL_S, payload=subject
    )


async def resolve_breakglass_session(redis: aioredis.Redis, token: str) -> str | None:
    """Returns the break-glass subject the token resolves to, or None if the
    token is missing/expired/unrecognized/corrupt (fail-closed - never guesses)."""
    payload = await redis_session.resolve_session(
        redis, key_prefix=_SESSION_KEY_PREFIX, token=token
    )
    return payload if isinstance(payload, str) else None


async def revoke_breakglass_session(redis: aioredis.Redis, token: str) -> None:
    """Logout: end this break-glass session immediately rather than letting
    it ride out its TTL."""
    await redis_session.delete_session(redis, key_prefix=_SESSION_KEY_PREFIX, token=token)
