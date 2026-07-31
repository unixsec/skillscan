"""M2M authentication: OAuth2 client-credentials, mTLS, or username/password
(coding spec §11.2, FR-API-080, FR-OIDC-020).

SECURITY: M2M callers get a minimal, per-service-account scope/tier grant (see
M2MGrant/resolve_grant below - never a single global grant shared by every
identity) - there is no "trusted service" bypass of the usual per-request
object-level authorization. Client-credentials tokens go through the exact
same introspection path as interactive tokens (no separate home-grown
validation).

2026-07-31 - THE USERNAME/PASSWORD PATH IS DELIBERATELY THE WEAKEST OF THE
THREE, and is here because a deployment with no IdP to introspect against
otherwise cannot let a marketplace call `/v1/market` at all. What it gives up,
stated plainly so nobody has to rediscover it:

  * a STANDING credential - no expiry, no revocation short of editing config
    and restarting, where an introspected token dies on its own and can be
    revoked centrally;
  * it is verified by US, so it is exactly the "separate home-grown validation"
    the paragraph above says client-credentials avoids.

What it does NOT give up, and each is enforced below rather than promised:
`is_machine=True` (so the console surface still refuses it), the same
`allowed_service_accounts` allowlist, the same per-account `M2MGrant` for
scopes/tier, scrypt-hashed passwords (never plaintext, INV-17), equal-cost
verification for unknown accounts, and a brute-force lockout. Prefer
client-credentials wherever an IdP exists.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass

import httpx
import redis.asyncio as aioredis
from common.config import SessionSettings
from common.log import get_logger
from common.mtls import parse_spiffe_identity, service_account_from_spiffe
from common.password import DUMMY_HASH, verify_password
from common.redis_window_counter import incr_in_window, read_in_window
from skillscan_core import TrustTier

from .session import IntrospectionCache, SessionContext, introspect_token

logger = get_logger(__name__)

# Brute-force bound for the password path. Same shape and same numbers as
# `admin.local_auth`'s human-login lockout - one fewer thing to reason about,
# and both now sit on the atomic counter in `common.redis_window_counter`.
_BASIC_FAIL_KEY_PREFIX = "skillscan:m2m:basic:failcount:"
_BASIC_LOCKOUT_THRESHOLD = 5
_BASIC_LOCKOUT_WINDOW_S = 900  # 15 min


@dataclass(frozen=True)
class M2MGrant:
    """What one machine identity is allowed to do.

    SECURITY (2026-07-28, 里程碑 B'): scopes used to be a module-level
    frozenset shared by EVERY M2M caller, so granting one identity a new scope
    granted it to all of them. `tier` used to be hardcoded to
    TrustTier.INTERNAL - the most PERMISSIVE tier (BLOCK at CRITICAL; PUBLIC
    blocks at HIGH) - which meant a caller submitting third-party content was
    judged by the internal-content threshold.
    """

    scopes: frozenset[str]
    tier: TrustTier


M2M_ROLES: frozenset[str] = frozenset({"submitter"})

# SECURITY: the default must never grant more than the pre-2026-07-28 behaviour
# did for scopes, and must be the STRICTEST tier rather than the old INTERNAL.
DEFAULT_M2M_GRANT: M2MGrant = M2MGrant(scopes=frozenset({"scan:submit"}), tier=TrustTier.PUBLIC)


def resolve_grant(service_account: str, grants: dict[str, M2MGrant]) -> M2MGrant:
    return grants.get(service_account, DEFAULT_M2M_GRANT)


class M2MError(Exception):
    """SECURITY: callers must treat this as fail-closed (401/403)."""


async def authenticate_client_credentials(
    token: str | None,
    *,
    settings: SessionSettings,
    http_client: httpx.AsyncClient,
    cache: IntrospectionCache,
    allowed_service_accounts: frozenset[str],
    grants: dict[str, M2MGrant],
) -> SessionContext:
    if not token:
        raise M2MError("no client-credentials token provided")
    payload = await introspect_token(token, settings=settings, http_client=http_client, cache=cache)
    if not payload.get("active"):
        raise M2MError("client-credentials token is not active")

    subject = payload.get("sub") or payload.get("client_id")
    if not subject:
        raise M2MError("introspection response missing sub/client_id")
    # SECURITY: even a validly-introspected M2M token must name an allowlisted
    # service account - prevents any client the IdP happens to authenticate
    # from automatically gaining API access. Fail CLOSED: an empty/unset
    # allowlist means nothing is allowed, not "no restriction" - do not
    # short-circuit this check away when allowed_service_accounts is empty.
    if not allowed_service_accounts or subject not in allowed_service_accounts:
        logger.info("m2m subject not allowlisted", extra={"context": {"subject": subject}})
        raise M2MError(f"service account {subject!r} is not allowlisted")

    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        raise M2MError("introspection response missing numeric exp")
    # SECURITY (FR-SES parity): client-credentials tokens must be checked
    # against their own introspection exp the same way interactive session
    # tokens are (see session.py's authenticate()) - active:true alone is not
    # sufficient if the IdP also returned a lapsed exp.
    if time.time() >= exp:
        raise M2MError("client-credentials token expired per introspection exp")

    grant = resolve_grant(subject, grants)
    return SessionContext(
        subject=subject,
        roles=M2M_ROLES,
        scopes=grant.scopes,
        tier=grant.tier,
        token_exp=float(exp),
        # SECURITY (2026-07-28, milestone B' C1): this module is the ONLY place
        # that may set this - see SessionContext's own docstring for what the
        # console refuses on the strength of it.
        is_machine=True,
    )


def _parse_basic_header(header: str | None) -> tuple[str, str] | None:
    """`Authorization: Basic base64(user:pass)` -> (user, pass), else None.

    Every malformed shape collapses to None rather than raising: a caller that
    sends garbage must get the same generic refusal as one that sends a wrong
    password, not a distinguishable parse error.
    """
    if not header or not header.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(header[len("basic ") :].strip(), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    username, separator, password = decoded.partition(":")
    if not separator:
        return None
    return username, password


async def authenticate_basic_service_account(
    authorization_header: str | None,
    *,
    redis: aioredis.Redis,
    accounts: dict[str, str],
    allowed_service_accounts: frozenset[str],
    grants: dict[str, M2MGrant],
) -> SessionContext:
    """Username/password for a MACHINE caller. See this module's docstring for
    what this path deliberately gives up relative to the other two.

    `accounts` maps service account -> scrypt hash (`common.password`). An empty
    mapping means the path is unavailable, not unrestricted: nothing matches, so
    an unconfigured deployment is closed by construction rather than by a
    separate feature flag that could be set wrong.
    """
    credentials = _parse_basic_header(authorization_header)
    if credentials is None:
        raise M2MError("no valid Basic credentials presented")
    service_account, password = credentials

    # Checked BEFORE the deliberately-slow scrypt verification, so a locked-out
    # account costs nothing to refuse and the lockout check is not itself a
    # timing oracle - same ordering `admin.local_auth.authenticate_local` uses.
    fail_key = f"{_BASIC_FAIL_KEY_PREFIX}{service_account}"
    failures, _ttl = await read_in_window(redis, fail_key, window_s=_BASIC_LOCKOUT_WINDOW_S)
    if failures >= _BASIC_LOCKOUT_THRESHOLD:
        raise M2MError("too many failed attempts for this service account")

    stored_hash = accounts.get(service_account)
    if stored_hash is None:
        # SECURITY: an unknown account still pays for one scrypt verification,
        # so response timing cannot separate "no such service account" from
        # "wrong password" and be used to enumerate configured accounts.
        verify_password(password, DUMMY_HASH)
        await incr_in_window(redis, fail_key, window_s=_BASIC_LOCKOUT_WINDOW_S)
        raise M2MError("invalid service account credentials")
    if not verify_password(password, stored_hash):
        await incr_in_window(redis, fail_key, window_s=_BASIC_LOCKOUT_WINDOW_S)
        raise M2MError("invalid service account credentials")

    # SECURITY: the allowlist is a SECOND gate, checked after the password the
    # same way the client-credentials path checks it after introspection - so
    # removing an account from it revokes access even while its hash is still
    # configured. Fail CLOSED: an empty allowlist allows nothing.
    if not allowed_service_accounts or service_account not in allowed_service_accounts:
        logger.info(
            "m2m basic subject not allowlisted",
            extra={"context": {"subject": service_account}},
        )
        raise M2MError(f"service account {service_account!r} is not allowlisted")

    await redis.delete(fail_key)
    grant = resolve_grant(service_account, grants)
    return SessionContext(
        subject=service_account,
        roles=M2M_ROLES,
        scopes=grant.scopes,
        tier=grant.tier,
        # No token to expire: the credential is re-verified in full on every
        # request, so there is no finite exp to report - same as the mTLS path.
        token_exp=float("inf"),
        # SECURITY (milestone B' C1): a password-authenticated service account is
        # a machine, so the console surface must refuse it exactly as it refuses
        # the other two M2M paths.
        is_machine=True,
    )


def authenticate_mtls(
    forwarded_client_cert_header: str | None,
    *,
    allowed_service_accounts: frozenset[str],
    grants: dict[str, M2MGrant],
) -> SessionContext:
    """SECURITY: only trustworthy when the deployment topology guarantees this
    header can only be set by the mesh sidecar (SAD §3.4) - see common/mtls.py."""
    spiffe_id = parse_spiffe_identity(forwarded_client_cert_header)
    if spiffe_id is None:
        raise M2MError("no valid mTLS client identity presented")
    service_account = service_account_from_spiffe(spiffe_id)
    if not service_account:
        raise M2MError("could not extract a service account from the mTLS identity")
    # SECURITY: fail CLOSED - an empty/unset allowlist means nothing is
    # allowed, not "no restriction" (see authenticate_client_credentials above).
    if not allowed_service_accounts or service_account not in allowed_service_accounts:
        raise M2MError(f"service account {service_account!r} is not allowlisted")

    grant = resolve_grant(service_account, grants)
    return SessionContext(
        subject=service_account,
        roles=M2M_ROLES,
        scopes=grant.scopes,
        tier=grant.tier,
        # mTLS identity has no opaque-token expiry of its own - it's bounded by
        # mesh certificate rotation instead, so there's no finite exp to report.
        token_exp=float("inf"),
        # SECURITY (2026-07-28, milestone B' C1): same as the client-credentials
        # path above - a SPIFFE workload identity is a machine, full stop.
        is_machine=True,
    )
