"""M2M authentication: OAuth2 client-credentials or mTLS (coding spec §11.2,
FR-API-080, FR-OIDC-020).

SECURITY: M2M callers get a minimal, per-service-account scope/tier grant (see
M2MGrant/resolve_grant below - never a single global grant shared by every
identity) - there is no "trusted service" bypass of the usual per-request
object-level authorization. Client-credentials tokens go through the exact
same introspection path as interactive tokens (no separate home-grown
validation).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx
from common.config import SessionSettings
from common.log import get_logger
from common.mtls import parse_spiffe_identity, service_account_from_spiffe
from skillscan_core import TrustTier

from .session import IntrospectionCache, SessionContext, introspect_token

logger = get_logger(__name__)


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
