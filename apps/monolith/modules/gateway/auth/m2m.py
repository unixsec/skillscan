"""M2M authentication: OAuth2 client-credentials or mTLS (coding spec §11.2,
FR-API-080, FR-OIDC-020).

SECURITY: M2M callers get a fixed, minimal role/scope set - there is no
"trusted service" bypass of the usual per-request object-level authorization.
Client-credentials tokens go through the exact same introspection path as
interactive tokens (no separate home-grown validation).
"""

from __future__ import annotations

import time

import httpx
from common.config import SessionSettings
from common.log import get_logger
from common.mtls import parse_spiffe_identity, service_account_from_spiffe
from skillscan_core import TrustTier

from .session import IntrospectionCache, SessionContext, introspect_token

logger = get_logger(__name__)

M2M_ROLES: frozenset[str] = frozenset({"submitter"})
M2M_SCOPES: frozenset[str] = frozenset({"scan:submit"})


class M2MError(Exception):
    """SECURITY: callers must treat this as fail-closed (401/403)."""


async def authenticate_client_credentials(
    token: str | None,
    *,
    settings: SessionSettings,
    http_client: httpx.AsyncClient,
    cache: IntrospectionCache,
    allowed_service_accounts: frozenset[str],
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

    return SessionContext(
        subject=subject,
        roles=M2M_ROLES,
        scopes=M2M_SCOPES,
        tier=TrustTier.INTERNAL,
        token_exp=float(exp),
    )


def authenticate_mtls(
    forwarded_client_cert_header: str | None, *, allowed_service_accounts: frozenset[str]
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

    return SessionContext(
        subject=service_account,
        roles=M2M_ROLES,
        scopes=M2M_SCOPES,
        tier=TrustTier.INTERNAL,
        # mTLS identity has no opaque-token expiry of its own - it's bounded by
        # mesh certificate rotation instead, so there's no finite exp to report.
        token_exp=float("inf"),
    )
