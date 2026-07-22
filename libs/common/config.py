"""Environment-driven settings (coding spec §13).

SECURITY: zero hardcoded external endpoints - every URL is injected via env and
validated at construction time to resolve to an internal/private address only
(INV-14). Fail-closed: any DNS failure or public address rejects construction.

2026-07-09 history note: a scoped external-host-allowlist exception
(`resolve_llm_endpoint`) briefly lived here to support pointing the LLM
backend at DeepSeek's public cloud API. Reverted the same day once the
actual requirement turned out to be an enterprise-internal privatized model
deployment - i.e. exactly what `require_internal_endpoint` below already
supports without any exception, once that deployment's hostname genuinely
resolves to an internal/private address. No external-endpoint bypass exists
in this file as of this revert.

2026-07-10 history note: `require_internal_endpoint` validated a hostname
once at settings-construction time but the actual HTTP client resolved it
again, independently, at every real connection - a DNS-rebinding TOCTOU gap
(full-project review Finding #16). Fixed by pinning the validated resolution
via `common.pinned_dns` immediately after validation succeeds; see that
module's docstring for the full mechanism and its scope (in-process Python
network calls only, not subprocess-spawned tools).
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from common.pinned_dns import pin_internal_host


def is_internal_host(hostname: str) -> bool:
    """SECURITY: every resolved address for `hostname` must be private/loopback/
    link-local. Fail-closed: resolution failure or any public address -> False."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError:
        return False
    if not infos:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            return False
    return True


def require_internal_endpoint(url: str, *, field_name: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"{field_name}: unsupported scheme {parsed.scheme!r} in {url!r}")
    if not parsed.hostname:
        raise ValueError(f"{field_name}: no hostname in {url!r}")
    if not is_internal_host(parsed.hostname):
        raise ValueError(
            f"{field_name}: {parsed.hostname!r} does not resolve to an internal/private "
            "address - external endpoints are forbidden (INV-14)"
        )
    # SECURITY (Finding #16): pin this hostname's just-validated resolution so
    # a later, independent DNS lookup by the actual HTTP client can't be
    # rebound to a different, attacker-controlled address before it connects.
    # See pinned_dns.py's docstring for the full mechanism.
    pin_internal_host(parsed.hostname)
    return url


class OidcSettings(BaseSettings):
    """SECURITY:禁自研 token 校验 - authlib owns all signature/claims validation;
    this class only carries configuration, never validation logic."""

    model_config = SettingsConfigDict(env_prefix="SKILLSCAN_OIDC_")

    issuer: str
    client_id: str
    client_secret: str
    redirect_uri_allowlist: tuple[str, ...]
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    scopes: tuple[str, ...] = ("openid", "profile", "email")

    @model_validator(mode="after")
    def _validate_internal_endpoints(self) -> OidcSettings:
        require_internal_endpoint(self.issuer, field_name="oidc.issuer")
        require_internal_endpoint(
            self.authorization_endpoint, field_name="oidc.authorization_endpoint"
        )
        require_internal_endpoint(self.token_endpoint, field_name="oidc.token_endpoint")
        require_internal_endpoint(self.jwks_uri, field_name="oidc.jwks_uri")
        return self


class SamlSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SKILLSCAN_SAML_")

    sp_entity_id: str
    sp_acs_url: str
    idp_entity_id: str
    idp_sso_url: str
    idp_slo_url: str | None = None
    idp_x509_cert: str
    want_assertions_encrypted: bool = False

    @model_validator(mode="after")
    def _validate_internal_endpoints(self) -> SamlSettings:
        require_internal_endpoint(self.idp_sso_url, field_name="saml.idp_sso_url")
        if self.idp_slo_url:
            require_internal_endpoint(self.idp_slo_url, field_name="saml.idp_slo_url")
        return self


class SessionSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SKILLSCAN_SESSION_")

    introspection_endpoint: str
    introspection_client_id: str
    introspection_client_secret: str
    # SECURITY: bounds from coding spec §9/§13 - do not raise without a documented reason.
    introspection_cache_ttl_s: int = 30
    access_token_ttl_s: int = 600

    @model_validator(mode="after")
    def _validate(self) -> SessionSettings:
        require_internal_endpoint(
            self.introspection_endpoint, field_name="session.introspection_endpoint"
        )
        if self.introspection_cache_ttl_s > 30:
            raise ValueError("session.introspection_cache_ttl_s must be <= 30 (SAD FR-SES-040)")
        if self.access_token_ttl_s > 600:
            raise ValueError("session.access_token_ttl_s must be <= 600 (SAD FR-SES-030)")
        return self


class VaultSettings(BaseSettings):
    """coding spec §11.6: gate signs verdicts via Vault Transit - the private
    key never leaves Vault. `token` is whatever short-lived credential Vault
    Agent/the platform injects (e.g. a file-mounted token) - this class only
    carries it through, never generates or validates it itself."""

    model_config = SettingsConfigDict(env_prefix="SKILLSCAN_VAULT_")

    addr: str
    token: str
    transit_mount_point: str = "transit"
    transit_key_name: str
    # SECURITY: short TTL on issued verdict JWS, bound per coding spec §6 SignerPort/INV-13.
    signer_ttl_s: int = 300

    @model_validator(mode="after")
    def _validate_internal_endpoint(self) -> VaultSettings:
        require_internal_endpoint(self.addr, field_name="vault.addr")
        return self


class MarketplaceSettings(BaseSettings):
    """coding spec §11.6/SAD §4.3: reconciliation poll uses an INDEPENDENT,
    read-only marketplace credential, deliberately separate from the
    credential used to write verdicts/quarantine - so a compromised or buggy
    write path can never also suppress or forge what poll observes. Never
    read `poll_token` and `write_token` from the same env var."""

    model_config = SettingsConfigDict(env_prefix="SKILLSCAN_MARKETPLACE_")

    api_base_url: str
    poll_token: str
    write_token: str

    @model_validator(mode="after")
    def _validate(self) -> MarketplaceSettings:
        require_internal_endpoint(self.api_base_url, field_name="marketplace.api_base_url")
        # SECURITY: catches the most likely misconfiguration mistake (copy-pasting
        # one credential into both env vars) - independence is the whole point.
        if self.poll_token == self.write_token:
            raise ValueError(
                "marketplace.poll_token must differ from marketplace.write_token "
                "(SAD §4.3: poll uses an independent, read-only credential)"
            )
        return self


class ReconciliationSettings(BaseSettings):
    """coding spec §11.6/SAD §4.3: poll and push are two INDEPENDENT bools, not
    a single mode - poll alone gives full ORPHAN-detection coverage; push
    alone structurally cannot (it only sees events the marketplace chooses to
    send). `push_hmac_secret` implements the "signed event" half of "mTLS or
    signed event" strong-auth options (SAD §4.3/TB14) - mTLS is a
    network/ingress-layer control (same boundary as M7's NetworkPolicy work),
    not something this Python layer can enforce alone."""

    model_config = SettingsConfigDict(env_prefix="SKILLSCAN_RECONCILIATION_")

    poll_enabled: bool = False  # SECURITY: off -> startup alert, never silent (coding spec §13)
    push_enabled: bool = False
    push_hmac_secret: str | None = None
    # SECURITY (TB14 anti-replay): a push event whose timestamp is older than this
    # window is rejected outright, bounding the replay window for a captured event.
    push_replay_window_s: int = 300
    # SECURITY: push-sourced MISMATCH/ORPHAN auto-correction defaults OFF (SAD §4.3
    # correction-side asymmetry) - forgeable/replayable provenance must never be able
    # to trigger an automatic takedown; enabling this is a deliberate, separate opt-in.
    push_auto_quarantine_enabled: bool = False

    @model_validator(mode="after")
    def _validate(self) -> ReconciliationSettings:
        if self.push_enabled and not self.push_hmac_secret:
            raise ValueError(
                "reconciliation.push_hmac_secret is required when push_enabled=True "
                "(SAD §4.3/TB14: push must be strongly authenticated)"
            )
        return self
