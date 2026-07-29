"""Unified application settings (coding spec §13, spec gap fixed 2026-07-06).

SECURITY: every external-facing endpoint field is validated at construction
time via `common.config.require_internal_endpoint` (fail-closed: unset/empty
fields are skipped, since most of these are optional features that stay off
until configured, but any NON-EMPTY value must resolve internal-only) -
`main.py` previously read `SKILLSCAN_VAULT_ADDR` via a raw `os.environ.get(...)`
for the break-glass credential port, bypassing this validation entirely even
though the signer path already went through it via `VaultSettings`. That
inconsistency is exactly the kind of gap a single, central settings object is
meant to close - every caller now goes through the same validated `Settings`
instance instead of each re-implementing (or forgetting) its own env read.

This class is the single, spec-named home (`apps/monolith/config.py`, per
coding spec §3) for the handful of top-level settings §13 lists directly. The
more elaborate, per-concern settings (`OidcSettings`/`SamlSettings`/
`SessionSettings`/`VaultSettings`/`MarketplaceSettings`/`ReconciliationSettings`
in `libs/common/config.py`) stay separate, already-validated, already-tested
classes - `Settings` does not duplicate their fields or re-derive their own
cross-field validation (OIDC's redirect allowlist, marketplace's
poll-token-must-differ-from-write-token check, etc.); a caller that needs
those still constructs them directly. `Settings` covers the fields spec §13
lists that don't already belong to one of those - and, critically, is the
thing `main.py` should read `SKILLSCAN_VAULT_ADDR` through everywhere, not
just in the one place someone remembered to wrap it.
"""

from __future__ import annotations

import json
import os

from common.config import require_internal_endpoint
from common.log import get_logger
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from skillscan_core import TrustTier

from monolith.modules.gateway.auth.m2m import M2MGrant

_logger = get_logger("skillscan.monolith.config")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SKILLSCAN_")

    mysql_dsn_prefix: str = "mysql+aiomysql"
    redis_url: str = "redis://localhost:6379/0"
    minio_endpoint: str = ""
    blobstore_root: str = "var/blobstore"
    # SECURITY (INV-14): internal vLLM endpoint for the skillspector adapter's
    # LLM analysis - see services/engine_runner/adapters/skillspector.py's
    # make_adapter(openai_base_url=...). No live caller invokes that adapter
    # yet (same "real code, no live caller" gap as the scan-worker-loop and
    # intel-sync-network-sync items - out of scope for this fix), but the
    # validated field belongs here so a future caller has one place to read it
    # from instead of reaching for a raw env var the way the adapter's own
    # tests currently do.
    vllm_base_url: str = ""
    # SECURITY (INV-14): osv-scanner's adapter (services/engine_runner/
    # adapters/osv.py) hardcodes `--offline` as a deliberate, non-negotiable
    # security decision (see that file's own comment) - unlike skillspector's
    # OSV lookup, osv-scanner has no legitimate "point me at an internal
    # mirror" mode this adapter chooses to expose, so this field exists for
    # spec §13 schema completeness and is validated like every other endpoint
    # field, but the adapter intentionally does NOT consume it - loosening a
    # already-hardened `--offline`-only adapter to satisfy a config-schema
    # checkbox would be a real security regression, not a fix.
    osv_source: str = "offline"
    intel_mode: str = "offline_import"
    idp_issuer: str = ""
    vault_addr: str = ""
    # SECURITY (§16.2 reporting schedule destination): validated the same as
    # every other endpoint field. See modules/integration_relay/siem.py for
    # the actual SIEM emitter this feeds.
    siem_endpoint: str = ""
    # NOT a `marketplace_api` field here, deliberately: unlike `siem_endpoint`
    # (which has no dedicated settings class of its own), the marketplace
    # endpoint's home is `common.config.MarketplaceSettings` - one of the
    # "elaborate, per-concern settings classes" this class's own docstring
    # says never to duplicate. `main._build_marketplace()` reads
    # `SKILLSCAN_MARKETPLACE_API_BASE_URL` and constructs `MarketplaceSettings`
    # directly, which validates it via that class's own
    # `require_internal_endpoint` call - the same validation this field would
    # have applied, just at the read site instead of here. A `marketplace_api`
    # field briefly existed on this class anyway, bound to a DIFFERENT env var
    # (`SKILLSCAN_MARKETPLACE_API`, no trailing `_BASE_URL`) that nothing ever
    # read or set - dead weight next to the real, already-validated path,
    # removed rather than wired up, to avoid two spellings of one endpoint.
    introspection_cache_ttl_s: int = 30
    access_token_ttl_s: int = 600
    reconciliation_poll_enabled: bool = False
    reconciliation_push_enabled: bool = False
    # SECURITY: default-off per spec §13 - dynamic sandbox itself (SAD's
    # optional M7+ component) was never built in this codebase; this field
    # exists so setting it to true is at least loudly rejected at startup
    # (see main.py's own check) instead of silently doing nothing, which
    # would be a worse failure mode than not having the flag at all.
    dynamic_sandbox_enabled: bool = False
    max_findings: int = 5000
    # gateway.runtime.ScanRuntime.scan_deadline_s - raise together with
    # engine_runner's SKILLSCAN_LLM_ENGINE_TIMEOUT_S for a slower sandbox-LLM
    # backend (see services/engine_runner/adapters/aig.py's make_adapter()
    # docstring for why raising only one of the two does nothing).
    scan_deadline_s: float = 300.0
    # How long the gate waits for the sandbox engines before deciding without
    # them (D2, 2026-07-27). Deliberately equal to scan_deadline_s: the sandbox
    # subprocesses are bounded by that same budget, so waiting longer cannot
    # produce more results. sweep_sandbox_wait_timeouts adds its own small
    # grace on top so an engine's own TIMEOUT report wins the race.
    sandbox_wait_timeout_s: float = 300.0
    breakglass_enabled: bool = False
    # 2026-07-13 local-auth addition - same "disabled by default" posture as
    # breakglass_enabled (INV-17).
    local_auth_enabled: bool = False
    # Background worker loop (apps/monolith/worker.py): engine execution,
    # score+decide, lifecycle sync, audit/outbox drains, report schedules.
    # SECURITY/testability: default OFF - the automated test suite drives
    # every one of those ticks explicitly and must never race a background
    # consumer for the same Redis stream messages; live deployments
    # (scripts/dev/run_local.py, docker-compose) turn this on explicitly.
    worker_enabled: bool = False
    worker_interval_s: float = 1.0
    # SECURITY (2026-07-28, 里程碑 B'): per-service-account M2M scope/tier
    # grants (see modules/gateway/auth/m2m.py's M2MGrant/resolve_grant) -
    # empty by default, so every unconfigured service account still resolves
    # to DEFAULT_M2M_GRANT (scan:submit only, PUBLIC tier) rather than this
    # field silently widening anyone's access.
    m2m_grants: dict[str, M2MGrant] = {}
    # 2026-07-28, 里程碑 B' Task 5 (spec §6.3): per-service-account polling
    # rate limit - see modules/marketplace_api/ratelimit.py's check_rate_limit.
    # This is the penalty for a caller that ignores the poll_after_ms hint
    # (marketplace_api.views.POLL_AFTER_MS); it does not replace the hint,
    # which is what actually keeps well-behaved callers under this budget.
    marketplace_rate_limit_per_min: int = 120

    @model_validator(mode="after")
    def _validate(self) -> Settings:
        for field_name in (
            "minio_endpoint",
            "vllm_base_url",
            "idp_issuer",
            "vault_addr",
            "siem_endpoint",
        ):
            value: str = getattr(self, field_name)
            if value:
                require_internal_endpoint(value, field_name=field_name)
        if self.osv_source != "offline":
            require_internal_endpoint(self.osv_source, field_name="osv_source")
        if self.introspection_cache_ttl_s > 30:
            raise ValueError("introspection_cache_ttl_s must be <= 30 (SAD FR-SES-040)")
        if self.access_token_ttl_s > 600:
            raise ValueError("access_token_ttl_s must be <= 600 (SAD FR-SES-030)")
        return self


def _parse_m2m_grants(raw: str) -> dict[str, M2MGrant]:
    """Parse `SKILLSCAN_M2M_GRANTS_JSON`.

    SECURITY: same fail-closed posture as `main.py`'s `_load_policy` - a
    malformed value must crash startup, never be silently swallowed into the
    empty-dict default. Silently falling back would leave an operator
    believing their configured grants took effect when they never did.
    """
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"SKILLSCAN_M2M_GRANTS_JSON is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(
            "SKILLSCAN_M2M_GRANTS_JSON must be a JSON object of service_account -> grant"
        )

    grants: dict[str, M2MGrant] = {}
    for service_account, grant_obj in parsed.items():
        if not isinstance(grant_obj, dict):
            raise ValueError(
                f"SKILLSCAN_M2M_GRANTS_JSON entry {service_account!r} must be a JSON object"
            )
        try:
            scopes = grant_obj["scopes"]
            tier_raw = grant_obj["tier"]
        except KeyError as exc:
            raise ValueError(
                f"SKILLSCAN_M2M_GRANTS_JSON entry {service_account!r} missing required key {exc}"
            ) from exc
        if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
            raise ValueError(
                f"SKILLSCAN_M2M_GRANTS_JSON entry {service_account!r}: "
                "'scopes' must be a JSON array of strings"
            )
        try:
            tier = TrustTier(tier_raw)
        except ValueError as exc:
            raise ValueError(
                f"SKILLSCAN_M2M_GRANTS_JSON entry {service_account!r}: invalid tier {tier_raw!r}"
            ) from exc
        grants[service_account] = M2MGrant(scopes=frozenset(scopes), tier=tier)
    return grants


def load_settings() -> Settings:
    """SECURITY: reads directly from `os.environ` (pydantic-settings' own env
    binding would work too, but this project's other `_env()`-style helpers in
    `main.py` all read `os.environ` explicitly - matching that convention
    rather than mixing two different env-loading mechanisms in one process)."""
    return Settings(
        mysql_dsn_prefix=os.environ.get("SKILLSCAN_MYSQL_DSN_PREFIX", "mysql+aiomysql"),
        redis_url=os.environ.get("SKILLSCAN_REDIS_URL", "redis://localhost:6379/0"),
        minio_endpoint=os.environ.get("SKILLSCAN_MINIO_ENDPOINT", ""),
        blobstore_root=os.environ.get("SKILLSCAN_BLOBSTORE_ROOT", "var/blobstore"),
        vllm_base_url=os.environ.get("SKILLSCAN_VLLM_BASE_URL", ""),
        osv_source=os.environ.get("SKILLSCAN_OSV_SOURCE", "offline"),
        intel_mode=os.environ.get("SKILLSCAN_INTEL_MODE", "offline_import"),
        idp_issuer=os.environ.get("SKILLSCAN_IDP_ISSUER", ""),
        vault_addr=os.environ.get("SKILLSCAN_VAULT_ADDR", ""),
        siem_endpoint=os.environ.get("SKILLSCAN_SIEM_ENDPOINT", ""),
        introspection_cache_ttl_s=int(os.environ.get("SKILLSCAN_INTROSPECTION_CACHE_TTL_S", "30")),
        access_token_ttl_s=int(os.environ.get("SKILLSCAN_ACCESS_TOKEN_TTL_S", "600")),
        reconciliation_poll_enabled=os.environ.get(
            "SKILLSCAN_RECONCILIATION_POLL_ENABLED", "false"
        ).lower()
        == "true",
        reconciliation_push_enabled=os.environ.get(
            "SKILLSCAN_RECONCILIATION_PUSH_ENABLED", "false"
        ).lower()
        == "true",
        dynamic_sandbox_enabled=os.environ.get("SKILLSCAN_DYNAMIC_SANDBOX_ENABLED", "false").lower()
        == "true",
        max_findings=int(os.environ.get("SKILLSCAN_MAX_FINDINGS", "5000")),
        breakglass_enabled=os.environ.get("SKILLSCAN_BREAKGLASS_ENABLED", "false").lower()
        == "true",
        local_auth_enabled=os.environ.get("SKILLSCAN_LOCAL_AUTH_ENABLED", "false").lower()
        == "true",
        worker_enabled=os.environ.get("SKILLSCAN_WORKER_ENABLED", "false").lower() == "true",
        worker_interval_s=float(os.environ.get("SKILLSCAN_WORKER_INTERVAL_S", "1.0")),
        m2m_grants=_parse_m2m_grants(os.environ.get("SKILLSCAN_M2M_GRANTS_JSON", "")),
        marketplace_rate_limit_per_min=int(
            os.environ.get("SKILLSCAN_MARKETPLACE_RATE_LIMIT_PER_MIN", "120")
        ),
    )


def warn_on_unbuildable_dynamic_sandbox(settings: Settings) -> None:
    # SECURITY: setting a flag that does nothing must never be silent (same
    # posture as reconciliation's poll=off startup warning) - dynamic sandbox
    # itself was never built in this codebase (SAD's optional M7+ component).
    if settings.dynamic_sandbox_enabled:
        _logger.warning(
            "SKILLSCAN_DYNAMIC_SANDBOX_ENABLED=true but no dynamic-sandbox implementation "
            "exists in this codebase - this setting currently has no effect",
            extra={"context": {"metric": "dynamic_sandbox_unimplemented"}},
        )
