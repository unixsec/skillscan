"""FastAPI app assembly (coding spec §11.3 M3 skeleton spine).

SECURITY: this is the one place that wires together every module's
independent, least-privilege DB engine (coding spec §7.2) - `create_app()`
never hands out a shared/superuser connection, only per-module engines built
from per-module DSNs. Real production configuration (Vault-sourced secrets,
real OIDC/SAML IdP endpoints, real MinIO) replaces the local-dev defaults here
via environment variables; nothing is hardcoded.

Run locally (see docs/USER_GUIDE.md): `uvicorn monolith.main:create_app --factory`
"""

from __future__ import annotations

import asyncio
import datetime
import os
import socket
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import httpx
import redis.asyncio as aioredis
from common.blobstore import (
    ENGINE_RUNNER_PROBE_ROLE,
    MONOLITH_PROBE_ROLE,
    SHARE_PROBE_GRACE_S,
    SHARE_PROBE_INTERVAL_S,
    LocalFilesystemBlobStore,
    ShareProbeMonitor,
    log_share_status,
    probe_identity,
)
from common.config import (
    MarketplaceSettings,
    OidcSettings,
    ReconciliationSettings,
    SamlSettings,
    SessionSettings,
    VaultSettings,
)
from common.db import make_engine, make_session_factory
from common.log import get_logger
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import FastAPI
from skillscan_core import GatePolicy, TrustTier
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from monolith.config import Settings, load_settings, warn_on_unbuildable_dynamic_sandbox
from monolith.modules.admin.breakglass import BreakGlassCredentialPort
from monolith.modules.admin.breakglass_vault import VaultBreakGlassCredentialPort
from monolith.modules.admin.local_auth import (
    DbLocalAccountStore,
    LocalAccountStore,
    LocalAuthError,
    load_local_accounts_from_json,
)
from monolith.modules.admin.models import GroupRoleMappingRow, LocalAccountRow
from monolith.modules.admin.router import router as admin_router
from monolith.modules.audit.router import router as audit_router
from monolith.modules.gate.policy import load_gate_policy
from monolith.modules.gate.reviews_router import router as reviews_router
from monolith.modules.gate.router import router as allowlist_router
from monolith.modules.gate.service import SignerPort
from monolith.modules.gate.signer import LocalDevSigner, VaultTransitSigner
from monolith.modules.gateway.auth.dependencies import AuthRuntime
from monolith.modules.gateway.auth.login_router import router as login_router
from monolith.modules.gateway.auth.m2m import M2MGrant
from monolith.modules.gateway.auth.middleware import SecurityHeadersMiddleware
from monolith.modules.gateway.auth.rbac import KNOWN_ROLES, load_group_role_map
from monolith.modules.gateway.auth.session import IntrospectionCache
from monolith.modules.gateway.infra_router import router as infra_router
from monolith.modules.gateway.router import router as scan_router
from monolith.modules.gateway.runtime import ScanRuntime, SessionFactory
from monolith.modules.integration_relay.marketplace import HttpMarketplaceAdapter, MarketplacePort
from monolith.modules.integration_relay.siem import SyslogSiemAdapter
from monolith.modules.intel.router import router as intel_router
from monolith.modules.inventory.router import router as inventory_router
from monolith.modules.marketplace_api.router import router as marketplace_router
from monolith.modules.marketplace_api.views import POLL_AFTER_MS
from monolith.modules.orchestration.floor import floor_engines
from monolith.modules.reeval.reconciliation import reconciliation_mode_warnings
from monolith.modules.reeval.router import router as reeval_router
from monolith.modules.reporting.router import router as reports_router
from monolith.worker import run_worker_loop

_LOCAL_DEV_DEFAULT_PASSWORD = "local-dev-only-not-a-secret"  # noqa: S105 - documented local-dev default
_DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2] / "policies" / "gate" / "v1.yaml"
_DEFAULT_GROUP_ROLE_MAP_PATH = (
    Path(__file__).resolve().parents[2] / "policies" / "rbac" / "group_role_map.yaml"
)
_logger = get_logger("skillscan.monolith.main")


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _default_module_dsn(user: str) -> str:
    password = os.environ.get(
        f"SKILLSCAN_DB_PASSWORD_{user.split('_', 1)[1].upper()}", _LOCAL_DEV_DEFAULT_PASSWORD
    )
    host = _env("SKILLSCAN_DB_HOST", "localhost")
    database = _env("SKILLSCAN_DB_NAME", "skillscan")
    return f"mysql+aiomysql://{user}:{password}@{host}/{database}"


def _load_policy() -> GatePolicy:
    # SECURITY (INV-1 floor backstop, coding spec §11.6): policy is now loaded
    # from the versioned, PR-reviewed policies/gate/*.yaml (config-as-code) -
    # a missing/malformed file is a genuine operator error and must crash
    # startup (GatePolicyLoadError propagates), never silently fall back to
    # an empty/permissive policy. Every floor engine (M1 StaticKeywordEngine +
    # M4 in-house detectors) is still required in policies/gate/v1.yaml -
    # verified by test_gate_policy.py against the REAL shipped file.
    path = Path(_env("SKILLSCAN_GATE_POLICY_PATH", str(_DEFAULT_POLICY_PATH)))
    return load_gate_policy(path)


def _build_signer(settings: Settings) -> SignerPort:
    if not settings.vault_addr:
        # SECURITY: no Vault configured - local dev/test default only, never
        # production (see LocalDevSigner's own module docstring).
        _logger.warning("SKILLSCAN_VAULT_ADDR not set - using LocalDevSigner (dev/test only)")
        return LocalDevSigner()

    import hvac  # local import: only needed on the real-Vault path

    # SECURITY: settings.vault_addr already went through Settings' own
    # require_internal_endpoint validation at construction time - VaultSettings
    # re-validates it again here (harmless double-check, same value), since
    # VaultSettings is also what carries the Vault-specific fields (token,
    # transit_key_name/mount_point, signer_ttl_s) this signer needs that
    # Settings deliberately doesn't duplicate.
    vault_settings = VaultSettings(
        addr=settings.vault_addr,
        token=os.environ["SKILLSCAN_VAULT_TOKEN"],
        transit_key_name=_env("SKILLSCAN_VAULT_TRANSIT_KEY_NAME", "skillscan-gate-signing"),
    )
    client = hvac.Client(url=vault_settings.addr, token=vault_settings.token)
    return VaultTransitSigner(
        client=client,
        key_name=vault_settings.transit_key_name,
        mount_point=vault_settings.transit_mount_point,
        ttl_s=vault_settings.signer_ttl_s,
    )


def _build_marketplace() -> MarketplacePort | None:
    # SECURITY (INV-14): `base_url` is read raw here, same shape as every other
    # optional-endpoint read in this file - but unlike a bare `os.environ.get`
    # used directly, it is validated a few lines below, at construction of
    # `MarketplaceSettings(api_base_url=base_url, ...)`: that class's own
    # `require_internal_endpoint` model_validator (libs/common/config.py)
    # fires on ANY non-empty value regardless of source, so this is "validate
    # at the read site", the same choice `_build_signer`'s `VaultSettings`
    # construction makes for `SKILLSCAN_VAULT_ADDR`. `monolith.config.Settings`
    # deliberately carries no `marketplace_api` field of its own - see that
    # class's docstring for why duplicating a field `MarketplaceSettings`
    # already owns and validates would just be a second, driftable spelling.
    base_url = os.environ.get("SKILLSCAN_MARKETPLACE_API_BASE_URL")
    if not base_url:
        _logger.warning(
            "SKILLSCAN_MARKETPLACE_API_BASE_URL not set - marketplace writeback/"
            "reconciliation disabled (outbox drain falls back to log-only)"
        )
        return None
    settings = MarketplaceSettings(
        api_base_url=base_url,
        poll_token=os.environ["SKILLSCAN_MARKETPLACE_POLL_TOKEN"],
        write_token=os.environ["SKILLSCAN_MARKETPLACE_WRITE_TOKEN"],
    )
    return HttpMarketplaceAdapter(
        base_url=settings.api_base_url,
        poll_token=settings.poll_token,
        write_token=settings.write_token,
    )


def _build_siem_notifier(settings: Settings) -> SyslogSiemAdapter | None:
    # SECURITY (2026-07-06 spec-compliance audit fix): settings.siem_endpoint
    # already went through Settings' own require_internal_endpoint validation
    # at construction time - see SyslogSiemAdapter's own module docstring for
    # why this is a fail-SOFT notifier (a SIEM outage must never affect the
    # gate_outbox drain it's attached to), same guard shape as
    # _build_marketplace()'s "unset -> disabled, not an error" posture.
    if not settings.siem_endpoint:
        _logger.warning(
            "SKILLSCAN_SIEM_ENDPOINT not set - SIEM event forwarding disabled "
            "(verdict_issued events still dispatch to marketplace if configured)"
        )
        return None
    return SyslogSiemAdapter(endpoint=settings.siem_endpoint)


def _build_oidc_settings() -> OidcSettings | None:
    issuer = os.environ.get("SKILLSCAN_OIDC_ISSUER")
    if not issuer:
        _logger.warning("SKILLSCAN_OIDC_ISSUER not set - OIDC login stays disabled (404)")
        return None
    return OidcSettings(
        issuer=issuer,
        client_id=os.environ["SKILLSCAN_OIDC_CLIENT_ID"],
        client_secret=os.environ["SKILLSCAN_OIDC_CLIENT_SECRET"],
        redirect_uri_allowlist=tuple(
            os.environ["SKILLSCAN_OIDC_REDIRECT_URI_ALLOWLIST"].split(",")
        ),
        authorization_endpoint=os.environ["SKILLSCAN_OIDC_AUTHORIZATION_ENDPOINT"],
        token_endpoint=os.environ["SKILLSCAN_OIDC_TOKEN_ENDPOINT"],
        jwks_uri=os.environ["SKILLSCAN_OIDC_JWKS_URI"],
    )


def _build_saml_settings() -> SamlSettings | None:
    sp_entity_id = os.environ.get("SKILLSCAN_SAML_SP_ENTITY_ID")
    if not sp_entity_id:
        _logger.warning("SKILLSCAN_SAML_SP_ENTITY_ID not set - SAML login stays disabled (404)")
        return None
    return SamlSettings(
        sp_entity_id=sp_entity_id,
        sp_acs_url=os.environ["SKILLSCAN_SAML_SP_ACS_URL"],
        idp_entity_id=os.environ["SKILLSCAN_SAML_IDP_ENTITY_ID"],
        idp_sso_url=os.environ["SKILLSCAN_SAML_IDP_SSO_URL"],
        idp_slo_url=os.environ.get("SKILLSCAN_SAML_IDP_SLO_URL"),
        idp_x509_cert=os.environ["SKILLSCAN_SAML_IDP_X509_CERT"],
    )


def _build_breakglass_credential_port(settings: Settings) -> BreakGlassCredentialPort | None:
    # SECURITY (INV-17): breakglass.enabled defaults to False - it must be
    # EXPLICITLY turned on, and even then only takes effect if Vault is also
    # reachable (SKILLSCAN_VAULT_ADDR) - never a fallback/default credential
    # source of any kind.
    if not settings.breakglass_enabled:
        return None
    # SECURITY (2026-07-06 spec-compliance audit fix): this previously read
    # SKILLSCAN_VAULT_ADDR via a raw os.environ.get(...), bypassing the
    # internal-address validation _build_signer()'s VaultSettings path already
    # applied - settings.vault_addr went through Settings' own
    # require_internal_endpoint check at construction time, so both Vault
    # call sites are now validated the same way.
    if not settings.vault_addr:
        _logger.warning(
            "SKILLSCAN_BREAKGLASS_ENABLED=true but SKILLSCAN_VAULT_ADDR is not set - "
            "break-glass stays disabled (no credential source configured)"
        )
        return None

    import hvac

    client = hvac.Client(url=settings.vault_addr, token=os.environ["SKILLSCAN_VAULT_TOKEN"])
    return VaultBreakGlassCredentialPort(
        client=client,
        secret_path=_env("SKILLSCAN_BREAKGLASS_VAULT_SECRET_PATH", "skillscan/breakglass"),
    )


def _build_local_account_store(
    settings: Settings, admin_session_factory: SessionFactory
) -> LocalAccountStore | None:
    # SECURITY (INV-17, mirrors _build_breakglass_credential_port): disabled
    # by default. 2026-07-14 (item #13): accounts now live in `local_account`
    # (DbLocalAccountStore reads it live) rather than a fixed env-JSON list -
    # the fail-closed "there must be at least one usable account" check moved
    # to `_seed_admin_tables_if_empty` (async, can actually query the table),
    # since this function is called synchronously and can't.
    if not settings.local_auth_enabled:
        return None
    return DbLocalAccountStore(admin_session_factory)


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


async def _seed_admin_tables_if_empty(
    scan_runtime: ScanRuntime, auth_runtime: AuthRuntime, settings: Settings
) -> None:
    """2026-07-14 (item #13): local_account/group_role_mapping are now
    DB-authoritative, but a fresh deployment starts with an empty DB and
    needs its first admin account/role mapping from somewhere - seeded once,
    here, from the pre-existing config sources
    (SKILLSCAN_LOCAL_ACCOUNTS_JSON / policies/rbac/group_role_map.yaml),
    same fail-closed posture `_build_local_account_store` used to enforce
    synchronously before this. Runs on EVERY boot but only writes when the
    table is actually empty - cheap and idempotent, and (deliberately) not
    gated on whether this call's `auth_runtime`/`scan_runtime` were caller-
    built vs `_build_*`-built: this environment's own monolith-entrypoint
    ConfigMap script builds its own runtimes and passes them into
    `create_app()` pre-built (see docs/superpowers/plans/2026-07-11-web-
    console-redesign-STATUS.md for why - the SAME class of bug bit
    local_auth's `local_redis` wiring earlier this session), so gating this
    on "auth_runtime is None" would silently never run there.

    After this call, `auth_runtime.group_role_map` reflects the DB's current
    content (freshly seeded or pre-existing from an earlier boot) - mutated
    IN PLACE (not reassigned) so the dict every request dependency already
    holds a reference to picks it up without a restart.

    KNOWN LIMITATION: this process holds the only in-memory copy of
    group_role_map - a horizontally-scaled deployment (more than the single
    replica this environment runs) would need a cross-replica invalidation
    signal (e.g. Redis pub/sub) for an edit made on one replica to reach the
    others. Out of scope for what was actually asked; noted, not built.
    """
    if scan_runtime.admin_session_factory is None:
        return
    async with scan_runtime.admin_session_factory() as session, session.begin():
        if settings.local_auth_enabled:
            has_account = (await session.execute(select(LocalAccountRow.id).limit(1))).first()
            if has_account is None:
                raw_json = os.environ.get("SKILLSCAN_LOCAL_ACCOUNTS_JSON")
                if not raw_json:
                    raise LocalAuthError(
                        "SKILLSCAN_LOCAL_AUTH_ENABLED=true, local_account is empty, and "
                        "SKILLSCAN_LOCAL_ACCOUNTS_JSON is not set - no way to bootstrap the "
                        "first admin account"
                    )
                seed_accounts = load_local_accounts_from_json(raw_json, known_roles=KNOWN_ROLES)
                now = _naive_utcnow()
                for account in seed_accounts:
                    session.add(
                        LocalAccountRow(
                            username=account.username,
                            password_hash=account.password_hash,
                            role=account.role,
                            status="active",
                            created_by="bootstrap-seed",
                            created_at=now,
                            updated_at=now,
                        )
                    )
                _logger.warning(
                    "seeded local_account from SKILLSCAN_LOCAL_ACCOUNTS_JSON (first boot only)",
                    extra={"context": {"count": len(seed_accounts)}},
                )

        existing_mappings = (await session.execute(select(GroupRoleMappingRow))).scalars().all()
        if existing_mappings:
            live_map = {m.group_name: m.role for m in existing_mappings}
        else:
            yaml_map = load_group_role_map(
                Path(_env("SKILLSCAN_RBAC_GROUP_ROLE_MAP_PATH", str(_DEFAULT_GROUP_ROLE_MAP_PATH)))
            )
            now = _naive_utcnow()
            for group_name, role in yaml_map.items():
                session.add(
                    GroupRoleMappingRow(
                        group_name=group_name,
                        role=role,
                        updated_by="bootstrap-seed",
                        updated_at=now,
                    )
                )
            _logger.warning(
                "seeded group_role_mapping from policies/rbac/group_role_map.yaml "
                "(first boot only)",
                extra={"context": {"count": len(yaml_map)}},
            )
            live_map = dict(yaml_map)

    auth_runtime.group_role_map.clear()
    auth_runtime.group_role_map.update(live_map)


def _load_trusted_intel_public_keys() -> tuple[RSAPublicKey, ...]:
    # SECURITY (SEC-UPD-010): unset/empty by default - intel_sync.
    # import_offline_package fails closed ("no trusted public keys
    # configured") rather than accepting an unverifiable package.
    keys_dir = os.environ.get("SKILLSCAN_INTEL_TRUSTED_KEYS_DIR")
    if not keys_dir:
        return ()
    keys: list[RSAPublicKey] = []
    for pem_path in sorted(Path(keys_dir).glob("*.pem")):
        public_key = load_pem_public_key(pem_path.read_bytes())
        if not isinstance(public_key, RSAPublicKey):
            _logger.warning(
                "skipping non-RSA key in intel trusted-keys dir",
                extra={"context": {"path": str(pem_path)}},
            )
            continue
        keys.append(public_key)
    return tuple(keys)


def _build_auth_runtime(
    *,
    m2m_grants: dict[str, M2MGrant] | None = None,
    breakglass_redis: aioredis.Redis | None = None,
    saml_redis: aioredis.Redis | None = None,
    local_redis: aioredis.Redis | None = None,
) -> AuthRuntime:
    settings = SessionSettings(
        introspection_endpoint=_env(
            "SKILLSCAN_SESSION_INTROSPECTION_ENDPOINT", "https://localhost/introspect"
        ),
        introspection_client_id=_env("SKILLSCAN_SESSION_INTROSPECTION_CLIENT_ID", "gateway"),
        introspection_client_secret=_env(
            "SKILLSCAN_SESSION_INTROSPECTION_CLIENT_SECRET", "local-dev-only-not-a-secret"
        ),
    )
    group_role_map = load_group_role_map(
        Path(_env("SKILLSCAN_RBAC_GROUP_ROLE_MAP_PATH", str(_DEFAULT_GROUP_ROLE_MAP_PATH)))
    )
    return AuthRuntime(
        breakglass_redis=breakglass_redis,
        # SECURITY (2026-07-06 login-callback fix): SAML sessions are Redis-
        # backed the same way break-glass's are (see AuthRuntime's own
        # docstring on why SAML can't use OIDC's introspection-based model) -
        # reuses the SAME connection scan_runtime.redis already holds, same
        # reasoning as breakglass_redis above.
        saml_redis=saml_redis,
        local_redis=local_redis,
        settings=settings,
        http_client=httpx.AsyncClient(),
        cache=IntrospectionCache(ttl_s=settings.introspection_cache_ttl_s),
        group_role_map=group_role_map,
        allowed_m2m_service_accounts=frozenset(
            _env("SKILLSCAN_M2M_ALLOWED_SERVICE_ACCOUNTS", "").split(",")
        )
        - frozenset({""}),
        m2m_grants=m2m_grants,
    )


def _build_reconciliation_settings() -> ReconciliationSettings:
    return ReconciliationSettings(
        poll_enabled=_env("SKILLSCAN_RECONCILIATION_POLL_ENABLED", "false").lower() == "true",
        push_enabled=_env("SKILLSCAN_RECONCILIATION_PUSH_ENABLED", "false").lower() == "true",
        push_hmac_secret=os.environ.get("SKILLSCAN_RECONCILIATION_PUSH_HMAC_SECRET"),
    )


def _warn_if_marketplace_poll_hint_too_slow(settings: Settings) -> None:
    """coding spec §6.3 startup self-check: the RUNNING poll_after_ms hint
    (marketplace_api.views.POLL_AFTER_MS) only reduces marketplace polling load
    if a caller that follows it can still observe the terminal state before the
    gate's sandbox wait budget (`sandbox_wait_timeout_s`) runs out. Require the
    hint to be at most a quarter of that budget - a caller polling near the
    hint's own cadence needs headroom for network latency and its own
    processing time, not just the bare minimum.

    Never raises: whoever tunes `sandbox_wait_timeout_s` down later (see that
    field's own docstring in config.py) has no reason to think of this file, so
    the drift has to be caught here rather than assumed away. A stale hint
    makes a well-behaved caller poll too slowly and repeatedly miss the
    terminal state - a real operational cost, but not a reason to refuse to
    start.
    """
    threshold_ms = settings.sandbox_wait_timeout_s * 1000 / 4
    running_hint_ms = POLL_AFTER_MS["RUNNING"]
    if running_hint_ms > threshold_ms:
        _logger.warning(
            "marketplace POLL_AFTER_MS['RUNNING'] exceeds a quarter of "
            "sandbox_wait_timeout_s - a caller polling at the hinted cadence will "
            "repeatedly miss the terminal state before the sandbox wait budget "
            "expires",
            extra={
                "context": {
                    "metric": "marketplace_poll_hint_too_slow",
                    "poll_after_ms_running": running_hint_ms,
                    "sandbox_wait_timeout_s": settings.sandbox_wait_timeout_s,
                    "threshold_ms": threshold_ms,
                }
            },
        )


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        _logger.warning(
            f"{name} is not a number - using the default",
            extra={"context": {"value": raw, "default": default}},
        )
        return default


def _probe_instance() -> str:
    # Kubernetes sets HOSTNAME to the pod name; outside k8s the hostname is
    # still the thing that distinguishes two processes sharing one store.
    return os.environ.get("HOSTNAME") or socket.gethostname()


def _build_share_probe_monitor(scan_runtime: ScanRuntime) -> ShareProbeMonitor | None:
    """The blobstore share self-check (里程碑 E spec §4.3), or None if it can't
    or shouldn't run in this process.

    CORRECTNESS: when this monolith and the engine-runner are not looking at the
    same store, NOTHING errors - both pods are Running, /healthz is 200, the
    logs are clean, and every scan sits at RUNNING forever waiting for a
    findings blob written into a store this process never reads. That is why
    the check is on by default and why turning it off logs a warning.
    """
    if _env("SKILLSCAN_BLOBSTORE_SHARE_CHECK", "1").lower() not in {"1", "true", "yes", "on"}:
        _logger.warning(
            "blobstore share self-check DISABLED - if this process and the engine-runner "
            "end up on different volumes, scans will stay RUNNING forever with no error",
            extra={"context": {"metric": "blobstore_share_check_disabled"}},
        )
        return None
    store = scan_runtime.blobstore
    if not isinstance(store, LocalFilesystemBlobStore):
        # Nothing else implements BlobStorePort today; if something ever does,
        # skipping is the honest answer rather than pretending the check ran.
        _logger.warning(
            "blobstore share self-check skipped - store is not filesystem-backed",
            extra={"context": {"store": type(store).__name__}},
        )
        return None
    return ShareProbeMonitor(
        store,
        identity=probe_identity(MONOLITH_PROBE_ROLE, _probe_instance()),
        peer_role=ENGINE_RUNNER_PROBE_ROLE,
        started_at=time.time(),
        grace_s=_env_float("SKILLSCAN_BLOBSTORE_SHARE_GRACE_S", SHARE_PROBE_GRACE_S),
    )


async def _run_share_probe_loop(
    monitor: ShareProbeMonitor, *, interval_s: float, stop_event: asyncio.Event
) -> None:
    """ROBUSTNESS: the probe's filesystem work runs in a thread. The shared
    store is an RWX volume (NFS in the reference deployment) - a hung server
    there must degrade readiness, not block this process's event loop and take
    every HTTP request down with it."""
    while not stop_event.is_set():
        try:
            status = await asyncio.to_thread(monitor.check, time.time())
            log_share_status(_logger, status, peer_role=monitor.peer_role)
        except Exception:  # noqa: BLE001 - a probe failure must never kill the loop
            _logger.exception("blobstore share probe failed - continuing")
        with suppress(TimeoutError):
            await asyncio.wait_for(stop_event.wait(), timeout=interval_s)


def _build_scan_runtime() -> tuple[ScanRuntime, tuple[AsyncEngine, ...]]:
    """Returns the runtime plus the SQLAlchemy engines it created, so
    `create_app()`'s lifespan can dispose them on shutdown - only when it
    built them itself (a caller-supplied `scan_runtime` owns its own engines'
    lifecycle, e.g. test fixtures managing a shared engine across tests)."""
    settings = load_settings()
    warn_on_unbuildable_dynamic_sandbox(settings)
    _warn_if_marketplace_poll_hint_too_slow(settings)
    orchestration_engine = make_engine(_default_module_dsn("svc_orchestration"))
    gate_engine = make_engine(_default_module_dsn("svc_gate"))
    reeval_engine = make_engine(_default_module_dsn("svc_reeval"))
    reporting_engine = make_engine(_default_module_dsn("svc_reporting"))
    inventory_engine = make_engine(_default_module_dsn("svc_inventory"))
    audit_engine = make_engine(_default_module_dsn("svc_audit"))
    intel_engine = make_engine(_default_module_dsn("svc_intel"))
    relay_engine = make_engine(_default_module_dsn("svc_relay"))
    admin_engine = make_engine(_default_module_dsn("svc_admin"))
    # 里程碑 B' spec §7 - marketplace_api's own least-privilege user
    # (policies/grants/manifest.yaml: INSERT+SELECT on marketplace_fetch_log
    # and nothing else, so even a bug here cannot touch another module's data).
    marketplace_engine = make_engine(_default_module_dsn("svc_marketplace"))
    admin_session_factory = make_session_factory(admin_engine)
    redis = aioredis.Redis.from_url(settings.redis_url)
    blobstore = LocalFilesystemBlobStore(Path(settings.blobstore_root))
    engines = floor_engines()
    reconciliation_settings = _build_reconciliation_settings()
    runtime = ScanRuntime(
        redis=redis,
        blobstore=blobstore,
        orchestration_session_factory=make_session_factory(orchestration_engine),
        gate_session_factory=make_session_factory(gate_engine),
        policy=_load_policy(),
        engine_metadatas=tuple(e.metadata for e in engines.values()),
        # KNOWN GAP (see docs/stories/BACKLOG.md's M8 status note): this is a
        # startup-time snapshot, not a live view - `gate.service.
        # list_active_allowlist_entries` now exists (M8 §9 /v1/allowlist) but
        # `_build_scan_runtime` is synchronous and can't await it here.
        # Lower-priority than it looks: the scan-decision worker loop that
        # would actually CONSUME this value (orchestration.service.
        # run_result_collector_tick) is itself never invoked by any live
        # process in this codebase yet (same status note) - fixing allowlist
        # freshness in isolation wouldn't make scanning work end-to-end.
        allowlist=(),
        signer=_build_signer(settings),
        default_trust_tier=TrustTier.INTERNAL,
        scan_deadline_s=settings.scan_deadline_s,
        sandbox_wait_timeout_s=settings.sandbox_wait_timeout_s,
        reeval_session_factory=make_session_factory(reeval_engine),
        marketplace=_build_marketplace(),
        siem_notifier=_build_siem_notifier(settings),
        push_hmac_secret=reconciliation_settings.push_hmac_secret,
        push_replay_window_s=reconciliation_settings.push_replay_window_s,
        push_auto_quarantine_enabled=reconciliation_settings.push_auto_quarantine_enabled,
        breakglass_enabled=settings.breakglass_enabled,
        breakglass_credentials=_build_breakglass_credential_port(settings),
        local_auth_enabled=settings.local_auth_enabled,
        local_account_store=_build_local_account_store(settings, admin_session_factory),
        reporting_session_factory=make_session_factory(reporting_engine),
        inventory_session_factory=make_session_factory(inventory_engine),
        audit_session_factory=make_session_factory(audit_engine),
        intel_session_factory=make_session_factory(intel_engine),
        trusted_intel_public_keys=_load_trusted_intel_public_keys(),
        relay_session_factory=make_session_factory(relay_engine),
        admin_session_factory=admin_session_factory,
        marketplace_session_factory=make_session_factory(marketplace_engine),
        marketplace_rate_limit_per_min=settings.marketplace_rate_limit_per_min,
    )
    return runtime, (
        orchestration_engine,
        gate_engine,
        reeval_engine,
        reporting_engine,
        inventory_engine,
        audit_engine,
        intel_engine,
        relay_engine,
        admin_engine,
        marketplace_engine,
    )


def create_app(
    *, auth_runtime: AuthRuntime | None = None, scan_runtime: ScanRuntime | None = None
) -> FastAPI:
    """SECURITY: tests supply `auth_runtime`/`scan_runtime` overrides (e.g. an
    `httpx.MockTransport` in place of a real IdP) so the REAL router/
    orchestration/gate/audit code paths are exercised end-to-end against real
    local MySQL/Redis without needing a real IdP running in this environment.
    """
    self_built_engines: tuple[AsyncEngine, ...] = ()
    if scan_runtime is None:
        scan_runtime, self_built_engines = _build_scan_runtime()
    worker_settings = load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # 2026-07-14 (item #13): seed local_account/group_role_mapping on
        # first boot and load the live group_role_map into whichever
        # AuthRuntime this process is actually using (app.state.auth is set
        # below, unconditionally, before create_app() returns - see this
        # function's own docstring for why this deliberately does NOT check
        # `auth_runtime is None` the way oidc_settings/saml_settings do).
        await _seed_admin_tables_if_empty(scan_runtime, app.state.auth, worker_settings)

        # Background worker (apps/monolith/worker.py) - the live process that
        # actually executes queued scans, decides verdicts, drives the skill
        # lifecycle, chains audit intents, drains the outbox, and fires report
        # schedules. Default OFF (see Settings.worker_enabled) so the test
        # suite's explicit tick-driving never races a background consumer.
        worker_task: asyncio.Task[None] | None = None
        stop_event = asyncio.Event()
        if worker_settings.worker_enabled:
            worker_task = asyncio.create_task(
                run_worker_loop(
                    scan_runtime,
                    interval_s=worker_settings.worker_interval_s,
                    stop_event=stop_event,
                )
            )

        # 里程碑 E spec §4.3 - shared-blobstore self-check. Started here (not in
        # create_app's body) so a test-built app, which httpx.ASGITransport
        # runs WITHOUT a lifespan, never starts a background probe; `/readyz`
        # leaves the check out entirely when no monitor is parked on app.state.
        share_monitor = _build_share_probe_monitor(scan_runtime)
        app.state.blobstore_share_monitor = share_monitor
        share_task: asyncio.Task[None] | None = None
        if share_monitor is not None:
            share_task = asyncio.create_task(
                _run_share_probe_loop(
                    share_monitor,
                    interval_s=_env_float(
                        "SKILLSCAN_BLOBSTORE_SHARE_INTERVAL_S", SHARE_PROBE_INTERVAL_S
                    ),
                    stop_event=stop_event,
                )
            )
        try:
            yield
        finally:
            stop_event.set()
            for task in (worker_task, share_task):
                if task is None:
                    continue
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
            # SECURITY/hygiene: only dispose engines THIS call built - a
            # caller-supplied scan_runtime (tests, mainly) owns its own
            # engines' lifecycle, e.g. a fixture shared across several tests.
            for engine in self_built_engines:
                await engine.dispose()

    app = FastAPI(title="skillscan monolith", debug=False, lifespan=lifespan)
    app.add_middleware(SecurityHeadersMiddleware)
    # SECURITY: break-glass session state lives in the SAME Redis the scan
    # runtime already uses (scan_runtime.redis) - not a second, independent
    # connection - so a session admin.router's breakglass/login endpoint
    # creates is immediately visible to get_session_context's own check.
    app.state.auth = (
        auth_runtime
        if auth_runtime is not None
        else _build_auth_runtime(
            m2m_grants=worker_settings.m2m_grants,
            breakglass_redis=scan_runtime.redis,
            saml_redis=scan_runtime.redis,
            local_redis=scan_runtime.redis,
        )
    )
    app.state.scan = scan_runtime
    # SECURITY (2026-07-06 login-callback fix): None when unconfigured -
    # login_router's own handlers 404 cleanly rather than erroring, matching
    # the "optional until configured" posture the rest of this file uses for
    # marketplace/SIEM/break-glass. A caller-supplied auth_runtime (tests)
    # bypasses this entirely, same as it bypasses _build_auth_runtime itself.
    if auth_runtime is None:
        app.state.oidc_settings = _build_oidc_settings()
        app.state.saml_settings = _build_saml_settings()
    app.include_router(scan_router)
    app.include_router(admin_router)
    app.include_router(login_router)
    app.include_router(reports_router)
    app.include_router(infra_router)
    app.include_router(inventory_router)
    app.include_router(audit_router)
    app.include_router(reeval_router)
    app.include_router(allowlist_router)
    app.include_router(reviews_router)
    app.include_router(intel_router)
    # 里程碑 B' - the marketplace's own /v1/market surface. Mounted alongside
    # the console's routers but deliberately sharing nothing with them: its
    # responses are `marketplace_api.views` projections, never the internal
    # model (spec §3.1).
    app.include_router(marketplace_router)

    # SECURITY (coding spec §13 startup self-check): a degraded reconciliation
    # posture must never be silent - poll=off (with or without push) always
    # gets logged here, deployment-wide, regardless of which scan_runtime is
    # in use (a test-supplied runtime doesn't change this deployment's actual
    # env-var configuration).
    reconciliation_settings = _build_reconciliation_settings()
    for warning in reconciliation_mode_warnings(
        poll_enabled=reconciliation_settings.poll_enabled,
        push_enabled=reconciliation_settings.push_enabled,
    ):
        _logger.warning(warning, extra={"context": {"metric": "reconciliation_inactive"}})

    # `/healthz`, `/readyz` and `/.well-known/jwks.json` live in
    # `modules/gateway/infra_router.py` (coding spec §9), included above.
    #
    # BUG (found implementing 里程碑 E's §4.3 readiness check): this file also
    # carried its own copies of all three, defined AFTER `include_router`.
    # Starlette matches routes in registration order, so the router's copies
    # always won and these were dead code that merely looked authoritative -
    # confirmed by running both registrations against a real app, not by
    # reading. Adding the share check to the copy here would have shipped a
    # self-check that never executed: exactly the milestone's recurring shape,
    # where the path that runs and the path that looks like it runs differ.

    return app
