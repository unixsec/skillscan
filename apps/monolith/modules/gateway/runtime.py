"""Per-request runtime wiring for the /v1 scan endpoints (coding spec §11.3).

Bundles what `router.py` needs, attached to `app.state.scan` once at startup -
mirrors `auth.dependencies.AuthRuntime`'s pattern.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

import redis.asyncio as aioredis
from common.blobstore import BlobStorePort
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from ports import NotificationPort
from skillscan_core import AllowlistEntry, EngineMetadata, GatePolicy, TrustTier
from sqlalchemy.ext.asyncio import AsyncSession

from monolith.modules.admin.breakglass import BreakGlassCredentialPort
from monolith.modules.admin.local_auth import LocalAccountStore
from monolith.modules.gate.service import SignerPort
from monolith.modules.integration_relay.marketplace import MarketplacePort

SessionFactory = Callable[[], AsyncSession]


@dataclass
class ScanRuntime:
    redis: aioredis.Redis
    blobstore: BlobStorePort
    orchestration_session_factory: SessionFactory
    gate_session_factory: SessionFactory
    policy: GatePolicy
    engine_metadatas: Sequence[EngineMetadata]
    allowlist: Sequence[AllowlistEntry]
    signer: SignerPort
    default_trust_tier: TrustTier = TrustTier.INTERNAL
    # coding spec §11.6 - all optional so existing (M3-M5) callers/tests that
    # never touch reconciliation/marketplace keep working unchanged.
    reeval_session_factory: SessionFactory | None = None
    marketplace: MarketplacePort | None = None
    # coding spec §13 siem_endpoint / §16.2 reporting SIEM destination
    # (2026-07-06 spec-compliance audit fix) - same "stored on the runtime for
    # whenever a live gate_outbox-draining process exists" posture as
    # `marketplace` above; neither is invoked by any live process in this
    # codebase yet (see docs/stories/BACKLOG.md's worker-loop status note).
    siem_notifier: NotificationPort | None = None
    push_hmac_secret: str | None = None
    push_replay_window_s: int = 300
    push_auto_quarantine_enabled: bool = False
    # coding spec §16.3 (INV-17) - None/False by default (breakglass.enabled=false
    # is the mandatory default; see main.py's _build_breakglass_credential_port).
    breakglass_enabled: bool = False
    breakglass_credentials: BreakGlassCredentialPort | None = None
    # 2026-07-13 local-auth addition - same "disabled by default" posture as
    # breakglass_enabled above (INV-17).
    local_auth_enabled: bool = False
    local_account_store: LocalAccountStore | None = None
    # coding spec §16.2 (FR-REP) - optional so existing callers/tests that never
    # touch reporting keep working unchanged, same shape as reeval_session_factory.
    reporting_session_factory: SessionFactory | None = None
    # coding spec §16.2 (FR-INV) - optional, same shape as reporting_session_factory.
    inventory_session_factory: SessionFactory | None = None
    # coding spec §9 GET /v1/audit - optional, same shape.
    audit_session_factory: SessionFactory | None = None
    # coding spec §9 GET/POST /v1/admin/intel - optional, same shape.
    intel_session_factory: SessionFactory | None = None
    # svc_relay's own session for the background worker's gate_outbox drain
    # (integration_relay.service.drain_pending_outbox) - optional, same shape.
    relay_session_factory: SessionFactory | None = None
    # 2026-07-14 (item #13) - admin's own local_account/group_role_mapping
    # tables, optional same shape as the other per-module factories above.
    admin_session_factory: SessionFactory | None = None
    # SECURITY (SEC-UPD-010): empty by default - intel_sync.import_offline_package
    # fails closed ("no trusted public keys configured") when this is empty,
    # never silently accepting an unverifiable package.
    trusted_intel_public_keys: tuple[RSAPublicKey, ...] = ()
    # coding spec §11.3 - orchestration.service.submit_scan's own deadline_s
    # default, surfaced here so a deployment with a slower sandbox-engine LLM
    # backend (services/engine_runner/adapters/aig.py's own timeout_s) can
    # raise both together via SKILLSCAN_SCAN_DEADLINE_S - raising only one of
    # the two does nothing, see aig.py's make_adapter() docstring.
    scan_deadline_s: float = 300.0
