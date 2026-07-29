"""Per-request runtime wiring for the /v1 scan endpoints (coding spec §11.3).

Bundles what `router.py` needs, attached to `app.state.scan` once at startup -
mirrors `auth.dependencies.AuthRuntime`'s pattern.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

import redis.asyncio as aioredis
from common.blobstore import BlobStorePort
from common.observability import SecurityMetrics
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from ports import NotificationPort
from skillscan_core import AllowlistEntry, EngineMetadata, GatePolicy, TrustTier, toolchain_digest
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
    # (2026-07-06 spec-compliance audit fix) - same "stored on the runtime,
    # used by whatever drains gate_outbox" posture as `marketplace` above.
    # Both ARE live now: `worker.worker_tick` passes them to
    # `integration_relay.service.drain_pending_outbox` on every tick, and
    # `worker.run_due_report_schedules` emits through this notifier too.
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
    # 里程碑 B' spec §7 - marketplace_api's own append-only fetch audit table,
    # written with svc_marketplace's INSERT+SELECT-only credentials. Optional,
    # same shape as the other per-module factories above; when it is None the
    # marketplace router logs a warning and still returns the polled result
    # (the audit write must never be able to fail a fetch - spec §7).
    marketplace_session_factory: SessionFactory | None = None
    # 里程碑 B' spec §6.3 - per-service-account polling budget for /v1/market
    # (Settings.marketplace_rate_limit_per_min). Lives on the runtime rather
    # than being re-read from the environment per request, same as
    # scan_deadline_s below.
    marketplace_rate_limit_per_min: int = 120
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
    # orchestration.service.sweep_sandbox_wait_timeouts' own `wait_timeout_s`
    # (D2, 2026-07-27) - how long the gate waits for the sandbox engines
    # before deciding without them. Deliberately defaults to the same value as
    # `scan_deadline_s`: the sandbox subprocesses are themselves bounded by
    # that budget, so waiting longer than it cannot produce more results.
    sandbox_wait_timeout_s: float = 300.0
    # Whether this deployment has an internal LLM endpoint (Settings.
    # vllm_base_url / SKILLSCAN_VLLM_BASE_URL - one ConfigMap key the monolith
    # and the engine-runner both consume). NOT the URL: this process never
    # calls it (INV-11 - the monolith parses no untrusted content), it only
    # needs to know whether the engine-runner will have constructed its
    # LLM-gated sandbox engines, because the gate must not wait on an engine
    # that cannot report. See worker._active_sandbox_waited_engines. False by
    # default, which waits for less rather than stalling every scan on an
    # engine that was never going to answer.
    sandbox_llm_configured: bool = False
    # Task 12 (2026-07-29, milestone C engine-management): ONE `SecurityMetrics`
    # instance for this process's whole lifetime, exposed at `GET /metrics`
    # (`gateway/infra_router.py`). `default_factory` (not `None`-then-build,
    # unlike the optional session factories above) so every ScanRuntime -
    # production or a test's hand-built one - always has a real, working
    # registry; SecurityMetrics()'s own default gives each instance a FRESH
    # CollectorRegistry, so tests that build several ScanRuntimes never share
    # counters. Task 13 (2026-07-29) wired real production writers for eight
    # of the nine collectors - see `infra_router.metrics`'s comment for which
    # readings are now honest and which are still "unmeasured"
    # (`sandbox_egress_denied_total` has no writer and cannot get one from
    # Python). Every writer reaches this object through the runtime it is
    # already holding; the ONE exception is `common.pinned_dns`, a process-
    # wide socket patch with no runtime in scope, which `main.create_app`
    # points at THIS instance via `set_rebinding_observer` rather than
    # building a second registry nothing would scrape.
    security_metrics: SecurityMetrics = field(default_factory=SecurityMetrics)

    async def current_toolchain_digest(self) -> str:
        """INV-7's `toolchain_digest` for the engines and policy THIS process
        would actually run right now - the value `orchestration.submit_scan`
        would stamp on a scan_job submitted this instant.

        ONE definition, on the object that holds both inputs. It used to be
        recomputed inline wherever it was needed (`reeval.router`, and the
        worker's digest-advance step would have been a third), which is the
        "second registry not updated" shape this codebase keeps paying for:
        `policy.version` changes on every hot-reload, so a call site that
        passed a stale policy would silently disagree with the one that
        stamped the job, and every skill would read as permanently stale.

        `cache_policy_version`, NOT `version` (milestone C Tasks 5 and 11): the
        policy's weights move the persisted score and its thresholds move the
        persisted verdict, neither of which moves the version string. This is
        also the expression that decides what `reeval` calls STALE, so binding
        the policy here is what makes a threshold edit reach the published
        inventory at all.

        ENABLED ENGINES, NOT ALL OF THEM, and async for exactly that reason
        (2026-07-29, milestone C correctness review N-3). This hashed
        `self.engine_metadatas` while every writer of a persisted digest -
        `gateway.router.create_scan`, `marketplace_api.router`, and the
        `skill_version.toolchain_digest` write beside them - hashes
        `filter_enabled_engines(...)` of the same list. The two agree only
        while nothing is admin-disabled, and the docstring here used to claim
        they were "asserted equal in apps/monolith/tests/test_gate_service.py",
        a file that contained no reference to either. The guard now exists, in
        `apps/monolith/tests/test_toolchain_digest_agreement.py`, and it
        disables an engine first - which is the only state in which the claim
        was ever worth making.

        WHY THE ENABLED SET IS THE CORRECT ONE, rather than making the writers
        match this. This value has no writers at all: it exists only to be
        COMPARED against `scan_job.toolchain_digest`, `skill_version.
        toolchain_digest` and the `cache_key` built from them, every one of
        which is written from the enabled set. A comparison value that cannot
        equal what was recorded is simply wrong, and it failed in the
        fail-OPEN direction on the cache: `cache_key` is content+toolchain, so
        a digest that ignores the disabled set would let a verdict reached
        with an engine that no longer runs be served for a submission made
        after it was switched off. Disabling an engine genuinely changes what
        a scan does, so it must genuinely change the toolchain's identity.

        Reads Redis (`filter_enabled_engines`) rather than a cached snapshot:
        the disabled set is shared fleet-wide precisely so an admin action
        applies to every replica at once, and a per-process cache of it is the
        same "second registry" defect the paragraph above is about.
        """
        # Imported here, not at module scope: `admin.router` imports THIS
        # module for `ScanRuntime`, so a module-level import of anything under
        # `admin` that transitively reaches it would close a cycle.
        # `engine_registry` does not import gateway today - this keeps that
        # from becoming a constraint on it.
        from monolith.modules.admin.engine_registry import filter_enabled_engines

        enabled = await filter_enabled_engines(self.redis, self.engine_metadatas)
        return toolchain_digest(enabled, self.policy.cache_policy_version)
