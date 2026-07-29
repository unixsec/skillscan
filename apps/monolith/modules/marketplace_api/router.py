"""Marketplace-facing endpoints (里程碑 B' spec §4) - the pull-model contract.

The marketplace submits through `POST /v1/market/scans` and then polls
`GET /v1/market/scans/{scan_id}`. Both live under their own `/v1/market`
prefix, entirely separate from the console's `/v1/scans` (spec §3.1 rule 3):
two audiences, two surfaces, so an internal refactor of the console's response
shape can never become a breaking change for an external integrator.

SECURITY / ARCHITECTURE - the four rules this file exists to enforce:

1. **Nothing internal leaks out.** Every response body is `views.project_scan`'s
   output and nothing else - never an ORM row, never an internal dataclass.
   The projection is a WHITELIST (see views.py), so a new internal column is
   invisible externally by default. One `return job` here would make the
   internal model the contract, permanently.

2. **No caller-supplied `trust_tier`.** That value decides the BLOCK threshold
   (spec §4.1), so accepting it would let a caller submitting untrusted public
   content declare itself `internal` and downgrade a HIGH finding that should
   have blocked. The tier comes from `session.tier`, resolved per service
   account by `gateway.auth.m2m.resolve_grant`. A caller that sends the field
   anyway gets a 400 rather than silent removal - silently ignoring it leaves
   them believing their setting took effect.

3. **Object-level authz answers 404, not 403.** A 403 on someone else's scan
   confirms that scan_id exists, which is enough to enumerate the console's
   submissions. Same shape as `gateway/router.py`'s `get_scan`.

4. **The fetch audit can never fail a fetch.** `_record_fetch` swallows
   everything and logs - same fail-soft posture as `integration_relay.siem`'s
   adapter, and for the same reason: the polled result is already decided and
   signed, so an audit-sink problem must not be able to withhold it.

This module holds no business logic and imports no other module's ORM classes
(scripts/check_import_boundaries.py). Scan/verdict data arrives through the
owning modules' own service-layer accessors, already reduced to plain dicts.
"""

from __future__ import annotations

import datetime
from typing import Any

from common.log import get_logger
from engine_runner.normalizer import UnpackRejected, unpack_hardened
from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile

from monolith.modules.admin.engine_registry import filter_enabled_engines
from monolith.modules.gate.policy import tier_direction
from monolith.modules.gate.service import get_verdict_view
from monolith.modules.gateway.auth.dependencies import require_csrf, require_role
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.orchestration.service import (
    SubmissionChannel,
    get_scan_result_view,
    get_scan_state_and_tier,
    is_scan_submitter,
    submit_scan,
    submitter_attribution,
)

from . import views
from .models import MarketplaceFetchLogRow
from .ratelimit import check_rate_limit

router = APIRouter(prefix="/v1/market", tags=["marketplace"])

_logger = get_logger("skillscan.marketplace_api.router")

# spec §4: submit needs `scan:submit`, polling needs `scan:read`. Both are
# granted PER SERVICE ACCOUNT (m2m.M2MGrant) - an identity that was never
# configured keeps the pre-2026-07-28 default of `scan:submit` only, so this
# module cannot hand any existing caller a capability it did not already have.
_SUBMIT_SCOPE = "scan:submit"
_READ_SCOPE = "scan:read"

# NOTE: hoisted so `Depends(...)` below wraps a plain reference rather than a
# nested call - the convention gateway/router.py established (ruff B008).
_authenticated = require_role()


def _get_scan_runtime(request: Request) -> ScanRuntime:
    runtime: ScanRuntime = request.app.state.scan
    return runtime


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


async def _rate_limited_session(
    session: SessionContext = Depends(_authenticated),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> SessionContext:
    """Authentication plus the per-service-account request budget (spec §6.3).

    Applied to the WHOLE `/v1/market` surface, not just polling: the budget is
    "requests per minute per service account", and leaving submission
    unmetered would leave the more expensive endpoint of the two uncapped.

    Counted BEFORE the per-endpoint scope check on purpose, so probing for
    scopes one does not hold is itself rate-limited.

    The 429 carries `Retry-After` (seconds). It is the penalty half of spec
    §6.3; `poll_after_ms` in the response body is the guidance half - a
    well-behaved client never reaches this path.
    """
    retry_after = await check_rate_limit(
        runtime.redis,
        service_account=session.subject,
        limit_per_min=runtime.marketplace_rate_limit_per_min,
    )
    if retry_after is not None:
        raise HTTPException(
            status_code=429,
            detail="request rate limit exceeded for this service account",
            headers={"Retry-After": str(retry_after)},
        )
    return session


def _require_scope(session: SessionContext, scope: str) -> None:
    # SECURITY: 403 (authenticated but not permitted), distinct from the 404 a
    # foreign scan_id gets - the scope a caller holds is its OWN configuration,
    # so naming it leaks nothing about anyone else's data.
    if scope not in session.scopes:
        raise HTTPException(
            status_code=403, detail=f"this service account is not granted the {scope!r} scope"
        )


async def _record_fetch(
    runtime: ScanRuntime, *, scan_id: str, service_account: str, projected: dict[str, Any]
) -> None:
    """Append one `marketplace_fetch_log` row (spec §7): what we told whom, when.

    SECURITY / DESIGN: fail-soft, exactly like `integration_relay.siem`'s
    adapter. By the time this runs the verdict has already been decided and
    signed, and the response body is already built - a full disk, a revoked
    grant, or a dropped connection on the audit sink must degrade to a logged
    error, never to a withheld or failed poll. The inverse (blocking the
    marketplace from reading a BLOCK verdict because a log write failed) would
    be a strictly worse security outcome than the missing audit row.

    The write IS awaited rather than dispatched to a background task: what
    spec §7 requires is that it cannot fail the response, and swallowing the
    exception is what delivers that. An un-awaited task would additionally be
    able to disappear at shutdown, trading a bounded latency cost for silently
    lost audit records.
    """
    if runtime.marketplace_session_factory is None:
        _logger.warning(
            "marketplace fetch audit is not configured - this fetch went unrecorded",
            extra={
                "context": {
                    "metric": "marketplace_fetch_audit_unconfigured",
                    "scan_id": scan_id,
                    "service_account": service_account,
                }
            },
        )
        return
    verdict_shown = projected.get("verdict")
    try:
        async with runtime.marketplace_session_factory() as db_session, db_session.begin():
            db_session.add(
                MarketplaceFetchLogRow(
                    scan_id=scan_id,
                    service_account=service_account,
                    fetched_at=_naive_utcnow(),
                    status_shown=str(projected["status"]),
                    verdict_shown=None if verdict_shown is None else str(verdict_shown),
                )
            )
    except Exception:
        _logger.exception(
            "marketplace fetch audit write failed - the polled result was still returned",
            extra={
                "context": {
                    "metric": "marketplace_fetch_audit_write_failed",
                    "scan_id": scan_id,
                    "service_account": service_account,
                }
            },
        )


@router.post("/scans", status_code=202, dependencies=[Depends(require_csrf)])
async def submit_marketplace_scan(
    request: Request,
    package: UploadFile,
    trust_tier: str | None = Form(default=None),
    session: SessionContext = Depends(_rate_limited_session),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, str]:
    """Submit a package for scanning. Response is `{"scan_id": ...}` only.

    This endpoint exists so the marketplace submits under the SAME identity it
    later polls with - without that, §6.2's "you may only read your own scans"
    has nothing to compare against (spec §4).

    Deliberately narrower than the console's `POST /v1/scans`: no `skill_id`
    and therefore no inventory-lifecycle side effects. Registering a skill and
    driving its lifecycle is an internal, human-reviewed workflow; the external
    contract is scan-in, verdict-out.
    """
    _require_scope(session, _SUBMIT_SCOPE)
    # SECURITY (spec §4.1, constraint 2 in this module's docstring): reject,
    # never ignore. The query-string is checked too - a `?trust_tier=internal`
    # would otherwise be dropped with no signal at all, which is the exact
    # false-confidence failure the 400 exists to prevent.
    if trust_tier is not None or "trust_tier" in request.query_params:
        raise HTTPException(
            status_code=400,
            detail=(
                "trust_tier is determined server-side from the calling service "
                "account's configuration and must not be supplied by the caller"
            ),
        )

    raw = await package.read()
    try:
        files = unpack_hardened(raw)
    except UnpackRejected as exc:
        # SECURITY (FR-API-060): the reason describes the caller's OWN upload,
        # never internal state - safe to return verbatim, same as the console's
        # equivalent rejection.
        raise HTTPException(status_code=400, detail=f"invalid package archive: {exc}") from exc

    # Same admin engine-disable filter the console applies: beyond honouring
    # the toggle, `submit_scan` derives `toolchain_digest` (and thus the
    # single-flight `cache_key`) from this set, so an unfiltered set here would
    # fork identical content into two scan_jobs depending on which door it
    # arrived through.
    enabled_engine_metadatas = await filter_enabled_engines(runtime.redis, runtime.engine_metadatas)
    async with runtime.orchestration_session_factory() as db_session, db_session.begin():
        scan_id = await submit_scan(
            db_session,
            runtime.redis,
            runtime.blobstore,
            files=files,
            submitter=session.subject,
            engine_metadatas=enabled_engine_metadatas,
            policy=runtime.policy,
            # SECURITY: the tier this identity was GRANTED (m2m.M2MGrant.tier,
            # PUBLIC for any unconfigured account - the strictest), persisted
            # onto the scan by submit_scan so the worker judges by it long
            # after this session is gone. Never runtime.default_trust_tier,
            # and never anything the caller said.
            trust_tier=session.tier,
            # 里程碑 F Task 12: this handler IS the marketplace channel, and
            # this is the only moment that is knowable - `session.is_machine`
            # does not outlive the request. Recorded on this caller's OWN
            # `scan_submitter` row, so a package the console already scanned
            # (dedup: the same bytes collapse onto the existing scan_job) ends
            # up with BOTH channels on record rather than only the first one.
            # Never inferred later from the service-account NAME - see
            # `SubmissionChannel`'s docstring.
            source=SubmissionChannel.MARKETPLACE,
            # 里程碑 F Task 14: the tier THIS service account asked for, on its
            # OWN `scan_submitter` row. Same value as `trust_tier` above - a
            # marketplace caller cannot supply a tier at all (400 above), so
            # its granted tier IS its request - but a different fate: this one
            # is recorded even when dedup hands it a scan_job the console
            # already created and a verdict reached at the console's tier.
            #
            # This is the dangerous direction in practice. An unconfigured
            # service account gets PUBLIC, the STRICTEST tier
            # (`policies/gate/v1.yaml` blocks it at HIGH), while the console
            # commonly submits at `internal` (blocks only at CRITICAL). A
            # marketplace poll of content the console scanned first therefore
            # returns a verdict made under a more permissive ruleset than this
            # caller asked for, and until this column that was invisible.
            requested_trust_tier=session.tier,
            deadline_s=runtime.scan_deadline_s,
        )
    return {"scan_id": scan_id}


@router.get("/scans/{scan_id}")
async def get_marketplace_scan(
    scan_id: str,
    session: SessionContext = Depends(_rate_limited_session),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    """Poll one scan's status and result (spec §4/§5).

    Returns `views.project_scan`'s output verbatim - three external states,
    three-valued verdict, whitelisted findings. `failed` reports as
    `COMPLETED` + `BLOCK` + `fail_closed: true`, never as a failure: the system
    made and signed a real conservative decision, and calling that "failed"
    would invite a retry that bypasses it (spec §5.1).
    """
    _require_scope(session, _READ_SCOPE)

    async with runtime.orchestration_session_factory() as db_session:
        identity = await get_scan_state_and_tier(db_session, scan_id=scan_id)
        # SECURITY (spec §6.2): unknown scan and someone else's scan are the
        # SAME 404, deliberately indistinguishable. Note there is no
        # reviewer-role escape hatch here (unlike the console's get_scan):
        # every caller on this surface is a machine identity reading back its
        # own submissions, so "read anyone's scan" has no legitimate use.
        if identity is None:
            raise HTTPException(status_code=404, detail="scan not found")
        internal_state, judged_at_tier = identity
        # SECURITY (C2): membership in `scan_submitter`, NOT equality against
        # `ScanJob.submitter`. `submit_scan` is single-flight on content +
        # toolchain, so a marketplace submission of a package the console
        # already scanned is handed that existing scan_job - which still names
        # the console user. Comparing against it returned 404 for a scan_id we
        # had just issued to this very caller, permanently (re-submitting
        # returns the same id), and §6.2 makes that 404 indistinguishable from
        # "no such scan" - so the marketplace could not even diagnose it.
        if not await is_scan_submitter(db_session, scan_id=scan_id, subject=session.subject):
            raise HTTPException(status_code=404, detail="scan not found")
        # 里程碑 F Task 18: the tier THIS service account asked for, off its OWN
        # `scan_submitter` row - so the response can say whether the verdict it
        # is handing back was adjudicated under the ruleset that was requested.
        # Read AFTER the authorization check above, never as part of it: this
        # is the same `submitter_attribution` producer the console's three
        # endpoints use, and it is a RESPONSE shape. Authorization stays on
        # `is_scan_submitter`, the accessor built for it, so that a later change
        # to the attribution shape cannot become a change to who may read.
        #
        # SECURITY: the full submitter list this returns must NOT reach the
        # marketplace - §6.2 gives a machine identity no business knowing which
        # console user also submitted the same bytes. Only this caller's own
        # entry is read here, and `views.project_scan`'s whitelist is what makes
        # that structural rather than a promise: nothing that is not in
        # EXTERNAL_TOP_LEVEL_FIELDS can leave, however this local dict grows.
        attribution = (await submitter_attribution(db_session, scan_ids=[scan_id])).get(scan_id, {})
        requested_tier = next(
            (
                entry["requested_trust_tier"]
                for entry in attribution.get("submitter_sources", ())
                if entry["submitter"] == session.subject
                and entry["requested_trust_tier"] is not None
            ),
            None,
        )
        result_row = await get_scan_result_view(db_session, scan_id=scan_id)

    # Separate session: gate's tables are behind gate's own least-privilege
    # MySQL user, same reason the console's get_scan does two queries rather
    # than one join.
    async with runtime.gate_session_factory() as gate_session:
        verdict_row = await get_verdict_view(gate_session, scan_id=scan_id)

    projected = views.project_scan(
        scan_id=scan_id,
        internal_state=internal_state,
        verdict_row=verdict_row,
        result_row=result_row,
        judged_at_tier=judged_at_tier,
        requested_tier=requested_tier,
        # Computed here rather than in `views`, which is pure by contract: the
        # answer depends on `GatePolicy.block_threshold`, since strictness lives
        # in `tier_block_overrides` and not in the order of the tier names.
        tier_direction=tier_direction(
            runtime.policy, requested=requested_tier, judged=judged_at_tier
        ),
    )
    await _record_fetch(
        runtime, scan_id=scan_id, service_account=session.subject, projected=projected
    )
    return projected
