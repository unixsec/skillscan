"""§9 /v1 API endpoints - M3 wires `POST/GET /v1/scans` end-to-end;
allowlist/gate policy land in M6, reconciliation/rescan-trigger in M7,
inventory/admin/reports/breakglass in M8 (§16) - see each module's own router
file (admin_router.py, inventory_router.py) for the rest of §9.

SECURITY: every route requires authentication via M2's `require_role()`
(fail-closed 401/403, enforced server-side - never trust a client-supplied
role). Object-level authorization (a submitter may only read their OWN scans;
approver/auditor/admin may read any) is enforced here in the handler, never
left to the frontend (FR-API defense against IDOR). Every state-changing
route also depends on `require_csrf` (coding spec §16.1 INV-16) - a no-op for
bearer-token (M2M/API) callers, enforced for cookie-authenticated (BFF)
callers.
"""

from __future__ import annotations

import json
import time
from typing import Any

from engine_runner.normalizer import UnpackRejected, unpack_hardened
from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile
from skillscan_core import TrustTier
from skillscan_core import content_hash as compute_content_hash
from skillscan_core import toolchain_digest as compute_toolchain_digest
from sqlalchemy import select

from monolith.modules.admin.engine_registry import filter_enabled_engines
from monolith.modules.gate.models import VerdictRow
from monolith.modules.gateway.auth.dependencies import require_csrf, require_role
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.inventory.lifecycle import InvalidTransitionError
from monolith.modules.inventory.models import SkillVersionRow
from monolith.modules.inventory.service import register_skill_version, transition_skill
from monolith.modules.orchestration.models import ScanJob, ScanResultRow
from monolith.modules.orchestration.service import submit_scan
from monolith.modules.reeval.reconciliation import (
    MarketplacePublishedEntry,
    PushEventVerificationError,
    verify_push_event_signature,
)
from monolith.modules.reeval.service import apply_push_event
from monolith.modules.reporting import service as reporting_service

from .runtime import ScanRuntime

router = APIRouter(prefix="/v1")

# NOTE: hoisted so Depends(...) below wraps a plain reference, not a nested
# call - matches the convention established in auth/dependencies tests (ruff
# B008 flags function calls in argument defaults otherwise).
_submitter_or_above = require_role()

_REVIEWER_ROLES = ("approver", "admin", "auditor")


def get_scan_runtime(request: Request) -> ScanRuntime:
    runtime: ScanRuntime = request.app.state.scan
    return runtime


@router.post("/scans", status_code=202, dependencies=[Depends(require_csrf)])
async def create_scan(
    package: UploadFile,
    skill_id: str | None = Form(default=None, max_length=255),
    trust_tier: str | None = Form(default=None),
    session: SessionContext = Depends(_submitter_or_above),
    runtime: ScanRuntime = Depends(get_scan_runtime),
) -> dict[str, str]:
    # Optional inventory registration (coding spec §7.1/§16.2, FR-INV): a
    # submission that names a skill_id registers skill + skill_version and
    # enters the lifecycle state machine (submitted -> scanning here; the
    # background worker drives scanning -> published/review_pending off the
    # verdict). Anonymous submissions (no skill_id) scan exactly as before.
    tier = runtime.default_trust_tier
    if trust_tier is not None:
        try:
            tier = TrustTier(trust_tier)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"invalid trust_tier {trust_tier!r}, expected one of "
                f"{[t.value for t in TrustTier]}",
            ) from exc
    raw = await package.read()
    try:
        files = unpack_hardened(raw)
    except UnpackRejected as exc:
        # SECURITY: hardening rejections (oversized/malformed/traversal/
        # symlink/decompression-bomb) are all a 400, and the specific reason
        # is safe to return here - it describes the upload the caller just
        # made, not any internal system state (FR-API-060 only forbids
        # leaking internals, not caller-supplied-input diagnostics).
        raise HTTPException(status_code=400, detail=f"invalid package archive: {exc}") from exc

    # coding spec §9 Admin·Engines: an admin-disabled engine (never a required
    # floor engine - engine_registry.set_engine_enabled enforces that INV-1
    # invariant at write time) takes effect on the NEXT submission.
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
            deadline_s=runtime.scan_deadline_s,
        )

    if skill_id:
        if runtime.inventory_session_factory is None:
            raise HTTPException(status_code=503, detail="inventory module is not configured")
        c_hash = compute_content_hash(files)
        t_digest = compute_toolchain_digest(enabled_engine_metadatas, runtime.policy.version)
        async with runtime.inventory_session_factory() as inv_session, inv_session.begin():
            known = await inv_session.get(SkillVersionRow, c_hash)
            if known is None:
                try:
                    await register_skill_version(
                        inv_session,
                        skill_id=skill_id,
                        source="web-upload",
                        trust_tier=tier.value,
                        content_hash=c_hash,
                        toolchain_digest=t_digest,
                        declared_perms=None,
                        operator=session.subject,
                    )
                    await transition_skill(
                        inv_session,
                        skill_id=skill_id,
                        to_state="scanning",
                        reason=f"scan {scan_id} submitted",
                        actor=session.subject,
                        content_hash=c_hash,
                    )
                except InvalidTransitionError as exc:
                    # SECURITY (found live 2026-07-24 via a real clawhub.ai
                    # re-import batch): re-submitting new content for a
                    # skill_id that's already published/quarantined/retired
                    # is a real, expected caller scenario (a duplicate or
                    # re-run submission), not a system fault - it must not
                    # crash as an unhandled 500. Same FR-API-060 posture as
                    # the sibling 409 below: this message only describes
                    # skill_id's OWN lifecycle state, never internal system
                    # state, so it's safe to return verbatim.
                    raise HTTPException(
                        status_code=409,
                        detail=f"cannot submit a new scan for skill {skill_id!r}: {exc}",
                    ) from exc
            elif str(known.skill_id) != skill_id:
                # SECURITY: the same content is already registered under a
                # DIFFERENT skill_id - never silently re-attribute it.
                raise HTTPException(
                    status_code=409,
                    detail=f"this content is already registered to skill {str(known.skill_id)!r}",
                )
    return {"scan_id": scan_id}


@router.get("/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    session: SessionContext = Depends(_submitter_or_above),
    runtime: ScanRuntime = Depends(get_scan_runtime),
) -> dict[str, Any]:
    async with runtime.orchestration_session_factory() as db_session:
        job = (
            await db_session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
        ).scalar_one_or_none()
        if job is None:
            raise HTTPException(status_code=404, detail="scan not found")
        # SECURITY: object-level authz (IDOR defense) - a plain submitter may
        # only read their own scans; approver/auditor/admin may read any. A
        # 404 (not 403) so existence of another user's scan_id isn't leaked.
        if job.submitter != session.subject and not session.has_role(*_REVIEWER_ROLES):
            raise HTTPException(status_code=404, detail="scan not found")

        result_row = (
            await db_session.execute(select(ScanResultRow).where(ScanResultRow.scan_id == scan_id))
        ).scalar_one_or_none()

    async with runtime.gate_session_factory() as gate_session:
        verdict_row = (
            await gate_session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
        ).scalar_one_or_none()

    return {
        "scan_id": scan_id,
        "state": job.state,
        "submitter": job.submitter,
        "verdict": verdict_row.verdict if verdict_row is not None else None,
        "severity": result_row.severity if result_row is not None else None,
        "findings": result_row.findings if result_row is not None else [],
        "provenance": result_row.provenance if result_row is not None else [],
        "required_ok": result_row.required_ok if result_row is not None else None,
        "hard_gate_hits": result_row.hard_gate_hits if result_row is not None else [],
        "reasons": verdict_row.reasons if verdict_row is not None else [],
        "sarif_ref": f"/v1/scans/{scan_id}/sarif",
    }


@router.get("/scans/{scan_id}/sarif")
async def get_scan_sarif(
    scan_id: str,
    session: SessionContext = Depends(_submitter_or_above),
    runtime: ScanRuntime = Depends(get_scan_runtime),
) -> dict[str, Any]:
    # SECURITY: same object-level authz (IDOR defense) as GET /v1/scans/{scan_id}
    # above - a 404 (not 403) so existence of another user's scan_id isn't leaked.
    # This lookup happens against orchestration's own ScanJob table rather than
    # trusting reporting.export_sarif_for_scans (which has no notion of
    # ownership - it just returns an empty SARIF document for any scan_id with
    # no matching row, decided or not, own or not).
    async with runtime.orchestration_session_factory() as db_session:
        job = (
            await db_session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
        ).scalar_one_or_none()
        if job is None:
            raise HTTPException(status_code=404, detail="scan not found")
        if job.submitter != session.subject and not session.has_role(*_REVIEWER_ROLES):
            raise HTTPException(status_code=404, detail="scan not found")

    if runtime.reporting_session_factory is None:
        # SECURITY: fail-closed - a misconfigured deployment (reporting module
        # not wired) must never look like "no data", it must be an explicit 500.
        raise HTTPException(status_code=500, detail="reporting module is not configured")
    async with runtime.reporting_session_factory() as reporting_session:
        return await reporting_service.export_sarif_for_scans(reporting_session, [scan_id])


@router.get("/scans")
async def list_scans(
    state: str | None = None,
    limit: int = 50,
    offset: int = 0,
    session: SessionContext = Depends(_submitter_or_above),
    runtime: ScanRuntime = Depends(get_scan_runtime),
) -> dict[str, Any]:
    bounded_limit = max(1, min(limit, 200))
    stmt = select(ScanJob)
    # SECURITY: object-level authz - a plain submitter only ever sees their own
    # scans in the list; approver/auditor/admin see all.
    if not session.has_role(*_REVIEWER_ROLES):
        stmt = stmt.where(ScanJob.submitter == session.subject)
    if state is not None:
        stmt = stmt.where(ScanJob.state == state)
    stmt = stmt.order_by(ScanJob.created_at.desc()).limit(bounded_limit).offset(max(0, offset))

    async with runtime.orchestration_session_factory() as db_session:
        jobs = (await db_session.execute(stmt)).scalars().all()

    scan_ids = [j.scan_id for j in jobs]
    content_hashes = [j.content_hash for j in jobs]

    # SECURITY (object-level authz already applied above, via `jobs`): these
    # two lookups are scoped to exactly the scan_ids/content_hashes already
    # authorized - never a broader query. Separate sessions because verdict
    # and inventory are separate modules with their own least-privilege DB
    # grants (same reason GET /v1/scans/{scan_id} above does two queries
    # instead of one JOIN - gate and inventory aren't in the same schema/user).
    verdicts_by_scan: dict[str, str] = {}
    if scan_ids:
        async with runtime.gate_session_factory() as gate_session:
            rows = (
                await gate_session.execute(
                    select(VerdictRow.scan_id, VerdictRow.verdict).where(
                        VerdictRow.scan_id.in_(scan_ids)
                    )
                )
            ).all()
        verdicts_by_scan = dict(rows)

    skill_ids_by_hash: dict[str, str] = {}
    if content_hashes and runtime.inventory_session_factory is not None:
        async with runtime.inventory_session_factory() as inv_session:
            rows = (
                await inv_session.execute(
                    select(SkillVersionRow.content_hash, SkillVersionRow.skill_id).where(
                        SkillVersionRow.content_hash.in_(content_hashes)
                    )
                )
            ).all()
        skill_ids_by_hash = dict(rows)

    return {
        "items": [
            {
                "scan_id": j.scan_id,
                "state": j.state,
                "submitter": j.submitter,
                "content_hash": j.content_hash,
                "verdict": verdicts_by_scan.get(j.scan_id),
                "skill_id": skill_ids_by_hash.get(j.content_hash),
                "skill_name": j.skill_name,
            }
            for j in jobs
        ]
    }


@router.post("/marketplace/webhook", status_code=202)
async def marketplace_push_webhook(
    request: Request,
    runtime: ScanRuntime = Depends(get_scan_runtime),
) -> dict[str, str]:
    """coding spec §11.6/SAD §4.3 push reconciliation. SECURITY: this endpoint
    is authenticated by the signed-event HMAC below, NOT `require_role()` -
    the caller is an external marketplace system, not one of our own IdP-
    authenticated users/services (mTLS is the OTHER strong-auth option SAD
    §4.3 allows; that's an ingress/network-layer control, out of this
    handler's scope). Verification happens over the RAW request body bytes,
    before any JSON parsing, since HMAC must cover exactly what the sender
    signed - a re-serialized copy could differ byte-for-byte even with
    identical field values.
    """
    if runtime.push_hmac_secret is None:
        # SECURITY: push disabled entirely - behave as if the route doesn't
        # exist rather than confirming/denying based on signature validity.
        raise HTTPException(status_code=404, detail="not found")

    signature_header = request.headers.get("X-Marketplace-Signature")
    timestamp_header = request.headers.get("X-Marketplace-Timestamp")
    if not signature_header or not timestamp_header:
        raise HTTPException(status_code=401, detail="missing signature/timestamp header")
    try:
        timestamp = int(timestamp_header)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid timestamp header") from exc

    body = await request.body()
    try:
        verify_push_event_signature(
            body=body,
            signature_header=signature_header,
            timestamp=timestamp,
            hmac_secret=runtime.push_hmac_secret,
            replay_window_s=runtime.push_replay_window_s,
            now=time.time(),
        )
    except PushEventVerificationError as exc:
        raise HTTPException(status_code=401, detail="signature verification failed") from exc

    try:
        payload = json.loads(body)
        entry = MarketplacePublishedEntry(
            content_hash=str(payload["content_hash"]), skill_id=str(payload["skill_id"])
        )
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        # SECURITY: signature verified but the body itself doesn't match the
        # expected shape - this is a caller-input problem (safe to describe),
        # not a forged/replayed event (already ruled out above).
        raise HTTPException(status_code=400, detail=f"invalid webhook payload: {exc}") from exc

    if runtime.marketplace is None or runtime.reeval_session_factory is None:
        # SECURITY: signature verified but no marketplace/reeval wiring is
        # configured in this deployment - accept (the event WAS authentic)
        # but there is nothing to act on yet; fail-visible via the response
        # body, not a fabricated "processed" result.
        return {"status": "accepted_but_not_configured"}

    async with (
        runtime.gate_session_factory() as gate_session,
        runtime.reeval_session_factory() as reeval_session,
        reeval_session.begin(),
    ):
        outcome = await apply_push_event(
            entry,
            gate_session=gate_session,
            reeval_session=reeval_session,
            marketplace=runtime.marketplace,
            push_auto_quarantine_enabled=runtime.push_auto_quarantine_enabled,
        )
    return {"status": "processed", "result": outcome.result.value}


@router.get("/me")
async def get_current_session(
    session: SessionContext = Depends(_submitter_or_above),
) -> dict[str, Any]:
    """SECURITY: UX-only ("frontend隐藏仅UX", coding spec §9) - the frontend
    uses this to decide what nav/actions to SHOW, never as an authorization
    decision itself (every route independently re-checks via require_role)."""
    return {
        "subject": session.subject,
        "roles": sorted(session.roles),
        "tier": session.tier.value,
    }
