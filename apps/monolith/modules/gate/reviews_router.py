"""`GET /v1/reviews`, `POST /v1/reviews/{scan_id}` (coding spec §9).

SECURITY: approver+ only; the decision endpoint additionally enforces SoD
(reviewer != submitter, `reviews.submit_review_decision`) and CSRF
(state-changing, coding spec §16.1 INV-16).
"""

from __future__ import annotations

import contextlib
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select

from monolith.modules.gateway.auth.dependencies import require_csrf, require_role
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.inventory.lifecycle import LifecyclePosition, pending_review_is_superseded
from monolith.modules.inventory.models import SkillVersionRow
from monolith.modules.inventory.service import latest_lifecycle_positions
from monolith.modules.orchestration.models import ScanJob
from monolith.modules.orchestration.service import submitter_attribution

from .reviews import (
    InvalidDecisionError,
    NotPendingReviewError,
    ReviewNotFoundError,
    SodViolationError,
    SupersededReviewError,
    submit_review_decision,
)
from .service import list_pending_reviews

router = APIRouter(prefix="/v1/reviews")

_reader_or_decider = require_role("approver", "admin")

# 里程碑 F Task 16: what an entry with no `scan_submitter` rows renders as -
# empty lists, never the scalar first-submitter promoted into a one-element
# list. Same choice, and same reasoning, as `gateway.router._EMPTY_ATTRIBUTION`.
_EMPTY_ATTRIBUTION: dict[str, Any] = {
    "submitters": (),
    "submitter_sources": (),
    "source": (),
}


def _get_scan_runtime(request: Request) -> ScanRuntime:
    runtime: ScanRuntime = request.app.state.scan
    return runtime


class _ReviewDecisionBody(BaseModel):
    decision: str
    reason: str = ""


@router.get("")
async def list_reviews(
    session: SessionContext = Depends(_reader_or_decider),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    async with runtime.gate_session_factory() as db_session:
        pending = await list_pending_reviews(db_session)

    scan_ids = [v.scan_id for v in pending]
    content_hashes = [v.content_hash for v in pending]

    # SECURITY (object-level authz already applied by list_pending_reviews'
    # own REVIEW-verdict filter): these lookups are scoped to exactly the
    # scan_ids/content_hashes already selected, never a broader query. Same
    # two-separate-sessions shape as GET /v1/scans (gateway.router.list_scans)
    # and for the same reason - gate/orchestration/inventory are separate
    # modules with their own least-privilege DB grants.
    submitters_by_scan: dict[str, str] = {}
    # 里程碑 F Task 16: full attribution, in the SAME shape the scan detail and
    # scan list responses use - one function produces all three. This queue used
    # to show only the scalar `ScanJob.submitter`, the FIRST submitter, so on a
    # deduplicated scan an approver was reading one name out of several.
    #
    # The gap Task 16 reported here is CLOSED (Task 18): SoD in
    # `reviews.submit_review_decision` now refuses anyone in `scan_submitter`,
    # not only the scalar `ScanJob.submitter`, so a co-submitter deduplicated
    # onto an existing scan_job can no longer approve their own submission.
    # Showing every name here remains what makes the situation legible to a
    # human approver - it was never the enforcement.
    attribution: dict[str, dict[str, Any]] = {}
    if scan_ids:
        async with runtime.orchestration_session_factory() as orch_session:
            result = await orch_session.execute(
                select(ScanJob.scan_id, ScanJob.submitter).where(ScanJob.scan_id.in_(scan_ids))
            )
            rows = result.tuples().all()
            attribution = await submitter_attribution(orch_session, scan_ids=scan_ids)
        submitters_by_scan = dict(rows)

    skill_ids_by_hash: dict[str, str] = {}
    # I3 (2026-07-29): where each of those skills' lifecycles actually STANDS.
    # A REVIEW verdict survives `review_pending -> submitted`, so the queue was
    # listing entries for content the skill has already moved off - and a
    # decision on one of those is discarded by `worker.sync_lifecycle_tick`
    # (it acts only on `scanning`/`review_pending`), throwing the approver's
    # work away with no feedback. Read here, from the SAME session that already
    # resolves skill_id, and surfaced rather than silently hidden: an entry
    # that vanishes teaches an approver nothing.
    positions: dict[str, LifecyclePosition] = {}
    if content_hashes and runtime.inventory_session_factory is not None:
        async with runtime.inventory_session_factory() as inv_session:
            result = await inv_session.execute(
                select(SkillVersionRow.content_hash, SkillVersionRow.skill_id).where(
                    SkillVersionRow.content_hash.in_(content_hashes)
                )
            )
            rows = result.tuples().all()
            skill_ids_by_hash = dict(rows)
            positions = dict(
                await latest_lifecycle_positions(
                    inv_session, skill_ids=sorted(set(skill_ids_by_hash.values()))
                )
            )

    def _superseded(content_hash: str) -> bool:
        skill_id = skill_ids_by_hash.get(content_hash)
        position = positions.get(skill_id) if skill_id is not None else None
        return pending_review_is_superseded(position, review_content_hash=content_hash)

    return {
        "scans": [
            {
                "scan_id": v.scan_id,
                "content_hash": v.content_hash,
                "verdict": v.verdict,
                "reasons": v.reasons,
                "issued_at": v.issued_at.isoformat(),
                "skill_id": skill_ids_by_hash.get(v.content_hash),
                # The FIRST submitter, kept for compatibility. `submitters`
                # below is the authoritative list.
                "submitter": submitters_by_scan.get(v.scan_id),
                "superseded": _superseded(v.content_hash),
                # 里程碑 F Task 16: `submitters` / `submitter_sources` /
                # `source`, byte-for-byte the shape both scan endpoints return.
                **attribution.get(v.scan_id, _EMPTY_ATTRIBUTION),
            }
            for v in pending
        ]
    }


@router.post("/{scan_id}", dependencies=[Depends(require_csrf)])
async def decide_review(
    scan_id: str,
    body: _ReviewDecisionBody,
    session: SessionContext = Depends(_reader_or_decider),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    # I3: `submit_review_decision` needs an inventory read to tell whether the
    # skill has moved past the content under review. `None` when this
    # deployment wires no inventory module - the same condition `list_reviews`
    # above already tests, and in that deployment there is no lifecycle for a
    # decision to be discarded by.
    inventory_cm = (
        runtime.inventory_session_factory()
        if runtime.inventory_session_factory is not None
        else contextlib.nullcontext(None)
    )
    try:
        async with (
            runtime.orchestration_session_factory() as orchestration_session,
            inventory_cm as inventory_session,
            runtime.gate_session_factory() as gate_session,
            gate_session.begin(),
        ):
            verdict_row = await submit_review_decision(
                orchestration_session=orchestration_session,
                gate_session=gate_session,
                inventory_session=inventory_session,
                scan_id=scan_id,
                decision=body.decision,
                reviewer=session.subject,
                reason=body.reason,
                signer=runtime.signer,
                # The score this decision writes is recomputed under the
                # policy's `category_weights` (milestone C Task 5), so the
                # policy this process has loaded has to come along.
                policy=runtime.policy,
            )
    except InvalidDecisionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SodViolationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ReviewNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (NotPendingReviewError, SupersededReviewError) as exc:
        # Both are "conflict with the resource's current state" - one about the
        # verdict, one about the skill's lifecycle.
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"scan_id": scan_id, "verdict": verdict_row.verdict}
