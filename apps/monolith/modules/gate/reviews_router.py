"""`GET /v1/reviews`, `POST /v1/reviews/{scan_id}` (coding spec §9).

SECURITY: approver+ only; the decision endpoint additionally enforces SoD
(reviewer != submitter, `reviews.submit_review_decision`) and CSRF
(state-changing, coding spec §16.1 INV-16).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select

from monolith.modules.gateway.auth.dependencies import require_csrf, require_role
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.inventory.models import SkillVersionRow
from monolith.modules.orchestration.models import ScanJob

from .reviews import (
    InvalidDecisionError,
    NotPendingReviewError,
    ReviewNotFoundError,
    SodViolationError,
    submit_review_decision,
)
from .service import list_pending_reviews

router = APIRouter(prefix="/v1/reviews")

_reader_or_decider = require_role("approver", "admin")


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
    if scan_ids:
        async with runtime.orchestration_session_factory() as orch_session:
            result = await orch_session.execute(
                select(ScanJob.scan_id, ScanJob.submitter).where(ScanJob.scan_id.in_(scan_ids))
            )
            rows = result.tuples().all()
        submitters_by_scan = dict(rows)

    skill_ids_by_hash: dict[str, str] = {}
    if content_hashes and runtime.inventory_session_factory is not None:
        async with runtime.inventory_session_factory() as inv_session:
            result = await inv_session.execute(
                select(SkillVersionRow.content_hash, SkillVersionRow.skill_id).where(
                    SkillVersionRow.content_hash.in_(content_hashes)
                )
            )
            rows = result.tuples().all()
        skill_ids_by_hash = dict(rows)

    return {
        "scans": [
            {
                "scan_id": v.scan_id,
                "content_hash": v.content_hash,
                "verdict": v.verdict,
                "reasons": v.reasons,
                "issued_at": v.issued_at.isoformat(),
                "skill_id": skill_ids_by_hash.get(v.content_hash),
                "submitter": submitters_by_scan.get(v.scan_id),
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
    try:
        async with (
            runtime.orchestration_session_factory() as orchestration_session,
            runtime.gate_session_factory() as gate_session,
            gate_session.begin(),
        ):
            verdict_row = await submit_review_decision(
                orchestration_session=orchestration_session,
                gate_session=gate_session,
                scan_id=scan_id,
                decision=body.decision,
                reviewer=session.subject,
                reason=body.reason,
                signer=runtime.signer,
            )
    except InvalidDecisionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SodViolationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ReviewNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except NotPendingReviewError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"scan_id": scan_id, "verdict": verdict_row.verdict}
