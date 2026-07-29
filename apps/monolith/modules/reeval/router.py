"""`GET /v1/reeval`, `POST /v1/reeval/{skill_id}`, `GET /v1/reconciliation`
(coding spec §9/§11.7).

SECURITY: read routes require approver/admin (reeval) or admin/auditor
(reconciliation, matching the spec table exactly); the manual-trigger route
requires admin - triggering a rescan is a real compute-cost action, not a
read.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select

from monolith.modules.gateway.auth.dependencies import require_csrf, require_role
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.inventory.models import SkillLifecycleEventRow, SkillVersionRow
from monolith.modules.orchestration.drift import is_drift
from monolith.modules.orchestration.models import BaselineReadOnly

from .controller import is_stale, list_published_toolchain_statuses, trigger_rescans
from .service import list_reconciliation_outcomes

router = APIRouter(prefix="/v1")

# SECURITY: matches the exact literal `_quarantine_if_drifted` (apps/monolith/
# worker.py) writes into skill_lifecycle_event.reason on a real drift-triggered
# quarantine - used below to find genuine historical drift events, never a
# guess/heuristic over free-text reason strings.
#
# The `SUP-05` inside this string is FROZEN and must not be "corrected" to the
# catalog's current `SUPPLY-06` (2026-07-28). It is a persisted token, not a
# spec citation: every skill_lifecycle_event row ever written by
# `_quarantine_if_drifted` contains this exact prefix, and this constant is
# matched against them with `.startswith()`. Renaming it would silently drop
# every historical drift event from the reeval page - the rows would still be
# there, just invisible. Surrounding prose/comments were renumbered to
# SUPPLY-06; this value deliberately was not.
_DRIFT_REASON_PREFIX = "drift detected (SUP-05):"

_reeval_reader = require_role("approver", "admin")
_reeval_admin = require_role("admin")
_reconciliation_reader = require_role("admin", "auditor")


def _get_scan_runtime(request: Request) -> ScanRuntime:
    runtime: ScanRuntime = request.app.state.scan
    return runtime


def _require_reeval_session_factory(runtime: ScanRuntime) -> Any:
    if runtime.reeval_session_factory is None:
        raise HTTPException(status_code=500, detail="reeval module is not configured")
    return runtime.reeval_session_factory


@router.get("/reeval")
async def list_reeval_status(
    session: SessionContext = Depends(_reeval_reader),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    session_factory = _require_reeval_session_factory(runtime)
    current_digest = runtime.current_toolchain_digest()
    async with session_factory() as db_session:
        statuses = await list_published_toolchain_statuses(db_session)
    return {
        "current_toolchain_digest": current_digest,
        "skills": [
            {
                "skill_id": s.skill_id,
                "trust_tier": s.trust_tier.value,
                "content_hash": s.content_hash,
                "recorded_toolchain_digest": s.recorded_toolchain_digest,
                "stale": is_stale(s, current_digest),
            }
            for s in statuses
        ],
        "drift": await _drift_summary(runtime),
    }


async def _drift_summary(runtime: ScanRuntime) -> dict[str, Any]:
    """Content-drift monitoring (coding spec SUPPLY-06 "拔地毯") - deliberately
    SEPARATE from the toolchain-staleness data above, which compares scanner/
    policy VERSION, not skill CONTENT (see reeval.router module docstring's
    2026-07-14 addition for why conflating the two was the actual point of
    confusion this was built to fix).

    Two honestly-distinct pieces, never blended into one guessed "current
    drift status":
    - `skills`: a LIVE re-comparison (orchestration.drift.is_drift, the same
      pure function `_quarantine_if_drifted` uses) of each baselined skill's
      approved baseline against its most-recently-recorded content_hash. This
      answers "if a scan of the current content_hash landed right now, would
      it be flagged" - it is NOT a record of a past decision, and the UI must
      say so, since drift is actually enforced only at publish-time
      (apps/monolith/worker.py's `_quarantine_if_drifted`), not continuously.
    - `events`: genuine historical quarantine-by-drift events, read verbatim
      from skill_lifecycle_event - never fabricated, this is what actually
      happened and when.
    """
    if runtime.orchestration_session_factory is None or runtime.inventory_session_factory is None:
        return {"skills": [], "events": []}

    async with runtime.orchestration_session_factory() as orch_session:
        baselines = (await orch_session.execute(select(BaselineReadOnly))).scalars().all()

    drift_skills: list[dict[str, Any]] = []
    if baselines:
        async with runtime.inventory_session_factory() as inv_session:
            for b in baselines:
                latest = (
                    await inv_session.execute(
                        select(SkillVersionRow.content_hash)
                        .where(SkillVersionRow.skill_id == b.skill_id)
                        .order_by(SkillVersionRow.created_at.desc())
                        .limit(1)
                    )
                ).scalar_one_or_none()
                drift_skills.append(
                    {
                        "skill_id": b.skill_id,
                        "baseline_content_hash": b.content_hash,
                        "latest_content_hash": latest,
                        "drifted": is_drift(b.content_hash, latest)
                        if latest is not None
                        else False,
                    }
                )

    async with runtime.inventory_session_factory() as inv_session:
        rows = (
            (
                await inv_session.execute(
                    select(SkillLifecycleEventRow)
                    .where(SkillLifecycleEventRow.reason.startswith(_DRIFT_REASON_PREFIX))
                    .order_by(SkillLifecycleEventRow.occurred_at.desc())
                    .limit(50)
                )
            )
            .scalars()
            .all()
        )
    events = [
        {
            "skill_id": e.skill_id,
            "content_hash": e.content_hash,
            "occurred_at": e.occurred_at.isoformat(),
            "reason": e.reason,
        }
        for e in rows
    ]
    return {"skills": drift_skills, "events": events}


@router.post("/reeval/{skill_id}", dependencies=[Depends(require_csrf)])
async def trigger_reeval(
    skill_id: str,
    session: SessionContext = Depends(_reeval_admin),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    session_factory = _require_reeval_session_factory(runtime)
    current_digest = runtime.current_toolchain_digest()
    async with session_factory() as db_session, db_session.begin():
        statuses = await list_published_toolchain_statuses(db_session)
        targets = [s for s in statuses if s.skill_id == skill_id]
        if not targets:
            raise HTTPException(status_code=404, detail="skill not found in published inventory")
        # SECURITY/DESIGN: a MANUAL trigger deliberately bypasses the
        # staleness filter (batch_rescan_targets) - the whole point of
        # "manually trigger reeval" (coding spec §9: "手动触发重评") is to
        # force a rescan even when the automatic controller wouldn't have
        # picked this skill, e.g. an admin acting on an out-of-band signal.
        queued = await trigger_rescans(
            db_session, targets, toolchain_digest=current_digest, submitter=session.subject
        )
    return {"skill_id": skill_id, "versions_queued": queued}


@router.get("/reconciliation")
async def get_reconciliation_status(
    session: SessionContext = Depends(_reconciliation_reader),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    session_factory = _require_reeval_session_factory(runtime)
    async with session_factory() as db_session:
        outcomes = await list_reconciliation_outcomes(db_session)
    return {
        "outcomes": [
            {
                "content_hash": o.content_hash,
                "skill_id": o.skill_id,
                "result": o.result,
                "source": o.source,
                "detected_at": o.detected_at.isoformat(),
            }
            for o in outcomes
        ]
    }
