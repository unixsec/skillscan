"""`GET /v1/inventory*`, `POST /v1/inventory/{skill_id}/{quarantine,retire,
baseline}` (coding spec §9/§16.2 FR-INV).

SECURITY: read routes require approver/auditor/admin; quarantine/retire/
baseline require admin specifically (coding spec §16.2: "quarantine/retire 需
admin"; baseline-setting is the same class of high-risk admin action - it's
what worker.py's drift-triggered auto-quarantine (SUPPLY-06) keys off) plus CSRF
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

from .lifecycle import InvalidTransitionError
from .models import BaselineRow, SkillRow, SkillVersionRow
from .service import current_state, set_baseline, transition_skill

router = APIRouter(prefix="/v1/inventory")

_reader = require_role("approver", "auditor", "admin")
_admin_only = require_role("admin")


def _get_scan_runtime(request: Request) -> ScanRuntime:
    runtime: ScanRuntime = request.app.state.scan
    return runtime


def _require_inventory_session_factory(runtime: ScanRuntime) -> Any:
    if runtime.inventory_session_factory is None:
        raise HTTPException(status_code=500, detail="inventory module is not configured")
    return runtime.inventory_session_factory


class _TransitionBody(BaseModel):
    reason: str


class _SetBaselineBody(BaseModel):
    content_hash: str


@router.get("")
async def list_inventory(
    session: SessionContext = Depends(_reader),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    session_factory = _require_inventory_session_factory(runtime)
    async with session_factory() as db_session:
        skills = (await db_session.execute(select(SkillRow))).scalars().all()
        # NOTE: one query per skill (N+1) - simple and correct; inventories are
        # not expected to be large enough to make this a real bottleneck, and
        # optimizing to a single grouped query can be done later if it is.
        items = [
            {
                "skill_id": skill.skill_id,
                "source": skill.source,
                "trust_tier": skill.trust_tier,
                "state": await current_state(db_session, skill_id=skill.skill_id),
            }
            for skill in skills
        ]
    return {"skills": items}


@router.get("/{skill_id}")
async def get_inventory_item(
    skill_id: str,
    session: SessionContext = Depends(_reader),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    session_factory = _require_inventory_session_factory(runtime)
    async with session_factory() as db_session:
        skill = await db_session.get(SkillRow, skill_id)
        if skill is None:
            raise HTTPException(status_code=404, detail="skill not found")
        versions = (
            (
                await db_session.execute(
                    select(SkillVersionRow)
                    .where(SkillVersionRow.skill_id == skill_id)
                    .order_by(SkillVersionRow.created_at.asc())
                )
            )
            .scalars()
            .all()
        )
        baseline = await db_session.get(BaselineRow, skill_id)
        state = await current_state(db_session, skill_id=skill_id)
    return {
        "skill_id": skill.skill_id,
        "source": skill.source,
        "trust_tier": skill.trust_tier,
        "state": state,
        "versions": [
            {
                "content_hash": v.content_hash,
                "toolchain_digest": v.toolchain_digest,
                "created_at": v.created_at.isoformat(),
            }
            for v in versions
        ],
        "baseline": (
            {"content_hash": baseline.content_hash, "approved_at": baseline.approved_at.isoformat()}
            if baseline
            else None
        ),
    }


async def _do_transition(
    skill_id: str,
    to_state: str,
    body: _TransitionBody,
    session: SessionContext,
    runtime: ScanRuntime,
) -> dict[str, Any]:
    session_factory = _require_inventory_session_factory(runtime)
    try:
        async with session_factory() as db_session, db_session.begin():
            await transition_skill(
                db_session,
                skill_id=skill_id,
                to_state=to_state,
                reason=body.reason,
                actor=session.subject,
            )
    except InvalidTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        # SECURITY: transition_skill raises plain ValueError for "no recorded
        # events yet" (unknown skill_id) - fail closed as 404, not 500.
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"skill_id": skill_id, "state": to_state}


@router.post("/{skill_id}/quarantine", dependencies=[Depends(require_csrf)])
async def quarantine_skill(
    skill_id: str,
    body: _TransitionBody,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    return await _do_transition(skill_id, "quarantined", body, session, runtime)


@router.post("/{skill_id}/retire", dependencies=[Depends(require_csrf)])
async def retire_skill(
    skill_id: str,
    body: _TransitionBody,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    return await _do_transition(skill_id, "retired", body, session, runtime)


@router.post("/{skill_id}/baseline", dependencies=[Depends(require_csrf)])
async def set_skill_baseline(
    skill_id: str,
    body: _SetBaselineBody,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    """Sets/replaces the approved drift-detection baseline (coding spec
    SUPPLY-06) for `skill_id`. This is the ONLY HTTP-reachable way to call
    `inventory.service.set_baseline` - previously that function had no
    caller anywhere, so worker.py's drift-triggered auto-quarantine could
    never fire in any real deployment (it always read `has_baseline=False`).
    """
    session_factory = _require_inventory_session_factory(runtime)
    async with session_factory() as db_session, db_session.begin():
        skill = await db_session.get(SkillRow, skill_id)
        if skill is None:
            raise HTTPException(status_code=404, detail="skill not found")
        await set_baseline(
            db_session,
            skill_id=skill_id,
            content_hash=body.content_hash,
            actor=session.subject,
        )
    return {"skill_id": skill_id, "content_hash": body.content_hash}
