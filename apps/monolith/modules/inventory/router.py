"""`GET /v1/inventory*`, `POST /v1/inventory/{skill_id}/{quarantine,restore,
retire,baseline,owner}`, `GET|POST /v1/inventory/ownership/*` (coding spec
§9/§16.2 FR-INV).

SECURITY: read routes require approver/auditor/admin; quarantine/restore/
retire/baseline require admin specifically (coding spec §16.2: "quarantine/
retire 需 admin"; restore is the same class of action from the other
direction, and baseline-setting is the same class of high-risk admin action -
it's what worker.py's drift-triggered auto-quarantine (SUPPLY-06) keys off)
plus CSRF (state-changing, coding spec §16.1 INV-16).

The ownership routes (milestone F Task 15) are admin + CSRF for a stronger
reason still: they are the only writers of `skill.owner`, which decides who may
submit a new version of a skill at all (`ownership.authorize_skill_write`). A
route that changes who holds authority over an object is a privilege change,
so each assignment writes its own `audit_intent` row naming the previous owner
as well as the new one.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from monolith.modules.gateway.auth.dependencies import require_csrf, require_role
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime

from .lifecycle import InvalidTransitionError
from .models import BaselineRow, SkillRow, SkillVersionRow
from .ownership import InvalidOwnerError, OwnerAssignmentConflictError, normalize_owner
from .service import (
    assign_skill_owner,
    count_unowned_skills,
    current_state,
    list_unowned_skills,
    set_baseline,
    transition_skill,
)

router = APIRouter(prefix="/v1/inventory")

_reader = require_role("approver", "auditor", "admin")
_admin_only = require_role("admin")

# The unowned worklist is a server-side window. 200 is the same order as
# `GET /v1/scans`'s own clamp, and the deployed VM's ~481 unowned rows is
# exactly the case this exists for - three pages, not one unbounded response.
_UNOWNED_DEFAULT_LIMIT = 100
_UNOWNED_MAX_LIMIT = 200

# Bounded for the same reason the read side is: one bulk request must be a
# reviewable unit of work, not "assign the entire inventory" behind one click.
_MAX_BULK_ASSIGNMENTS = 200


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


class _SetOwnerBody(BaseModel):
    owner: str
    reason: str
    # COMPARE-AND-SET, defaulting to the safe side. True means "I believe this
    # skill is unowned"; a skill that acquired an owner since the caller read
    # it conflicts (409) instead of being silently overwritten. Setting it
    # False is what makes a request a TRANSFER - an explicit statement that the
    # caller knows someone owns this and intends to take it from them. See
    # `ownership.validate_owner_assignment`.
    expect_unowned: bool = True


class _BulkAssignOwnerBody(BaseModel):
    owner: str
    reason: str
    skill_ids: list[str] = Field(min_length=1, max_length=_MAX_BULK_ASSIGNMENTS)


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
                # null = no owner on record, which FAILS CLOSED on the
                # submission path (admin only). Surfaced here because "why can
                # nobody submit a new version of this?" is otherwise a question
                # the console cannot answer at all. Readable by approver/
                # auditor/admin - the roles that can already read everything
                # else about a skill - and never by the submitter who gets the
                # 403, whose error body deliberately names no identity.
                "owner": skill.owner,
            }
            for skill in skills
        ]
    return {"skills": items}


@router.get("/ownership/unowned")
async def list_unowned(
    limit: int = Query(default=_UNOWNED_DEFAULT_LIMIT, ge=1, le=_UNOWNED_MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    """The admin worklist for milestone F Task 15: every skill with no
    recorded owner, plus its genesis actor as ADVISORY evidence.

    Two path segments (`/ownership/unowned`) rather than one, so it can never
    be shadowed by - or shadow - `GET /{skill_id}` for a skill that happens to
    be called "unowned". Route-order-dependent correctness is a trap worth not
    setting.

    ADMIN-ONLY, unlike the sibling read routes. This is the input side of an
    authorization decision and it dumps identities (every genesis actor) in
    bulk; the roles that may read a skill's own record do not need a directory
    of who first submitted what.

    `total` is the count of ALL unowned skills, not of this page: an admin
    needs to know the size of the job (~481 on the deployed VM) before they
    start, and a page of 100 that says nothing about the rest reads as "that's
    all of them".

    THE GENESIS ACTOR IS EVIDENCE, NOT A DECISION. It is returned so an admin
    can see who first registered a skill before choosing its owner. Nothing in
    this codebase copies it into `skill.owner` - not this endpoint, not the
    console, not a migration. See `ownership.validate_owner_assignment`.
    """
    session_factory = _require_inventory_session_factory(runtime)
    async with session_factory() as db_session:
        total = await count_unowned_skills(db_session)
        rows = await list_unowned_skills(db_session, limit=limit, offset=offset)
    return {
        "total": total,
        "skills": [
            {
                "skill_id": row.skill_id,
                "source": row.source,
                "trust_tier": row.trust_tier,
                "state": row.state,
                "genesis_actor": row.genesis_actor,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ],
    }


@router.post("/ownership/assign", dependencies=[Depends(require_csrf)])
async def assign_owner_bulk(
    body: _BulkAssignOwnerBody,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    """Assigns one owner to many UNOWNED skills - the bulk half of Task 15,
    because ~481 stranded rows is not a one-at-a-time form.

    ASSIGNMENT ONLY, NEVER TRANSFER. There is deliberately no `expect_unowned`
    field here: it is hardcoded True, so this route can only ever move a skill
    from "nobody" to "somebody" and can never take one away from its current
    owner. A transfer is a different act - it revokes someone's authority - and
    it belongs on the single-skill route where the admin sees that one skill's
    current owner and says so explicitly. Mass-revoking authority behind one
    click, over a row set an admin selected from a list, is not a capability
    worth having.

    PARTIAL SUCCESS IS REPORTED, NOT ROLLED BACK. Each skill is assigned in its
    OWN transaction and its own audit row; a skill that was claimed since the
    worklist was rendered lands in `failed` while the rest go through. One
    all-or-nothing transaction would let a single such row block the other 480,
    and the admin would re-run into the same wall. The per-skill audit rows are
    the point too: "who granted alice authority over skill X" has to be
    answerable from X, not from a single opaque batch record.
    """
    session_factory = _require_inventory_session_factory(runtime)
    # Rejected ONCE, here, rather than as N identical per-skill failures: a
    # malformed owner is a property of the request, not of any skill in it.
    try:
        normalize_owner(body.owner)
    except InvalidOwnerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # Deduplicated, order preserved: the same skill twice in one batch would
    # otherwise write two audit rows for one decision, the second of them a
    # 409 against the change the first just made.
    ordered_ids = list(dict.fromkeys(body.skill_ids))
    assigned: list[str] = []
    failed: list[dict[str, str]] = []
    for skill_id in ordered_ids:
        try:
            async with session_factory() as db_session, db_session.begin():
                await assign_skill_owner(
                    db_session,
                    skill_id=skill_id,
                    new_owner=body.owner,
                    reason=body.reason,
                    actor=session.subject,
                    expect_unowned=True,
                )
        except (OwnerAssignmentConflictError, ValueError) as exc:
            # `OwnerAssignmentConflictError` (already owned) and the plain
            # ValueError for an unknown skill_id are both per-row facts the
            # admin needs to see, not reasons to fail the whole batch.
            failed.append({"skill_id": skill_id, "error": str(exc)})
        else:
            assigned.append(skill_id)
    return {"owner": body.owner.strip(), "assigned": assigned, "failed": failed}


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
        # See `list_inventory` for why this is exposed to the reader roles.
        "owner": skill.owner,
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


@router.post("/{skill_id}/restore", dependencies=[Depends(require_csrf)])
async def restore_skill(
    skill_id: str,
    body: _TransitionBody,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    """Lifts a quarantine: `quarantined -> published` (coding spec §16.2's own
    "[quarantined <-> published]" - the only cycle in the machine).

    SECURITY (2026-07-29, milestone F Task 11 follow-up C2): this edge was
    structurally legal in `lifecycle.VALID_TRANSITIONS` and UNREACHABLE - no
    caller anywhere produced it, and the console offered only Quarantine and
    Retire. That mattered beyond a missing button: `VALID_TRANSITIONS` refuses
    `quarantined -> submitted` and justifies the refusal by naming this route
    ("an admin restores it to `published` first, then iterates normally"). A
    gate whose escape hatch does not exist is not a gate, it is a dead end -
    every quarantined skill was terminal in practice, with only `retired`
    reachable from it.

    Same posture as its quarantine/retire siblings: admin-only (§16.2
    "quarantine/retire 需 admin" - lifting one is the same class of action, if
    anything a higher one) + CSRF, and audited by `transition_skill`'s own
    same-transaction `audit_intent` row (INV-12), never by a separate log line
    that could succeed while the write rolled back.

    SECURITY: fail-closed on the SOURCE state, which is why this cannot just
    call `_do_transition` the way its siblings do. `published` is also a legal
    target from `scanning` and `review_pending`, so an unguarded "set it to
    published" admin route would double as a way to publish a skill whose scan
    is still in flight, or to clear a `review_pending` skill without the human
    review that state exists to force - in both cases with no verdict backing
    the release at all. Restoring is only ever about a QUARANTINED skill.

    SECURITY: deliberately does NOT touch the drift baseline. A restore is a
    decision about content that was already approved, not an approval of new
    content; re-baselining here would let an admin launder swapped content
    into the approved baseline with one click and no scan. The baseline moves
    only for a publish carrying a fresh signed verdict - see
    `service.advance_baseline_on_publish`.
    """
    session_factory = _require_inventory_session_factory(runtime)
    try:
        async with session_factory() as db_session, db_session.begin():
            state = await current_state(db_session, skill_id=skill_id)
            if state is None:
                raise HTTPException(status_code=404, detail="skill not found")
            if state != "quarantined":
                raise HTTPException(
                    status_code=409,
                    detail=f"only a quarantined skill can be restored, this one is {state!r}",
                )
            await transition_skill(
                db_session,
                skill_id=skill_id,
                to_state="published",
                reason=body.reason,
                actor=session.subject,
            )
    except InvalidTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"skill_id": skill_id, "state": "published"}


@router.post("/{skill_id}/retire", dependencies=[Depends(require_csrf)])
async def retire_skill(
    skill_id: str,
    body: _TransitionBody,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    return await _do_transition(skill_id, "retired", body, session, runtime)


@router.post("/{skill_id}/owner", dependencies=[Depends(require_csrf)])
async def set_skill_owner(
    skill_id: str,
    body: _SetOwnerBody,
    session: SessionContext = Depends(_admin_only),
    runtime: ScanRuntime = Depends(_get_scan_runtime),
) -> dict[str, Any]:
    """Sets or CHANGES `skill.owner` - the single-skill primitive behind Task
    15, and the only transfer path in the system.

    WHY THE SYSTEM NEEDS THIS. `skill.owner` was added NULLABLE and
    deliberately not backfilled, so every skill registered before it existed
    reads NULL, fails closed, and is admin-only - roughly 481 real skills on
    the deployed VM with no route back to whoever owns them. And with no
    transfer path, an owner who leaves strands every skill in their name
    forever. Fail-closed is the right default exactly because an admin can
    resolve it deliberately; without a resolution path it is just a dead end.

    ADMIN-ONLY, and there is no self-service claim of an unowned skill by
    design (milestone F Task 15 Step 3, decided NO). Letting any submitter
    claim an unowned skill is first-come-first-served as an authorization
    model, which is the same class of hole C1 just closed: the system holds no
    evidence distinguishing the rightful owner of an unowned skill from anyone
    else who can read its skill_id off the console, so "claimed first" would
    become "owns it". An admin deciding with the genesis actor in front of
    them is a judgement; a claim button is a race.

    SECURITY: audited as a privilege change by `service.assign_skill_owner`,
    in the same transaction as the UPDATE, recording the previous owner too.

    `expect_unowned` (default True) is the compare-and-set guard - an
    assignment that finds an owner already there is a 409, not a silent
    overwrite. A TRANSFER passes it False, which is the request explicitly
    saying it intends to take the skill from its current owner.
    """
    session_factory = _require_inventory_session_factory(runtime)
    try:
        async with session_factory() as db_session, db_session.begin():
            previous_owner = await assign_skill_owner(
                db_session,
                skill_id=skill_id,
                new_owner=body.owner,
                reason=body.reason,
                actor=session.subject,
                expect_unowned=body.expect_unowned,
            )
    except InvalidOwnerError as exc:
        # Checked BEFORE the two ValueError branches below: both of those are
        # its superclass, so a wider clause first would swallow it and answer
        # 404/409 to a malformed owner.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OwnerAssignmentConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        # `assign_skill_owner` raises plain ValueError for an unregistered
        # skill_id - fail closed as 404, never 500.
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "skill_id": skill_id,
        "owner": body.owner.strip(),
        "previous_owner": previous_owner,
    }


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
