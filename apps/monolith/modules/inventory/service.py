"""Inventory service (coding spec §16.2, FR-INV) - CRUD for skill/
skill_version/baseline plus lifecycle transition recording, in ONE
transaction with its audit_intent row (INV-12), mirroring
gate.service.decide_and_record's own same-transaction pattern.
"""

from __future__ import annotations

import datetime
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .lifecycle import LifecyclePosition, validate_transition
from .models import (
    AuditIntentInsertOnly,
    BaselineRow,
    SkillLifecycleEventRow,
    SkillRow,
    SkillVersionRow,
)
from .ownership import authorize_skill_write, validate_owner_assignment


class ContentRegisteredToAnotherSkillError(ValueError):
    """SECURITY: this exact `content_hash` is already a recorded version of a
    DIFFERENT `skill_id`. `skill_version.content_hash` is the PRIMARY KEY, so
    one package's bytes belong to exactly one skill and can never be silently
    re-attributed to a second one. Callers surface this as a 409 (a conflict
    with the resource's current state), never a 500 - it is an ordinary,
    reachable caller mistake.

    Distinct from `SkillOwnershipError` on purpose: that one is "you may not
    write this skill", an authorization failure (403). This one is "these
    bytes are not this skill's", which is true regardless of who is asking.
    """


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


@dataclass(frozen=True, slots=True)
class RegisteredSkill:
    """What a caller outside this module needs to know about an
    already-registered skill BEFORE it commits to a submission.

    Plain values, never the ORM row: `gateway/router.py` must not issue its own
    queries against inventory's tables (scripts/check_import_boundaries.py -
    the same "plain values cross the boundary" rule
    `orchestration.service.is_scan_submitter` documents).
    """

    owner: str | None
    trust_tier: str


async def get_registered_skill(session: AsyncSession, *, skill_id: str) -> RegisteredSkill | None:
    """Returns the recorded owner + trust tier for `skill_id`, or None if this
    skill_id has never been registered (in which case the caller is about to
    become its owner).

    SECURITY: this is a PRE-FLIGHT read, so a caller who is not authorized can
    be refused before any scan job, blob or `scan_submitter` row is created on
    their behalf. It is NOT the authoritative check - `register_skill_version`
    re-runs `authorize_skill_write` inside the writing transaction, because
    anything read in a separate earlier session is a TOCTOU window by
    construction.
    """
    skill = await session.get(SkillRow, skill_id)
    if skill is None:
        return None
    return RegisteredSkill(owner=skill.owner, trust_tier=skill.trust_tier)


@dataclass(frozen=True, slots=True)
class UnownedSkill:
    """One row of the admin ownership-assignment worklist: a skill whose
    `owner` is NULL, plus the ADVISORY evidence an admin should see before
    deciding who owns it.

    `genesis_actor` is the `actor` recorded on this skill's genesis
    (`from_state IS NULL`) lifecycle event - by construction the identity that
    first registered it. It is carried here as EVIDENCE and nothing else. It is
    not written to `skill.owner` by this module, by a migration, or by any
    one-click console action; an admin reads it and then names the owner
    themselves. See `ownership.validate_owner_assignment` for why that line is
    where it is. None means this skill has no genesis event on record at all -
    reported as unknown, never filled in with a guess.
    """

    skill_id: str
    source: str
    trust_tier: str
    state: str | None
    genesis_actor: str | None
    created_at: datetime.datetime


async def count_unowned_skills(session: AsyncSession) -> int:
    """How many skills have no recorded owner, in total - i.e. how much work
    the assignment worklist actually represents, independent of the page the
    caller is looking at."""
    return int(
        (
            await session.execute(
                select(func.count()).select_from(SkillRow).where(SkillRow.owner.is_(None))
            )
        ).scalar_one()
    )


async def genesis_actors(session: AsyncSession, *, skill_ids: Sequence[str]) -> dict[str, str]:
    """The identity that first registered each of `skill_ids`, keyed by
    skill_id, read from the genesis (`from_state IS NULL`) lifecycle event. A
    skill with no such event is simply absent from the result.

    BATCHED, like `latest_lifecycle_positions` next door and for the same
    reason: the caller is a list endpoint over hundreds of rows, and one query
    per row is how a worklist becomes N+1.

    `ORDER BY id ASC` + `setdefault` keeps the EARLIEST genesis event per skill.
    There should only ever be one - `register_skill_version` records
    `from_state=None` only when the skill has no prior state - but if a row set
    ever contained two, the first one is the honest answer to "who registered
    this", not whichever the database happened to return.
    """
    if not skill_ids:
        return {}
    rows = (
        await session.execute(
            select(SkillLifecycleEventRow.skill_id, SkillLifecycleEventRow.actor)
            .where(
                SkillLifecycleEventRow.skill_id.in_(list(skill_ids)),
                SkillLifecycleEventRow.from_state.is_(None),
            )
            .order_by(SkillLifecycleEventRow.id.asc())
        )
    ).all()
    actors: dict[str, str] = {}
    for row in rows:  # oldest first - first hit per skill wins
        actors.setdefault(str(row.skill_id), str(row.actor))
    return actors


async def list_unowned_skills(
    session: AsyncSession, *, limit: int, offset: int
) -> list[UnownedSkill]:
    """The `owner IS NULL` worklist, oldest first, one page at a time.

    Ordered by `created_at, skill_id` rather than by insertion order alone:
    `skill_id` breaks ties so the ordering is TOTAL, which is what makes
    offset paging stable. Without a tiebreak, two rows created in the same
    second can swap places between two page requests and an admin silently
    never sees one of them.
    """
    rows = (
        (
            await session.execute(
                select(SkillRow)
                .where(SkillRow.owner.is_(None))
                .order_by(SkillRow.created_at.asc(), SkillRow.skill_id.asc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    skill_ids = [str(row.skill_id) for row in rows]
    positions = await latest_lifecycle_positions(session, skill_ids=skill_ids)
    actors = await genesis_actors(session, skill_ids=skill_ids)
    return [
        UnownedSkill(
            skill_id=str(row.skill_id),
            source=str(row.source),
            trust_tier=str(row.trust_tier),
            state=(positions[str(row.skill_id)].state if str(row.skill_id) in positions else None),
            genesis_actor=actors.get(str(row.skill_id)),
            created_at=row.created_at,
        )
        for row in rows
    ]


async def assign_skill_owner(
    session: AsyncSession,
    *,
    skill_id: str,
    new_owner: str,
    reason: str,
    actor: str,
    expect_unowned: bool,
) -> str | None:
    """Writes `skill.owner` for an ALREADY-REGISTERED skill and audits it.
    Returns the PREVIOUS owner (None if the skill was unowned).

    This is the only function in the tree that changes `skill.owner` after
    genesis, and it exists so that the fail-closed NULL `authorize_skill_write`
    imposes on legacy rows is recoverable rather than permanent - see
    `ownership.validate_owner_assignment` for the full reasoning, including why
    the genesis actor is shown as evidence and never adopted automatically.

    SECURITY: authorization is the CALLER's concern - `inventory/router.py`'s
    `require_role("admin")` + `require_csrf`, the same split `transition_skill`
    documents. What this function owns is that the write and its audit record
    commit together.

    SECURITY: audited as a PRIVILEGE CHANGE, in the same transaction as the
    UPDATE (INV-12), and the payload records the previous owner as well as the
    new one. "alice owns it" answers nothing after the fact; "it was unowned,
    admin-bob gave it to alice, for this reason" is the record. A separate log
    line written outside the transaction could succeed while the UPDATE rolled
    back, which is the failure mode this codebase avoids everywhere else too.

    Raises `ValueError` for an unknown skill_id (caller: 404),
    `InvalidOwnerError` for a malformed owner (400), and
    `OwnerAssignmentConflictError` when `expect_unowned` does not hold (409).

    SECURITY: caller must run this inside `async with session.begin():` - same
    convention as every other writer in this module.
    """
    skill = await session.get(SkillRow, skill_id)
    if skill is None:
        raise ValueError(f"skill_id {skill_id!r} is not registered")
    previous_owner = skill.owner
    # The compare-and-set decision is made INSIDE this transaction against the
    # row this statement is about to write, not against whatever a list
    # endpoint read minutes ago - otherwise the guard describes a state the
    # database may have left since, which is no guard at all.
    normalized = validate_owner_assignment(
        skill_id=skill_id,
        recorded_owner=previous_owner,
        new_owner=new_owner,
        expect_unowned=expect_unowned,
    )
    skill.owner = normalized
    session.add(
        AuditIntentInsertOnly(
            operator=actor,
            action="skill_owner_assigned",
            payload={
                "skill_id": skill_id,
                "previous_owner": previous_owner,
                "new_owner": normalized,
                "reason": reason,
            },
        )
    )
    await session.flush()
    return previous_owner


async def register_skill_version(
    session: AsyncSession,
    *,
    skill_id: str,
    source: str,
    trust_tier: str,
    content_hash: str,
    toolchain_digest: str,
    declared_perms: dict[str, Any] | None,
    operator: str,
    actor_is_admin: bool,
    scope: str | None = None,
) -> None:
    """Registers a new Skill (if `skill_id` is new) + its SkillVersion (if
    this `content_hash` is new), and records the genesis 'submitted'
    lifecycle event - but ONLY if `skill_id` has no real lifecycle history
    yet. SECURITY: a `skill_id` that already
    has real history (e.g. is `published`/`quarantined`) must never get a
    FABRICATED second `None->submitted` genesis event - that would make
    `current_state()` lie about this skill_id having no prior state, which
    would let the caller's immediately-following `transition_skill(...)`
    read the fake `submitted` state as legitimate and sail through a
    transition that `VALID_TRANSITIONS` would otherwise reject (e.g.
    `published` skipping straight back to `scanning`). For that case, this
    instead runs a NORMAL, validated transition off the skill's REAL current
    state, to_state="submitted" - which `validate_transition()` will reject
    with `InvalidTransitionError` unless the state machine actually allows
    it (fail closed, same as every other transition in this module).

    That re-entry edge is what makes a skill_id's SECOND and later versions
    possible. It exists for the settled states (published / review_pending /
    blocked) and deliberately NOT for `scanning` (races the in-flight
    verdict), `retired` (terminal), or `quarantined` (re-entry there would
    make the admin-only restore optional - an admin restores to `published`
    first, then versioning proceeds normally) - see
    `lifecycle.VALID_TRANSITIONS`, which argues each exclusion. Callers
    surface the rejection as a client error (gateway/router.py returns 409),
    never as a 500.

    SECURITY (2026-07-29, milestone F Task 11 follow-up C1): re-entry is
    OWNERSHIP-GATED. Making a settled skill re-enter at `submitted` is what
    lets a v2 ship - but the old always-failing transition had also been
    acting, accidentally, as the only thing stopping a caller from submitting
    against SOMEONE ELSE's `skill_id`. `authorize_skill_write` below is the
    real control that replaces it, and it runs HERE, inside the writing
    transaction, rather than only in the router: a check performed in an
    earlier, separate session is a TOCTOU window, and this function is also
    the chokepoint every future submission path must pass through. That is why
    `actor_is_admin` is a REQUIRED keyword with no default - exactly the
    posture `orchestration.submit_scan` uses for `trust_tier`/`source`. A new
    call site that has not thought about authorization is then a type error at
    the call site, not a silently unauthorized write; a default of False would
    quietly break admins, and a default of True would quietly reopen the hole.

    IDENTICAL CONTENT (2026-07-29, milestone F Task 11 follow-up I1): a
    resubmission whose `content_hash` is ALREADY a recorded version of this
    same `skill_id` is a real request, not a no-op. It is the policy-fix /
    re-run case: the package did not change, the RULESET did, and the caller
    wants the current toolchain's opinion on bytes that were BLOCKed under the
    old one. So the duplicate `skill_version` row is skipped (its
    `content_hash` primary key is what makes single-flight dedup and the
    verdict cache work - it must stay one row per package) while the lifecycle
    re-entry runs exactly as it would for new content. Before this, the
    gateway skipped the whole call for known content and returned 202 having
    written no lifecycle event at all: the skill sat at `blocked` forever,
    `worker.sync_lifecycle_tick` never looked at it again (it matches only
    `scanning`/`review_pending`), and the submitter was told it worked.

    What is NOT rewritten on that path: `skill_version.toolchain_digest`
    keeps the digest the content was FIRST submitted under. Advancing it here
    would claim "scanned by the current toolchain" at submission time, before
    any verdict exists - a fail-OPEN write to the staleness signal
    `reeval.controller` uses to decide what needs rescanning. The honest
    record is the old digest until something actually re-scans.

    SECURITY: caller must run this inside `async with session.begin():` -
    same convention as gate.service.decide_and_record."""
    existing_skill = await session.get(SkillRow, skill_id)
    if existing_skill is None:
        session.add(
            SkillRow(
                skill_id=skill_id,
                source=source,
                trust_tier=trust_tier,
                scope=scope,
                # Registering a skill_id nobody holds is what makes you its
                # owner. Recorded once, here, and never rewritten below - see
                # `ownership.authorize_skill_write` on why neither a
                # resubmission nor an admin override transfers ownership.
                owner=operator,
                created_at=_naive_utcnow(),
            )
        )
    else:
        # SECURITY: raises `SkillOwnershipError` -> the caller surfaces 403.
        # Note what is NOT updated in this branch: not `owner`, and not
        # `trust_tier` either. The skill's recorded tier is the one it was
        # registered at, and a resubmission must be judged AT that tier rather
        # than at whatever tier the submitter passed on the form - otherwise
        # the tier is a caller-chosen input on every version after the first.
        # `gateway/router.py` reads it back via `get_registered_skill` and
        # feeds it to `submit_scan` for exactly that reason.
        authorize_skill_write(
            skill_id=skill_id,
            recorded_owner=existing_skill.owner,
            actor=operator,
            actor_is_admin=actor_is_admin,
        )
    # SECURITY: the ownership decision above runs FIRST and unconditionally.
    # "These bytes belong to another skill" names a skill_id the caller may
    # have no relationship with, so it must never be answerable to someone who
    # is not even allowed to write the skill_id they DID name.
    existing_version = await session.get(SkillVersionRow, content_hash)
    if existing_version is not None and str(existing_version.skill_id) != skill_id:
        raise ContentRegisteredToAnotherSkillError(
            f"this content is already registered to skill {str(existing_version.skill_id)!r}"
        )
    if existing_version is None:
        session.add(
            SkillVersionRow(
                content_hash=content_hash,
                skill_id=skill_id,
                toolchain_digest=toolchain_digest,
                declared_perms=declared_perms,
                created_at=_naive_utcnow(),
            )
        )
    prior_state = await current_state(session, skill_id=skill_id)
    if prior_state is None:
        reason = "new submission"
    elif existing_version is not None:
        # Named distinctly on purpose: this row is the only durable trace that
        # a resubmission of UNCHANGED bytes happened, and calling it "new
        # content" in the audit trail would be false.
        reason = "resubmission of existing content"
    else:
        reason = "new content for existing skill"
    await _record_transition(
        session,
        skill_id=skill_id,
        content_hash=content_hash,
        from_state=prior_state,
        to_state="submitted",
        reason=reason,
        actor=operator,
    )
    await session.flush()


async def current_state(session: AsyncSession, *, skill_id: str) -> str | None:
    """Returns the `to_state` of the most recent lifecycle event for this
    skill_id, or None if the skill_id has no recorded events at all."""
    result = await session.execute(
        select(SkillLifecycleEventRow.to_state)
        .where(SkillLifecycleEventRow.skill_id == skill_id)
        .order_by(SkillLifecycleEventRow.id.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def latest_lifecycle_positions(
    session: AsyncSession, *, skill_ids: Sequence[str]
) -> dict[str, LifecyclePosition]:
    """Where each of `skill_ids` currently stands, keyed by skill_id. A
    skill_id with no recorded events is simply absent from the result.

    Plain values, never ORM rows: this is the service-layer accessor other
    modules go through instead of issuing their own `select()` against
    `skill_lifecycle_event` (scripts/check_import_boundaries.py). Batched on
    purpose - `GET /v1/reviews` needs the position of every skill in the
    queue, and one query per row is how a list endpoint becomes N+1.

    Collapsed newest-first in Python (`ORDER BY id DESC` + `setdefault`), the
    same idiom `worker.sync_lifecycle_tick` uses on the same table, rather
    than a per-skill correlated subquery.
    """
    if not skill_ids:
        return {}
    rows = (
        await session.execute(
            select(
                SkillLifecycleEventRow.skill_id,
                SkillLifecycleEventRow.to_state,
                SkillLifecycleEventRow.content_hash,
            )
            .where(SkillLifecycleEventRow.skill_id.in_(list(skill_ids)))
            .order_by(SkillLifecycleEventRow.id.desc())
        )
    ).all()
    positions: dict[str, LifecyclePosition] = {}
    for row in rows:  # newest first - first hit per skill wins
        positions.setdefault(
            str(row.skill_id),
            LifecyclePosition(
                skill_id=str(row.skill_id),
                state=str(row.to_state),
                content_hash=row.content_hash,
            ),
        )
    return positions


async def skill_id_for_content(session: AsyncSession, *, content_hash: str) -> str | None:
    """Which skill_id this exact content is registered under, or None if these
    bytes have never been registered as a skill version.

    The service-layer accessor behind `gateway.router.create_scan`'s
    "already registered to another skill" PRE-FLIGHT (2026-07-29, milestones
    E+F review). `register_skill_version` makes the same read inside its
    writing transaction and that one stays authoritative - this exists so the
    common case is refused BEFORE `submit_scan` commits a `scan_job`, an
    artifact blob and a `scan_submitter` row that the 409 then leaves behind.

    Plain value, never the ORM row - same "plain values cross the module
    boundary" rule `RegisteredSkill` documents above.
    """
    skill_id = (
        await session.execute(
            select(SkillVersionRow.skill_id).where(SkillVersionRow.content_hash == content_hash)
        )
    ).scalar_one_or_none()
    return None if skill_id is None else str(skill_id)


async def lifecycle_position_for_content(
    session: AsyncSession, *, content_hash: str
) -> LifecyclePosition | None:
    """The lifecycle position of whichever skill owns `content_hash`, or None
    when this content was never registered as a skill version at all (an
    anonymous submission - see `pending_review_is_superseded`, which treats
    that as "nothing can supersede it", not as "superseded")."""
    skill_id = (
        await session.execute(
            select(SkillVersionRow.skill_id).where(SkillVersionRow.content_hash == content_hash)
        )
    ).scalar_one_or_none()
    if skill_id is None:
        return None
    positions = await latest_lifecycle_positions(session, skill_ids=[str(skill_id)])
    return positions.get(str(skill_id))


async def transition_skill(
    session: AsyncSession,
    *,
    skill_id: str,
    to_state: str,
    reason: str,
    actor: str,
    content_hash: str | None = None,
    scan_id: str | None = None,
) -> None:
    """SECURITY: caller must run this inside `async with session.begin():`.
    Authorization (e.g. "quarantine/retire needs admin", coding spec §16.2)
    is the CALLER's concern (the admin API router's `require_role("admin")`),
    not this function's - this only validates the transition is
    structurally legal, then records it (skill_lifecycle_event +
    audit_intent, same transaction, INV-12).

    `scan_id` (2026-07-29, milestones E+F review finding C1) is the scan whose
    verdict is supposed to resolve the state being entered - required in
    practice for `-> scanning`, since that is the event `worker.
    sync_lifecycle_tick` resolves, and propagated by the worker onto the
    transitions it writes OFF a waiting state so the link survives
    `scanning -> review_pending -> published`. It is an OPTIONAL keyword rather
    than a required one because the admin quarantine/retire/restore routes and
    the drift-triggered quarantine record no scan: there is none. See
    `SkillLifecycleEventRow.scan_id`."""
    from_state = await current_state(session, skill_id=skill_id)
    if from_state is None:
        raise ValueError(f"skill_id {skill_id!r} has no recorded lifecycle events yet")
    await _record_transition(
        session,
        skill_id=skill_id,
        content_hash=content_hash,
        scan_id=scan_id,
        from_state=from_state,
        to_state=to_state,
        reason=reason,
        actor=actor,
    )
    await session.flush()


async def _record_transition(
    session: AsyncSession,
    *,
    skill_id: str,
    content_hash: str | None,
    from_state: str | None,
    to_state: str,
    reason: str,
    actor: str,
    scan_id: str | None = None,
) -> None:
    validate_transition(from_state, to_state)  # raises InvalidTransitionError - fail closed
    now = _naive_utcnow()
    session.add(
        SkillLifecycleEventRow(
            skill_id=skill_id,
            content_hash=content_hash,
            scan_id=scan_id,
            from_state=from_state,
            to_state=to_state,
            reason=reason,
            actor=actor,
            occurred_at=now,
        )
    )
    session.add(
        AuditIntentInsertOnly(
            operator=actor,
            action="skill_lifecycle_transition",
            payload={
                "skill_id": skill_id,
                "content_hash": content_hash,
                # C1: in the audit payload too, not only on the row. The audit
                # chain is where "which verdict released this skill?" has to be
                # answerable after the fact, and until this column existed the
                # only trace of the scan was whatever `reason` happened to say.
                "scan_id": scan_id,
                "from_state": from_state,
                "to_state": to_state,
                "reason": reason,
            },
        )
    )


async def advance_baseline_on_publish(
    session: AsyncSession, *, skill_id: str, content_hash: str, actor: str
) -> bool:
    """Moves the SUPPLY-06 drift baseline onto the content a PIPELINE publish
    just approved. Returns True if the baseline now records `content_hash`.

    SECURITY (2026-07-29, milestone F Task 11 follow-up C3): drift detection
    exists to catch content changing under a published skill WITHOUT going
    through the pipeline (orchestration/drift.py: the "rug-pull"). A version
    that was submitted, scanned and given a fresh signed verdict is the exact
    opposite of that - it is the intended path - so it must not be treated as
    drift. Before this function existed, `set_baseline`'s only caller was the
    admin endpoint, nothing ever re-baselined, and `worker._quarantine_if_
    drifted` therefore quarantined EVERY second version of a baselined skill
    on publish (a v2 has a different content_hash by definition). That was
    invisible only because a second version was impossible at all until Task
    11 made `published -> submitted` legal.

    THE RULE, and why it is not simply "always adopt": the baseline advances
    along the skill's OWN published history. It is adopted when the skill has
    no baseline yet (its first publish establishes one), or when the baseline
    still records the content this skill was last published at - i.e. this
    publish is the next link in that chain. It is NOT adopted when the
    baseline points somewhere the skill has never published, because the only
    way that happens is an admin having pinned it out of band via `POST
    /v1/inventory/{skill_id}/baseline` - a deliberate human statement of "the
    approved content for this skill is X". A pipeline publish must not
    silently overwrite that statement; the caller's follow-up drift check
    still quarantines, which is the reachable positive case the publish-time
    SUPPLY-06 control has and always had.

    SECURITY: caller must run this INSIDE the same `async with
    session.begin():` as the `-> published` transition, and BEFORE recording
    it - "the content this skill was last published at" is read from the
    lifecycle events, so running after would read the transition being made
    right now and always decline. Rolling back together with the transition is
    the point: a baseline that advanced for a publish that did not commit
    would silently disarm the next real drift check.
    """
    existing = await session.get(BaselineRow, skill_id)
    if existing is not None and existing.content_hash == content_hash:
        return True  # re-publish of the same content - already recorded
    # NULL content_hash is skipped, not treated as "published at nothing": the
    # admin restore route (`POST /v1/inventory/{skill_id}/restore`) records a
    # `-> published` event with no content_hash, exactly like its quarantine/
    # retire siblings. Reading that NULL as the last published content would
    # make every baselined skill's FIRST version after a restore fail the
    # comparison below and quarantine - the same one-hop-further dead end this
    # whole fix exists to remove.
    prior_published_hash = (
        await session.execute(
            select(SkillLifecycleEventRow.content_hash)
            .where(
                SkillLifecycleEventRow.skill_id == skill_id,
                SkillLifecycleEventRow.to_state == "published",
                SkillLifecycleEventRow.content_hash.is_not(None),
            )
            .order_by(SkillLifecycleEventRow.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None and existing.content_hash != prior_published_hash:
        return False  # admin-pinned baseline - leave it, let the drift check act
    await set_baseline(session, skill_id=skill_id, content_hash=content_hash, actor=actor)
    return True


async def set_baseline(
    session: AsyncSession, *, skill_id: str, content_hash: str, actor: str
) -> None:
    """Sets/replaces the approved baseline for drift detection (M4's
    orchestration.drift, which reads this via a cross-module SELECT-only
    grant). SECURITY: caller must run this inside `async with
    session.begin():`; audited the same way lifecycle transitions are."""
    existing = await session.get(BaselineRow, skill_id)
    now = _naive_utcnow()
    if existing is None:
        session.add(BaselineRow(skill_id=skill_id, content_hash=content_hash, approved_at=now))
    else:
        existing.content_hash = content_hash
        existing.approved_at = now
    session.add(
        AuditIntentInsertOnly(
            operator=actor,
            action="baseline_set",
            payload={"skill_id": skill_id, "content_hash": content_hash},
        )
    )
    await session.flush()
