"""Inventory service (coding spec §16.2, FR-INV) - CRUD for skill/
skill_version/baseline plus lifecycle transition recording, in ONE
transaction with its audit_intent row (INV-12), mirroring
gate.service.decide_and_record's own same-transaction pattern.
"""

from __future__ import annotations

import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .lifecycle import validate_transition
from .models import (
    AuditIntentInsertOnly,
    BaselineRow,
    SkillLifecycleEventRow,
    SkillRow,
    SkillVersionRow,
)


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


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
    scope: str | None = None,
) -> None:
    """Registers a new Skill (if `skill_id` is new) + its SkillVersion, and
    records the genesis 'submitted' lifecycle event - but ONLY if `skill_id`
    has no real lifecycle history yet. SECURITY: a `skill_id` that already
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
                created_at=_naive_utcnow(),
            )
        )
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
    await _record_transition(
        session,
        skill_id=skill_id,
        content_hash=content_hash,
        from_state=prior_state,
        to_state="submitted",
        reason="new submission" if prior_state is None else "new content for existing skill",
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


async def transition_skill(
    session: AsyncSession,
    *,
    skill_id: str,
    to_state: str,
    reason: str,
    actor: str,
    content_hash: str | None = None,
) -> None:
    """SECURITY: caller must run this inside `async with session.begin():`.
    Authorization (e.g. "quarantine/retire needs admin", coding spec §16.2)
    is the CALLER's concern (the admin API router's `require_role("admin")`),
    not this function's - this only validates the transition is
    structurally legal, then records it (skill_lifecycle_event +
    audit_intent, same transaction, INV-12)."""
    from_state = await current_state(session, skill_id=skill_id)
    if from_state is None:
        raise ValueError(f"skill_id {skill_id!r} has no recorded lifecycle events yet")
    await _record_transition(
        session,
        skill_id=skill_id,
        content_hash=content_hash,
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
) -> None:
    validate_transition(from_state, to_state)  # raises InvalidTransitionError - fail closed
    now = _naive_utcnow()
    session.add(
        SkillLifecycleEventRow(
            skill_id=skill_id,
            content_hash=content_hash,
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
                "from_state": from_state,
                "to_state": to_state,
                "reason": reason,
            },
        )
    )


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
