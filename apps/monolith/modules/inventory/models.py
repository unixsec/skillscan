"""SQLAlchemy ORM for inventory's own tables (coding spec §7.1): skill,
skill_version, baseline, plus skill_lifecycle_event (coding spec §16.2,
M8 - see db/migrations/versions/2307212254dd_*.py for why this is a separate,
additive table rather than a column on skill/skill_version) and an
INSERT-only view onto audit_intent (mirroring gate.models.
AuditIntentInsertOnly's precedent - svc_inventory is granted INSERT on
audit_intent and nothing else on it).
"""

from __future__ import annotations

import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class SkillRow(Base):
    __tablename__ = "skill"

    skill_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    trust_tier: Mapped[str] = mapped_column(String(16), nullable=False)
    scope: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # SECURITY (milestone F Task 11 follow-up C1): the identity that FIRST
    # registered this skill, and the only identity (besides an admin) allowed
    # to submit further versions of it - see `ownership.authorize_skill_write`,
    # which is the single place that decision is made. Written once by
    # `service.register_skill_version` at genesis and never updated by any
    # SUBMISSION path: a resubmission does not transfer ownership, and neither
    # does an admin override.
    #
    # NULLABLE and NOT backfilled. NULL means "no owner is on record" (every
    # row registered before this column existed) and FAILS CLOSED - only an
    # admin may write such a skill. `authorize_skill_write`'s docstring records
    # why the available-looking backfill from `skill_lifecycle_event`'s genesis
    # actor was rejected rather than overlooked.
    #
    # milestone F Task 15: `service.assign_skill_owner` is the ONE writer that
    # may change this column after genesis - an explicit, admin-only, audited
    # `POST /v1/inventory/{skill_id}/owner`, never a side effect of anything
    # else. It is what makes the fail-closed NULL above recoverable (and a
    # departing owner's skills transferable) instead of permanent; see
    # `ownership.validate_owner_assignment`.
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)


class SkillVersionRow(Base):
    __tablename__ = "skill_version"

    content_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    skill_id: Mapped[str] = mapped_column(String(128), nullable=False)
    toolchain_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    declared_perms: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)


class BaselineRow(Base):
    __tablename__ = "baseline"

    skill_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    approved_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)


class SkillLifecycleEventRow(Base):
    __tablename__ = "skill_lifecycle_event"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    skill_id: Mapped[str] = mapped_column(String(128), nullable=False)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # SECURITY (2026-07-29, milestones E+F review finding C1): the scan whose
    # verdict is supposed to resolve THIS event - `verdict.scan_id`, that
    # table's primary key. `worker.sync_lifecycle_tick` used to resolve a
    # `scanning` skill by taking the newest verdict for its `content_hash`,
    # with no link to the scan the event named (the scan_id lived only in the
    # free-text `reason`) and no check that the verdict post-dated the event.
    # Resubmitting unchanged bytes under a NEW toolchain therefore published
    # the skill on the OLD toolchain's PASS within a tick, and the new scan's
    # BLOCK arrived to a skill that had already left `scanning` and was dropped.
    #
    # NULLABLE and NOT backfilled - NULL means "no scan is on record for this
    # event", which is the truth for every row written before the column
    # existed, for the admin quarantine/retire/restore routes and the
    # drift-triggered quarantine (no scan is involved), and for the genesis /
    # re-entry `submitted` event (the following `-> scanning` event carries it).
    # See db/migrations/versions/7f2ad4c9e1b3_*.py for why this is an explicit
    # link rather than an `issued_at >= occurred_at` filter, and
    # `worker.sync_lifecycle_tick` for the narrower legacy-only fallback NULL
    # still gets.
    scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    from_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    occurred_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)


class AuditIntentInsertOnly(Base):
    """SECURITY: inventory's view onto audit_intent is INSERT-only at the DB
    GRANT level (svc_inventory has no SELECT/UPDATE on this table) - exists
    only so lifecycle transitions can be audited in the same transaction as
    the skill_lifecycle_event row; must never be queried from here."""

    __tablename__ = "audit_intent"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    operator: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
