"""SQLAlchemy ORM for reeval's own table (coding spec §7.1: reconciliation)
plus an INSERT-only view onto orchestration's scan_job (coding spec §11.7
controller.py's "触发重扫" - trigger a rescan; the deliberate cross-module
contract seam, mirroring gate.models.AuditIntentInsertOnly's precedent:
svc_reeval is granted INSERT on scan_job and nothing else on it).

SECURITY: `svc_reeval` (policies/grants/manifest.yaml §7.2) has NO grant on
`verdict` (gate's table) - reconciliation logic never reads it directly; see
`gate.service.list_issued_verdicts`, which whoever orchestrates a
reconciliation pass calls using GATE's own session/credentials instead.
"""

from __future__ import annotations

import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ReconciliationRow(Base):
    __tablename__ = "reconciliation"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    skill_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    result: Mapped[str] = mapped_column(String(16), nullable=False)  # MATCH/ORPHAN/MISMATCH
    source: Mapped[str] = mapped_column(String(8), nullable=False)  # poll/push
    detected_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)


class ScanJobInsertOnly(Base):
    """SECURITY: reeval's view onto scan_job is INSERT-only at the DB GRANT
    level (svc_reeval has no SELECT/UPDATE on this table) - this ORM class
    exists only so controller.py's code can construct+insert a rescan job
    row; it must never be queried from here. The newly-queued row is picked
    up by orchestration's OWN existing worker-tick polling (state='queued'),
    unmodified by this milestone - reeval never touches the scan pipeline
    itself, only adds an entry to its existing queue."""

    __tablename__ = "scan_job"

    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    toolchain_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    cache_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    submitter: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    # SECURITY (2026-07-28, milestone B' C3): mapped so a reeval-triggered
    # rescan CARRIES the skill's trust tier. Without this column here the INSERT
    # simply omitted it and every rescan landed with trust_tier=NULL, which the
    # decide path falls back to `runtime.default_trust_tier` (INTERNAL - the
    # most permissive tier) for. A PUBLIC skill that BLOCKed on a HIGH finding
    # was therefore re-judged at the INTERNAL threshold and came back REVIEW:
    # re-evaluation, whose entire purpose is to re-apply CURRENT detection to
    # already-published content, was silently relaxing every verdict it touched.
    trust_tier: Mapped[str | None] = mapped_column(String(16), nullable=True)


class SkillReadOnly(Base):
    """SECURITY: reeval's view onto inventory's `skill` table is SELECT-only
    at the DB GRANT level (svc_reeval has no INSERT/UPDATE on this table) -
    controller.py reads trust_tier from here; it must never write to it."""

    __tablename__ = "skill"

    skill_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    trust_tier: Mapped[str] = mapped_column(String(16), nullable=False)


class SkillVersionReadOnly(Base):
    """SECURITY: reeval's view onto inventory's `skill_version` table -
    SELECT-only, same rationale as SkillReadOnly above."""

    __tablename__ = "skill_version"

    content_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    skill_id: Mapped[str] = mapped_column(String(128), nullable=False)
    toolchain_digest: Mapped[str] = mapped_column(String(64), nullable=False)
