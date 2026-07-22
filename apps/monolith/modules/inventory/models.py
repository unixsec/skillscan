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
