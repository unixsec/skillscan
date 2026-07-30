"""SQLAlchemy ORM for gate's own tables only (coding spec §7.1): verdict,
allowlist, gate_outbox, policy_proposal (M8 §9 admin·policy two-person
hard-gate approval workflow), plus an INSERT-only view onto audit_intent (the
deliberate cross-module contract seam, coding spec §7.2 - svc_gate is granted
INSERT on audit_intent and nothing else on it)."""

from __future__ import annotations

import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, SmallInteger, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class VerdictRow(Base):
    __tablename__ = "verdict"

    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    jti: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    jws_signature: Mapped[str] = mapped_column(Text, nullable=False)
    effective_severity: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    score: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    # SECURITY (2026-07-30): was this BLOCK the INV-1 fail-closed answer to an
    # INCOMPLETE scan (a required engine missing or failed), rather than a
    # decision about content that was actually examined? Written from
    # `VerdictResult.fail_closed`, which `skillscan_core.gate.decide` sets on
    # exactly one branch.
    #
    # It exists because the previous answer was INFERRED - "a verdict with no
    # ScanResultRow" - and that inference only holds for the dead-letter path.
    # The collector path writes a result row (`required_ok=False`) and its
    # fail-closed BLOCKs therefore reported `fail_closed: false`; on a real
    # 226-package run that was 17 of the 18 BLOCKs.
    #
    # NOT NULL, backfilled exactly (see db/migrations/versions/
    # a1f4c7b2e903_*.py: the marker string is one gate wrote itself into
    # `reasons`, not a repurposed field). The ORM-side `default=False` is for
    # test fixtures that build a verdict row directly; the one production writer
    # (`service.decide_and_record`) always passes the real value, and the value
    # it passes cannot be forgotten because `VerdictResult.fail_closed` is a
    # required field with no default of its own.
    fail_closed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    issued_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)


class AllowlistRow(Base):
    __tablename__ = "allowlist"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scope_type: Mapped[str] = mapped_column(String(16), nullable=False)
    scope_value: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    approved_by: Mapped[str] = mapped_column(String(255), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class GateOutboxRow(Base):
    __tablename__ = "gate_outbox"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    aggregate_id: Mapped[str] = mapped_column(String(36), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    dispatched: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)


class PolicyProposalRow(Base):
    __tablename__ = "policy_proposal"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    proposed_policy_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    changes_hard_gate_rules: Mapped[bool] = mapped_column(Boolean, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    proposed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    decided_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=False), nullable=True
    )


class AuditIntentInsertOnly(Base):
    """SECURITY: gate's view onto audit_intent is INSERT-only at the DB GRANT
    level (svc_gate has no SELECT/UPDATE on this table) - this ORM class exists
    only so gate's service code can construct+insert a row in the same
    transaction as verdict/gate_outbox; it must never be queried from here."""

    __tablename__ = "audit_intent"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    operator: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
