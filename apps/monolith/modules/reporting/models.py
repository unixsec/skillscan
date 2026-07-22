"""SQLAlchemy ORM for reporting's own table (`report_schedule`, coding spec
§16.2 FR-REP) plus SELECT-only mirrors onto `audit_entry` (audit module) and
`scan_result` (orchestration module) - the deliberate cross-module contract
seams (policies/grants/manifest.yaml: svc_reporting has SELECT-only on both,
never INSERT/UPDATE). Reports are built FROM other modules' already-committed
history, never written back to them."""

from __future__ import annotations

import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ReportScheduleRow(Base):
    __tablename__ = "report_schedule"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    template: Mapped[str] = mapped_column(String(64), nullable=False)
    cron: Mapped[str] = mapped_column(String(64), nullable=False)
    targets: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)


class AuditEntryReadOnly(Base):
    """SECURITY: reporting's view onto audit's `audit_entry` table is SELECT-
    only at the DB GRANT level (svc_reporting has no INSERT/UPDATE on it) -
    every report template is a read/aggregate over this history, never a
    write. Only the columns reporting actually consumes are mapped here
    (mirrors orchestration.models.BaselineReadOnly's minimal-mirror style) -
    the chain-integrity columns (prev_hash/entry_hash) are audit module's own
    concern via `GET /v1/audit`, not reporting's."""

    __tablename__ = "audit_entry"

    seq: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    operator: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    chained_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)


class ScanResultReadOnly(Base):
    """SECURITY: reporting's view onto orchestration's `scan_result` table is
    SELECT-only - needed only for bulk SARIF export (audit_entry's
    verdict_issued payload carries no per-finding detail, coding spec
    §16.2's redaction discipline lives entirely inside each finding's
    `evidence_redacted` field, already applied before this table is written)."""

    __tablename__ = "scan_result"

    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
