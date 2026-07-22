"""SQLAlchemy ORM for orchestration's own tables (coding spec §7.1): scan_job,
scan_result, plus a SELECT-only view onto inventory's `baseline` table (the
deliberate cross-module contract seam for drift.py, coding spec §7.2 -
svc_orchestration is granted SELECT on baseline and nothing else on it,
mirroring gate's INSERT-only view onto audit_intent). svc_orchestration has no
other access to any other module's tables (enforced by MySQL GRANTs,
policies/grants/manifest.yaml)."""

from __future__ import annotations

import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, SmallInteger, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ScanJob(Base):
    __tablename__ = "scan_job"

    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    toolchain_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    cache_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    submitter: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    # Parsed once at submission time from the package's SKILL.md frontmatter
    # `name:` field (gateway/router.py's create_scan) - nullable because not
    # every upload has a valid SKILL.md/name. Deliberately NOT derived from
    # skill_id/skill_version: most ad-hoc scans never register a skill_id at
    # all, but should still show something to distinguish them in the list.
    skill_name: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ScanResultRow(Base):
    __tablename__ = "scan_result"

    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    confidence_at_max: Mapped[float] = mapped_column(Float, nullable=False)
    trifecta_present: Mapped[bool] = mapped_column(Boolean, nullable=False)
    findings_capped: Mapped[bool] = mapped_column(Boolean, nullable=False)
    required_ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    provenance: Mapped[list[list[str]]] = mapped_column(JSON, nullable=False)
    hard_gate_hits: Mapped[list[str]] = mapped_column(JSON, nullable=False)


class BaselineReadOnly(Base):
    """SECURITY: orchestration's view onto inventory's `baseline` table is
    SELECT-only at the DB GRANT level (svc_orchestration has no INSERT/UPDATE
    on this table) - this ORM class exists only so drift.py can read the
    approved baseline for a skill_id; it must never be written from here."""

    __tablename__ = "baseline"

    skill_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    approved_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)
