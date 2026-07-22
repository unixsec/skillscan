"""SQLAlchemy ORM for admin's own tables (2026-07-14, item #13): local_account
and group_role_mapping, plus an INSERT-only view onto audit_intent (mirroring
gate.models.AuditIntentInsertOnly's precedent - svc_admin is granted INSERT on
audit_intent and nothing else on it). Admin's first-ever owned tables - see
db/migrations/versions/772bfe6609de_*.py's docstring for why every prior
admin/router.py write borrowed another module's session instead.
"""

from __future__ import annotations

import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class LocalAccountRow(Base):
    __tablename__ = "local_account"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="active"
    )  # active|disabled
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    updated_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)


class GroupRoleMappingRow(Base):
    __tablename__ = "group_role_mapping"

    group_name: Mapped[str] = mapped_column(String(255), primary_key=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_by: Mapped[str] = mapped_column(String(255), nullable=False)
    updated_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)


class AuditIntentInsertOnly(Base):
    """SECURITY: admin's view onto audit_intent is INSERT-only at the DB GRANT
    level (svc_admin has no SELECT/UPDATE on this table) - exists only so
    account/role-map mutations can be audited in the same transaction as the
    business-data row (INV-12); must never be queried from here."""

    __tablename__ = "audit_intent"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    operator: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
