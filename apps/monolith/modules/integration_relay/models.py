"""SQLAlchemy ORM for integration_relay's cross-module view onto `gate_outbox`
(coding spec §7.2) - relay is granted SELECT+UPDATE only, never touches
`verdict`/`allowlist`/`audit_intent` (policies/grants/manifest.yaml svc_relay)."""

from __future__ import annotations

import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class GateOutboxReadWrite(Base):
    """SECURITY: relay's view onto gate's `gate_outbox` table - DB GRANTs limit
    this module's MySQL user to SELECT+UPDATE on this one table (never INSERT:
    only gate produces outbox events, relay only drains them)."""

    __tablename__ = "gate_outbox"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    aggregate_id: Mapped[str] = mapped_column(String(36), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    dispatched: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)
