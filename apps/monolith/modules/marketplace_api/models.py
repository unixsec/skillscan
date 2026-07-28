"""Marketplace fetch audit (里程碑 B' spec §7).

Records what the marketplace actually collected. Three uses: non-repudiation
(we can show what we told them and when), reverse-gap detection (a verdict that
was issued but never fetched suggests they may have published without reading
our answer - the closest achievable analogue of ORPHAN in a pull-only model),
and real polling data for tuning poll_after_ms.
"""

from __future__ import annotations

import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class MarketplaceFetchLogRow(Base):
    """SECURITY: append-only audit trail - svc_marketplace is granted
    INSERT+SELECT only on this table (policies/grants/manifest.yaml), never
    UPDATE/DELETE. An audit record that can be rewritten is not an audit
    record."""

    __tablename__ = "marketplace_fetch_log"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    service_account: Mapped[str] = mapped_column(String(255), nullable=False)
    fetched_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    status_shown: Mapped[str] = mapped_column(String(16), nullable=False)
    verdict_shown: Mapped[str | None] = mapped_column(String(16), nullable=True)
