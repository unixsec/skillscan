"""SQLAlchemy ORM for intel's own table (coding spec §7.1): threat_indicator."""

from __future__ import annotations

import datetime

from sqlalchemy import DateTime, Enum, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ThreatIndicator(Base):
    __tablename__ = "threat_indicator"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ioc_type: Mapped[str] = mapped_column(
        Enum("domain", "ip", "md5", name="ioc_type"), nullable=False
    )
    ioc_value: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    imported_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)
