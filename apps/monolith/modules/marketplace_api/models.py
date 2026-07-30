"""Marketplace fetch audit (里程碑 B' spec §7).

Records what the marketplace actually collected. Three uses: non-repudiation
(we can show what we told them and when), reverse-gap detection (a verdict that
was issued but never fetched suggests they may have published without reading
our answer - the closest achievable analogue of ORPHAN in a pull-only model),
and real polling data for tuning poll_after_ms.
"""

from __future__ import annotations

import datetime

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class MarketplaceFetchLogRow(Base):
    """SECURITY: append-only audit trail - svc_marketplace is granted
    INSERT+SELECT only on this table (policies/grants/manifest.yaml), never
    UPDATE/DELETE. An audit record that can be rewritten is not an audit
    record.

    2026-07-30: the polled key became `skill_id` and the answer became binary, so
    the record of "what we told whom" had to follow. Every added column is NULLABLE
    with no backfill: rows written under the scan-keyed contract genuinely have no
    skill_id, no content_hash and no is_safe, and NULL is the honest way to say a
    field predates the question. Nothing existing was renamed or repurposed - a
    column whose meaning shifts under it is the one thing an audit trail cannot
    survive.
    """

    __tablename__ = "marketplace_fetch_log"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # The KEY the caller actually asked with, as of 2026-07-30. Nullable only for
    # rows written before that; every new row sets it.
    skill_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    # Now nullable: a poll for a skill whose latest version has never been scanned
    # is a real, answerable request ("not_yet_scanned") and there is no scan to
    # name. Recording 0 or an empty string instead would fabricate a scan.
    scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    # WHICH VERSION the answer was about - the response says so, and a
    # non-repudiation record of "we told them safe" is worth little without it.
    content_hash_shown: Mapped[str | None] = mapped_column(String(64), nullable=True)
    service_account: Mapped[str] = mapped_column(String(255), nullable=False)
    fetched_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    status_shown: Mapped[str] = mapped_column(String(16), nullable=False)
    # The internal verdict the answer was DERIVED from. Kept, with its meaning
    # stated rather than quietly widened: the response no longer carries `verdict`
    # at all (the contract is binary), so this is no longer a copy of a returned
    # field. It stays because dropping it would make the fetch log unable to
    # explain its own is_safe column after a policy change.
    verdict_shown: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # The two fields the response actually conveys now.
    is_safe_shown: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    unsafe_reason_shown: Mapped[str | None] = mapped_column(String(32), nullable=True)
