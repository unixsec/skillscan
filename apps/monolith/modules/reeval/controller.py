"""Toolchain-staleness rescan controller (coding spec §11.7).

SECURITY: identifies PUBLISHED skills whose most recently recorded scan used
an outdated `toolchain_digest` (INV-7: toolchain_digest 定靶重评/reeval), and
queues a rescan for each - tiered by trust tier, public/partner first,
internal last (coding spec: "分级批重评(public/partner 先,internal 后)"),
since a public-tier skill's exposure/blast-radius from a stale (potentially
weaker) detection toolchain is highest.

"BLOCK -> auto_quarantine" (coding spec's own phrasing for this module) is
NOT duplicated here: once a queued rescan resolves to a non-PASS verdict, the
skill is still-published-but-no-longer-PASS, which is EXACTLY a poll-sourced
MISMATCH on reeval's own next reconciliation pass - `reeval.quarantine`
already auto-quarantines that by default (SAD §4.3's correction-side
asymmetry). This module's job stops at "identify + queue"; the existing M6
reconciliation loop supplies the correction.

SECURITY: `svc_reeval`'s grant on skill/skill_version is read-only and its
grant on scan_job is INSERT-only (policies/grants/manifest.yaml) - this
module can queue a rescan but can never read scan_job back, matching
gate_outbox's asymmetric-grant precedent elsewhere in this codebase.

HONESTY (known integration gap): `skill`/`skill_version` are only ever
non-empty once something populates them. No M1-M8 milestone's own "模块与文件"
scope explicitly assigns building the `inventory` module's WRITE side (the
coding spec's §3 directory sketch names `modules/inventory/` but no
milestone's file list calls out its service.py) - until that exists,
`list_published_toolchain_statuses` correctly returns empty, which is not a
bug, just an honest reflection of upstream data that doesn't exist yet.
"""

from __future__ import annotations

import datetime
import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from skillscan_core import TrustTier, cache_key
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .models import ScanJobInsertOnly, SkillReadOnly, SkillVersionReadOnly

# SECURITY: lower number = higher priority - public-tier exposure is highest,
# so it is rescanned first; internal is lowest priority, rescanned last.
_TIER_ORDER: dict[TrustTier, int] = {
    TrustTier.PUBLIC: 0,
    TrustTier.PARTNER: 1,
    TrustTier.INTERNAL: 2,
}


@dataclass(frozen=True, slots=True)
class PublishedToolchainStatus:
    skill_id: str
    trust_tier: TrustTier
    content_hash: str
    recorded_toolchain_digest: str


def is_stale(status: PublishedToolchainStatus, current_toolchain_digest: str) -> bool:
    return status.recorded_toolchain_digest != current_toolchain_digest


def batch_rescan_targets(
    statuses: Sequence[PublishedToolchainStatus], current_toolchain_digest: str
) -> tuple[PublishedToolchainStatus, ...]:
    """Filters to stale entries only, ordered public -> partner -> internal.
    Ties within a tier keep their original relative order (stable sort)."""
    stale = [s for s in statuses if is_stale(s, current_toolchain_digest)]
    return tuple(sorted(stale, key=lambda s: _TIER_ORDER[s.trust_tier]))


def build_rescan_job(
    status: PublishedToolchainStatus,
    *,
    toolchain_digest: str,
    submitter: str,
    now: datetime.datetime,
) -> ScanJobInsertOnly:
    """Pure construction of a new scan_job row targeting the SAME content
    (content_hash unchanged - this is a rescan, not a new submission) under
    the CURRENT toolchain_digest. Reuses skillscan_core's own cache_key
    function so the single-flight UNIQUE constraint behaves identically to
    every other scan_job insertion path (a rescan already in flight for this
    exact content+toolchain combination is naturally deduplicated by the DB,
    not by this function)."""
    return ScanJobInsertOnly(
        scan_id=str(uuid.uuid4()),
        content_hash=status.content_hash,
        toolchain_digest=toolchain_digest,
        cache_key=cache_key(status.content_hash, toolchain_digest),
        state="queued",
        submitter=submitter,
        created_at=now,
    )


async def list_published_toolchain_statuses(
    session: AsyncSession,
) -> Sequence[PublishedToolchainStatus]:
    """SECURITY: read-only (svc_reeval: skill/skill_version [SELECT]). One row
    per skill_version - a skill with multiple historical content_hash
    versions on record appears once per version, since scanning/rescanning is
    inherently content-addressable (INV-6), not skill_id-addressable."""
    result = await session.execute(
        select(
            SkillReadOnly.skill_id,
            SkillReadOnly.trust_tier,
            SkillVersionReadOnly.content_hash,
            SkillVersionReadOnly.toolchain_digest,
        ).join(SkillVersionReadOnly, SkillVersionReadOnly.skill_id == SkillReadOnly.skill_id)
    )
    return tuple(
        PublishedToolchainStatus(
            skill_id=row.skill_id,
            trust_tier=TrustTier(row.trust_tier),
            content_hash=row.content_hash,
            recorded_toolchain_digest=row.toolchain_digest,
        )
        for row in result
    )


async def trigger_rescans(
    reeval_session: AsyncSession,
    targets: Sequence[PublishedToolchainStatus],
    *,
    toolchain_digest: str,
    submitter: str = "system:reeval-controller",
) -> int:
    """Queues one rescan job per target, via reeval's own (INSERT-only)
    session. Returns the count actually inserted - a target already queued
    under this exact content_hash+toolchain_digest combination is silently
    skipped (the cache_key UNIQUE constraint on scan_job makes this a no-op,
    not an error), so calling this repeatedly (e.g. on every controller tick)
    is always safe."""
    now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
    queued = 0
    for target in targets:
        job = build_rescan_job(
            target, toolchain_digest=toolchain_digest, submitter=submitter, now=now
        )
        try:
            # SECURITY: a SAVEPOINT per target so one duplicate (already-queued)
            # cache_key only rolls back THIS target's insert, not the whole
            # batch's already-successful ones - the outer transaction is the
            # caller's, per this codebase's usual "caller owns the transaction
            # boundary" convention (see gate.service.decide_and_record).
            async with reeval_session.begin_nested():
                reeval_session.add(job)
                await reeval_session.flush()
        except IntegrityError:
            # Expected/benign: this exact content_hash+toolchain_digest rescan
            # is already queued (cache_key UNIQUE constraint) - not a failure.
            continue
        queued += 1
    return queued
