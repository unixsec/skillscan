"""Tests for `reeval.controller` (coding spec §11.7: toolchain-staleness
rescan controller). Pure logic (staleness/tiering/job construction) plus real
local MySQL integration tests proving the read (skill/skill_version, via
`svc_reeval`'s read-only grant) and write (scan_job, via its INSERT-only
grant) sides both work against genuinely separate, least-privilege
credentials - `skill`/`skill_version` are seeded via `inventory_sessionmaker`
(svc_inventory, the actual owning module's credentials) since no inventory
module's own write-side code exists yet (see controller.py's own honesty
note on this integration gap).
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from skillscan_core import TrustTier
from skillscan_core import cache_key as core_cache_key
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from monolith.modules.orchestration.models import ScanJob
from monolith.modules.reeval.controller import (
    PublishedToolchainStatus,
    batch_rescan_targets,
    build_rescan_job,
    is_stale,
    list_published_toolchain_statuses,
    trigger_rescans,
)
from monolith.modules.reeval.models import ScanJobInsertOnly, SkillReadOnly
from monolith.tests.conftest import SessionmakerFixture


class _InventoryBase(DeclarativeBase):
    pass


class _SkillRow(_InventoryBase):
    __tablename__ = "skill"

    skill_id: Mapped[str] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column()
    trust_tier: Mapped[str] = mapped_column()


class _SkillVersionRow(_InventoryBase):
    __tablename__ = "skill_version"

    content_hash: Mapped[str] = mapped_column(primary_key=True)
    skill_id: Mapped[str] = mapped_column()
    toolchain_digest: Mapped[str] = mapped_column()


def _status(
    *, skill_id: str = "skill-1", tier: TrustTier = TrustTier.INTERNAL, digest: str = "old-digest"
) -> PublishedToolchainStatus:
    return PublishedToolchainStatus(
        skill_id=skill_id,
        trust_tier=tier,
        content_hash=uuid.uuid4().hex + uuid.uuid4().hex,
        recorded_toolchain_digest=digest,
    )


class TestIsStale:
    def test_matching_digest_is_not_stale(self) -> None:
        status = _status(digest="current-digest")
        assert is_stale(status, "current-digest") is False

    def test_different_digest_is_stale(self) -> None:
        status = _status(digest="old-digest")
        assert is_stale(status, "current-digest") is True


class TestBatchRescanTargets:
    def test_filters_out_non_stale_entries(self) -> None:
        fresh = _status(skill_id="fresh", digest="current")
        stale = _status(skill_id="stale", digest="old")
        result = batch_rescan_targets([fresh, stale], "current")
        assert [s.skill_id for s in result] == ["stale"]

    def test_orders_public_before_partner_before_internal(self) -> None:
        internal = _status(skill_id="i", tier=TrustTier.INTERNAL, digest="old")
        public = _status(skill_id="p", tier=TrustTier.PUBLIC, digest="old")
        partner = _status(skill_id="pa", tier=TrustTier.PARTNER, digest="old")
        result = batch_rescan_targets([internal, public, partner], "current")
        assert [s.skill_id for s in result] == ["p", "pa", "i"]

    def test_empty_input_yields_empty_output(self) -> None:
        assert batch_rescan_targets([], "current") == ()

    def test_all_fresh_yields_empty_output(self) -> None:
        result = batch_rescan_targets([_status(digest="current")], "current")
        assert result == ()


class TestBuildRescanJob:
    def test_preserves_content_hash_targets_new_toolchain_digest(self) -> None:
        status = _status(digest="old-digest")
        job = build_rescan_job(
            status,
            toolchain_digest="new-digest",
            submitter="tester",
            now=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
        )
        assert job.content_hash == status.content_hash  # rescan, not a new submission
        assert job.toolchain_digest == "new-digest"
        assert job.state == "queued"
        assert job.submitter == "tester"

    def test_cache_key_matches_skillscan_core_computation(self) -> None:
        status = _status(digest="old-digest")
        job = build_rescan_job(
            status,
            toolchain_digest="new-digest",
            submitter="tester",
            now=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
        )
        assert job.cache_key == core_cache_key(status.content_hash, "new-digest")

    def test_fresh_scan_id_each_call(self) -> None:
        status = _status()
        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        job_a = build_rescan_job(status, toolchain_digest="d", submitter="t", now=now)
        job_b = build_rescan_job(status, toolchain_digest="d", submitter="t", now=now)
        assert job_a.scan_id != job_b.scan_id

    @pytest.mark.parametrize(
        "tier", [TrustTier.PUBLIC, TrustTier.PARTNER, TrustTier.INTERNAL], ids=lambda t: t.value
    )
    def test_carries_the_skills_own_trust_tier(self, tier: TrustTier) -> None:
        # SECURITY (C3): the rescan must be judged at the SAME tier the skill is
        # registered under. An unmapped/omitted column here writes NULL, and the
        # decide path reads NULL as "fall back to runtime.default_trust_tier"
        # (INTERNAL - the most permissive), so every reeval quietly re-decided
        # public content at the internal threshold. Parametrized over all three
        # tiers so a hardcoded constant cannot pass this.
        status = _status(tier=tier, digest="old-digest")
        job = build_rescan_job(
            status,
            toolchain_digest="new-digest",
            submitter="tester",
            now=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
        )
        assert job.trust_tier == tier.value


class TestListPublishedToolchainStatuses:
    @pytest.mark.asyncio
    async def test_reads_joined_skill_and_skill_version_via_readonly_grant(
        self,
        inventory_sessionmaker: SessionmakerFixture,
        reeval_sessionmaker: SessionmakerFixture,
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex
        async with inventory_sessionmaker() as session, session.begin():
            session.add(_SkillRow(skill_id=skill_id, source="test", trust_tier="public"))
            session.add(
                _SkillVersionRow(
                    content_hash=content_hash, skill_id=skill_id, toolchain_digest="digest-v1"
                )
            )

        async with reeval_sessionmaker() as session:
            statuses = await list_published_toolchain_statuses(session)
        matching = [s for s in statuses if s.skill_id == skill_id]
        assert len(matching) == 1
        assert matching[0].trust_tier is TrustTier.PUBLIC
        assert matching[0].content_hash == content_hash
        assert matching[0].recorded_toolchain_digest == "digest-v1"

    @pytest.mark.asyncio
    async def test_reeval_session_cannot_write_to_skill_table(
        self, reeval_sessionmaker: SessionmakerFixture
    ) -> None:
        # SECURITY: svc_reeval's grant on skill/skill_version is SELECT-only -
        # proves the DB itself rejects a write attempt, not just app-layer
        # convention (same isolation property test_grant_isolation.py proves
        # for other cross-module seams).
        with pytest.raises(DBAPIError):
            async with reeval_sessionmaker() as session, session.begin():
                session.add(
                    SkillReadOnly(
                        skill_id=f"nope-{uuid.uuid4().hex}", source="x", trust_tier="internal"
                    )
                )
                await session.flush()


class TestTriggerRescans:
    @pytest.mark.asyncio
    async def test_queues_a_real_scan_job_visible_to_orchestration(
        self,
        reeval_sessionmaker: SessionmakerFixture,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        status = _status(digest="old-digest")
        toolchain_digest = f"new-digest-{uuid.uuid4().hex[:12]}"

        async with reeval_sessionmaker() as session, session.begin():
            queued = await trigger_rescans(
                session, [status], toolchain_digest=toolchain_digest, submitter="tester"
            )
        assert queued == 1

        # SECURITY: svc_reeval cannot read scan_job back (INSERT-only) - the
        # real proof this row is usable comes from ORCHESTRATION's own
        # credentials seeing it, exactly as its worker-tick polling would.
        async with orchestration_sessionmaker() as session:
            row = (
                await session.execute(
                    select(ScanJob).where(ScanJob.content_hash == status.content_hash)
                )
            ).scalar_one()
        assert row.state == "queued"
        assert row.toolchain_digest == toolchain_digest

    @pytest.mark.asyncio
    async def test_the_queued_row_records_the_skills_trust_tier(
        self,
        reeval_sessionmaker: SessionmakerFixture,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        # SECURITY (C3): the unit test above proves `build_rescan_job` sets the
        # attribute; this proves it actually reaches the DATABASE through
        # svc_reeval's INSERT-only grant. A column the ORM class does not map is
        # silently dropped from the INSERT with no error anywhere - which is
        # exactly how this shipped - so only a read-back under orchestration's
        # own credentials can tell the two apart.
        status = _status(tier=TrustTier.PUBLIC, digest="old-digest")
        toolchain_digest = f"new-digest-{uuid.uuid4().hex[:12]}"

        async with reeval_sessionmaker() as session, session.begin():
            await trigger_rescans(
                session, [status], toolchain_digest=toolchain_digest, submitter="tester"
            )

        async with orchestration_sessionmaker() as session:
            row = (
                await session.execute(
                    select(ScanJob).where(ScanJob.content_hash == status.content_hash)
                )
            ).scalar_one()
        assert row.trust_tier == TrustTier.PUBLIC.value

    @pytest.mark.asyncio
    async def test_reeval_session_cannot_read_scan_job_back(
        self, reeval_sessionmaker: SessionmakerFixture
    ) -> None:
        with pytest.raises(DBAPIError):
            async with reeval_sessionmaker() as session:
                await session.execute(select(ScanJobInsertOnly))

    @pytest.mark.asyncio
    async def test_calling_twice_for_the_same_target_only_queues_once(
        self, reeval_sessionmaker: SessionmakerFixture
    ) -> None:
        status = _status(digest="old-digest")
        toolchain_digest = f"new-digest-{uuid.uuid4().hex[:12]}"

        async with reeval_sessionmaker() as session, session.begin():
            first = await trigger_rescans(
                session, [status], toolchain_digest=toolchain_digest, submitter="tester"
            )
        async with reeval_sessionmaker() as session, session.begin():
            second = await trigger_rescans(
                session, [status], toolchain_digest=toolchain_digest, submitter="tester"
            )
        assert first == 1
        assert second == 0  # SECURITY: cache_key UNIQUE constraint - safe to call repeatedly

    @pytest.mark.asyncio
    async def test_partial_failure_does_not_block_other_targets_in_the_batch(
        self,
        reeval_sessionmaker: SessionmakerFixture,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        toolchain_digest = f"new-digest-{uuid.uuid4().hex[:12]}"
        already_queued = _status(digest="old-digest")
        fresh_target = _status(digest="old-digest")

        # Pre-queue `already_queued` under the same toolchain_digest so the
        # batch call below hits one duplicate (skipped) and one new insert.
        async with reeval_sessionmaker() as session, session.begin():
            await trigger_rescans(
                session, [already_queued], toolchain_digest=toolchain_digest, submitter="tester"
            )

        async with reeval_sessionmaker() as session, session.begin():
            queued = await trigger_rescans(
                session,
                [already_queued, fresh_target],
                toolchain_digest=toolchain_digest,
                submitter="tester",
            )
        assert queued == 1  # only fresh_target, already_queued was a no-op

        async with orchestration_sessionmaker() as session:
            row = (
                await session.execute(
                    select(ScanJob).where(ScanJob.content_hash == fresh_target.content_hash)
                )
            ).scalar_one()
        assert row.state == "queued"
