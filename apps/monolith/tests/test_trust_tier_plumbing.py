"""Trust-tier plumbing tests (milestone B' Task 4, coding spec §4.1's actual
fix): `SessionContext.tier` (Task 2, resolved per service account) now reaches
`gate.decide()` via `ScanJob.trust_tier`, recorded by `submit_scan` at
submission time and read back per-scan at decide time - not a single
process-wide `runtime.default_trust_tier` regardless of who submitted.

SECURITY (the reason this file exists, and the lesson from Task 2's own
review): a test that only checks "trust_tier was written to a column and
reads back unchanged" proves nothing about whether the gate ever consults it.
Task 2 got `SessionContext.tier` resolving correctly, tested in isolation, and
STILL shipped a gate that never saw it - `session.tier` was read in exactly
one place in the whole monolith (gateway/router.py's whoami diagnostic), while
every verdict used `runtime.default_trust_tier`. Every test below therefore
submits a HIGH-severity finding at two DIFFERENT tiers and asserts the
recorded VERDICT differs (policies/gate/v1.yaml: `public` blocks at HIGH via
`tier_block_overrides`, every other tier blocks at CRITICAL) - proving the
tier actually reaches and changes the decision, never merely that it
round-trips through a column.

Against real local MySQL + Redis + a tmp_path blob store, same posture as
test_orchestration_pipeline.py.
"""

from __future__ import annotations

import datetime
import json
import uuid
from collections.abc import Sequence

import pytest
import redis.asyncio as aioredis
from common import airlock
from common.blobstore import LocalFilesystemBlobStore, findings_key
from schemas.findings import serialize_engine_result
from skillscan_core import (
    DetectionEngine,
    GatePolicy,
    Severity,
    StaticKeywordEngine,
    TrustTier,
    Verdict,
)
from sqlalchemy import select

from monolith.modules.gate.models import VerdictRow
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.orchestration.models import ScanJob
from monolith.modules.orchestration.service import (
    _try_score_and_decide,
    run_mock_engine_worker_tick,
    run_result_collector_tick,
    submit_scan,
)
from monolith.modules.reeval.controller import PublishedToolchainStatus, trigger_rescans
from monolith.tests.conftest import SessionmakerFixture

_ENGINE = StaticKeywordEngine()
_ENGINES_BY_NAME: dict[str, DetectionEngine] = {_ENGINE.metadata.name: _ENGINE}

# HIGH severity per skillscan_core's static-keyword ruleset (static.eval_call) -
# the same rule test_orchestration_pipeline.py's TestHappyPathEndToEnd.
# test_flagged_content_blocks already relies on being HIGH.
#
# SECURITY: "eval(user_input)" here is inert byte content fed to the
# static-keyword detector as the scanned ARTIFACT - a simple `pattern in line`
# substring match (skillscan_core.engines.StaticKeywordEngine.analyze). It is
# never imported, parsed, or executed by this test or by skillscan itself,
# same as every other use of this exact string across the test suite (see
# test_orchestration_pipeline.py's `_unique_file`).
_HIGH_SEVERITY_LINE = b"eval(user_input)\n"


def _policy(*, version: str) -> GatePolicy:
    """Mirrors policies/gate/v1.yaml's REAL tier behaviour (block_on_severity=
    CRITICAL, tier_block_overrides public->HIGH) - deliberately NOT
    test_orchestration_pipeline.py's own bare `_policy()` (empty
    tier_block_overrides), which could never exercise this distinction at
    all: every tier would resolve to the same CRITICAL threshold."""
    return GatePolicy(
        version=version,
        required_engines=frozenset({_ENGINE.metadata.name}),
        hard_gate_rules=frozenset(),
        tier_block_overrides=((TrustTier.PUBLIC, Severity.HIGH),),
        fail_closed_verdict=Verdict.BLOCK,
    )


def _high_severity_file(marker: str) -> list[tuple[str, int, bytes]]:
    return [(f"skill_{marker}.py", 0o644, _HIGH_SEVERITY_LINE + f"# {marker}\n".encode())]


async def _run_pipeline_once(
    *,
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
    files: Sequence[tuple[str, int, bytes]],
    policy: GatePolicy,
    trust_tier: TrustTier,
    collector_default_trust_tier: TrustTier,
) -> str:
    """`collector_default_trust_tier` is deliberately passed as the WRONG tier
    by every caller below (see each test) - `run_result_collector_tick`'s
    `default_trust_tier` is now only a fallback for a `job.trust_tier` that is
    NULL (a pre-migration row). If the decide path ever regresses to reading
    this parameter instead of the scan's own `job.trust_tier` (recorded by
    `submit_scan` from `trust_tier` above), the resulting verdict would
    silently match `collector_default_trust_tier` instead - and these tests
    would catch that immediately, rather than passing by coincidence because
    both parameters happened to agree.
    """
    await airlock.ensure_groups(redis_client)
    consumer = f"test-{uuid.uuid4()}"

    async with orchestration_sessionmaker() as session, session.begin():
        scan_id = await submit_scan(
            session,
            redis_client,
            blobstore,
            files=files,
            submitter="trust-tier-test",
            engine_metadatas=(_ENGINE.metadata,),
            policy=policy,
            trust_tier=trust_tier,
        )

    for _ in range(20):
        await run_mock_engine_worker_tick(
            redis_client, blobstore, engines_by_name=_ENGINES_BY_NAME, consumer=consumer
        )
        decided = await run_result_collector_tick(
            redis_client,
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            policy=policy,
            default_trust_tier=collector_default_trust_tier,
            allowlist=(),
            signer=LocalDevSigner(),
            consumer=consumer,
        )
        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        if job.state in ("decided", "failed"):
            break
        if decided == 0:
            # nothing new happened and we're not done - avoid spinning forever
            # on a genuine bug; a real deployment would just wait for the next
            # message instead of a tight retry loop.
            continue
    return scan_id


async def _verdict_for(gate_sessionmaker: SessionmakerFixture, scan_id: str) -> str:
    async with gate_sessionmaker() as session:
        row = (
            await session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
        ).scalar_one()
    return str(row.verdict)


class TestTierChangesTheVerdict:
    """The core assertion this file exists for (see module docstring):
    identical content, two different tiers, two different verdicts.

    `_policy()`'s `version=` differs between the two submissions in each test
    purely to give each its own `toolchain_digest` - `submit_scan`'s
    single-flight dedup keys off `content_hash + toolchain_digest`, NEVER
    trust_tier, so two byte-identical submissions at the SAME policy version
    would silently collapse into ONE scan_job (whichever tier arrived first
    wins), which would make the "different tiers, different verdicts"
    assertion tautologically true or outright wrong for the wrong reason. The
    scanned file bytes themselves - what actually produces the HIGH finding -
    are identical between both submissions in every test below; only this
    orthogonal cache-partitioning knob differs.

    2026-07-28 (C2): "whichever tier arrived first wins" is now an ADJUDICATED
    product decision, not just a fixture nuisance noted in passing. The verdict
    is decided once and is not re-run for a later submitter, so it cannot be
    re-tiered for one either - and the marketplace is told which tier it was
    actually judged at, via `views.project_scan`'s `judged_at_tier`. What that
    same dedup used to ALSO do - refuse the later submitter the scan entirely -
    was a real defect; see test_marketplace_router.py's
    TestDeduplicatedSubmissionsStayReadableByEverySubmitter.
    """

    @pytest.mark.asyncio
    async def test_public_tier_blocks_a_high_severity_finding(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        marker = uuid.uuid4().hex[:8]
        scan_id = await _run_pipeline_once(
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            redis_client=redis_client,
            blobstore=blobstore,
            files=_high_severity_file(marker),
            policy=_policy(version=f"tier-plumbing-public-{marker}"),
            trust_tier=TrustTier.PUBLIC,
            collector_default_trust_tier=TrustTier.INTERNAL,  # wrong on purpose
        )
        assert await _verdict_for(gate_sessionmaker, scan_id) == "BLOCK"

    @pytest.mark.asyncio
    async def test_internal_tier_only_reviews_the_same_finding(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        marker = uuid.uuid4().hex[:8]
        scan_id = await _run_pipeline_once(
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            redis_client=redis_client,
            blobstore=blobstore,
            files=_high_severity_file(marker),
            policy=_policy(version=f"tier-plumbing-internal-{marker}"),
            trust_tier=TrustTier.INTERNAL,
            collector_default_trust_tier=TrustTier.PUBLIC,  # wrong on purpose
        )
        assert await _verdict_for(gate_sessionmaker, scan_id) == "REVIEW"

    @pytest.mark.asyncio
    async def test_same_content_two_tiers_diverge(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        """Both halves of the core assertion in ONE test, against the exact
        same file bytes, so a future refactor cannot pass by accident by
        tuning the two tests above's fixtures independently of each other."""
        marker = uuid.uuid4().hex[:8]
        files = _high_severity_file(marker)

        public_scan_id = await _run_pipeline_once(
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            redis_client=redis_client,
            blobstore=blobstore,
            files=files,
            policy=_policy(version=f"tier-plumbing-both-public-{marker}"),
            trust_tier=TrustTier.PUBLIC,
            collector_default_trust_tier=TrustTier.INTERNAL,
        )
        internal_scan_id = await _run_pipeline_once(
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            redis_client=redis_client,
            blobstore=blobstore,
            files=files,
            policy=_policy(version=f"tier-plumbing-both-internal-{marker}"),
            trust_tier=TrustTier.INTERNAL,
            collector_default_trust_tier=TrustTier.PUBLIC,
        )

        public_verdict = await _verdict_for(gate_sessionmaker, public_scan_id)
        internal_verdict = await _verdict_for(gate_sessionmaker, internal_scan_id)
        assert public_verdict == "BLOCK"
        assert internal_verdict == "REVIEW"
        assert public_verdict != internal_verdict


class TestNullTrustTierFallsBackWithoutCrashing:
    """A scan_job row written before this column existed has trust_tier=NULL
    (no backfill - see this column's migration docstring). The decide path
    must fall back to the deployment default (`runtime.default_trust_tier`,
    threaded through as `default_trust_tier`) rather than raising - and the
    fallback must actually take effect, not just avoid crashing, which is why
    these two tests use different defaults and expect different verdicts.

    Seeded directly (bypassing `submit_scan`, which now REQUIRES trust_tier
    and therefore can never itself produce a NULL row) to simulate exactly
    that pre-migration row shape.
    """

    @staticmethod
    async def _seed_null_tier_scan_with_high_finding(
        orchestration_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        *,
        marker: str,
    ) -> tuple[str, GatePolicy]:
        policy = _policy(version=f"tier-plumbing-null-{marker}")
        scan_id = str(uuid.uuid4())
        async with orchestration_sessionmaker() as session, session.begin():
            session.add(
                ScanJob(
                    scan_id=scan_id,
                    content_hash=uuid.uuid4().hex + uuid.uuid4().hex,
                    toolchain_digest=uuid.uuid4().hex + uuid.uuid4().hex,
                    cache_key=uuid.uuid4().hex + uuid.uuid4().hex,
                    state="queued",
                    submitter="pre-migration-row",
                    created_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                    trust_tier=None,
                )
            )
        path, _mode, data = _high_severity_file(marker)[0]
        result = _ENGINE.analyze({path: data})
        assert result.findings, "setup: eval( must be detected as a real HIGH finding"
        blobstore.put(
            findings_key(scan_id, _ENGINE.metadata.name),
            json.dumps(serialize_engine_result(result)).encode("utf-8"),
        )
        return scan_id, policy

    @pytest.mark.asyncio
    async def test_null_tier_falls_back_to_public_default_and_blocks(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        marker = uuid.uuid4().hex[:8]
        scan_id, policy = await self._seed_null_tier_scan_with_high_finding(
            orchestration_sessionmaker, blobstore, marker=marker
        )
        decided = await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(policy.required_engines)),
            policy=policy,
            default_trust_tier=TrustTier.PUBLIC,
            allowlist=(),
            signer=LocalDevSigner(),
            operator="test",
        )
        assert decided is True
        assert await _verdict_for(gate_sessionmaker, scan_id) == "BLOCK"

    @pytest.mark.asyncio
    async def test_null_tier_falls_back_to_internal_default_and_only_reviews(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        marker = uuid.uuid4().hex[:8]
        scan_id, policy = await self._seed_null_tier_scan_with_high_finding(
            orchestration_sessionmaker, blobstore, marker=marker
        )
        decided = await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(policy.required_engines)),
            policy=policy,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=LocalDevSigner(),
            operator="test",
        )
        assert decided is True
        assert await _verdict_for(gate_sessionmaker, scan_id) == "REVIEW"


class TestReevalRescanIsJudgedAtTheSkillsOwnTier:
    """SECURITY (2026-07-28, milestone B' review C3): a reeval-triggered rescan
    must be re-decided at the SKILL's registered tier, not at the deployment
    default.

    `reeval.controller.build_rescan_job` used to construct its scan_job through
    an ORM class that never mapped `trust_tier`, so every rescan inserted NULL
    and fell back to `default_trust_tier` (INTERNAL in production - the most
    PERMISSIVE tier). A PUBLIC skill that BLOCKed on a HIGH finding therefore
    came back REVIEW the moment the toolchain digest moved or an admin pressed
    `POST /v1/reeval/{skill_id}` - re-evaluation, whose whole purpose is to
    re-apply current detection to already-published content, silently relaxed
    every verdict it touched.

    Both tests pass a `default_trust_tier` that is DELIBERATELY WRONG, the same
    device the rest of this file uses: if the rescan's own tier ever stops
    travelling with it, the verdict flips to the fallback's and the assertion
    fails, rather than passing by coincidence.
    """

    @staticmethod
    async def _rescan_via_reeval(
        reeval_sessionmaker: SessionmakerFixture,
        orchestration_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        *,
        marker: str,
        tier: TrustTier,
    ) -> tuple[str, GatePolicy]:
        """Queue a rescan through reeval's real (INSERT-only) path, then seed the
        engine blob the collector would find, and hand back its scan_id."""
        policy = _policy(version=f"tier-plumbing-reeval-{marker}")
        status = PublishedToolchainStatus(
            skill_id=f"skill-{marker}",
            trust_tier=tier,
            content_hash=uuid.uuid4().hex + uuid.uuid4().hex,
            recorded_toolchain_digest="stale-digest",
        )
        async with reeval_sessionmaker() as session, session.begin():
            queued = await trigger_rescans(
                session,
                [status],
                toolchain_digest=f"fresh-digest-{marker}",
                submitter="system:reeval-controller",
            )
        assert queued == 1, "setup: reeval must have queued exactly one rescan"

        # svc_reeval cannot read scan_job back (INSERT-only grant), so the
        # scan_id is recovered through orchestration's own credentials.
        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(
                    select(ScanJob).where(ScanJob.content_hash == status.content_hash)
                )
            ).scalar_one()
        scan_id = str(job.scan_id)

        path, _mode, data = _high_severity_file(marker)[0]
        result = _ENGINE.analyze({path: data})
        assert result.findings, "setup: eval( must be detected as a real HIGH finding"
        blobstore.put(
            findings_key(scan_id, _ENGINE.metadata.name),
            json.dumps(serialize_engine_result(result)).encode("utf-8"),
        )
        return scan_id, policy

    @pytest.mark.asyncio
    async def test_a_public_skills_rescan_still_blocks_at_high(
        self,
        reeval_sessionmaker: SessionmakerFixture,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        marker = uuid.uuid4().hex[:8]
        scan_id, policy = await self._rescan_via_reeval(
            reeval_sessionmaker,
            orchestration_sessionmaker,
            blobstore,
            marker=marker,
            tier=TrustTier.PUBLIC,
        )
        decided = await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(policy.required_engines)),
            policy=policy,
            # Wrong on purpose - and it is exactly the production value
            # (`runtime.default_trust_tier`) that the pre-C3 NULL fell back to.
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=LocalDevSigner(),
            operator="test",
        )
        assert decided is True
        assert await _verdict_for(gate_sessionmaker, scan_id) == "BLOCK"

    @pytest.mark.asyncio
    async def test_an_internal_skills_rescan_is_not_over_tightened_either(
        self,
        reeval_sessionmaker: SessionmakerFixture,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        # The mirror direction: fixing C3 must not staple every rescan to the
        # strictest tier either - it must carry whichever tier the skill has.
        marker = uuid.uuid4().hex[:8]
        scan_id, policy = await self._rescan_via_reeval(
            reeval_sessionmaker,
            orchestration_sessionmaker,
            blobstore,
            marker=marker,
            tier=TrustTier.INTERNAL,
        )
        decided = await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(policy.required_engines)),
            policy=policy,
            default_trust_tier=TrustTier.PUBLIC,  # wrong on purpose
            allowlist=(),
            signer=LocalDevSigner(),
            operator="test",
        )
        assert decided is True
        assert await _verdict_for(gate_sessionmaker, scan_id) == "REVIEW"
