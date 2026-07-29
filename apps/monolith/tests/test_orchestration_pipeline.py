"""End-to-end scan pipeline tests (coding spec §11.3 M3 acceptance bar):
提交→入队→(mock 引擎)→回读校验→aggregate→decide→签名(占位)→写 outbox;
幂等去重(2 次同内容→1 job); poison-pill→死信+BLOCK.

Against real local MySQL + Redis + a tmp_path-backed blob store; only the mock
engine substitutes for a real sandboxed worker (coding spec §10, M4/M5).
"""

from __future__ import annotations

import asyncio
import datetime
import json
import uuid
from collections.abc import Sequence
from typing import Any

import pytest
import redis.asyncio as aioredis
from common import airlock
from common.blobstore import LocalFilesystemBlobStore, artifact_key, findings_key
from schemas.findings import serialize_engine_result
from skillscan_core import (
    CategoryWeights,
    DetectionEngine,
    EngineCapability,
    EngineMetadata,
    EngineResult,
    EngineStatus,
    Finding,
    GatePolicy,
    ScanMode,
    StaticKeywordEngine,
    TrustTier,
    Verdict,
)
from skillscan_core import content_hash as compute_content_hash
from sqlalchemy import select, update
from sqlalchemy.exc import DBAPIError

from monolith.modules.gate.models import VerdictRow
from monolith.modules.gate.service import decide_and_record as real_decide_and_record
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.orchestration import service as orchestration_service
from monolith.modules.orchestration.models import ScanEngineHealthRow, ScanJob, ScanResultRow
from monolith.modules.orchestration.retention import (
    DEFAULT_RETENTION_DAYS,
    RETENTION_DAYS_ENV,
    sweep_engine_health_retention,
)
from monolith.modules.orchestration.service import (
    RESULT_POISON_PILL_REASON,
    STATE_DECIDED,
    SubmissionChannel,
    _dead_letter_and_decide,
    _try_score_and_decide,
    run_mock_engine_worker_tick,
    run_result_collector_tick,
    submit_scan,
    sweep_sandbox_wait_timeouts,
)
from monolith.tests.conftest import SessionmakerFixture

_ENGINE = StaticKeywordEngine()
_ENGINES_BY_NAME: dict[str, DetectionEngine] = {_ENGINE.metadata.name: _ENGINE}


def _policy(*, version: str) -> GatePolicy:
    return GatePolicy(
        version=version,
        required_engines=frozenset({_ENGINE.metadata.name}),
        hard_gate_rules=frozenset(),
        fail_closed_verdict=Verdict.BLOCK,
    )


# 2026-07-27 (D2, TestSandboxWait below): a single shared policy/signer is
# fine here - unlike TestHappyPathEndToEnd's per-test versioned `_policy()`,
# nothing in TestSandboxWait exercises `submit_scan`'s cache_key dedup (each
# test builds its own scan_id/content_hash directly via
# `_seed_scan_with_all_required_blobs`), so there is no collision to avoid by
# varying `version` per test.
_POLICY = _policy(version="test-sandbox-wait")


def _signer() -> LocalDevSigner:
    return LocalDevSigner()


def _write_engine_blob(
    blobstore: LocalFilesystemBlobStore,
    scan_id: str,
    engine_name: str,
    *,
    findings: Sequence[Finding] = (),
    status: EngineStatus = EngineStatus.OK,
    error: str | None = None,
    analyze_duration_ms: int | None = None,
) -> None:
    """Writes a real, schema-valid findings blob directly to the blob store -
    the same shape `run_mock_engine_worker_tick`/the real engine-runner would
    write - without going through either dispatch path. Used by
    TestSandboxWait to simulate "this engine already reported" independent of
    whichever engine (required or sandbox/advisory) is under test.

    `status`/`error`/`analyze_duration_ms` (milestone C Task 8) default to
    exactly what this helper always wrote, so every existing caller produces a
    byte-identical blob; TestEngineHealthRows varies them to exercise the three
    duration states and the reported-ERROR case. `analyze_duration_ms=None`
    OMITS the key, which is what a pre-Task-7 engine-runner image writes."""
    result = EngineResult(
        engine=EngineMetadata(
            name=engine_name,
            version="test",
            ruleset_digest="test",
            capabilities=frozenset({EngineCapability.STATIC}),
        ),
        findings=tuple(findings),
        status=status,
        scan_mode=ScanMode.STATIC,
        llm_used=False,
        error=error,
    )
    blobstore.put(
        findings_key(scan_id, engine_name),
        json.dumps(serialize_engine_result(result, analyze_duration_ms=analyze_duration_ms)).encode(
            "utf-8"
        ),
    )


async def _seed_scan_with_all_required_blobs(
    orchestration_sessionmaker: SessionmakerFixture,
    blobstore: LocalFilesystemBlobStore,
    redis_client: aioredis.Redis,
    *,
    created_at: datetime.datetime | None = None,
    sandbox_wait_started_at: datetime.datetime | None = None,
    state: str = "queued",
) -> str:
    """TestSandboxWait's shared setup: a scan_job row (built directly, bypassing
    `submit_scan`'s dedup/artifact-packing plumbing, which this test class
    doesn't need) with every one of `_POLICY.required_engines` already
    reporting BOTH a findings blob and an airlock result message - exactly
    what a real floor-engine dispatch tick writes - so
    `_try_score_and_decide`'s required-engines wait is already satisfied
    before any test in this class runs, and only the sandbox
    (waited_advisory) engine's absence is ever under test. The result
    messages matter specifically for
    `test_a_long_wait_does_not_trip_the_poison_pill_counter`, which drives
    `run_result_collector_tick` (message-driven) rather than calling
    `_try_score_and_decide` directly like the rest of this class."""
    await airlock.ensure_groups(redis_client)
    scan_id = str(uuid.uuid4())
    content_hash = uuid.uuid4().hex + uuid.uuid4().hex  # 64 hex chars, unique
    async with orchestration_sessionmaker() as session, session.begin():
        session.add(
            ScanJob(
                scan_id=scan_id,
                content_hash=content_hash,
                toolchain_digest=uuid.uuid4().hex + uuid.uuid4().hex,
                cache_key=uuid.uuid4().hex + uuid.uuid4().hex,
                state=state,
                submitter="test-sandbox-wait",
                created_at=created_at or datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                sandbox_wait_started_at=sandbox_wait_started_at,
            )
        )
    for engine_name in sorted(_POLICY.required_engines):
        _write_engine_blob(blobstore, scan_id, engine_name, findings=[])
        await airlock.produce_result(
            redis_client,
            scan_id=scan_id,
            findings_key=findings_key(scan_id, engine_name),
            engine=engine_name,
            status=EngineStatus.OK.value,
        )
    return scan_id


def _unique_file(*, marker: str, benign: bool) -> list[tuple[str, int, bytes]]:
    body = b"print('hello')\n" if benign else b"eval(user_input)\n"
    # NOTE: "eval(user_input)" is scanned CONTENT for the static-keyword engine
    # to detect (skillscan_core.engines._STATIC_KEYWORD_PATTERNS) - it is never
    # executed by anything in this test or in skillscan itself.
    return [(f"skill_{marker}.py", 0o644, body + f"# {marker}\n".encode())]


async def _run_pipeline_once(
    *,
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
    files: list[tuple[str, int, bytes]],
    policy: GatePolicy,
) -> str:
    await airlock.ensure_groups(redis_client)
    consumer = f"test-{uuid.uuid4()}"

    async with orchestration_sessionmaker() as session, session.begin():
        scan_id = await submit_scan(
            session,
            redis_client,
            blobstore,
            files=files,
            submitter="alice",
            engine_metadatas=(_ENGINE.metadata,),
            policy=policy,
            trust_tier=TrustTier.INTERNAL,
            source=SubmissionChannel.CONSOLE,
            requested_trust_tier=TrustTier.INTERNAL,
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
            default_trust_tier=TrustTier.INTERNAL,
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


class TestHappyPathEndToEnd:
    @pytest.mark.asyncio
    async def test_benign_content_passes(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        policy = _policy(version=f"test-benign-{uuid.uuid4().hex[:8]}")
        scan_id = await _run_pipeline_once(
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            redis_client=redis_client,
            blobstore=blobstore,
            files=_unique_file(marker=uuid.uuid4().hex[:8], benign=True),
            policy=policy,
        )

        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        assert job.state == "decided"

        async with gate_sessionmaker() as gate_session:
            verdict = (
                await gate_session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
            ).scalar_one()
        assert verdict.verdict == "PASS"
        assert verdict.jws_signature  # signed, even if by the M3 dev placeholder key

    @pytest.mark.asyncio
    async def test_flagged_content_blocks(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        policy = _policy(version=f"test-flagged-{uuid.uuid4().hex[:8]}")
        scan_id = await _run_pipeline_once(
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            redis_client=redis_client,
            blobstore=blobstore,
            files=_unique_file(marker=uuid.uuid4().hex[:8], benign=False),
            policy=policy,
        )

        async with gate_sessionmaker() as gate_session:
            verdict = (
                await gate_session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
            ).scalar_one()
        # eval( is HIGH severity in the static-keyword ruleset (skillscan_core)
        # and this policy's default review_confidence/block thresholds resolve
        # HIGH to at least REVIEW.
        assert verdict.verdict in ("REVIEW", "BLOCK")


class TestSingleFlightDedup:
    @pytest.mark.asyncio
    async def test_two_submissions_of_same_content_collapse_to_one_job(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        policy = _policy(version=f"test-dedup-{uuid.uuid4().hex[:8]}")
        files = _unique_file(marker=uuid.uuid4().hex[:8], benign=True)

        async with orchestration_sessionmaker() as session, session.begin():
            scan_id_1 = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="alice",
                engine_metadatas=(_ENGINE.metadata,),
                policy=policy,
                trust_tier=TrustTier.INTERNAL,
                source=SubmissionChannel.CONSOLE,
                requested_trust_tier=TrustTier.INTERNAL,
            )
        async with orchestration_sessionmaker() as session, session.begin():
            scan_id_2 = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="alice",
                engine_metadatas=(_ENGINE.metadata,),
                policy=policy,
                trust_tier=TrustTier.INTERNAL,
                source=SubmissionChannel.CONSOLE,
                requested_trust_tier=TrustTier.INTERNAL,
            )

        assert scan_id_1 == scan_id_2

        async with orchestration_sessionmaker() as session:
            count = (
                (await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id_1)))
                .scalars()
                .all()
            )
        assert len(count) == 1


class TestReweightingBreaksTheSingleFlightDedup:
    """INV-7, milestone C acceptance criterion 5 - the DB-level half of
    `tests/test_invariants.py::test_inv7_category_weight_change_invalidates_cache_key`.

    Same bytes, same `policy.version`, one `category_weights` field changed:
    the second submission must NOT be handed the first scan's job. It is the
    same dedup mechanism `TestSingleFlightDedup` above proves works - here it
    has to NOT fire, because the answer it would hand back carries a `score`
    computed under the weights that were in force before the edit.
    """

    @pytest.mark.asyncio
    async def test_a_weight_change_alone_produces_a_second_scan_job(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        version = f"test-reweight-{uuid.uuid4().hex[:8]}"
        unweighted = _policy(version=version)
        reweighted = GatePolicy(
            version=version,  # deliberately NOT bumped - that is the whole test
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
            category_weights=CategoryWeights(data_credential=2.0),
        )
        files = _unique_file(marker=uuid.uuid4().hex[:8], benign=True)

        async with orchestration_sessionmaker() as session, session.begin():
            scan_id_1 = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="alice",
                engine_metadatas=(_ENGINE.metadata,),
                policy=unweighted,
                trust_tier=TrustTier.INTERNAL,
                source=SubmissionChannel.CONSOLE,
                requested_trust_tier=TrustTier.INTERNAL,
            )
        async with orchestration_sessionmaker() as session, session.begin():
            scan_id_2 = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="alice",
                engine_metadatas=(_ENGINE.metadata,),
                policy=reweighted,
                trust_tier=TrustTier.INTERNAL,
                source=SubmissionChannel.CONSOLE,
                requested_trust_tier=TrustTier.INTERNAL,
            )

        assert scan_id_1 != scan_id_2, (
            "a category_weights change must invalidate the cache_key even with "
            "policy.version untouched - otherwise the second submission is served "
            "a score computed under the old weights"
        )

        async with orchestration_sessionmaker() as session:
            rows = (
                (
                    await session.execute(
                        select(ScanJob).where(ScanJob.scan_id.in_([scan_id_1, scan_id_2]))
                    )
                )
                .scalars()
                .all()
            )
        assert len({row.cache_key for row in rows}) == 2
        # Same bytes: only the toolchain digest may differ, never the content hash.
        assert len({row.content_hash for row in rows}) == 1

    @pytest.mark.asyncio
    async def test_an_unweighted_policy_still_dedups(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        # The control: declaring all-1.0 weights explicitly must not break
        # single-flight against a policy that declared none. This is what stops
        # the feature shipping as a mass rescan of every published skill.
        version = f"test-reweight-noop-{uuid.uuid4().hex[:8]}"
        implicit = _policy(version=version)
        explicit = GatePolicy(
            version=version,
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
            category_weights=CategoryWeights(),
        )
        files = _unique_file(marker=uuid.uuid4().hex[:8], benign=True)

        ids = []
        for policy in (implicit, explicit):
            async with orchestration_sessionmaker() as session, session.begin():
                ids.append(
                    await submit_scan(
                        session,
                        redis_client,
                        blobstore,
                        files=files,
                        submitter="alice",
                        engine_metadatas=(_ENGINE.metadata,),
                        policy=policy,
                        trust_tier=TrustTier.INTERNAL,
                        source=SubmissionChannel.CONSOLE,
                        requested_trust_tier=TrustTier.INTERNAL,
                    )
                )
        assert ids[0] == ids[1]


class TestParseSkillNameRootPathOnly:
    """2026-07-27: `_parse_skill_name` must match SKILL.md at the package
    ROOT only, never by basename anywhere in the tree - it supplies the
    display name written to `ScanJob.skill_name`, and a bundled example
    (`examples/SKILL.md`) must never masquerade as the whole package's name.
    Pure function, no DB/Redis - unlike the rest of this file, these run
    locally with no fixtures."""

    def test_a_non_root_skill_md_is_ignored_not_used_as_the_name(self) -> None:
        files = [
            ("examples/SKILL.md", 0o644, b"---\nname: example-only\n---\n"),
        ]
        assert orchestration_service._parse_skill_name(files) is None

    def test_a_root_skill_md_still_populates_the_name_regression_guard(self) -> None:
        files = [
            ("SKILL.md", 0o644, b"---\nname: real-skill\n---\n"),
            ("examples/SKILL.md", 0o644, b"---\nname: example-only\n---\n"),
        ]
        assert orchestration_service._parse_skill_name(files) == "real-skill"


class TestSkillNameParsing:
    """2026-07-14: Scans list page needs a name to distinguish targets even for
    ad-hoc submissions with no registered skill_id - parsed once at submit
    time from SKILL.md's YAML frontmatter, never from skill_id/skill_version
    (most scans in this suite's own fixtures don't have either)."""

    @pytest.mark.asyncio
    async def test_valid_skill_md_frontmatter_populates_skill_name(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        policy = _policy(version=f"test-skillname-{uuid.uuid4().hex[:8]}")
        marker = uuid.uuid4().hex[:8]
        files = _unique_file(marker=marker, benign=True) + [
            (
                "SKILL.md",
                0o644,
                b"---\nname: cool-formatter\ndescription: does formatting\n---\n\n# Cool\n",
            )
        ]

        async with orchestration_sessionmaker() as session, session.begin():
            scan_id = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="alice",
                engine_metadatas=(_ENGINE.metadata,),
                policy=policy,
                trust_tier=TrustTier.INTERNAL,
                source=SubmissionChannel.CONSOLE,
                requested_trust_tier=TrustTier.INTERNAL,
            )

        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        assert job.skill_name == "cool-formatter"

    @pytest.mark.asyncio
    async def test_missing_skill_md_leaves_skill_name_none(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        policy = _policy(version=f"test-skillname-{uuid.uuid4().hex[:8]}")
        files = _unique_file(marker=uuid.uuid4().hex[:8], benign=True)  # no SKILL.md at all

        async with orchestration_sessionmaker() as session, session.begin():
            scan_id = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="alice",
                engine_metadatas=(_ENGINE.metadata,),
                policy=policy,
                trust_tier=TrustTier.INTERNAL,
                source=SubmissionChannel.CONSOLE,
                requested_trust_tier=TrustTier.INTERNAL,
            )

        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        assert job.skill_name is None

    @pytest.mark.parametrize(
        "skill_md_body",
        [
            pytest.param(b"# no frontmatter here at all\n", id="no-delimiters"),
            pytest.param(b"---\nname: [this is not valid: yaml\n---\n", id="malformed-yaml"),
            pytest.param(b"---\ndescription: no name key\n---\n", id="no-name-key"),
            pytest.param(b"---\nname: 12345\n---\n", id="name-not-a-string"),
            pytest.param(b'---\nname: "   "\n---\n', id="name-blank"),
        ],
    )
    @pytest.mark.asyncio
    async def test_malformed_or_absent_name_never_raises(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
        skill_md_body: bytes,
    ) -> None:
        policy = _policy(version=f"test-skillname-{uuid.uuid4().hex[:8]}")
        files = _unique_file(marker=uuid.uuid4().hex[:8], benign=True) + [
            ("SKILL.md", 0o644, skill_md_body)
        ]

        async with orchestration_sessionmaker() as session, session.begin():
            scan_id = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="alice",
                engine_metadatas=(_ENGINE.metadata,),
                policy=policy,
                trust_tier=TrustTier.INTERNAL,
                source=SubmissionChannel.CONSOLE,
                requested_trust_tier=TrustTier.INTERNAL,
            )

        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        assert job.skill_name is None


class TestPoisonPill:
    @pytest.mark.asyncio
    async def test_undeliverable_job_dead_letters_to_block(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        """SECURITY (INV-5): a scan job redelivered past MAX_DELIVERY_COUNT
        must dead-letter to a real, signed BLOCK verdict + scan_job.state =
        'failed' - never retried forever, never silently dropped."""
        policy = _policy(version=f"test-poison-{uuid.uuid4().hex[:8]}")
        files = _unique_file(marker=uuid.uuid4().hex[:8], benign=True)
        await airlock.ensure_groups(redis_client)

        async with orchestration_sessionmaker() as session, session.begin():
            scan_id = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="alice",
                engine_metadatas=(_ENGINE.metadata,),
                policy=policy,
                trust_tier=TrustTier.INTERNAL,
                source=SubmissionChannel.CONSOLE,
                requested_trust_tier=TrustTier.INTERNAL,
            )

        # Force delivery_count past the threshold by repeatedly claiming (via
        # XCLAIM against a real consumer group/PEL) WITHOUT ever acking - this
        # simulates a worker that crashes every time it picks up the job,
        # exactly the scenario INV-5's poison-pill handling exists for.
        message_id = None
        jobs = await airlock.claim_scan_jobs(redis_client, consumer="poison-setup", count=50)
        for job in jobs:
            if job.scan_id == scan_id:
                message_id = job.message_id
        assert message_id is not None, "expected our scan_job message to be claimable"

        for _ in range(airlock.MAX_DELIVERY_COUNT + 1):
            await redis_client.xclaim(
                airlock.SCANS_STREAM,
                airlock.WORKERS_GROUP,
                "poison-claimer",
                min_idle_time=0,
                message_ids=[message_id],
            )

        consumer = f"test-{uuid.uuid4()}"
        for _ in range(10):
            # reclaim_idle_ms=0: this job is only "idle" a few ms in test time
            # (we just XCLAIMed it above) - real deployments use the default
            # 60s crash-recovery window; this test isn't waiting that long.
            await run_mock_engine_worker_tick(
                redis_client,
                blobstore,
                engines_by_name=_ENGINES_BY_NAME,
                consumer=consumer,
                reclaim_idle_ms=0,
            )
            await run_result_collector_tick(
                redis_client,
                blobstore,
                orchestration_sessionmaker,
                gate_sessionmaker,
                policy=policy,
                default_trust_tier=TrustTier.INTERNAL,
                allowlist=(),
                signer=LocalDevSigner(),
                consumer=consumer,
            )
            async with orchestration_sessionmaker() as session:
                job_row = (
                    await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
                ).scalar_one()
            if job_row.state == "failed":
                break

        assert job_row.state == "failed"

        async with gate_sessionmaker() as gate_session:
            verdict = (
                await gate_session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
            ).scalar_one()
        assert verdict.verdict == "BLOCK"
        assert "poison_pill" in verdict.reasons[0]

    @pytest.mark.asyncio
    async def test_missing_artifact_dead_letters_on_first_encounter(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        """A scan-job stream message whose artifact is gone from the blob store
        is a PERMANENT failure - the mock engine worker must dead-letter it on
        the FIRST encounter (one processed job, immediate ack), never leave it
        unacked to churn the stream for MAX_DELIVERY_COUNT redeliveries and
        starve live jobs behind it. Regression for a real backlog-starvation
        observed against stream messages left over from a wiped blob store."""
        policy = _policy(version=f"test-missing-{uuid.uuid4().hex[:8]}")
        files = _unique_file(marker=uuid.uuid4().hex[:8], benign=True)
        await airlock.ensure_groups(redis_client)

        async with orchestration_sessionmaker() as session, session.begin():
            scan_id = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="alice",
                engine_metadatas=(_ENGINE.metadata,),
                policy=policy,
                trust_tier=TrustTier.INTERNAL,
                source=SubmissionChannel.CONSOLE,
                requested_trust_tier=TrustTier.INTERNAL,
            )
        # Delete the artifact the submission just wrote, so the worker's
        # blobstore.get raises BlobNotFoundError on its very first attempt.
        content_hash = compute_content_hash(files)
        blobstore._path_for(artifact_key(content_hash)).unlink()  # noqa: SLF001

        consumer = f"test-{uuid.uuid4()}"
        # count is generous (default is 10) so this test's own just-produced
        # message - the newest in the stream - is reached within this ONE call
        # even if earlier tests left backlog ahead of it; `>=` rather than `==`
        # since a large count may also dead-letter some of that backlog in the
        # same tick - the property under test is "handled within one dispatch
        # call", not "the only thing this call touched".
        processed = await run_mock_engine_worker_tick(
            redis_client, blobstore, engines_by_name=_ENGINES_BY_NAME, consumer=consumer, count=500
        )
        assert processed >= 1  # dead-lettered on first encounter, not left unacked

        for _ in range(10):
            await run_result_collector_tick(
                redis_client,
                blobstore,
                orchestration_sessionmaker,
                gate_sessionmaker,
                policy=policy,
                default_trust_tier=TrustTier.INTERNAL,
                allowlist=(),
                signer=LocalDevSigner(),
                consumer=consumer,
            )
            async with orchestration_sessionmaker() as session:
                job_row = (
                    await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
                ).scalar_one()
            if job_row.state == "failed":
                break
        assert job_row.state == "failed"


class TestBlobstoreOffloadedToThread:
    """SECURITY/robustness regression: `run_mock_engine_worker_tick` and
    `_try_score_and_decide` both run on the SAME event loop as the FastAPI app
    (the worker is started via `asyncio.create_task` in `main.py`'s lifespan),
    so a blocking `blobstore.get/put/exists` call (real disk I/O via
    `LocalFilesystemBlobStore`) invoked directly - no `await`/`to_thread` -
    would stall the entire event loop for its duration: health checks, scan
    submissions, every other admin API call freezes right along with it. These
    tests assert every blobstore call site in these two functions is routed
    through `asyncio.to_thread` rather than called inline, by spying on
    `asyncio.to_thread` itself (still delegating to the real implementation,
    so the pipeline continues to behave correctly end-to-end - this is not a
    stub that fakes success)."""

    @staticmethod
    def _spy_to_thread(monkeypatch: pytest.MonkeyPatch) -> list[str]:
        calls: list[str] = []
        real_to_thread = asyncio.to_thread

        async def _spying_to_thread(func: Any, *args: Any, **kwargs: Any) -> Any:
            calls.append(getattr(func, "__name__", repr(func)))
            return await real_to_thread(func, *args, **kwargs)

        # NOTE: `service.py` does `import asyncio` (not a per-module copy),
        # so patching the `asyncio` module imported directly here patches
        # `asyncio.to_thread` process-wide for the duration of the test -
        # `monkeypatch` restores the original after the test regardless of
        # pass/fail, and `_spying_to_thread` always delegates to the real
        # implementation, so this is safe even though it's global rather than
        # module-scoped.
        monkeypatch.setattr(asyncio, "to_thread", _spying_to_thread)
        return calls

    @pytest.mark.asyncio
    async def test_worker_tick_offloads_get_and_put_to_a_thread(
        self,
        monkeypatch: pytest.MonkeyPatch,
        orchestration_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        policy = _policy(version=f"test-offload-worker-{uuid.uuid4().hex[:8]}")
        files = _unique_file(marker=uuid.uuid4().hex[:8], benign=True)
        await airlock.ensure_groups(redis_client)

        # submit_scan is out of this bugfix's scope (task named only
        # run_mock_engine_worker_tick/_try_score_and_decide) - it still calls
        # blobstore directly, inline, so submit BEFORE spying starts, and
        # only start the spy right before the worker tick under test, so
        # submit_scan's own (out-of-scope, still-blocking) blobstore calls
        # don't pollute this test's assertion about the worker tick.
        async with orchestration_sessionmaker() as session, session.begin():
            await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="alice",
                engine_metadatas=(_ENGINE.metadata,),
                policy=policy,
                trust_tier=TrustTier.INTERNAL,
                source=SubmissionChannel.CONSOLE,
                requested_trust_tier=TrustTier.INTERNAL,
            )

        calls = self._spy_to_thread(monkeypatch)
        consumer = f"test-{uuid.uuid4()}"
        processed = await run_mock_engine_worker_tick(
            redis_client, blobstore, engines_by_name=_ENGINES_BY_NAME, consumer=consumer
        )
        assert processed >= 1
        # blobstore.get (the artifact read) and blobstore.put (the findings
        # write) must both have gone through asyncio.to_thread - a regression
        # here (someone reverting to a direct call) would leave `calls` empty
        # for the corresponding bound method.
        assert "get" in calls, f"expected blobstore.get offloaded to a thread, got calls={calls}"
        assert "put" in calls, f"expected blobstore.put offloaded to a thread, got calls={calls}"

    @pytest.mark.asyncio
    async def test_score_and_decide_offloads_exists_to_a_thread(
        self,
        monkeypatch: pytest.MonkeyPatch,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        policy = _policy(version=f"test-offload-decide-{uuid.uuid4().hex[:8]}")
        files = _unique_file(marker=uuid.uuid4().hex[:8], benign=True)
        await airlock.ensure_groups(redis_client)
        consumer = f"test-{uuid.uuid4()}"

        async with orchestration_sessionmaker() as session, session.begin():
            scan_id = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="alice",
                engine_metadatas=(_ENGINE.metadata,),
                policy=policy,
                trust_tier=TrustTier.INTERNAL,
                source=SubmissionChannel.CONSOLE,
                requested_trust_tier=TrustTier.INTERNAL,
            )
        # Get the mock engine to actually write the findings blob first (a
        # real precondition for _try_score_and_decide's `blobstore.exists`
        # check to have something to find), THEN start spying - the property
        # under test is specifically the `.exists` call inside
        # run_result_collector_tick -> _try_score_and_decide, under the
        # SELECT ... FOR UPDATE lock (coding spec: this is also where holding
        # the row lock across a blocking call would extend MySQL lock time).
        await run_mock_engine_worker_tick(
            redis_client, blobstore, engines_by_name=_ENGINES_BY_NAME, consumer=consumer
        )

        calls = self._spy_to_thread(monkeypatch)
        decided = await run_result_collector_tick(
            redis_client,
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            policy=policy,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=LocalDevSigner(),
            consumer=consumer,
        )
        assert decided == 1
        assert "exists" in calls, (
            f"expected blobstore.exists (under SELECT ... FOR UPDATE) offloaded "
            f"to a thread, got calls={calls}"
        )

        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        assert job.state == "decided"


class TestResultCollectorExceptionIsolation:
    """SECURITY regression: unlike its sibling `run_mock_engine_worker_tick`
    (which wraps each job's processing in try/except Exception: ... continue),
    `run_result_collector_tick`'s per-scan_id loop previously had no exception
    isolation. If one scan_id's `_dead_letter_and_decide`/`_try_score_and_decide`
    call raised (e.g. an IntegrityError from two replicas racing to
    dead-letter/decide the same scan_id concurrently - this function's own
    docstring names this as an expected scenario), the exception propagated out
    of the `by_scan_id` loop entirely, skipping the LATER, unconditional
    `for r in results: await airlock.ack_result(...)` loop - so every OTHER
    already-successfully-decided scan_id claimed that same tick went unacked
    and was needlessly delayed until stream redelivery, even though its own
    verdict had already been recorded."""

    @pytest.mark.asyncio
    async def test_one_scan_ids_failure_does_not_block_another_scan_ids_ack(
        self,
        monkeypatch: pytest.MonkeyPatch,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        policy_good = _policy(version=f"test-isolation-good-{uuid.uuid4().hex[:8]}")
        policy_bad = _policy(version=f"test-isolation-bad-{uuid.uuid4().hex[:8]}")
        await airlock.ensure_groups(redis_client)
        consumer = f"test-{uuid.uuid4()}"

        async with orchestration_sessionmaker() as session, session.begin():
            scan_id_good = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=_unique_file(marker=uuid.uuid4().hex[:8], benign=True),
                submitter="alice",
                engine_metadatas=(_ENGINE.metadata,),
                policy=policy_good,
                trust_tier=TrustTier.INTERNAL,
                source=SubmissionChannel.CONSOLE,
                requested_trust_tier=TrustTier.INTERNAL,
            )
        async with orchestration_sessionmaker() as session, session.begin():
            scan_id_bad = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=_unique_file(marker=uuid.uuid4().hex[:8], benign=True),
                submitter="alice",
                engine_metadatas=(_ENGINE.metadata,),
                policy=policy_bad,
                trust_tier=TrustTier.INTERNAL,
                source=SubmissionChannel.CONSOLE,
                requested_trust_tier=TrustTier.INTERNAL,
            )

        # Get both scans' findings reported so a single run_result_collector_tick
        # call has both scan_ids' results claimable in the SAME batch (the
        # property under test: ONE tick, TWO scan_ids, one fails).
        for _ in range(5):
            await run_mock_engine_worker_tick(
                redis_client, blobstore, engines_by_name=_ENGINES_BY_NAME, consumer=consumer
            )

        async def _decide_and_record_raising_for_bad(
            session: Any, *, scan_id: str, **kwargs: Any
        ) -> Any:
            if scan_id == scan_id_bad:
                # Simulates the documented concurrent-replica race (e.g. an
                # IntegrityError from two collectors deciding the same
                # scan_id at once) without needing to actually orchestrate a
                # second real replica - the property under test is what
                # run_result_collector_tick does when THIS call raises, not
                # how the raise was produced.
                raise RuntimeError("simulated IntegrityError: concurrent decide race")
            return await real_decide_and_record(session, scan_id=scan_id, **kwargs)

        monkeypatch.setattr(
            orchestration_service, "decide_and_record", _decide_and_record_raising_for_bad
        )

        decided = await run_result_collector_tick(
            redis_client,
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            policy=policy_good,  # required_engines identical for both test policies
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=LocalDevSigner(),
            consumer=consumer,
        )
        # Only the good scan_id should have been decided this tick - the bad
        # one's exception must not have prevented it.
        assert decided == 1

        async with orchestration_sessionmaker() as session:
            good_job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id_good))
            ).scalar_one()
            bad_job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id_bad))
            ).scalar_one()
        assert good_job.state == "decided"
        # The bad scan_id must NOT have been silently marked decided/failed by
        # the exception path. _try_score_and_decide commits scan_job.state =
        # "scored" (and writes the ScanResultRow) in its OWN transaction
        # BEFORE calling out to decide_and_record - so by the time our mocked
        # decide_and_record raises, "scored" is already durably committed;
        # this scan_id is left mid-pipeline, not reverted, exactly matching
        # this module's own documented "known gap" (a crash between scored
        # and decided leaves scan_job stuck at 'scored' - see
        # run_result_collector_tick's docstring) rather than any NEW state
        # this fix introduces.
        assert bad_job.state == "scored"

        async with gate_sessionmaker() as gate_session:
            good_verdict = (
                await gate_session.execute(
                    select(VerdictRow).where(VerdictRow.scan_id == scan_id_good)
                )
            ).scalar_one_or_none()
            bad_verdict = (
                await gate_session.execute(
                    select(VerdictRow).where(VerdictRow.scan_id == scan_id_bad)
                )
            ).scalar_one_or_none()
        assert good_verdict is not None  # the other scan_id's verdict WAS recorded
        assert bad_verdict is None  # the failing scan_id never got a (partial) verdict

        # Regression for the ack-starvation half of the bug: confirm directly
        # via XPENDING (same primitive `airlock.delivery_count` already uses
        # for the scan-jobs stream) that the BAD scan_id's result message(s)
        # are still pending/unacked in the consumer group - i.e. genuinely
        # left for legitimate redelivery, not silently dropped, and NOT
        # ack'd-by-accident alongside the good scan_id's message(s) the way
        # the original unconditional `for r in results: ack` loop would have.
        pending = await redis_client.xpending_range(
            airlock.RESULTS_STREAM,
            airlock.ORCHESTRATORS_GROUP,
            min="-",
            max="+",
            count=1000,
            consumername=consumer,
        )
        pending_ids = [
            p["message_id"].decode() if isinstance(p["message_id"], bytes) else p["message_id"]
            for p in pending
        ]
        assert pending_ids, "expected the bad scan_id's result message(s) to still be pending"

        pending_scan_ids: set[str] = set()
        for message_id in pending_ids:
            entries = await redis_client.xrange(
                airlock.RESULTS_STREAM, min=message_id, max=message_id, count=1
            )
            _mid, fields = entries[0]
            decoded_fields = {
                (k.decode() if isinstance(k, bytes) else k): (
                    v.decode() if isinstance(v, bytes) else v
                )
                for k, v in fields.items()
            }
            pending_scan_ids.add(decoded_fields["scan_id"])

        assert pending_scan_ids == {scan_id_bad}, (
            f"expected ONLY the bad scan_id's message(s) still pending, got "
            f"pending_scan_ids={pending_scan_ids}"
        )


class TestSandboxWait:
    """2026-07-27 (D2): the gate now waits for the sandbox engines instead of
    deciding the moment the in-process floor engines finish. Their findings
    were durably written but only counted when they happened to win a race."""

    @pytest.mark.asyncio
    async def test_decision_waits_while_a_sandbox_blob_is_missing(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        decided = await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(_POLICY.required_engines)),
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=_signer(),
            operator="test",
            waited_advisory_engines=("bandit",),
        )
        assert decided is False, "must not decide while a waited sandbox engine has no blob"

    @pytest.mark.asyncio
    async def test_decision_proceeds_once_the_sandbox_blob_lands(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        _write_engine_blob(blobstore, scan_id, "bandit", findings=[])
        decided = await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(_POLICY.required_engines)),
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=_signer(),
            operator="test",
            waited_advisory_engines=("bandit",),
        )
        assert decided is True

    @pytest.mark.asyncio
    async def test_force_decide_proceeds_without_the_sandbox_blob(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        decided = await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(_POLICY.required_engines)),
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=_signer(),
            operator="test",
            waited_advisory_engines=("bandit",),
            force_decide=True,
        )
        assert decided is True

    @pytest.mark.asyncio
    async def test_timeout_records_which_engines_did_not_arrive(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """The reason string is how an operator learns this verdict was made
        with fewer engines than usual - a silent downgrade would be worse than
        the delay this feature costs."""
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(_POLICY.required_engines)),
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=_signer(),
            operator="test",
            waited_advisory_engines=("bandit", "yara"),
            force_decide=True,
        )
        async with gate_sessionmaker() as s:
            row = (
                await s.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
            ).scalar_one()
        joined = " ".join(row.reasons)
        assert "sandbox_wait_timeout" in joined
        assert "bandit" in joined and "yara" in joined

    @pytest.mark.asyncio
    async def test_a_long_wait_does_not_trip_the_poison_pill_counter(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """SECURITY (D2.4): result messages are ACKed even when the scan is not
        yet decidable, so waiting cannot cause redelivery and cannot consume
        MAX_DELIVERY_COUNT. Without this, a wait longer than
        STALE_CLAIM_IDLE_MS (60s) would manufacture a fake fail-closed BLOCK."""
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        consumer = "test-consumer"
        for _ in range(airlock.MAX_DELIVERY_COUNT + 2):
            await run_result_collector_tick(
                redis_client,
                blobstore,
                orchestration_sessionmaker,
                gate_sessionmaker,
                policy=_POLICY,
                default_trust_tier=TrustTier.INTERNAL,
                allowlist=(),
                signer=_signer(),
                consumer=consumer,
                waited_advisory_engines=("bandit",),
            )
        async with orchestration_sessionmaker() as s:
            job = (await s.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))).scalar_one()
        assert job.state in ("queued", "running"), "still waiting, not dead-lettered"

        # The actual SECURITY property under test (2026-07-27 review, Important
        # 3): RESULTS_STREAM/ORCHESTRATORS_GROUP has no reclaim/XCLAIM path
        # anywhere in this codebase, so a message that was never ACKed would
        # just sit pending forever rather than being redelivered - the
        # `job.state` assertion above would pass identically whether or not
        # `run_result_collector_tick` actually ACKs while still waiting. Prove
        # the ACK happened for real via XPENDING, same primitive
        # `TestResultCollectorExceptionIsolation` already uses below, just
        # asserting ABSENCE for a scan that's still waiting rather than
        # PRESENCE for one whose decide raised.
        pending = await redis_client.xpending_range(
            airlock.RESULTS_STREAM,
            airlock.ORCHESTRATORS_GROUP,
            min="-",
            max="+",
            count=1000,
            consumername=consumer,
        )
        pending_scan_ids: set[str] = set()
        for p in pending:
            message_id = (
                p["message_id"].decode() if isinstance(p["message_id"], bytes) else p["message_id"]
            )
            entries = await redis_client.xrange(
                airlock.RESULTS_STREAM, min=message_id, max=message_id, count=1
            )
            if not entries:
                continue
            _mid, fields = entries[0]
            decoded_fields = {
                (k.decode() if isinstance(k, bytes) else k): (
                    v.decode() if isinstance(v, bytes) else v
                )
                for k, v in fields.items()
            }
            pending_scan_ids.add(decoded_fields["scan_id"])
        assert scan_id not in pending_scan_ids, (
            "this scan_id's result message(s) are still pending/unacked - waiting "
            "must ACK on arrival, never leave a message for (nonexistent) redelivery"
        )


_WAIT_TIMEOUT_S = 300.0


def _ago(seconds: float) -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None) - datetime.timedelta(
        seconds=seconds
    )


async def _verdict_exists(gate_sessionmaker: SessionmakerFixture, scan_id: str) -> bool:
    async with gate_sessionmaker() as session:
        row = (
            await session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
        ).scalar_one_or_none()
    return row is not None


async def _sweep(
    blobstore: LocalFilesystemBlobStore,
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
) -> int:
    return await sweep_sandbox_wait_timeouts(
        blobstore,
        orchestration_sessionmaker,
        gate_sessionmaker,
        policy=_POLICY,
        default_trust_tier=TrustTier.INTERNAL,
        allowlist=(),
        signer=_signer(),
        waited_advisory_engines=("bandit",),
        wait_timeout_s=_WAIT_TIMEOUT_S,
        operator="test-sweep",
    )


class _BlobStoreRaisingFor:
    """Delegates to a real blob store but raises for one scan_id's keys, so a
    single scan inside a sweep batch fails the way a real transient blob-store
    error would."""

    def __init__(self, inner: LocalFilesystemBlobStore, poisoned_scan_id: str) -> None:
        self._inner = inner
        self._poisoned = poisoned_scan_id

    def _guard(self, key: str) -> None:
        if self._poisoned in key:
            raise RuntimeError("simulated blob-store failure")

    def put(self, key: str, data: bytes) -> None:
        self._guard(key)
        self._inner.put(key, data)

    def get(self, key: str) -> bytes:
        self._guard(key)
        return self._inner.get(key)

    def list_prefix(self, prefix: str) -> list[str]:
        return self._inner.list_prefix(prefix)

    def exists(self, key: str) -> bool:
        self._guard(key)
        return self._inner.exists(key)


class TestSandboxWaitSweep:
    """`sweep_sandbox_wait_timeouts` had ZERO test coverage before 2026-07-27
    (nothing anywhere called it; `TestSandboxWait` above only drives
    `_try_score_and_decide(force_decide=True)` directly). Its selection
    predicate, ordering, batch limit and per-scan error isolation were all
    unexercised - which is how the wrong clock survived: the sweep's own
    behaviour was never observed by a test at all.
    """

    @pytest.mark.asyncio
    async def test_a_scan_that_has_only_just_started_waiting_is_not_swept(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """REGRESSION (final review, F-2). The sweep measured from `created_at`,
        so this exact row - submitted 10 minutes ago, but whose floor blobs
        only landed a moment ago after a worker outage - was force-decided in
        the same tick that produced it. The verdict is then signed from floor
        findings only: a package whose only HIGH finding comes from bandit gets
        PASS instead of REVIEW, which is precisely the backlog case D2's own
        comments enumerate.
        """
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker,
            blobstore,
            redis_client,
            created_at=_ago(600),  # a long-queued submission...
            sandbox_wait_started_at=_ago(1),  # ...that only just started waiting
        )
        assert await _sweep(blobstore, orchestration_sessionmaker, gate_sessionmaker) == 0
        assert not await _verdict_exists(gate_sessionmaker, scan_id)

    @pytest.mark.asyncio
    async def test_a_scan_that_never_started_waiting_is_never_swept(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """NULL means "has never started waiting" - an ancient row that never
        reached the wait must not be selected at all."""
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker,
            blobstore,
            redis_client,
            created_at=_ago(86_400),
            sandbox_wait_started_at=None,
        )
        assert await _sweep(blobstore, orchestration_sessionmaker, gate_sessionmaker) == 0
        assert not await _verdict_exists(gate_sessionmaker, scan_id)

    @pytest.mark.asyncio
    async def test_a_wait_past_the_budget_is_forced_through(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """The sweep's actual purpose: once the wait itself is past
        timeout+grace, decide and record WHICH engine never arrived."""
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker,
            blobstore,
            redis_client,
            sandbox_wait_started_at=_ago(
                _WAIT_TIMEOUT_S + orchestration_service._SWEEP_GRACE_S + 60
            ),
        )
        assert await _sweep(blobstore, orchestration_sessionmaker, gate_sessionmaker) == 1
        async with gate_sessionmaker() as session:
            row = (
                await session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
            ).scalar_one()
        assert "sandbox_wait_timeout:bandit" in " ".join(row.reasons)

    @pytest.mark.asyncio
    async def test_a_wait_inside_the_grace_window_is_not_swept_yet(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """The grace exists so the engine's own TIMEOUT blob - a more
        informative outcome than our guess - wins the race."""
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker,
            blobstore,
            redis_client,
            sandbox_wait_started_at=_ago(_WAIT_TIMEOUT_S + 1),
        )
        assert await _sweep(blobstore, orchestration_sessionmaker, gate_sessionmaker) == 0
        assert not await _verdict_exists(gate_sessionmaker, scan_id)

    @pytest.mark.asyncio
    async def test_an_already_decided_scan_is_not_swept_again(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker,
            blobstore,
            redis_client,
            sandbox_wait_started_at=_ago(100_000),
            state="decided",
        )
        assert await _sweep(blobstore, orchestration_sessionmaker, gate_sessionmaker) == 0
        assert not await _verdict_exists(gate_sessionmaker, scan_id)

    @pytest.mark.asyncio
    async def test_the_longest_waiting_scans_go_first_within_the_batch_limit(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Ordering is by the SAME column the cutoff filters on, so "oldest"
        means "waiting longest", not "submitted first". Without it, a cluster
        of rows that keeps raising could occupy the whole batch every tick and
        starve everything behind it."""
        monkeypatch.setattr(orchestration_service, "_SWEEP_BATCH", 2)
        base = _WAIT_TIMEOUT_S + orchestration_service._SWEEP_GRACE_S + 60
        waited_longest = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker,
            blobstore,
            redis_client,
            created_at=_ago(10),  # newest submission, longest wait
            sandbox_wait_started_at=_ago(base + 300),
        )
        waited_middle = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker,
            blobstore,
            redis_client,
            sandbox_wait_started_at=_ago(base + 200),
        )
        waited_least = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker,
            blobstore,
            redis_client,
            created_at=_ago(100_000),  # oldest submission, shortest wait
            sandbox_wait_started_at=_ago(base + 100),
        )
        assert await _sweep(blobstore, orchestration_sessionmaker, gate_sessionmaker) == 2
        assert await _verdict_exists(gate_sessionmaker, waited_longest)
        assert await _verdict_exists(gate_sessionmaker, waited_middle)
        assert not await _verdict_exists(gate_sessionmaker, waited_least)

    @pytest.mark.asyncio
    async def test_one_failing_scan_does_not_stop_the_rest_of_the_batch(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        over_budget = _ago(_WAIT_TIMEOUT_S + orchestration_service._SWEEP_GRACE_S + 60)
        poisoned = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker,
            blobstore,
            redis_client,
            sandbox_wait_started_at=over_budget,
        )
        healthy = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker,
            blobstore,
            redis_client,
            sandbox_wait_started_at=over_budget,
        )
        failing_blobstore = _BlobStoreRaisingFor(blobstore, poisoned)
        decided = await sweep_sandbox_wait_timeouts(
            failing_blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=_signer(),
            waited_advisory_engines=("bandit",),
            wait_timeout_s=_WAIT_TIMEOUT_S,
            operator="test-sweep",
        )
        assert decided == 1
        assert await _verdict_exists(gate_sessionmaker, healthy)
        assert not await _verdict_exists(gate_sessionmaker, poisoned)


class TestSandboxWaitClock:
    """The other half of F-2: the sweep can only measure the wait if something
    records when it began."""

    @pytest.mark.asyncio
    async def test_the_clock_starts_when_a_sandbox_engine_is_first_seen_missing(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        async with orchestration_sessionmaker() as session:
            before = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
            assert before.sandbox_wait_started_at is None

        decided = await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(_POLICY.required_engines)),
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=_signer(),
            operator="test",
            waited_advisory_engines=("bandit",),
        )
        assert decided is False
        async with orchestration_sessionmaker() as session:
            after = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        assert after.sandbox_wait_started_at is not None

    @pytest.mark.asyncio
    async def test_the_clock_is_never_pushed_forward_by_a_later_tick(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """Every collector tick re-observes the same missing engine. Refreshing
        the timestamp each time would push the deadline out forever and the
        sweep would never fire."""
        started = _ago(1_000)
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker,
            blobstore,
            redis_client,
            sandbox_wait_started_at=started,
        )
        await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(_POLICY.required_engines)),
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=_signer(),
            operator="test",
            waited_advisory_engines=("bandit",),
        )
        async with orchestration_sessionmaker() as session:
            after = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        assert after.sandbox_wait_started_at == started

    @pytest.mark.asyncio
    async def test_the_clock_does_not_start_before_the_required_engines_report(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """A scan whose floor engines were never dispatched is not "waiting for
        the sandbox" - it must stay NULL, and therefore stay out of the sweep,
        rather than accumulating a wait it never began."""
        scan_id = str(uuid.uuid4())
        async with orchestration_sessionmaker() as session, session.begin():
            session.add(
                ScanJob(
                    scan_id=scan_id,
                    content_hash=uuid.uuid4().hex + uuid.uuid4().hex,
                    toolchain_digest=uuid.uuid4().hex + uuid.uuid4().hex,
                    cache_key=uuid.uuid4().hex + uuid.uuid4().hex,
                    state="queued",
                    submitter="test-sandbox-wait",
                    created_at=_ago(100_000),
                )
            )
        decided = await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(_POLICY.required_engines)),
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=_signer(),
            operator="test",
            waited_advisory_engines=("bandit",),
        )
        assert decided is False
        async with orchestration_sessionmaker() as session:
            after = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        assert after.sandbox_wait_started_at is None
        assert await _sweep(blobstore, orchestration_sessionmaker, gate_sessionmaker) == 0


async def _verdict_is_duplicated(gate_sessionmaker: SessionmakerFixture, scan_id: str) -> bool:
    async with gate_sessionmaker() as session:
        rows = (
            await session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
        ).all()
    return len(rows) > 1


class TestResultMessageLossStillConverges:
    """VM re-review, N-2: the results stream had no reclaim path at all
    (`claim_results` reads `">"` only, and unlike the scans stream there was no
    `reclaim_stale_*` counterpart). A collector that crashed between
    `XREADGROUP` and `ack_result` stranded that message forever - and with it
    the scan, whose findings blob was already durably written but which nothing
    would ever look at again. `sweep_queued_jobs_to_airlock` only handles
    `queued`, and `sweep_sandbox_wait_timeouts` cannot see it either because
    the collector never reached the point where it sets
    `sandbox_wait_started_at`.

    CAUTION, and the reason this class is shaped the way it is: this codebase
    already had one falsely-green test sitting on exactly this hole -
    `test_a_long_wait_does_not_trip_the_poison_pill_counter` was constant-green
    precisely BECAUSE nothing redelivers on this stream, so deleting the ACK it
    was meant to prove changed nothing. So these tests do not assert on
    XPENDING bookkeeping; they simulate the crash for real (claim without
    acking, then drop the consumer) and assert the scan reaches a VERDICT.
    That assertion is false without the reclaim path.
    """

    @pytest.mark.asyncio
    async def test_a_scan_still_reaches_a_verdict_after_its_result_message_is_stranded(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        # Simulate the crash: a dead consumer claims every pending result
        # message and never ACKs one of them. `">"` will never hand these to
        # anybody again.
        dead_consumer = f"crashed-{uuid.uuid4().hex[:8]}"
        claimed = await airlock.claim_results(redis_client, consumer=dead_consumer, count=100)
        assert any(r.scan_id == scan_id for r in claimed), "setup: message must have been claimed"

        live_consumer = f"live-{uuid.uuid4().hex[:8]}"
        assert (
            await airlock.claim_results(
                redis_client, consumer=live_consumer, count=100, block_ms=10
            )
            == []
        ), "setup: a stranded message must be invisible to a fresh consumer via '>'"

        decided = await run_result_collector_tick(
            redis_client,
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=_signer(),
            consumer=live_consumer,
            # 0ms: take over immediately rather than sleeping out the real
            # 60s STALE_CLAIM_IDLE_MS. The production default is unchanged.
            reclaim_idle_ms=0,
        )
        # Scan-scoped, not `== 1`: this Redis group is shared with the rest of
        # the session, so a tick with reclaim enabled can legitimately sweep up
        # another test's deliberately-unacked message too (see
        # TestResultCollectorExceptionIsolation). The property under test is
        # that THIS scan converged.
        assert decided >= 1, "the stranded scan must be recovered and decided"
        async with gate_sessionmaker() as session:
            row = (
                await session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
            ).scalar_one()
        assert row.verdict in tuple(v.name for v in Verdict)

    @pytest.mark.asyncio
    async def test_a_recovered_message_does_not_double_count_findings(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """The objection to adding redelivery: does a message delivered twice
        double a scan's findings? It cannot - the collector uses messages only
        to learn WHICH scan_ids to look at, then reads each engine's blob by
        name, and `scan_job.state` single-flights the decide. Proven rather
        than asserted in a comment."""
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        consumer = f"live-{uuid.uuid4().hex[:8]}"
        kwargs: dict[str, Any] = {
            "policy": _POLICY,
            "default_trust_tier": TrustTier.INTERNAL,
            "allowlist": (),
            "signer": _signer(),
            "consumer": consumer,
            "reclaim_idle_ms": 0,
        }
        first = await run_result_collector_tick(
            redis_client,
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            **kwargs,
        )
        second = await run_result_collector_tick(
            redis_client,
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            **kwargs,
        )
        assert first >= 1
        # The anti-double-count property, asserted scan-scoped rather than via
        # the tick's aggregate count (which this shared Redis group makes
        # unreliable - see the note in the previous test): the SECOND delivery
        # of the same message must not produce a second verdict, and must not
        # re-open a decided scan.
        assert second == 0 or not await _verdict_is_duplicated(gate_sessionmaker, scan_id)
        async with gate_sessionmaker() as session:
            rows = (
                await session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
            ).all()
        assert len(rows) == 1
        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        assert job.state == "decided"


async def _churn_result_messages(
    redis_client: aioredis.Redis, scan_id: str, *, deliveries: int
) -> tuple[str, ...]:
    """Drive this scan's results-stream messages up to `deliveries` extra
    redeliveries, by XCLAIMing them the way the scans-stream poison-pill test
    already does. Returns their message ids.

    XCLAIM (not JUSTID) is what increments `times_delivered`, which is the
    counter `airlock.result_delivery_count` reads - so this reproduces a
    collector that picked the message up and died before ACKing, `deliveries`
    times over, without needing to actually break the scoring transaction.
    """
    claimed = await airlock.claim_results(
        redis_client, consumer=f"churn-setup-{uuid.uuid4().hex[:8]}", count=200
    )
    message_ids = tuple(r.message_id for r in claimed if r.scan_id == scan_id)
    assert message_ids, "setup: this scan's result messages must have been claimable"
    for _ in range(deliveries):
        await redis_client.xclaim(
            airlock.RESULTS_STREAM,
            airlock.ORCHESTRATORS_GROUP,
            f"churner-{uuid.uuid4().hex[:8]}",
            min_idle_time=0,
            message_ids=list(message_ids),
        )
    return message_ids


class TestResultPoisonPill:
    """INV-5 on the RESULTS stream (2026-07-29, milestone C correctness review
    N-1). The scans stream has capped redelivery since M3; this one never did.

    THE HOLE. `run_result_collector_tick` deliberately leaves a scan_id's
    messages unacked when deciding it raises, so a transient failure retries.
    `reclaim_stale_results` hands them straight back. Nothing bounded that, so
    a DETERMINISTIC failure inside `_try_score_and_decide` retried forever: the
    scan never got a verdict and the stream never drained.

    Milestone C Task 8 is what made that reachable rather than theoretical - it
    put 15 `scan_engine_health` INSERTs, four CHECK constraints and a new GRANT
    inside that transaction, every one of which fails identically on retry.

    WHY THESE TESTS DO NOT BREAK THE TRANSACTION TO GET THERE. The cap's
    contract is about the DELIVERY COUNT, not about any particular cause: "this
    message has defeated every previous attempt". Driving the counter directly
    (as `TestPoisonPill` already does for the scans stream) tests exactly that
    contract, and does not quietly become a test of whichever failure mode was
    fashionable when it was written. The scans are seeded with every required
    blob present, so WITHOUT the cap they score cleanly - which is what makes
    the first test's BLOCK assertion a real signal rather than a coincidence.
    """

    @pytest.mark.asyncio
    async def test_a_result_message_past_the_delivery_cap_dead_letters_to_block(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """Not unacked forever, and not silently dropped either: a real, signed,
        audited fail-closed BLOCK carrying a reason that names the RESULTS
        stream, so an operator is pointed at the database/grants/policy rather
        than at the submitted package."""
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        await _churn_result_messages(
            redis_client, scan_id, deliveries=airlock.MAX_DELIVERY_COUNT + 1
        )

        consumer = f"live-{uuid.uuid4().hex[:8]}"
        job_row = None
        for _ in range(10):
            # Looped for the same reason TestPoisonPill loops: XAUTOCLAIM
            # sweeps the shared group from "0" in bounded batches, so this
            # scan's messages are not guaranteed to be in the first one.
            await run_result_collector_tick(
                redis_client,
                blobstore,
                orchestration_sessionmaker,
                gate_sessionmaker,
                policy=_POLICY,
                default_trust_tier=TrustTier.INTERNAL,
                allowlist=(),
                signer=_signer(),
                consumer=consumer,
                reclaim_idle_ms=0,
            )
            async with orchestration_sessionmaker() as session:
                job_row = (
                    await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
                ).scalar_one()
            if job_row.state == "failed":
                break

        assert job_row is not None and job_row.state == "failed"
        async with gate_sessionmaker() as session:
            verdict = (
                await session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
            ).scalar_one()
        assert verdict.verdict == "BLOCK"
        assert any(RESULT_POISON_PILL_REASON in reason for reason in verdict.reasons), (
            f"the dead-letter reason must name the results stream: {verdict.reasons}"
        )

    @pytest.mark.asyncio
    async def test_a_dead_lettered_result_message_stops_churning_the_stream(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """The other half of the contract, and the half an ack-and-drop fix
        would also satisfy - so it is asserted separately rather than assumed
        from the verdict: once dead-lettered, the message is ACKed and nothing
        hands it back. Asserted by actually re-running the reclaim, not by
        reading XPENDING bookkeeping."""
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        await _churn_result_messages(
            redis_client, scan_id, deliveries=airlock.MAX_DELIVERY_COUNT + 1
        )

        consumer = f"live-{uuid.uuid4().hex[:8]}"
        for _ in range(10):
            await run_result_collector_tick(
                redis_client,
                blobstore,
                orchestration_sessionmaker,
                gate_sessionmaker,
                policy=_POLICY,
                default_trust_tier=TrustTier.INTERNAL,
                allowlist=(),
                signer=_signer(),
                consumer=consumer,
                reclaim_idle_ms=0,
            )
            async with orchestration_sessionmaker() as session:
                state = (
                    await session.execute(select(ScanJob.state).where(ScanJob.scan_id == scan_id))
                ).scalar_one()
            if state == "failed":
                break
        assert state == "failed", "setup: the scan must have been dead-lettered first"

        still_pending = await airlock.reclaim_stale_results(
            redis_client, consumer=f"sweeper-{uuid.uuid4().hex[:8]}", min_idle_ms=0
        )
        assert not [r for r in still_pending if r.scan_id == scan_id], (
            "a dead-lettered scan's messages must be ACKed - anything else keeps the "
            "results stream churning on a scan that already has its final verdict"
        )

    @pytest.mark.asyncio
    async def test_a_redelivery_within_the_cap_is_still_scored_normally(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """The cap must not fire on a scan that merely got redelivered once or
        twice - that is what the reclaim path is FOR, and a cap that turned an
        ordinary crash-recovery into a forced BLOCK would be worse than the
        churn it replaces. Two extra deliveries plus the setup claim plus the
        tick's own XAUTOCLAIM is 4, comfortably under MAX_DELIVERY_COUNT."""
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        await _churn_result_messages(redis_client, scan_id, deliveries=2)

        await run_result_collector_tick(
            redis_client,
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=_signer(),
            consumer=f"live-{uuid.uuid4().hex[:8]}",
            reclaim_idle_ms=0,
        )
        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        assert job.state == STATE_DECIDED
        async with gate_sessionmaker() as session:
            verdict = (
                await session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
            ).scalar_one()
        assert not any(RESULT_POISON_PILL_REASON in reason for reason in verdict.reasons)


class TestEngineHealthRows:
    """Milestone C Task 8: per-engine health reaches a queryable table.

    VM-ONLY, and the point is not that these lines execute - the pure
    capture-side tests in `test_engine_health.py` already cover the logic. The
    point is the SCHEMA: this repo has shipped 1103 passing tests beside 88
    "Unknown column" errors in the deployed database, because the suite builds
    its own schema from head. Everything here fails loudly if
    `scan_engine_health` is missing, mis-typed, or missing its CHECK
    constraints on the database the test actually connects to.
    """

    @staticmethod
    async def _health(
        orchestration_sessionmaker: SessionmakerFixture, scan_id: str
    ) -> dict[str, ScanEngineHealthRow]:
        async with orchestration_sessionmaker() as session:
            rows = (
                await session.execute(
                    select(ScanEngineHealthRow).where(ScanEngineHealthRow.scan_id == scan_id)
                )
            ).scalars()
            return {row.engine_name: row for row in rows}

    @pytest.mark.asyncio
    async def test_a_never_reported_engine_is_not_stored_as_an_error(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """ACCEPTANCE CRITERION 8, end to end against a real database. The
        waited sandbox engine times out and is force-decided past; the required
        engine reported fine. Before this table both facts were one column, and
        the absence surfaced only as a `sandbox_wait_timeout:` substring inside
        the verdict's reasons."""
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        decided = await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(_POLICY.required_engines)),
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=_signer(),
            operator="test",
            waited_advisory_engines=("bandit",),
            force_decide=True,
        )
        assert decided is True

        health = await TestEngineHealthRows._health(orchestration_sessionmaker, scan_id)
        assert "bandit" in health, "the engine that never reported must still get a row"
        assert health["bandit"].report_state == "not_reported"
        # NOT "error". `aggregate.unavailable_engine_result` fabricates
        # EngineStatus.ERROR here so the gate fails closed; storing that
        # fabrication is what made a never-constructed engine read as a
        # permanently broken one.
        assert health["bandit"].engine_status is None
        assert health["bandit"].analyze_duration_ms is None

        reported = health[next(iter(_POLICY.required_engines))]
        assert reported.report_state == "reported"
        assert reported.engine_status == EngineStatus.OK.value

    @pytest.mark.asyncio
    async def test_a_reported_error_keeps_its_own_status_and_message(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        _write_engine_blob(
            blobstore,
            scan_id,
            "bandit",
            status=EngineStatus.ERROR,
            error="bandit: command not found",
            analyze_duration_ms=12,
        )
        await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(_POLICY.required_engines)),
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=_signer(),
            operator="test",
            waited_advisory_engines=("bandit",),
        )
        health = await TestEngineHealthRows._health(orchestration_sessionmaker, scan_id)
        assert health["bandit"].report_state == "reported"
        assert health["bandit"].engine_status == EngineStatus.ERROR.value
        assert health["bandit"].error == "bandit: command not found"
        assert health["bandit"].analyze_duration_ms == 12

    @pytest.mark.asyncio
    async def test_zero_and_unmeasured_durations_are_different_stored_values(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """Task 7's three states, at rest. `0` is what an in-process floor
        engine really measures; NULL is a blob from an engine-runner image that
        does not emit the field yet. A NOT NULL DEFAULT 0 column would have
        recorded the whole not-yet-upgraded pod as instant."""
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        _write_engine_blob(blobstore, scan_id, "bandit", analyze_duration_ms=0)
        _write_engine_blob(blobstore, scan_id, "yara")  # key omitted entirely
        await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(_POLICY.required_engines)),
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=_signer(),
            operator="test",
            waited_advisory_engines=("bandit", "yara"),
        )
        health = await TestEngineHealthRows._health(orchestration_sessionmaker, scan_id)
        assert health["bandit"].analyze_duration_ms == 0
        assert health["yara"].analyze_duration_ms is None

    @pytest.mark.asyncio
    async def test_every_aggregated_engine_gets_exactly_one_row(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """The aggregation set is deduplicated (`waited_advisory_engines` and
        `additional_engines` legitimately overlap in production), and the PK is
        (scan_id, engine_name) - so an un-deduplicated write would be an
        IntegrityError that aborts the whole decide, not a duplicate row."""
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        _write_engine_blob(blobstore, scan_id, "bandit")
        decided = await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(_POLICY.required_engines)),
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=_signer(),
            operator="test",
            waited_advisory_engines=("bandit",),
            additional_engines=("bandit", "aig-mcp-scan"),
        )
        assert decided is True
        health = await TestEngineHealthRows._health(orchestration_sessionmaker, scan_id)
        assert set(health) == set(_POLICY.required_engines) | {"bandit", "aig-mcp-scan"}
        # The LLM-gated engine this deployment's engine-runner never constructs
        # is the standing real-world "never reported" case (design §8).
        assert health["aig-mcp-scan"].report_state == "not_reported"

    @pytest.mark.asyncio
    async def test_an_engines_multi_kilobyte_error_does_not_abort_the_decide(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """MySQL runs in strict mode: an over-length value is an ERROR, not a
        silent truncation, and this INSERT shares the scoring transaction - so
        an untruncated adapter stderr dump would leave the scan permanently
        undecided. Only a REAL database can prove the truncation is enough."""
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        _write_engine_blob(
            blobstore, scan_id, "bandit", status=EngineStatus.ERROR, error="z" * 20000
        )
        decided = await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(_POLICY.required_engines)),
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=_signer(),
            operator="test",
            waited_advisory_engines=("bandit",),
        )
        assert decided is True
        health = await TestEngineHealthRows._health(orchestration_sessionmaker, scan_id)
        stored = health["bandit"].error
        assert stored is not None and stored.endswith("... (truncated)")

    @pytest.mark.asyncio
    async def test_a_dead_lettered_scan_records_no_engine_health_at_all(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """A poison pill / rejected unpack is a CONTENT-level failure decided
        without aggregating anything. Manufacturing `not_reported` rows for it
        would attribute a content rejection to the engines."""
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        await _dead_letter_and_decide(
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            signer=_signer(),
            operator="test",
            reason="poison_pill:max_delivery_exceeded",
        )
        assert await TestEngineHealthRows._health(orchestration_sessionmaker, scan_id) == {}

    @pytest.mark.asyncio
    async def test_the_database_itself_refuses_a_fabricated_status(
        self, orchestration_sessionmaker: SessionmakerFixture
    ) -> None:
        """`chk_engine_health_status_iff_reported` - the criterion-8 pairing as
        a DB constraint, not merely an application convention. Written as a
        direct INSERT because the application path cannot produce this shape;
        the constraint exists for the NEXT writer, which will not go through
        `EngineHealthRecord`."""
        async with orchestration_sessionmaker() as session, session.begin():
            session.add(
                ScanEngineHealthRow(
                    scan_id=str(uuid.uuid4()),
                    engine_name="bandit",
                    report_state="not_reported",
                    engine_status="error",  # the exact conflation this table exists to stop
                    analyze_duration_ms=None,
                    finding_count=None,
                    error=None,
                    recorded_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )
            with pytest.raises(DBAPIError, match=r"(?i)check constraint"):
                await session.flush()

    @pytest.mark.asyncio
    async def test_the_database_itself_refuses_an_unknown_report_state(
        self, orchestration_sessionmaker: SessionmakerFixture
    ) -> None:
        """`chk_engine_health_report_state`. Its value domain is owned by
        `aggregate.EngineReportState` and constrained here on purpose;
        `engine_status`'s domain is deliberately NOT constrained, because that
        enum belongs to `skillscan_core` and a new value there must not make
        every decide abort at the database."""
        async with orchestration_sessionmaker() as session, session.begin():
            session.add(
                ScanEngineHealthRow(
                    scan_id=str(uuid.uuid4()),
                    engine_name="bandit",
                    report_state="timeout",  # an EngineStatus value, not a report state
                    engine_status=None,
                    analyze_duration_ms=None,
                    finding_count=None,
                    error=None,
                    recorded_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )
            with pytest.raises(DBAPIError, match=r"(?i)check constraint"):
                await session.flush()


class TestEngineHealthRetention:
    """Milestone C Task 9: the first retention path this system has ever had.

    VM-ONLY. The sweep issues a real `DELETE ... LIMIT` against real InnoDB and
    every property below is a property of the database, not of the Python:
    `mysql_limit` is a dialect option that does not exist on SQLite, `rowcount`
    on a bulk DELETE is a driver behaviour, and the READ COMMITTED execution
    option only means anything against a server that takes gap locks. The pure
    side (the window's derivation, the compiled SQL, the call-site guard) is in
    `test_engine_health_retention.py` and runs anywhere.

    MUTATION IN BOTH DIRECTIONS, because a deletion path that is only tested
    for "it removes the right rows" is half tested. Half of the tests here
    assert what the sweep must NOT touch - the boundary row, the fresh rows, the
    scan_job and scan_result the health rows annotate, and the rows beyond one
    pass's budget.
    """

    @staticmethod
    async def _insert_health(
        orchestration_sessionmaker: SessionmakerFixture,
        *,
        scan_id: str,
        engines: Sequence[str],
        recorded_at: datetime.datetime,
    ) -> None:
        async with orchestration_sessionmaker() as session, session.begin():
            for engine_name in engines:
                session.add(
                    ScanEngineHealthRow(
                        scan_id=scan_id,
                        engine_name=engine_name,
                        report_state="reported",
                        engine_status="ok",
                        analyze_duration_ms=0,
                        finding_count=0,
                        error=None,
                        recorded_at=recorded_at,
                    )
                )

    @staticmethod
    async def _count(orchestration_sessionmaker: SessionmakerFixture, *, scan_id: str) -> int:
        async with orchestration_sessionmaker() as session:
            rows = (
                await session.execute(
                    select(ScanEngineHealthRow.engine_name).where(
                        ScanEngineHealthRow.scan_id == scan_id
                    )
                )
            ).all()
        return len(rows)

    @pytest.mark.asyncio
    async def test_it_deletes_rows_past_the_window(
        self, orchestration_sessionmaker: SessionmakerFixture
    ) -> None:
        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        old = str(uuid.uuid4())
        await TestEngineHealthRetention._insert_health(
            orchestration_sessionmaker,
            scan_id=old,
            engines=("bandit", "semgrep", "osv-scanner"),
            recorded_at=now - datetime.timedelta(days=DEFAULT_RETENTION_DAYS + 1),
        )
        deleted = await sweep_engine_health_retention(orchestration_sessionmaker, now=now)
        assert deleted >= 3
        assert await TestEngineHealthRetention._count(orchestration_sessionmaker, scan_id=old) == 0

    @pytest.mark.asyncio
    async def test_it_does_not_delete_rows_inside_the_window(
        self, orchestration_sessionmaker: SessionmakerFixture
    ) -> None:
        """THE DIRECTION THAT MATTERS. A sweep that deletes too much passes
        every "did it delete?" assertion ever written."""
        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        fresh = str(uuid.uuid4())
        just_inside = str(uuid.uuid4())
        await TestEngineHealthRetention._insert_health(
            orchestration_sessionmaker,
            scan_id=fresh,
            engines=("bandit", "semgrep"),
            recorded_at=now - datetime.timedelta(minutes=1),
        )
        await TestEngineHealthRetention._insert_health(
            orchestration_sessionmaker,
            scan_id=just_inside,
            engines=("bandit",),
            # One second younger than the cutoff: inside, and the row a sweep
            # with an off-by-one window would take.
            recorded_at=now
            - datetime.timedelta(days=DEFAULT_RETENTION_DAYS)
            + datetime.timedelta(seconds=1),
        )
        await sweep_engine_health_retention(orchestration_sessionmaker, now=now)
        assert (
            await TestEngineHealthRetention._count(orchestration_sessionmaker, scan_id=fresh) == 2
        )
        assert (
            await TestEngineHealthRetention._count(orchestration_sessionmaker, scan_id=just_inside)
            == 1
        )

    @pytest.mark.asyncio
    async def test_a_row_exactly_at_the_cutoff_survives(
        self, orchestration_sessionmaker: SessionmakerFixture
    ) -> None:
        """`<`, not `<=`. Arbitrary at microsecond resolution, and asserted
        anyway so a later edit cannot flip it unobserved."""
        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        boundary = str(uuid.uuid4())
        await TestEngineHealthRetention._insert_health(
            orchestration_sessionmaker,
            scan_id=boundary,
            engines=("bandit",),
            # MySQL DATETIME (no fractional seconds on this column) - truncate
            # so the stored value is EXACTLY the cutoff the sweep computes.
            recorded_at=(now - datetime.timedelta(days=DEFAULT_RETENTION_DAYS)).replace(
                microsecond=0
            ),
        )
        await sweep_engine_health_retention(
            orchestration_sessionmaker, now=now.replace(microsecond=0)
        )
        assert (
            await TestEngineHealthRetention._count(orchestration_sessionmaker, scan_id=boundary)
            == 1
        )

    @pytest.mark.asyncio
    async def test_it_never_touches_the_scan_it_annotates(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        blobstore: LocalFilesystemBlobStore,
        redis_client: aioredis.Redis,
    ) -> None:
        """A real, fully decided scan whose health rows have aged out. The
        health rows go; the scan_job, the scan_result and the verdict stay.

        `scan_engine_health` has no FK to `scan_job` (see d5a1c07f9e42), so
        nothing at the database level would stop a cascade written by mistake -
        this is the assertion that stands in for the constraint that is not
        there.
        """
        scan_id = await _seed_scan_with_all_required_blobs(
            orchestration_sessionmaker, blobstore, redis_client
        )
        assert await _try_score_and_decide(
            blobstore,
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            required_engines=tuple(sorted(_POLICY.required_engines)),
            policy=_POLICY,
            default_trust_tier=TrustTier.INTERNAL,
            allowlist=(),
            signer=_signer(),
            operator="test",
        )
        assert await TestEngineHealthRetention._count(orchestration_sessionmaker, scan_id=scan_id)

        # Age this scan's health rows past the window without touching the scan.
        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        async with orchestration_sessionmaker() as session, session.begin():
            await session.execute(
                update(ScanEngineHealthRow)
                .where(ScanEngineHealthRow.scan_id == scan_id)
                .values(recorded_at=now - datetime.timedelta(days=DEFAULT_RETENTION_DAYS + 2))
            )

        await sweep_engine_health_retention(orchestration_sessionmaker, now=now)

        assert (
            await TestEngineHealthRetention._count(orchestration_sessionmaker, scan_id=scan_id) == 0
        )
        async with orchestration_sessionmaker() as session:
            job = await session.get(ScanJob, scan_id)
            result = (
                await session.execute(select(ScanResultRow).where(ScanResultRow.scan_id == scan_id))
            ).scalar_one_or_none()
        assert job is not None, "the retention sweep deleted a scan_job row"
        assert job.state == STATE_DECIDED
        assert result is not None, "the retention sweep deleted a scan_result row"
        async with gate_sessionmaker() as gate_session:
            verdict = (
                await gate_session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
            ).scalar_one_or_none()
        assert verdict is not None, "the retention sweep reached across into gate's tables"

    @pytest.mark.asyncio
    async def test_a_pass_stops_at_its_budget_and_the_next_one_converges(
        self, orchestration_sessionmaker: SessionmakerFixture
    ) -> None:
        """The bound is real, not decorative: with more eligible rows than one
        pass may take, EXACTLY the budget goes and the remainder survives until
        the next pass. This is what makes a sweep that overlaps a burst of
        scans harmless - it never grows its own footprint to catch up."""
        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        scan_id = str(uuid.uuid4())
        engines = tuple(f"synthetic-engine-{i:03d}" for i in range(9))
        await TestEngineHealthRetention._insert_health(
            orchestration_sessionmaker,
            scan_id=scan_id,
            engines=engines,
            recorded_at=now - datetime.timedelta(days=DEFAULT_RETENTION_DAYS + 3),
        )
        # batch_size x max_batches = 4, against 9 eligible rows for this scan.
        first = await sweep_engine_health_retention(
            orchestration_sessionmaker, now=now, batch_size=2, max_batches=2
        )
        assert first == 4, "a pass must stop at its budget, not run to completion"
        # `>=`, not `==`: the DELETE has no ORDER BY and this suite shares one
        # MySQL, so another test's aged rows may legitimately be among the four
        # this pass took. What is being asserted is that AT MOST the budget went,
        # which is the property. Asserting exactly which rows went would be
        # asserting an ordering the statement does not promise.
        assert (
            await TestEngineHealthRetention._count(orchestration_sessionmaker, scan_id=scan_id)
            >= len(engines) - 4
        )

        for _ in range(10):
            if not await sweep_engine_health_retention(orchestration_sessionmaker, now=now):
                break
        assert (
            await TestEngineHealthRetention._count(orchestration_sessionmaker, scan_id=scan_id) == 0
        ), "repeated bounded passes must converge"

    @pytest.mark.asyncio
    async def test_an_empty_table_costs_one_statement_and_reports_zero(
        self, orchestration_sessionmaker: SessionmakerFixture
    ) -> None:
        """The ordinary case, 23 hours out of 24. A short first batch must end
        the pass rather than spend the remaining budget on empty statements."""
        deleted = await sweep_engine_health_retention(
            orchestration_sessionmaker,
            # A cutoff before this schema existed: nothing can be eligible.
            now=datetime.datetime(2020, 1, 1),
        )
        assert deleted == 0

    @pytest.mark.asyncio
    async def test_the_window_is_read_from_the_environment_at_sweep_time(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The env knob is live, not a module constant captured at import. A
        deployment that needs 90 days sets the variable; a deployment that
        needs one day gets one day, and both take effect on the next pass."""
        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        scan_id = str(uuid.uuid4())
        await TestEngineHealthRetention._insert_health(
            orchestration_sessionmaker,
            scan_id=scan_id,
            engines=("bandit", "semgrep"),
            # Inside the 26-day default, outside a 2-day override.
            recorded_at=now - datetime.timedelta(days=5),
        )
        monkeypatch.setenv(RETENTION_DAYS_ENV, str(DEFAULT_RETENTION_DAYS + 10))
        await sweep_engine_health_retention(orchestration_sessionmaker, now=now)
        assert (
            await TestEngineHealthRetention._count(orchestration_sessionmaker, scan_id=scan_id) == 2
        )

        monkeypatch.setenv(RETENTION_DAYS_ENV, "2")
        await sweep_engine_health_retention(orchestration_sessionmaker, now=now)
        assert (
            await TestEngineHealthRetention._count(orchestration_sessionmaker, scan_id=scan_id) == 0
        )
