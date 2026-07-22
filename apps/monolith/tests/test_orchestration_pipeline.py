"""End-to-end scan pipeline tests (coding spec §11.3 M3 acceptance bar):
提交→入队→(mock 引擎)→回读校验→aggregate→decide→签名(占位)→写 outbox;
幂等去重(2 次同内容→1 job); poison-pill→死信+BLOCK.

Against real local MySQL + Redis + a tmp_path-backed blob store; only the mock
engine substitutes for a real sandboxed worker (coding spec §10, M4/M5).
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
import redis.asyncio as aioredis
from common import airlock
from common.blobstore import LocalFilesystemBlobStore, artifact_key
from skillscan_core import DetectionEngine, GatePolicy, StaticKeywordEngine, TrustTier, Verdict
from skillscan_core import content_hash as compute_content_hash
from sqlalchemy import select

from monolith.modules.gate.models import VerdictRow
from monolith.modules.gate.service import decide_and_record as real_decide_and_record
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.orchestration import service as orchestration_service
from monolith.modules.orchestration.models import ScanJob
from monolith.modules.orchestration.service import (
    run_mock_engine_worker_tick,
    run_result_collector_tick,
    submit_scan,
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
            trust_tier=TrustTier.INTERNAL,
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
            )

        assert scan_id_1 == scan_id_2

        async with orchestration_sessionmaker() as session:
            count = (
                (await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id_1)))
                .scalars()
                .all()
            )
        assert len(count) == 1


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
            pytest.param(b"---\nname: \"   \"\n---\n", id="name-blank"),
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
                trust_tier=TrustTier.INTERNAL,
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
                trust_tier=TrustTier.INTERNAL,
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
            trust_tier=TrustTier.INTERNAL,
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
            trust_tier=TrustTier.INTERNAL,
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
