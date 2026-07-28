"""Background worker tests (apps/monolith/worker.py) - the live loop closing
the "scan-decision worker loop is never invoked by any live process" gap
(docs/MAINTENANCE_GUIDE.md §3 gap 1).

Against real local MySQL (per-module least-privilege users) + real Redis + a
tmp_path blob store, same posture as test_orchestration_pipeline.py. The
worker is exercised tick-by-tick (never as an unbounded background task) so
these tests stay deterministic.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import uuid
from typing import Any

import pytest
import redis.asyncio as aioredis
from common import airlock
from common.blobstore import LocalFilesystemBlobStore, artifact_key, findings_key
from schemas.findings import serialize_engine_result
from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    EngineResult,
    EngineStatus,
    Finding,
    GatePolicy,
    ScanMode,
    Severity,
    StaticKeywordEngine,
    Verdict,
)
from sqlalchemy import select

from monolith.modules.gate.models import PolicyProposalRow, VerdictRow
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.intel.models import ThreatIndicator
from monolith.modules.inventory.models import SkillLifecycleEventRow
from monolith.modules.inventory.service import current_state, register_skill_version
from monolith.modules.orchestration.models import ScanJob, ScanResultRow
from monolith.modules.orchestration.service import submit_scan
from monolith.modules.reporting.service import (
    InvalidCronError,
    cron_matches,
    schedule_report,
)
from monolith.tests.conftest import SessionmakerFixture
from monolith.worker import (
    SANDBOX_WAITED_ENGINE_NAMES,
    promote_approved_policy,
    reload_policy_if_changed,
    run_due_report_schedules,
    run_worker_loop,
    sweep_queued_jobs_to_airlock,
    sync_lifecycle_tick,
    worker_tick,
)

_ENGINE = StaticKeywordEngine()


def _policy(*, version: str) -> GatePolicy:
    return GatePolicy(
        version=version,
        required_engines=frozenset({_ENGINE.metadata.name}),
        hard_gate_rules=frozenset(),
        fail_closed_verdict=Verdict.BLOCK,
    )


def _unique_files(marker: str) -> list[tuple[str, int, bytes]]:
    return [(f"skill_{marker}.py", 0o644, f"print('ok')  # {marker}\n".encode())]


def _seed_sandbox_waited_engine_blobs(
    blobstore: LocalFilesystemBlobStore, scan_id: str, *, skip: frozenset[str] = frozenset()
) -> None:
    """2026-07-27 (D2): `worker_tick` now waits for `SANDBOX_WAITED_ENGINE_NAMES`
    before its collector step will decide a scan at all (see
    apps/monolith/worker.py's own `run_result_collector_tick` call). This
    process has no adapter for any of them - a real deployment gets these
    blobs from the separate engine-runner service's own subprocess adapters -
    so every end-to-end test in this file that polls `worker_tick` until a
    scan reaches 'decided' must simulate "the engine-runner already finished"
    the same way `test_sandbox_engine_finding_is_aggregated_but_never_
    dispatched_here` does below, or the wait would never resolve within the
    test's own tick budget (resolving it for real means waiting out
    ScanRuntime.sandbox_wait_timeout_s, which none of these tests exercise -
    that is TestSandboxWait's job, in test_orchestration_pipeline.py)."""
    for name in SANDBOX_WAITED_ENGINE_NAMES:
        if name in skip:
            continue
        result = EngineResult(
            engine=EngineMetadata(
                name=name,
                version="test",
                ruleset_digest="test",
                capabilities=frozenset({EngineCapability.STATIC}),
            ),
            findings=(),
            status=EngineStatus.OK,
            scan_mode=ScanMode.STATIC,
            llm_used=False,
        )
        blobstore.put(
            findings_key(scan_id, name),
            json.dumps(serialize_engine_result(result)).encode("utf-8"),
        )


class _RecordingNotifier:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def emit(self, event: dict[str, Any]) -> None:
        self.events.append(event)


def _runtime(
    *,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    inventory_sessionmaker: SessionmakerFixture | None = None,
    audit_sessionmaker: SessionmakerFixture | None = None,
    relay_sessionmaker: SessionmakerFixture | None = None,
    reporting_sessionmaker: SessionmakerFixture | None = None,
    intel_sessionmaker: SessionmakerFixture | None = None,
    policy: GatePolicy | None = None,
    notifier: _RecordingNotifier | None = None,
) -> ScanRuntime:
    return ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=orchestration_sessionmaker,
        gate_session_factory=gate_sessionmaker,
        policy=policy if policy is not None else _policy(version=f"vt-{uuid.uuid4().hex[:8]}"),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
        inventory_session_factory=inventory_sessionmaker,
        audit_session_factory=audit_sessionmaker,
        relay_session_factory=relay_sessionmaker,
        reporting_session_factory=reporting_sessionmaker,
        intel_session_factory=intel_sessionmaker,
        siem_notifier=notifier,
    )


class TestCronMatches:
    def test_wildcards_match_any_minute(self) -> None:
        at = datetime.datetime(2026, 7, 6, 14, 37)
        assert cron_matches("* * * * *", at)

    def test_exact_minute_hour(self) -> None:
        at = datetime.datetime(2026, 7, 6, 6, 0)
        assert cron_matches("0 6 * * *", at)
        assert not cron_matches("0 6 * * *", at.replace(minute=1))
        assert not cron_matches("0 6 * * *", at.replace(hour=7))

    def test_step_range_and_list(self) -> None:
        assert cron_matches("*/15 * * * *", datetime.datetime(2026, 7, 6, 1, 45))
        assert not cron_matches("*/15 * * * *", datetime.datetime(2026, 7, 6, 1, 46))
        assert cron_matches("10-20 * * * *", datetime.datetime(2026, 7, 6, 1, 15))
        assert cron_matches("5,25,55 * * * *", datetime.datetime(2026, 7, 6, 1, 25))
        assert cron_matches("10-20/5 * * * *", datetime.datetime(2026, 7, 6, 1, 20))
        assert not cron_matches("10-20/5 * * * *", datetime.datetime(2026, 7, 6, 1, 19))

    def test_weekday_sunday_is_0_and_7(self) -> None:
        sunday = datetime.datetime(2026, 7, 5, 3, 0)  # 2026-07-05 is a Sunday
        assert cron_matches("0 3 * * 0", sunday)
        assert cron_matches("0 3 * * 7", sunday)
        assert not cron_matches("0 3 * * 1", sunday)

    def test_dom_dow_or_rule_when_both_restricted(self) -> None:
        # 2026-07-06 is a Monday (cron weekday 1) and the 6th of the month.
        monday_the_6th = datetime.datetime(2026, 7, 6, 0, 0)
        # DOM matches (6), DOW doesn't (Friday=5) - classic cron fires anyway.
        assert cron_matches("0 0 6 * 5", monday_the_6th)
        # DOW matches (1), DOM doesn't (15th) - fires too.
        assert cron_matches("0 0 15 * 1", monday_the_6th)
        # Neither matches.
        assert not cron_matches("0 0 15 * 5", monday_the_6th)

    def test_out_of_range_and_garbage_raise(self) -> None:
        at = datetime.datetime(2026, 7, 6, 0, 0)
        with pytest.raises(InvalidCronError):
            cron_matches("60 * * * *", at)
        with pytest.raises(InvalidCronError):
            cron_matches("*/0 * * * *", at)
        with pytest.raises(InvalidCronError):
            cron_matches("* * * *", at)


class TestWorkerEndToEnd:
    @pytest.mark.asyncio
    async def test_submitted_scan_gets_decided_by_worker_ticks(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
        unique_consumer: str,
    ) -> None:
        """The gap this worker closes: a submitted scan previously had NO path
        off queued/running without a test manually driving the ticks."""
        await airlock.ensure_groups(redis_client)
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
        )
        async with orchestration_sessionmaker() as session, session.begin():
            scan_id = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=_unique_files(uuid.uuid4().hex),
                submitter="worker-test",
                engine_metadatas=(_ENGINE.metadata,),
                policy=runtime.policy,
                trust_tier=runtime.default_trust_tier,
            )
        # D2 (2026-07-27): worker_tick's collector now waits for the sandbox
        # engines too - simulate the engine-runner having already finished
        # (see _seed_sandbox_waited_engine_blobs' own docstring) so this test
        # can still reach 'decided' within its own tick budget.
        _seed_sandbox_waited_engine_blobs(blobstore, scan_id)

        # A generous bound, not 20: worker_tick's internal claim counts (10
        # each) are shared, backlog-sensitive budgets across the whole suite
        # run - enough accumulated unrelated backlog from earlier tests can
        # burn through a tight bound before ever reaching this test's own scan.
        for _ in range(200):
            await worker_tick(runtime, consumer=unique_consumer)
            async with orchestration_sessionmaker() as session:
                job = (
                    await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
                ).scalar_one()
            if job.state == "decided":
                break
        assert job.state == "decided"

        async with gate_sessionmaker() as session:
            verdict = (
                await session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
            ).scalar_one()
        assert verdict.verdict == "PASS"

    @pytest.mark.asyncio
    async def test_intel_matcher_finding_reaches_the_verdict_without_gating_the_wait(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        intel_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
        unique_consumer: str,
    ) -> None:
        """Closes the "IntelMatcher exists and is tested but has no live
        scan-pipeline caller" gap. A known-malicious domain, present in the
        threat_indicator table, appearing in scanned content must show up as
        a real finding on the decided ScanResultRow - proving both that
        `_floor_engines_with_intel` actually runs it (not just constructs
        it) AND that `_try_score_and_decide`'s `additional_engines` plumbing
        actually gets its finding into aggregation (not just written to the
        blob store and ignored, which was the gap immediately after the
        first, incomplete pass at this wiring)."""
        malicious_domain = f"evil-{uuid.uuid4().hex[:8]}.example.com"
        async with intel_sessionmaker() as session, session.begin():
            session.add(
                ThreatIndicator(
                    ioc_type="domain",
                    ioc_value=malicious_domain,
                    source="test-seed",
                    imported_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )

        await airlock.ensure_groups(redis_client)
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            intel_sessionmaker=intel_sessionmaker,
        )
        async with orchestration_sessionmaker() as session, session.begin():
            scan_id = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=[
                    (
                        f"skill_{uuid.uuid4().hex[:8]}.py",
                        0o644,
                        f"# beacon to {malicious_domain}\n".encode(),
                    )
                ],
                submitter="intel-wiring-test",
                engine_metadatas=(_ENGINE.metadata,),
                policy=runtime.policy,
                trust_tier=runtime.default_trust_tier,
            )
        # D2 (2026-07-27): see _seed_sandbox_waited_engine_blobs' own docstring.
        _seed_sandbox_waited_engine_blobs(blobstore, scan_id)

        # A generous bound, not 20: worker_tick's internal claim counts (10
        # each) are shared, backlog-sensitive budgets across the whole suite
        # run - enough accumulated unrelated backlog from earlier tests can
        # burn through a tight bound before ever reaching this test's own scan.
        for _ in range(200):
            await worker_tick(runtime, consumer=unique_consumer)
            async with orchestration_sessionmaker() as session:
                job = (
                    await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
                ).scalar_one()
            if job.state == "decided":
                break
        assert job.state == "decided"

        async with orchestration_sessionmaker() as session:
            result_row = (
                await session.execute(select(ScanResultRow).where(ScanResultRow.scan_id == scan_id))
            ).scalar_one()
        rule_ids = {f["rule_id"] for f in result_row.findings}
        assert "intel.ioc_match_domain" in rule_ids
        # CRITICAL is skillscan_core.models.Severity.CRITICAL's int value -
        # IntelMatcher always reports CRITICAL for a confirmed IOC match.
        assert result_row.severity == 4

    @pytest.mark.asyncio
    async def test_sandbox_engine_finding_is_aggregated_but_never_dispatched_here(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
        unique_consumer: str,
    ) -> None:
        """Closes the "sandbox engine (bandit/yara/osv-scanner/skillspector/
        aig-mcp-scan) findings are computed by the separate engine-runner
        service but never aggregated into any scan's verdict" gap - found via
        a real 95-skill bulk import, not by inspection: `SANDBOX_ADVISORY_
        ENGINE_NAMES` must reach `_try_score_and_decide`'s `additional_engines`
        (aggregation), the exact same way IntelMatcher does above, but must
        NEVER reach `run_mock_engine_worker_tick`'s `additional_engine_names`
        (dispatch) - this process has no adapter instance for any of them
        and would KeyError trying to run one. Simulates "the engine-runner
        already wrote its result before this tick runs" by writing directly
        to the blob store, exactly as services/engine_runner/worker.py's
        real `_dispatch_engines` does.

        Covers BOTH bandit and aig-mcp-scan (not just bandit) as a direct
        regression check: `SANDBOX_ADVISORY_ENGINE_NAMES` was previously a
        hardcoded 4-name tuple that omitted aig-mcp-scan entirely (added as
        the engine-runner's 5th adapter after that tuple was written and
        never updated) - its blob was written by the engine-runner but
        silently never read back into any verdict. It is now sourced from
        `engine_runner.sandbox_engines.SANDBOX_ENGINE_NAMES`, the single
        source of truth also used for dispatch-time gating, so this asserts
        the fix rather than merely bandit's pre-existing coverage."""
        await airlock.ensure_groups(redis_client)
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
        )
        async with orchestration_sessionmaker() as session, session.begin():
            scan_id = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=_unique_files(uuid.uuid4().hex),
                submitter="sandbox-advisory-test",
                engine_metadatas=(_ENGINE.metadata,),
                policy=runtime.policy,
                trust_tier=runtime.default_trust_tier,
            )

        bandit_result = EngineResult(
            engine=EngineMetadata(
                name="bandit",
                version="1.9.4",
                ruleset_digest="test",
                capabilities=frozenset({EngineCapability.STATIC}),
            ),
            findings=(
                Finding(
                    rule_id="B105",
                    test_item_id="CODE-01",
                    category=DetectionCategory.CODE,
                    title="hardcoded password string",
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                    source_engine="bandit",
                    source_capability=EngineCapability.STATIC,
                    trifecta_signals=frozenset(),
                    file_path="skill.py",
                    start_line=1,
                    snippet_hash=None,
                    evidence_redacted="hardcoded password string",
                ),
            ),
            status=EngineStatus.OK,
            scan_mode=ScanMode.STATIC,
            llm_used=False,
        )
        blobstore.put(
            findings_key(scan_id, "bandit"),
            json.dumps(serialize_engine_result(bandit_result)).encode("utf-8"),
        )

        # The regression target: aig-mcp-scan is the 5th engine-runner
        # adapter, added after SANDBOX_ADVISORY_ENGINE_NAMES was first
        # hardcoded - its finding must now also be aggregated.
        aig_result = EngineResult(
            engine=EngineMetadata(
                name="aig-mcp-scan",
                version="v4.1.15",
                ruleset_digest="test",
                capabilities=frozenset({EngineCapability.SEMANTIC_LLM}),
                requires_llm=True,
            ),
            findings=(
                Finding(
                    rule_id="aig.tool_poisoning",
                    test_item_id="CODE-02",
                    category=DetectionCategory.CODE,
                    title="tool description inconsistent with declared behavior",
                    severity=Severity.HIGH,
                    confidence=0.8,
                    source_engine="aig-mcp-scan",
                    source_capability=EngineCapability.SEMANTIC_LLM,
                    trifecta_signals=frozenset(),
                    file_path="skill.py",
                    start_line=1,
                    snippet_hash=None,
                    evidence_redacted="tool description inconsistent with declared behavior",
                ),
            ),
            status=EngineStatus.OK,
            scan_mode=ScanMode.STATIC,
            llm_used=True,
        )
        blobstore.put(
            findings_key(scan_id, "aig-mcp-scan"),
            json.dumps(serialize_engine_result(aig_result)).encode("utf-8"),
        )
        # D2 (2026-07-27): worker_tick's collector now WAITS for
        # SANDBOX_WAITED_ENGINE_NAMES (bandit already written above with a
        # real finding - skip it here so this doesn't clobber it) before it
        # will decide this scan at all. aig-mcp-scan is deliberately NOT in
        # the waited set (see SANDBOX_WAITED_ENGINE_NAMES' own comment) but is
        # already written above anyway, as this test's own regression target.
        _seed_sandbox_waited_engine_blobs(blobstore, scan_id, skip=frozenset({"bandit"}))

        # A generous bound, not 20: worker_tick's internal claim counts (10
        # each) are shared, backlog-sensitive budgets across the whole suite
        # run - enough accumulated unrelated backlog from earlier tests can
        # burn through a tight bound before ever reaching this test's own scan.
        for _ in range(200):
            await worker_tick(runtime, consumer=unique_consumer)
            async with orchestration_sessionmaker() as session:
                job = (
                    await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
                ).scalar_one()
            if job.state == "decided":
                break
        assert job.state == "decided"

        async with orchestration_sessionmaker() as session:
            result_row = (
                await session.execute(select(ScanResultRow).where(ScanResultRow.scan_id == scan_id))
            ).scalar_one()
        rule_ids = {f["rule_id"] for f in result_row.findings}
        assert "B105" in rule_ids
        # The actual regression assertion: aig-mcp-scan's finding must reach
        # the aggregated verdict too, not just bandit's.
        assert "aig.tool_poisoning" in rule_ids

    @pytest.mark.asyncio
    async def test_worker_loop_creates_consumer_groups_on_fresh_redis(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        """Regression (found on first VM deploy): the worker must create its own
        Redis consumer groups. Previously only test fixtures called
        ensure_groups, so a fresh deployment's worker failed every tick with
        NOGROUP and no scan ever left 'queued'. run_worker_loop must self-heal."""
        # Destroy the group if a prior test created it - simulate fresh Redis.
        try:
            await redis_client.xgroup_destroy(airlock.SCANS_STREAM, airlock.WORKERS_GROUP)
        except aioredis.ResponseError:
            pass

        # Pre-set stop_event: run_worker_loop runs its startup ensure_groups and
        # then the while-loop sees the stop already set and exits WITHOUT running
        # a tick - so this deterministically tests group creation without the
        # loop consuming any messages from the shared Redis stream.
        stop_event = asyncio.Event()
        stop_event.set()
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
        )
        await asyncio.wait_for(
            run_worker_loop(runtime, interval_s=0.05, consumer="grouptest", stop_event=stop_event),
            timeout=5,
        )
        groups = await redis_client.xinfo_groups(airlock.SCANS_STREAM)
        assert any(g["name"] in (b"workers", "workers") for g in groups), (
            "run_worker_loop must create the 'workers' consumer group on a fresh Redis"
        )

    @pytest.mark.asyncio
    async def test_sweep_dispatches_db_only_queued_job(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
        unique_consumer: str,
    ) -> None:
        """A scan_job INSERTed with no airlock message (exactly what
        reeval.controller.trigger_rescans produces - it has no Redis access
        by design) gets swept into the stream and decided."""
        await airlock.ensure_groups(redis_client)
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
        )
        files = _unique_files(uuid.uuid4().hex)
        # Submit normally once to get artifact + job, then reset to the
        # "DB row only, message long gone" shape sweep must handle.
        async with orchestration_sessionmaker() as session, session.begin():
            scan_id = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="sweep-test",
                engine_metadatas=(_ENGINE.metadata,),
                policy=runtime.policy,
                trust_tier=runtime.default_trust_tier,
            )
        # D2 (2026-07-27): see _seed_sandbox_waited_engine_blobs' own docstring.
        _seed_sandbox_waited_engine_blobs(blobstore, scan_id)
        # Consume-and-ack the original message WITHOUT processing it, then
        # backdate the row past the requeue threshold.
        stale = await airlock.claim_scan_jobs(
            redis_client, consumer=unique_consumer, count=50, block_ms=200
        )
        for job_msg in stale:
            await airlock.ack_scan_job(redis_client, job_msg.message_id)
        backdated = datetime.datetime.now(datetime.UTC).replace(tzinfo=None) - datetime.timedelta(
            seconds=120
        )
        async with orchestration_sessionmaker() as session, session.begin():
            job_row = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
            job_row.created_at = backdated

        swept = await sweep_queued_jobs_to_airlock(runtime)
        assert swept >= 1

        # A generous bound, not 20: worker_tick's internal claim counts (10
        # each) are shared, backlog-sensitive budgets across the whole suite
        # run - enough accumulated unrelated backlog from earlier tests can
        # burn through a tight bound before ever reaching this test's own scan.
        for _ in range(200):
            await worker_tick(runtime, consumer=unique_consumer)
            async with orchestration_sessionmaker() as session:
                job_row = (
                    await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
                ).scalar_one()
            if job_row.state == "decided":
                break
        assert job_row.state == "decided"

    @pytest.mark.asyncio
    async def test_queued_job_with_vanished_artifact_dead_letters_to_block(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
        unique_consumer: str,
    ) -> None:
        """SECURITY (INV-5 fail-closed): a queued job whose artifact no longer
        exists in the blob store can never run - the sweep must route it into
        the dead-letter path (signed BLOCK verdict + state=failed), never
        leave it stuck at 'queued' forever."""
        await airlock.ensure_groups(redis_client)
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
        )
        files = _unique_files(uuid.uuid4().hex)
        async with orchestration_sessionmaker() as session, session.begin():
            scan_id = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="vanished-artifact-test",
                engine_metadatas=(_ENGINE.metadata,),
                policy=runtime.policy,
                trust_tier=runtime.default_trust_tier,
            )
        # Ack away the original stream message, delete the artifact, backdate.
        stale = await airlock.claim_scan_jobs(
            redis_client, consumer=unique_consumer, count=50, block_ms=200
        )
        for job_msg in stale:
            await airlock.ack_scan_job(redis_client, job_msg.message_id)
        async with orchestration_sessionmaker() as session, session.begin():
            job_row = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
            content_hash = str(job_row.content_hash)
            job_row.created_at = datetime.datetime.now(datetime.UTC).replace(
                tzinfo=None
            ) - datetime.timedelta(seconds=120)
        blobstore._path_for(artifact_key(content_hash)).unlink()  # noqa: SLF001

        for _ in range(10):
            await worker_tick(runtime, consumer=unique_consumer)
            async with orchestration_sessionmaker() as session:
                job_row = (
                    await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
                ).scalar_one()
            if job_row.state == "failed":
                break
        assert job_row.state == "failed"
        async with gate_sessionmaker() as session:
            verdict = (
                await session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
            ).scalar_one()
        assert verdict.verdict == "BLOCK"


class TestLifecycleSync:
    @pytest.mark.asyncio
    async def test_pass_verdict_publishes_scanning_skill(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        inventory_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
        unique_consumer: str,
    ) -> None:
        """Full chain: registered skill + real pipeline verdict -> the worker's
        lifecycle sync moves scanning -> published (coding spec §16.2)."""
        await airlock.ensure_groups(redis_client)
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            inventory_sessionmaker=inventory_sessionmaker,
        )
        skill_id = f"lifecycle-{uuid.uuid4().hex[:12]}"
        files = _unique_files(skill_id)
        from skillscan_core import content_hash as compute_content_hash
        from skillscan_core import toolchain_digest as compute_toolchain_digest

        c_hash = compute_content_hash(files)
        t_digest = compute_toolchain_digest((_ENGINE.metadata,), runtime.policy.version)
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test",
                trust_tier="internal",
                content_hash=c_hash,
                toolchain_digest=t_digest,
                declared_perms=None,
                operator="lifecycle-test",
            )
            from monolith.modules.inventory.service import transition_skill

            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="test submission",
                actor="lifecycle-test",
                content_hash=c_hash,
            )

        async with orchestration_sessionmaker() as session, session.begin():
            scan_id = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="lifecycle-test",
                engine_metadatas=(_ENGINE.metadata,),
                policy=runtime.policy,
                trust_tier=runtime.default_trust_tier,
            )
        # D2 (2026-07-27): see _seed_sandbox_waited_engine_blobs' own docstring.
        _seed_sandbox_waited_engine_blobs(blobstore, scan_id)
        # A generous bound, not 20: worker_tick's internal claim counts (10
        # each) are shared, backlog-sensitive budgets across the whole suite
        # run - each tick only makes bounded progress, so enough accumulated
        # unrelated backlog from earlier tests can burn through a tight bound
        # before ever reaching this test's own skill.
        for _ in range(200):
            await worker_tick(runtime, consumer=unique_consumer)
            async with inventory_sessionmaker() as session:
                state = await current_state(session, skill_id=skill_id)
            if state == "published":
                break
        assert state == "published"

        # The transition itself must be audited (INV-12: same-transaction intent).
        async with inventory_sessionmaker() as session:
            events = (
                (
                    await session.execute(
                        select(SkillLifecycleEventRow)
                        .where(SkillLifecycleEventRow.skill_id == skill_id)
                        .order_by(SkillLifecycleEventRow.id)
                    )
                )
                .scalars()
                .all()
            )
        assert [e.to_state for e in events] == ["submitted", "scanning", "published"]

    @pytest.mark.asyncio
    async def test_drifted_content_gets_quarantined_after_publishing(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        inventory_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
        unique_consumer: str,
    ) -> None:
        """Closes "orchestration/drift.py exists, is tested, has zero
        callers anywhere" (coding spec SUPPLY-06, FR-REV-020). A skill with an
        approved baseline that gets a PASS-verdict scan under DIFFERENT
        content must end up quarantined, not left published - the rug-pull
        pattern this module exists to catch."""
        from monolith.modules.inventory.service import set_baseline, transition_skill

        skill_id = f"drift-{uuid.uuid4().hex[:12]}"
        baseline_hash = (
            uuid.uuid4().hex + uuid.uuid4().hex
        )  # 64 hex chars, unrelated to real content
        # set_baseline is inventory-owned (BaselineRow lives in inventory's
        # own models; orchestration only has a cross-module SELECT-only view
        # via BaselineReadOnly, which is all check_drift needs/uses).
        async with inventory_sessionmaker() as session, session.begin():
            await set_baseline(
                session, skill_id=skill_id, content_hash=baseline_hash, actor="drift-test-setup"
            )

        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            inventory_sessionmaker=inventory_sessionmaker,
        )
        files = _unique_files(skill_id)  # real content -> a DIFFERENT real content_hash
        from skillscan_core import content_hash as compute_content_hash
        from skillscan_core import toolchain_digest as compute_toolchain_digest

        c_hash = compute_content_hash(files)
        assert c_hash != baseline_hash  # sanity: this test only means something if they differ
        t_digest = compute_toolchain_digest((_ENGINE.metadata,), runtime.policy.version)
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test",
                trust_tier="internal",
                content_hash=c_hash,
                toolchain_digest=t_digest,
                declared_perms=None,
                operator="drift-test",
            )
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="test submission",
                actor="drift-test",
                content_hash=c_hash,
            )

        await airlock.ensure_groups(redis_client)
        async with orchestration_sessionmaker() as session, session.begin():
            scan_id = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="drift-test",
                engine_metadatas=(_ENGINE.metadata,),
                policy=runtime.policy,
                trust_tier=runtime.default_trust_tier,
            )
        # D2 (2026-07-27): see _seed_sandbox_waited_engine_blobs' own docstring.
        _seed_sandbox_waited_engine_blobs(blobstore, scan_id)
        # See the note on the "published" polling loop above: a generous
        # bound, not 20, since worker_tick's internal claim counts are
        # shared, backlog-sensitive budgets across the whole suite run, and
        # this test needs to reach BOTH "published" and then "quarantined".
        for _ in range(200):
            await worker_tick(runtime, consumer=unique_consumer)
            async with inventory_sessionmaker() as session:
                state = await current_state(session, skill_id=skill_id)
            if state == "quarantined":
                break
        assert state == "quarantined"

        async with inventory_sessionmaker() as session:
            events = (
                (
                    await session.execute(
                        select(SkillLifecycleEventRow)
                        .where(SkillLifecycleEventRow.skill_id == skill_id)
                        .order_by(SkillLifecycleEventRow.id)
                    )
                )
                .scalars()
                .all()
            )
        # Published first (state graph has no direct scanning->quarantined
        # edge), then quarantined as an explicit follow-up - both audited.
        assert [e.to_state for e in events] == [
            "submitted",
            "scanning",
            "published",
            "quarantined",
        ]

    @pytest.mark.asyncio
    async def test_no_baseline_means_no_drift_check_at_all(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        inventory_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
        unique_consumer: str,
    ) -> None:
        """The overwhelmingly common case (no baseline set yet) must publish
        normally and stay published - `is_drift`'s own contract (`None` is
        never drift) must hold end to end through the worker, not just in
        the pure function's own unit tests."""
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            inventory_sessionmaker=inventory_sessionmaker,
        )
        skill_id = f"nobaseline-{uuid.uuid4().hex[:12]}"
        files = _unique_files(skill_id)
        from skillscan_core import content_hash as compute_content_hash
        from skillscan_core import toolchain_digest as compute_toolchain_digest

        from monolith.modules.inventory.service import transition_skill

        c_hash = compute_content_hash(files)
        t_digest = compute_toolchain_digest((_ENGINE.metadata,), runtime.policy.version)
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test",
                trust_tier="internal",
                content_hash=c_hash,
                toolchain_digest=t_digest,
                declared_perms=None,
                operator="no-baseline-test",
            )
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="test submission",
                actor="no-baseline-test",
                content_hash=c_hash,
            )

        await airlock.ensure_groups(redis_client)
        async with orchestration_sessionmaker() as session, session.begin():
            scan_id = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="no-baseline-test",
                engine_metadatas=(_ENGINE.metadata,),
                policy=runtime.policy,
                trust_tier=runtime.default_trust_tier,
            )
        # D2 (2026-07-27): see _seed_sandbox_waited_engine_blobs' own docstring.
        _seed_sandbox_waited_engine_blobs(blobstore, scan_id)
        # A generous bound, not 20: worker_tick's internal claim counts (10
        # each) are shared, backlog-sensitive budgets across the whole suite
        # run - each tick only makes bounded progress, so enough accumulated
        # unrelated backlog from earlier tests can burn through a tight bound
        # before ever reaching this test's own skill.
        for _ in range(200):
            await worker_tick(runtime, consumer=unique_consumer)
            async with inventory_sessionmaker() as session:
                state = await current_state(session, skill_id=skill_id)
            if state == "published":
                break
        assert state == "published"

    @pytest.mark.asyncio
    async def test_block_verdict_never_publishes(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        inventory_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        """BLOCK maps to NO lifecycle transition (the §16.2 machine has no
        'blocked' state) - the skill must stay in scanning, never published."""
        skill_id = f"blocked-{uuid.uuid4().hex[:12]}"
        c_hash = uuid.uuid4().hex + uuid.uuid4().hex  # 64 hex chars, unique
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test",
                trust_tier="internal",
                content_hash=c_hash,
                toolchain_digest="t" * 64,
                declared_perms=None,
                operator="block-test",
            )
            from monolith.modules.inventory.service import transition_skill

            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="test",
                actor="block-test",
                content_hash=c_hash,
            )
        async with gate_sessionmaker() as session, session.begin():
            session.add(
                VerdictRow(
                    scan_id=str(uuid.uuid4()),
                    content_hash=c_hash,
                    verdict="BLOCK",
                    score=20,
                    policy_version="vt",
                    jti=str(uuid.uuid4()),
                    jws_signature="test",
                    effective_severity=4,
                    reasons=["test"],
                    issued_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            inventory_sessionmaker=inventory_sessionmaker,
        )
        await sync_lifecycle_tick(runtime)
        async with inventory_sessionmaker() as session:
            assert await current_state(session, skill_id=skill_id) == "scanning"


def _proposal_row(yaml_text: str) -> PolicyProposalRow:
    now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
    return PolicyProposalRow(
        proposed_policy_yaml=yaml_text,
        changes_hard_gate_rules=False,
        status="approved",
        proposed_by="proposer",
        approved_by="approver",
        created_at=now,
        decided_at=now,
    )


async def _delete_proposal(gate_sessionmaker: SessionmakerFixture, proposal_id: int) -> None:
    """SECURITY/hygiene: these tests share the local dev DB with the live dev
    backend - a leftover test row at status='applied' would be picked up by
    the REAL worker's reload and swap the REAL gate policy. Always delete."""
    async with gate_sessionmaker() as session, session.begin():
        row = await session.get(PolicyProposalRow, proposal_id)
        if row is not None:
            await session.delete(row)


class TestPolicyReload:
    @pytest.mark.asyncio
    async def test_promote_applies_and_marks_applied_then_reload_converges(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
        )
        new_version = f"vt-applied-{uuid.uuid4().hex[:8]}"
        yaml_text = (
            f'version: "{new_version}"\n'
            f"required_engines:\n  - {_ENGINE.metadata.name}\n"
            "hard_gate_rules: []\n"
            "fail_closed_verdict: BLOCK\n"
        )
        async with gate_sessionmaker() as session, session.begin():
            row = _proposal_row(yaml_text)
            session.add(row)
            await session.flush()
            proposal_id = row.id

        try:
            # The approve endpoint's apply path: swaps the live policy + marks applied.
            assert await promote_approved_policy(runtime, proposal_id=proposal_id)
            assert runtime.policy.version == new_version
            async with gate_sessionmaker() as session:
                status = (await session.get(PolicyProposalRow, proposal_id)).status  # type: ignore[union-attr]
            assert status == "applied"

            # A fresh runtime (= a restarted process / another replica) converges
            # on the applied policy via the worker's reload; then it's idempotent.
            fresh = _runtime(
                redis_client=redis_client,
                blobstore=blobstore,
                orchestration_sessionmaker=orchestration_sessionmaker,
                gate_sessionmaker=gate_sessionmaker,
            )
            assert await reload_policy_if_changed(fresh)
            assert fresh.policy.version == new_version
            assert not await reload_policy_if_changed(fresh)
        finally:
            await _delete_proposal(gate_sessionmaker, proposal_id)

    @pytest.mark.asyncio
    async def test_historic_approved_rows_stay_inert(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        """SECURITY: rows sitting at 'approved' (everything approved before the
        apply path existed, e.g. accumulated test data) must never auto-apply
        on worker start - activation is a deliberate per-proposal act."""
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
        )
        yaml_text = (
            f'version: "vt-inert-{uuid.uuid4().hex[:8]}"\n'
            f"required_engines:\n  - {_ENGINE.metadata.name}\n"
            "hard_gate_rules: []\n"
            "fail_closed_verdict: BLOCK\n"
        )
        async with gate_sessionmaker() as session, session.begin():
            row = _proposal_row(yaml_text)
            session.add(row)
            await session.flush()
            proposal_id = row.id
        try:
            # reload only ever reads 'applied' rows - an 'approved' row (this
            # one, and any shared-DB residue) must never become the policy.
            # (No == old_version assertion: a legitimately-'applied' row from
            # a concurrent/crashed run applying is correct reload behavior.)
            await reload_policy_if_changed(runtime)
            assert not runtime.policy.version.startswith("vt-inert-")
        finally:
            await _delete_proposal(gate_sessionmaker, proposal_id)

    @pytest.mark.asyncio
    async def test_policy_with_empty_required_engines_is_refused(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        """SECURITY (INV-1 floor backstop): a policy with no required engines
        would make every scan undecideable (zero engines run -> zero result
        messages -> the collector is never triggered). promote must refuse it
        and keep the current policy. Regression for a live pipeline stall
        caused by a test-residue `required_engines: []` proposal being applied."""
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
        )
        old_version = runtime.policy.version
        yaml_text = (
            f'version: "vt-empty-{uuid.uuid4().hex[:8]}"\n'
            "required_engines: []\n"
            "hard_gate_rules: []\n"
            "fail_closed_verdict: BLOCK\n"
        )
        async with gate_sessionmaker() as session, session.begin():
            row = _proposal_row(yaml_text)
            session.add(row)
            await session.flush()
            proposal_id = row.id
        try:
            assert not await promote_approved_policy(runtime, proposal_id=proposal_id)
            assert runtime.policy.version == old_version
        finally:
            await _delete_proposal(gate_sessionmaker, proposal_id)

    @pytest.mark.asyncio
    async def test_policy_requiring_unavailable_engine_is_refused(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        """SECURITY (fail-closed): a policy naming an engine this deployment
        doesn't have would make every future scan wait forever - promote must
        refuse it, keep the previous policy, and leave the row at 'approved'."""
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
        )
        old_version = runtime.policy.version
        yaml_text = (
            f'version: "vt-bad-{uuid.uuid4().hex[:8]}"\n'
            "required_engines:\n  - engine-that-does-not-exist\n"
            "hard_gate_rules: []\n"
            "fail_closed_verdict: BLOCK\n"
        )
        async with gate_sessionmaker() as session, session.begin():
            row = _proposal_row(yaml_text)
            session.add(row)
            await session.flush()
            proposal_id = row.id
        try:
            assert not await promote_approved_policy(runtime, proposal_id=proposal_id)
            assert runtime.policy.version == old_version
            async with gate_sessionmaker() as session:
                status = (await session.get(PolicyProposalRow, proposal_id)).status  # type: ignore[union-attr]
            assert status == "approved"
        finally:
            await _delete_proposal(gate_sessionmaker, proposal_id)


class TestReportSchedules:
    @pytest.mark.asyncio
    async def test_due_schedule_fires_exactly_once_per_minute(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        reporting_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        notifier = _RecordingNotifier()
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            reporting_sessionmaker=reporting_sessionmaker,
            notifier=notifier,
        )
        async with reporting_sessionmaker() as session, session.begin():
            row = await schedule_report(
                session,
                template="executive_summary",
                cron="* * * * *",
                targets=["siem"],
                created_by="schedule-test",
            )
            schedule_id = row.id
        at = datetime.datetime(2031, 1, 2, 3, 4)  # fixed minute far from other test runs
        fired_first = await run_due_report_schedules(runtime, now=at)
        fired_again = await run_due_report_schedules(runtime, now=at)
        assert fired_first >= 1
        assert fired_again == 0  # per-minute Redis NX dedup
        mine = [e for e in notifier.events if e.get("schedule_id") == schedule_id]
        assert len(mine) == 1
        assert mine[0]["template"] == "executive_summary"
        assert "total_verdicts" in mine[0]["summary"]
