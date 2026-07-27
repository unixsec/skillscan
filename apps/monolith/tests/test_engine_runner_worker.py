"""Tests for `engine_runner.worker.sandbox_engine_tick` - the previously
missing consumer that runs the OSS adapters (bandit/osv-scanner/yara/
skillspector) against a real submitted scan, independent of the in-monolith
floor engines.

Against real local Redis + a tmp_path blob store, same posture as
`test_orchestration_pipeline.py`. Only the parts of the OSS binaries that are
actually installed on the test host run for real (matching
`test_bandit_adapter.py`'s own `shutil.which` skip pattern) - the point of
these tests is to prove the CONSUMER LOOP (claim/unpack/dispatch/write/produce/
ack, on its own consumer group, independent of the floor path) is correct,
not to re-verify each adapter's own parsing logic (that's already covered by
test_bandit_adapter.py/test_osv_adapter.py/test_yara_adapter.py/
test_skillspector_adapter.py).
"""

from __future__ import annotations

import json
import shutil
import uuid

import pytest
import redis.asyncio as aioredis
from common import airlock
from common.blobstore import LocalFilesystemBlobStore, artifact_key
from common.engine_toggle import DISABLED_ENGINES_KEY
from engine_runner.sandbox_engines import sandbox_engines
from engine_runner.worker import SANDBOX_GROUP, ensure_sandbox_group, sandbox_engine_tick
from skillscan_core import (
    DetectionEngine,
    EngineCapability,
    EngineMetadata,
    EngineResult,
    EngineStatus,
    ScanMode,
)


def _pack_tar(files: list[tuple[str, int, bytes]]) -> bytes:
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for path, mode, data in files:
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            info.mode = mode
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class _FixedEngine:
    """A minimal, fast, always-available DetectionEngine test double - lets
    the consumer-loop tests below (claim/dispatch/write/produce/ack) run
    deterministically on any host, regardless of which real OSS binaries
    happen to be installed."""

    def __init__(self, name: str, *, status: EngineStatus = EngineStatus.OK) -> None:
        self._name = name
        self._status = status

    @property
    def metadata(self) -> EngineMetadata:
        return EngineMetadata(
            name=self._name,
            version="0",
            ruleset_digest="test",
            capabilities=frozenset({EngineCapability.STATIC}),
        )

    def analyze(self, files: dict[str, bytes], *, deadline: float | None = None) -> EngineResult:
        return EngineResult(
            engine=self.metadata,
            findings=(),
            status=self._status,
            scan_mode=ScanMode.STATIC,
            llm_used=False,
        )


async def _produce_job(
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
    *,
    files: list[tuple[str, int, bytes]],
) -> tuple[str, str]:
    """Returns (scan_id, message_id). NOTE: `redis_client` (conftest.py) is a
    real, shared, un-flushed Redis instance across every test in the whole
    suite - every assertion below filters by the scan_id/message_id THIS
    call produced, never by total stream/PEL length, exactly because other
    tests' jobs can and do coexist in the same stream."""
    scan_id = str(uuid.uuid4())
    content_hash = f"test-hash-{uuid.uuid4().hex}"
    a_key = artifact_key(content_hash)
    blobstore.put(a_key, _pack_tar(files))
    message_id = await airlock.produce_scan_job(
        redis_client,
        scan_id=scan_id,
        content_hash=content_hash,
        artifact_key=a_key,
        deadline_epoch=airlock.now_epoch() + 60,
        engines=(
            "static-keyword",
            "inhouse-pii",
        ),  # today's real required_engines, irrelevant to this consumer
    )
    return scan_id, message_id


class TestSandboxEngineTickConsumesIndependently:
    @pytest.mark.asyncio
    async def test_writes_findings_and_produces_result_for_each_engine(
        self, redis_client: aioredis.Redis, blobstore: LocalFilesystemBlobStore
    ) -> None:
        await airlock.ensure_groups(redis_client)  # results-stream group, for claim_results below
        await ensure_sandbox_group(redis_client)
        scan_id, _message_id = await _produce_job(
            redis_client, blobstore, files=[("skill.py", 0o644, b"print('hi')\n")]
        )
        engines_by_name: dict[str, DetectionEngine] = {
            "fixed-a": _FixedEngine("fixed-a"),
            "fixed-b": _FixedEngine("fixed-b"),
        }

        processed = await sandbox_engine_tick(
            redis_client,
            blobstore,
            engines_by_name=engines_by_name,
            consumer=f"test-{uuid.uuid4().hex[:8]}",
            count=50,  # generous enough to also drain any other tests' leftover jobs in one tick
        )

        assert processed >= 1  # >=, not ==: the shared stream may carry other tests' jobs too
        for engine_name in ("fixed-a", "fixed-b"):
            key = f"findings/{scan_id}/{engine_name}.json"
            assert blobstore.exists(key)
            payload = json.loads(blobstore.get(key))
            assert payload["status"] == "ok"

        # `claim_results` reads Redis Streams' `>` ID - "next never-delivered-to-
        # this-group" - so it never re-reads the same message twice, but a single
        # bounded count can still exhaust on backlog OTHER tests produced and
        # never claimed, pushing this test's own 2 messages past the window.
        # Looping makes guaranteed progress through any backlog (each call only
        # ever advances, never repeats) until this scan's own results surface.
        reported: set[str] = set()
        for _ in range(50):
            results = await airlock.claim_results(redis_client, consumer="collector-test", count=50)
            reported |= {r.engine for r in results if r.scan_id == scan_id}
            if reported == {"fixed-a", "fixed-b"} or not results:
                break
        assert reported == {"fixed-a", "fixed-b"}

    @pytest.mark.asyncio
    async def test_admin_disabled_engine_is_skipped_not_run(
        self, redis_client: aioredis.Redis, blobstore: LocalFilesystemBlobStore
    ) -> None:
        """SECURITY/HONESTY (2026-07-13 fix): the admin PATCH /v1/admin/
        engines/{name} toggle was previously write-only for sandbox engines -
        it recorded the disable in the same Redis set this reads, but nothing
        here ever checked it, so a "disabled" engine kept running anyway.
        Disabling via the exact same key the admin API writes must actually
        stop that engine's findings from being produced."""
        await ensure_sandbox_group(redis_client)
        await redis_client.sadd(DISABLED_ENGINES_KEY, "fixed-disabled")  # type: ignore[misc]
        try:
            scan_id, _message_id = await _produce_job(
                redis_client, blobstore, files=[("skill.py", 0o644, b"print('hi')\n")]
            )
            engines_by_name: dict[str, DetectionEngine] = {
                "fixed-disabled": _FixedEngine("fixed-disabled"),
                "fixed-enabled": _FixedEngine("fixed-enabled"),
            }

            processed = await sandbox_engine_tick(
                redis_client,
                blobstore,
                engines_by_name=engines_by_name,
                consumer=f"test-{uuid.uuid4().hex[:8]}",
                count=50,
            )

            assert processed >= 1
            assert blobstore.exists(f"findings/{scan_id}/fixed-enabled.json")
            assert not blobstore.exists(f"findings/{scan_id}/fixed-disabled.json")
        finally:
            await redis_client.srem(DISABLED_ENGINES_KEY, "fixed-disabled")  # type: ignore[misc]

    @pytest.mark.asyncio
    async def test_does_not_compete_with_the_floor_engine_consumer_group(
        self, redis_client: aioredis.Redis, blobstore: LocalFilesystemBlobStore
    ) -> None:
        """SECURITY: this is the core architectural claim of the whole
        module - a job produced once must be independently claimable by BOTH
        the floor-engine consumer group (`airlock.WORKERS_GROUP`, driven by
        `apps.monolith.worker`) and this sandbox consumer group
        (`SANDBOX_GROUP`), because they are separate Redis Streams consumer
        groups on the same stream, not competing consumers within one group."""
        await airlock.ensure_groups(redis_client)  # the floor path's own groups
        await ensure_sandbox_group(redis_client)
        scan_id, _message_id = await _produce_job(
            redis_client, blobstore, files=[("skill.py", 0o644, b"print('hi')\n")]
        )

        floor_claimed = await airlock.claim_scan_jobs(
            redis_client, consumer="floor-test", count=50, group=airlock.WORKERS_GROUP
        )
        sandbox_claimed = await airlock.claim_scan_jobs(
            redis_client, consumer="sandbox-test", count=50, group=SANDBOX_GROUP
        )

        floor_scan_ids = {j.scan_id for j in floor_claimed}
        sandbox_scan_ids = {j.scan_id for j in sandbox_claimed}
        assert scan_id in floor_scan_ids
        assert scan_id in sandbox_scan_ids

    @pytest.mark.asyncio
    async def test_missing_artifact_is_acked_not_retried_forever(
        self, redis_client: aioredis.Redis, blobstore: LocalFilesystemBlobStore
    ) -> None:
        await ensure_sandbox_group(redis_client)
        scan_id = str(uuid.uuid4())
        message_id = await airlock.produce_scan_job(
            redis_client,
            scan_id=scan_id,
            content_hash=f"never-written-{scan_id}",
            artifact_key=artifact_key(f"never-written-{scan_id}"),
            deadline_epoch=airlock.now_epoch() + 60,
            engines=(),
        )

        processed = await sandbox_engine_tick(
            redis_client,
            blobstore,
            engines_by_name={},
            consumer=f"test-{uuid.uuid4().hex[:8]}",
            count=50,
        )

        assert processed >= 1
        # xpending_range filtered to exactly this message_id (same pattern as
        # `airlock.delivery_count`) - True result means it's STILL pending
        # (not yet acked); an empty list means it was acked, which is what a
        # correctly dead-lettered missing-artifact job should do.
        still_pending = await redis_client.xpending_range(
            airlock.SCANS_STREAM, SANDBOX_GROUP, min=message_id, max=message_id, count=1
        )
        assert still_pending == []


@pytest.mark.skipif(shutil.which("bandit") is None, reason="bandit CLI not installed")
class TestRealBanditEndToEnd:
    @pytest.mark.asyncio
    async def test_real_bandit_binary_reports_a_finding_via_the_full_consumer_loop(
        self, redis_client: aioredis.Redis, blobstore: LocalFilesystemBlobStore
    ) -> None:
        """The one fully-real assertion in this file: an actual `bandit`
        subprocess, invoked through the real consumer loop (not called
        directly), finds a real MD5-usage issue in scanned content and the
        finding lands in the blob store - proof the previously-missing
        engine-runner piece genuinely works end to end for at least one of
        the four OSS adapters, not just that the plumbing compiles."""
        await ensure_sandbox_group(redis_client)
        vulnerable_code = b"import hashlib\nhashlib.md5(b'x')\n"
        scan_id, _message_id = await _produce_job(
            redis_client, blobstore, files=[("skill.py", 0o644, vulnerable_code)]
        )

        engines_by_name = {"bandit": sandbox_engines()["bandit"]}
        processed = await sandbox_engine_tick(
            redis_client,
            blobstore,
            engines_by_name=engines_by_name,
            consumer=f"test-{uuid.uuid4().hex[:8]}",
            count=50,
            reclaim_idle_ms=1,
        )

        assert processed >= 1
        payload = json.loads(blobstore.get(f"findings/{scan_id}/bandit.json"))
        assert payload["status"] == "ok"
        assert len(payload["findings"]) >= 1
