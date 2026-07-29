"""INV-7: the process's idea of "the current toolchain" and the digest actually
stamped on a scan must be the SAME expression, including when an engine is
admin-disabled.

THE GUARD `ScanRuntime.current_toolchain_digest`'s docstring used to claim
existed. It named `apps/monolith/tests/test_gate_service.py`, which contained no
reference to the digest at all - so the claim was not merely in the wrong file,
nothing anywhere checked it. This file is that guard, and it disables an engine
first, because with nothing disabled the two spellings agree by accident and any
assertion about them is vacuous.

WHAT WAS WRONG (2026-07-29, milestone C correctness review N-3).
`current_toolchain_digest` hashed `runtime.engine_metadatas` - every engine -
while every writer of a persisted digest hashes `filter_enabled_engines(...)` of
that same list: `gateway.router.create_scan` (the `scan_job`'s digest and
`cache_key`), the `skill_version.toolchain_digest` written beside it, and
`marketplace_api.router`. Disable one engine and the same bytes get two
different `cache_key`s, so:

  * single-flight dedup splits - a console submission and a `reeval` rescan of
    identical content occupy two different scan_jobs;
  * `worker.advance_scanned_toolchain_digests` filters `scan_job.toolchain_digest
    == current`, matches no console-submitted job, and never advances
    `skill_version.toolchain_digest`;
  * so `GET /v1/reeval` reports the ENTIRE published inventory permanently
    stale, and `POST /v1/reeval` queues all of it, forever.

Reproduced before the fix with the real functions (no infrastructure needed -
`filter_enabled_engines` is a set difference): with `inhouse-pii` in the
disabled set the two digests were `4e011677...` and `315594a6...`, and the two
cache_keys for identical bytes `fa7ec7b7...` and `b3ba8caa...`.

REACHABILITY, stated honestly. Today `runtime.engine_metadatas` is exactly
`floor_engines()` and `admin.router` refuses to disable any of those
(`required = floor_engine_names()`), so the split is not reachable through the
admin API as it currently stands. It IS reachable by writing
`skillscan:admin:disabled_engines` directly - that key is deliberately shared
with the separate engine-runner, and `filter_enabled_engines` does not re-check
the required set when reading it - and it becomes reachable through the API the
moment `engine_metadatas` grows past the floor set, which is the direction
milestone C Task 2 and the engine console are already pushing. These tests take
the out-of-band route deliberately: the property under test is that the two
expressions agree, not that a particular route to disagreement is open today.

Real MySQL + Redis: `submit_scan` writes a `scan_job` and `filter_enabled_engines`
reads the live Redis set. VM-only, per the repo's hard rule.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from common.blobstore import LocalFilesystemBlobStore
from common.engine_toggle import DISABLED_ENGINES_KEY
from skillscan_core import (
    EngineCapability,
    EngineMetadata,
    GatePolicy,
    StaticKeywordEngine,
    TrustTier,
)
from skillscan_core import toolchain_digest as compute_toolchain_digest
from sqlalchemy import select

from monolith.modules.admin.engine_registry import filter_enabled_engines
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.orchestration.models import ScanJob
from monolith.modules.orchestration.service import SubmissionChannel, submit_scan
from monolith.modules.reeval.controller import PublishedToolchainStatus, build_rescan_job
from monolith.tests.conftest import SessionmakerFixture

_FLOOR = StaticKeywordEngine().metadata


#: A second, DISABLEABLE engine alongside the floor one. Named uniquely per run
#: so a leaked Redis membership from one test can never silently change another
#: test's expected digest - the exact class of cross-test coupling that makes a
#: digest assertion look green for the wrong reason.
def _disableable(name: str) -> EngineMetadata:
    return EngineMetadata(
        name=name,
        version="1.0.0",
        ruleset_digest="d" * 64,
        capabilities=frozenset({EngineCapability.STATIC}),
    )


def _policy() -> GatePolicy:
    return GatePolicy(
        version=f"digest-agreement-{uuid.uuid4().hex[:8]}",
        required_engines=frozenset({_FLOOR.name}),
    )


@pytest_asyncio.fixture
async def disabled_engine(redis_client: aioredis.Redis) -> AsyncIterator[EngineMetadata]:
    """One engine in the live disabled set, removed again afterwards.

    Written straight to the Redis SET rather than through
    `engine_registry.set_engine_enabled`: see this module's docstring for why
    that is the reachable route today, and why the property under test is not
    about which route was taken.
    """
    metadata = _disableable(f"disableable-{uuid.uuid4().hex[:8]}")
    await redis_client.sadd(DISABLED_ENGINES_KEY, metadata.name)  # type: ignore[misc]
    try:
        yield metadata
    finally:
        await redis_client.srem(DISABLED_ENGINES_KEY, metadata.name)  # type: ignore[misc]


def _runtime(
    *,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    metadatas: tuple[EngineMetadata, ...],
    policy: GatePolicy,
) -> ScanRuntime:
    return ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=orchestration_sessionmaker,
        gate_session_factory=gate_sessionmaker,
        policy=policy,
        engine_metadatas=metadatas,
        allowlist=(),
        signer=LocalDevSigner(),
    )


class TestToolchainDigestAgreement:
    @pytest.mark.asyncio
    async def test_the_runtime_digest_is_the_one_a_submission_would_stamp(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
        disabled_engine: EngineMetadata,
    ) -> None:
        """THE assertion the old docstring claimed and nobody made: with an
        engine disabled, what `reeval` calls "current" must equal what
        `submit_scan` actually records. Asserted against a real `scan_job` row
        rather than against a re-derivation of the same expression - the whole
        defect was two spellings agreeing on paper."""
        policy = _policy()
        metadatas = (_FLOOR, disabled_engine)
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            metadatas=metadatas,
            policy=policy,
        )
        enabled = await filter_enabled_engines(redis_client, metadatas)
        assert disabled_engine not in enabled, "setup: the engine must really be disabled"

        files = [("SKILL.md", 0o644, f"---\nname: d-{uuid.uuid4().hex[:8]}\n---\n".encode())]
        async with orchestration_sessionmaker() as session, session.begin():
            scan_id = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="digest-agreement",
                engine_metadatas=enabled,
                policy=policy,
                trust_tier=TrustTier.INTERNAL,
                source=SubmissionChannel.CONSOLE,
                requested_trust_tier=TrustTier.INTERNAL,
            )
        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()

        assert await runtime.current_toolchain_digest() == job.toolchain_digest

    @pytest.mark.asyncio
    async def test_disabling_an_engine_actually_moves_the_current_digest(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
        disabled_engine: EngineMetadata,
    ) -> None:
        """The mutation catcher for the test above, which a
        `current_toolchain_digest` that ignored the disabled set could still
        pass if the enabled and full sets happened to coincide. Switching an
        engine off must change the toolchain's identity: `cache_key` is
        content+toolchain, so a digest that did not move would serve a verdict
        reached WITH an engine that no longer runs - fail-open on INV-7."""
        policy = _policy()
        metadatas = (_FLOOR, disabled_engine)
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            metadatas=metadatas,
            policy=policy,
        )
        all_engines = compute_toolchain_digest(metadatas, policy.cache_policy_version)
        assert await runtime.current_toolchain_digest() != all_engines
        assert await runtime.current_toolchain_digest() == compute_toolchain_digest(
            (_FLOOR,), policy.cache_policy_version
        )

    @pytest.mark.asyncio
    async def test_a_reeval_rescan_and_a_submission_share_one_cache_key(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
        disabled_engine: EngineMetadata,
    ) -> None:
        """The consequence, end to end. `reeval.controller.build_rescan_job`
        builds its `cache_key` from whatever digest the router hands it -
        `current_toolchain_digest`. If that differs from the submitter's, the
        same bytes occupy two scan_jobs, single-flight dedup splits, and
        `advance_scanned_toolchain_digests` can never retire the staleness."""
        policy = _policy()
        metadatas = (_FLOOR, disabled_engine)
        runtime = _runtime(
            redis_client=redis_client,
            blobstore=blobstore,
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            metadatas=metadatas,
            policy=policy,
        )
        enabled = await filter_enabled_engines(redis_client, metadatas)
        files = [("SKILL.md", 0o644, f"---\nname: c-{uuid.uuid4().hex[:8]}\n---\n".encode())]
        async with orchestration_sessionmaker() as session, session.begin():
            scan_id = await submit_scan(
                session,
                redis_client,
                blobstore,
                files=files,
                submitter="digest-agreement",
                engine_metadatas=enabled,
                policy=policy,
                trust_tier=TrustTier.INTERNAL,
                source=SubmissionChannel.CONSOLE,
                requested_trust_tier=TrustTier.INTERNAL,
            )
        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()

        rescan = build_rescan_job(
            PublishedToolchainStatus(
                skill_id=f"skill-{uuid.uuid4().hex[:8]}",
                trust_tier=TrustTier.INTERNAL,
                content_hash=str(job.content_hash),
                recorded_toolchain_digest="old-digest",
            ),
            toolchain_digest=await runtime.current_toolchain_digest(),
            submitter="reeval",
            now=job.created_at,
        )
        assert rescan.cache_key == job.cache_key, (
            "a rescan of the SAME content under the CURRENT toolchain must land on the "
            "cache_key the submission already occupies - otherwise dedup splits and "
            "reeval re-queues the same work forever"
        )
