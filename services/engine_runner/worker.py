"""Sandboxed engine-runner consumer loop (coding spec §10, INV-10/INV-11).

This is the piece that did not exist before: `apps.monolith.worker.worker_tick`
only ever drove `orchestration.floor.floor_engines()` (the in-monolith,
required, byte-matching floor) - the four real OSS adapters
(bandit/osv-scanner/yara/skillspector) were built and unit-tested but had no
process anywhere that called them against a live scan. This module is that
process's core tick logic; `main.py` is the actual entrypoint that loops it.

SECURITY (INV-10): touches ONLY Redis (the airlock control plane) and the
blob store - no DB session, no Vault client, no SQLAlchemy import anywhere in
this module or its callers. A credential leak or RCE in a vendored OSS
engine's parser therefore cannot reach a database or a signing key.

SECURITY (own consumer group, not `airlock.WORKERS_GROUP`): this consumer
claims scan jobs on `common.airlock.SCANS_STREAM` through its own, separate
consumer group (`SANDBOX_GROUP`) so it receives an INDEPENDENT copy of every
message - Redis Streams delivers once per group, not once per stream, so
this does not compete with or change the existing in-monolith floor-engine
consumer's delivery in any way (see `apps/monolith/worker.py`'s own
`run_mock_engine_worker_tick` call, which is untouched by this module).

SECURITY/HONESTY (deliberately does NOT gate verdicts yet): this writes real
findings to `findings/<scan_id>/<engine>.json` and produces real
`ResultMessage`s on `common.airlock.RESULTS_STREAM`, exactly like the floor
path does - `orchestration.service.run_result_collector_tick` will pick them
up and persist them alongside the floor engines' results. But
`GatePolicy.required_engines` still names only the 6 floor engines (unchanged
by this module), and `_try_score_and_decide` only WAITS for
`required_engines` before scoring - so these sandbox engines' findings can
race the floor engines' faster, always-in-process completion and may not
always make it into the verdict that's actually signed, even though they are
durably recorded. Whether these OSS findings should become fail-closed
`required_engines` (matching floor semantics - any bandit/osv/yara/skillspector
hiccup BLOCKs every scan) or an advisory tier that can only escalate
(mirroring the LLM-monotonicity-floor precedent in `skillscan_core.gate`) is
a real policy decision this module deliberately leaves unmade.
"""

from __future__ import annotations

import json

import redis.asyncio as aioredis
from common import airlock
from common.blobstore import BlobNotFoundError, BlobStorePort, findings_key
from common.engine_toggle import list_disabled_engines
from common.log import get_logger
from schemas.findings import serialize_engine_result
from skillscan_core import DetectionEngine

from engine_runner.normalizer import UnpackRejected, unpack_hardened

SANDBOX_GROUP = "sandbox_engines"

_logger = get_logger("skillscan.engine_runner.worker")


async def ensure_sandbox_group(redis: aioredis.Redis) -> None:
    await airlock.ensure_group(redis, airlock.SCANS_STREAM, SANDBOX_GROUP)


async def sandbox_engine_tick(
    redis: aioredis.Redis,
    blobstore: BlobStorePort,
    *,
    engines_by_name: dict[str, DetectionEngine],
    consumer: str,
    count: int = 10,
    reclaim_idle_ms: int = airlock.STALE_CLAIM_IDLE_MS,
) -> int:
    """Claims scan jobs from this service's OWN consumer group (see module
    docstring), unpacks each job's artifact exactly like the floor path does
    (same hardening function, same fail-closed dead-letter-on-reject
    behavior), and runs every configured sandbox engine against it -
    unconditionally, regardless of `job.engines` (which today only ever lists
    `policy.required_engines`, i.e. the floor set - this service's whole
    purpose is to run engines that AREN'T in that list). Returns the number
    of jobs processed.
    """
    jobs = list(
        await airlock.claim_scan_jobs(
            redis, consumer=consumer, count=count, block_ms=200, group=SANDBOX_GROUP
        )
    )
    jobs += await airlock.reclaim_stale_scan_jobs(
        redis, consumer=consumer, min_idle_ms=reclaim_idle_ms, group=SANDBOX_GROUP
    )
    if not jobs:
        return 0

    # SECURITY/HONESTY (2026-07-13): fetched once per tick, not per job - the
    # admin toggle (apps/monolith/modules/admin/router.py's PATCH /engines)
    # was previously write-only for these sandbox engines: it recorded the
    # disable in Redis but nothing here ever read it back, so a "disabled"
    # bandit/osv-scanner/yara/skillspector/aig-mcp-scan kept running anyway.
    disabled = await list_disabled_engines(redis)

    processed = 0
    for job in jobs:
        try:
            try:
                artifact = blobstore.get(job.artifact_key)
            except BlobNotFoundError:
                # Same reasoning as the floor path's identical branch: a
                # missing artifact is permanent, not transient - ack and move
                # on rather than let it churn this consumer's redelivery.
                await airlock.ack_scan_job(redis, job.message_id, group=SANDBOX_GROUP)
                processed += 1
                _logger.warning(
                    "sandbox tick: scan job's artifact is missing from the blob store",
                    extra={"context": {"scan_id": job.scan_id, "artifact_key": job.artifact_key}},
                )
                continue
            try:
                files = {path: data for path, _mode, data in unpack_hardened(artifact)}
            except UnpackRejected:
                # The floor consumer already dead-letters this exact case via
                # a poison/unpack-rejected result marker - this consumer just
                # acks and stays silent rather than producing a second,
                # redundant terminal signal for the same scan_id.
                await airlock.ack_scan_job(redis, job.message_id, group=SANDBOX_GROUP)
                processed += 1
                continue

            await _dispatch_engines(
                redis,
                blobstore,
                scan_id=job.scan_id,
                files=files,
                engines_by_name=engines_by_name,
                deadline=job.deadline_epoch,
                disabled=disabled,
            )
        except Exception:
            _logger.exception(
                "sandbox engine tick failed processing a scan job - leaving unacked for redelivery",
                extra={"context": {"scan_id": job.scan_id}},
            )
            continue
        await airlock.ack_scan_job(redis, job.message_id, group=SANDBOX_GROUP)
        processed += 1
    return processed


async def _dispatch_engines(
    redis: aioredis.Redis,
    blobstore: BlobStorePort,
    *,
    scan_id: str,
    files: dict[str, bytes],
    engines_by_name: dict[str, DetectionEngine],
    deadline: float | None,
    disabled: frozenset[str] = frozenset(),
) -> None:
    """Runs every sandbox engine sequentially against the same unpacked file
    set (skipping any admin-disabled via `common.engine_toggle` - the same
    Redis set the monolith's admin API writes). Each `SubprocessEngineAdapter.
    analyze()` call is a blocking `subprocess.run()` under the hood (base.py) -
    fine here because this service's entire job, unlike the shared monolith
    event loop, is running engines; there is nothing else this process needs
    to stay responsive to while one engine's subprocess runs."""
    for engine_name, engine in engines_by_name.items():
        if engine_name in disabled:
            _logger.info(
                "sandbox engine skipped (admin-disabled)",
                extra={"context": {"scan_id": scan_id, "engine": engine_name}},
            )
            continue
        result = engine.analyze(files, deadline=deadline)
        key = findings_key(scan_id, engine_name)
        blobstore.put(key, json.dumps(serialize_engine_result(result)).encode("utf-8"))
        await airlock.produce_result(
            redis, scan_id=scan_id, findings_key=key, engine=engine_name, status=result.status.value
        )
        _logger.info(
            "sandbox engine reported",
            extra={
                "context": {
                    "scan_id": scan_id,
                    "engine": engine_name,
                    "status": result.status.value,
                    "finding_count": len(result.findings),
                }
            },
        )
