"""Redis Streams airlock (coding spec §8, INV-10/INV-11).

SECURITY: the monolith and sandbox workers never talk directly - everything
crosses through Redis (control-plane messages) + a blob store (payloads, §8's
MinIO bucket layout via `libs/common/blobstore.py`). Whatever a worker writes
to the findings prefix is read back by the monolith and validated against an
untrusted schema before it's allowed to influence a verdict (INV-11) - that
validation happens in `orchestration/aggregate.py`, not here; this module
only moves bytes.

Lives in `libs/common` (not `apps/monolith`) deliberately: this module has
zero monolith-specific dependencies (only `redis.asyncio` + stdlib), and both
`apps/monolith` (the workers/orchestrators side) and `services/engine_runner`
(a genuinely separate, credential-free deployable per INV-10 that must not
import monolith-namespaced code) need the exact same wire-compatible stream
names/field layout to talk to each other through Redis.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import redis.asyncio as aioredis

SCANS_STREAM = "skillscan:scans"
RESULTS_STREAM = "skillscan:results"
WORKERS_GROUP = "workers"
ORCHESTRATORS_GROUP = "orchestrators"

# SECURITY (INV-5 poison-pill suppression): a message redelivered more than this
# many times is treated as unprocessable and dead-lettered rather than retried
# forever.
MAX_DELIVERY_COUNT = 5
STALE_CLAIM_IDLE_MS = 60_000


@dataclass(frozen=True, slots=True)
class ScanJobMessage:
    message_id: str
    scan_id: str
    content_hash: str
    artifact_key: str
    deadline_epoch: float
    engines: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ResultMessage:
    message_id: str
    scan_id: str
    findings_key: str
    engine: str
    status: str


async def ensure_group(redis: aioredis.Redis, stream: str, group: str) -> None:
    """Idempotent group creation for one (stream, group) pair - the single
    primitive `ensure_groups` composes for the built-in workers/orchestrators
    groups, and that a second, independent consumer group (e.g. a real
    sandboxed engine-runner reading the SAME `SCANS_STREAM` without competing
    with the in-monolith floor-engine consumer for message delivery - Redis
    Streams delivers every message once per group, not once per stream) can
    call directly for its own group name."""
    try:
        await redis.xgroup_create(stream, group, id="0", mkstream=True)
    except aioredis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


async def ensure_groups(redis: aioredis.Redis) -> None:
    for stream, group in ((SCANS_STREAM, WORKERS_GROUP), (RESULTS_STREAM, ORCHESTRATORS_GROUP)):
        await ensure_group(redis, stream, group)


async def produce_scan_job(
    redis: aioredis.Redis,
    *,
    scan_id: str,
    content_hash: str,
    artifact_key: str,
    deadline_epoch: float,
    engines: tuple[str, ...],
) -> str:
    # NOTE: the fields dict is inlined (not a pre-typed local) so mypy's
    # bidirectional literal inference matches it against redis-py's xadd stub -
    # a `dict[str, Any]` variable fails that match on key-type invariance even
    # though `str` is one of the union members.
    result: Any = await redis.xadd(
        SCANS_STREAM,
        {
            "scan_id": scan_id,
            "content_hash": content_hash,
            "artifact_key": artifact_key,
            "deadline_epoch": deadline_epoch,
            "engines": ",".join(engines),
        },
    )
    return result.decode() if isinstance(result, bytes) else result


async def claim_scan_jobs(
    redis: aioredis.Redis,
    *,
    consumer: str,
    count: int = 1,
    block_ms: int = 1000,
    group: str = WORKERS_GROUP,
) -> list[ScanJobMessage]:
    response = await redis.xreadgroup(
        group, consumer, {SCANS_STREAM: ">"}, count=count, block=block_ms
    )
    return _parse_scan_jobs(response)


async def reclaim_stale_scan_jobs(
    redis: aioredis.Redis,
    *,
    consumer: str,
    min_idle_ms: int = STALE_CLAIM_IDLE_MS,
    group: str = WORKERS_GROUP,
) -> list[ScanJobMessage]:
    """SECURITY: recovers messages an earlier consumer claimed but crashed before
    ACKing - without this, a worker crash silently drops the scan forever
    (violates INV-1 fail-closed at the availability level)."""
    _cursor, messages, _deleted = await redis.xautoclaim(
        SCANS_STREAM, group, consumer, min_idle_time=min_idle_ms, start_id="0"
    )
    return _parse_scan_jobs([(SCANS_STREAM.encode(), messages)] if messages else [])


def _parse_scan_jobs(response: list[Any]) -> list[ScanJobMessage]:
    jobs: list[ScanJobMessage] = []
    for _stream_name, messages in response:
        for message_id, fields in messages:
            decoded = _decode_fields(fields)
            jobs.append(
                ScanJobMessage(
                    message_id=_decode(message_id),
                    scan_id=decoded["scan_id"],
                    content_hash=decoded["content_hash"],
                    artifact_key=decoded["artifact_key"],
                    deadline_epoch=float(decoded["deadline_epoch"]),
                    engines=tuple(decoded["engines"].split(",")) if decoded["engines"] else (),
                )
            )
    return jobs


async def ack_scan_job(
    redis: aioredis.Redis, message_id: str, *, group: str = WORKERS_GROUP
) -> None:
    await redis.xack(SCANS_STREAM, group, message_id)


async def delivery_count(
    redis: aioredis.Redis, message_id: str, *, group: str = WORKERS_GROUP
) -> int:
    pending = await redis.xpending_range(
        SCANS_STREAM, group, min=message_id, max=message_id, count=1
    )
    if not pending:
        return 0
    return int(pending[0]["times_delivered"])


async def produce_result(
    redis: aioredis.Redis, *, scan_id: str, findings_key: str, engine: str, status: str
) -> str:
    result: Any = await redis.xadd(
        RESULTS_STREAM,
        {"scan_id": scan_id, "findings_key": findings_key, "engine": engine, "status": status},
    )
    return result.decode() if isinstance(result, bytes) else result


async def claim_results(
    redis: aioredis.Redis, *, consumer: str, count: int = 10, block_ms: int = 1000
) -> list[ResultMessage]:
    response = await redis.xreadgroup(
        ORCHESTRATORS_GROUP, consumer, {RESULTS_STREAM: ">"}, count=count, block=block_ms
    )
    results: list[ResultMessage] = []
    for _stream_name, messages in response:
        for message_id, fields in messages:
            decoded = _decode_fields(fields)
            results.append(
                ResultMessage(
                    message_id=_decode(message_id),
                    scan_id=decoded["scan_id"],
                    findings_key=decoded["findings_key"],
                    engine=decoded["engine"],
                    status=decoded["status"],
                )
            )
    return results


async def ack_result(redis: aioredis.Redis, message_id: str) -> None:
    await redis.xack(RESULTS_STREAM, ORCHESTRATORS_GROUP, message_id)


def _decode(value: bytes | str) -> str:
    return value.decode() if isinstance(value, bytes) else value


def _decode_fields(fields: dict[Any, Any]) -> dict[str, str]:
    return {_decode(k): _decode(v) for k, v in fields.items()}


def now_epoch() -> float:
    """Thin wrapper so callers don't reach for time.time() directly - kept as a
    single seam in case a deterministic clock is needed for testing later."""
    return time.time()
