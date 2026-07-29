"""Redis Streams airlock (coding spec §8, INV-10/INV-11).

SECURITY: the monolith and sandbox workers never talk directly - everything
crosses through Redis (control-plane messages) + a blob store (payloads, §8's
MinIO bucket layout via `libs/common/blobstore.py`). Whatever a worker writes
to the findings prefix is read back by the monolith and validated against an
untrusted schema before it's allowed to influence a verdict (INV-11) - that
validation happens in `orchestration/aggregate.py`, not here; this module
only moves bytes.

Lives in `libs/common` (not `apps/monolith`) deliberately: this module has
zero monolith-specific dependencies (only `redis.asyncio`, its sibling
`common.log` + stdlib), and both `apps/monolith` (the workers/orchestrators
side) and `services/engine_runner` (a genuinely separate, credential-free
deployable per INV-10 that must not import monolith-namespaced code) need the
exact same wire-compatible stream names/field layout to talk to each other
through Redis.

WIRE COMPATIBILITY (read before changing any field): because the two ends are
two independently deployed images, every rollout has a window in which one side
speaks a newer field set than the other. The rule this module holds to is that
BOTH directions must survive that window unaided:

  * a consumer reads each field by name and never requires one that older
    producers did not write (a new optional field parses to `None`, never to a
    plausible-looking default like `0`);
  * a producer only ever ADDS fields, and older consumers ignore what they do
    not read, because a Redis Stream entry is a flat field map, not a
    positional record.

So no field addition here is allowed to imply a deployment ordering constraint.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import redis.asyncio as aioredis

from common.log import get_logger

_logger = get_logger("skillscan.common.airlock")

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


# Wire field name for the per-engine timing added in milestone C Task 7. Named
# after the interval it measures rather than after the thing it is attached to:
# it is the wall-clock span of ONE `DetectionEngine.analyze()` call and nothing
# else. See `ResultMessage.analyze_duration_ms`.
ANALYZE_DURATION_MS_FIELD = "analyze_duration_ms"


@dataclass(frozen=True, slots=True)
class ResultMessage:
    message_id: str
    scan_id: str
    findings_key: str
    engine: str
    status: str
    # Milestone C Task 7. WHICH INTERVAL: wall-clock milliseconds spanning the
    # single `engine.analyze(files, deadline=...)` call that produced this
    # result - i.e. the adapter staging the file set into its tempdir, the
    # engine's own `subprocess.run`, and the parse of that subprocess's output
    # (`engine_runner/adapters/base.py`). It deliberately EXCLUDES time the
    # scan job spent queued on `SCANS_STREAM`, the artifact fetch, the hardened
    # unpack (paid once per job, shared by every engine) and the findings-blob
    # write.
    #
    # WHY THAT ONE: it is the only interval directly comparable to the knob a
    # deployer actually turns - `SKILLSCAN_ENGINE_TIMEOUTS_JSON`, milestone C
    # Task 4 - and its SUM across a scan's engines is precisely the quantity
    # Task 4 flagged as already unsafe (the shipped defaults sum to 480s
    # against a 300s scan deadline, with sequential dispatch, so the last
    # engine in line starves). Nothing had ever measured it, so "the defaults
    # are wrong" was theory. Queue-wait would answer a capacity question
    # instead, and dispatch-to-result wall time would fold both plus blob I/O
    # into one number that could not be compared to any configured limit.
    #
    # `None` means "no timing on this message", which is NOT 0ms. Three
    # producers legitimately have none: the poison-pill, unpack-rejected and
    # unrunnable-artifact markers (no engine ran at all), plus - during a
    # rolling upgrade - any producer still on a pre-Task-7 image.
    analyze_duration_ms: int | None = None


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


async def _delivery_count(redis: aioredis.Redis, stream: str, group: str, message_id: str) -> int:
    pending = await redis.xpending_range(stream, group, min=message_id, max=message_id, count=1)
    if not pending:
        return 0
    return int(pending[0]["times_delivered"])


async def delivery_count(
    redis: aioredis.Redis, message_id: str, *, group: str = WORKERS_GROUP
) -> int:
    """How many times the SCANS stream has delivered `message_id` to `group`."""
    return await _delivery_count(redis, SCANS_STREAM, group, message_id)


async def result_delivery_count(redis: aioredis.Redis, message_id: str) -> int:
    """The RESULTS stream's counterpart to `delivery_count` (2026-07-29, C
    correctness review N-1).

    A SEPARATE named function rather than a `stream=`/`group=` pair of keyword
    arguments on `delivery_count`: the two are not independent, and a call site
    that overrode one and forgot the other would be asking about a (stream,
    group) pairing that does not exist. The pairing is fixed here rather than
    left as a call-site obligation, the same reason `_parse_results` is shared
    rather than copied.
    """
    return await _delivery_count(redis, RESULTS_STREAM, ORCHESTRATORS_GROUP, message_id)


async def produce_result(
    redis: aioredis.Redis,
    *,
    scan_id: str,
    findings_key: str,
    engine: str,
    status: str,
    analyze_duration_ms: int | None = None,
) -> str:
    """`analyze_duration_ms` is OMITTED from the entry when None rather than
    written as an empty string or a 0, so a marker message (poison pill /
    unpack rejected / unrunnable) stays byte-identical to what pre-Task-7
    producers wrote, and so "absent" and "measured as zero" can never collide
    on the wire.

    NOTE (mypy): the fields mapping is annotated `dict[Any, Any]`, not
    `dict[str, str]` - redis-py's `xadd` stub takes `Mapping[FieldT,
    EncodableT]` and `Mapping`'s key parameter is invariant, so a concretely
    keyed dict variable fails the match even though `str` is one of the union
    members. (`produce_scan_job` sidesteps the same problem by inlining its
    literal; this one cannot, because it has a conditional field.)
    """
    fields: dict[Any, Any] = {
        "scan_id": scan_id,
        "findings_key": findings_key,
        "engine": engine,
        "status": status,
    }
    if analyze_duration_ms is not None:
        fields[ANALYZE_DURATION_MS_FIELD] = str(int(analyze_duration_ms))
    result: Any = await redis.xadd(RESULTS_STREAM, fields)
    return result.decode() if isinstance(result, bytes) else result


async def claim_results(
    redis: aioredis.Redis, *, consumer: str, count: int = 10, block_ms: int = 1000
) -> list[ResultMessage]:
    response = await redis.xreadgroup(
        ORCHESTRATORS_GROUP, consumer, {RESULTS_STREAM: ">"}, count=count, block=block_ms
    )
    results: list[ResultMessage] = []
    for _stream_name, messages in response:
        results += _parse_results(messages)
    return results


async def reclaim_stale_results(
    redis: aioredis.Redis,
    *,
    consumer: str,
    min_idle_ms: int = STALE_CLAIM_IDLE_MS,
) -> list[ResultMessage]:
    """SECURITY (2026-07-28, VM re-review N-2): the results stream had NO
    reclaim path, unlike the scans stream (`reclaim_stale_scan_jobs`).
    `claim_results` reads `">"` only - new messages - so a collector that
    crashed between `XREADGROUP` and `ack_result` left that message pending
    forever, and nothing would ever re-trigger `_try_score_and_decide` for
    that scan_id even though its findings blob was already durably on disk.
    The scan then sits in `running` for good: `sweep_queued_jobs_to_airlock`
    only handles `queued`, and `sweep_sandbox_wait_timeouts` cannot see it
    either, because the collector never got far enough to set
    `sandbox_wait_started_at`. Fail-stuck rather than fail-open - no verdict is
    invented - but the submitter never gets an answer, which is a real outage.

    (Before the F-2 fix this was masked by accident: the sweep selected on
    `created_at`, so it happened to pick these scans up as a side effect of a
    clock that was wrong for other reasons.)

    Redelivery is safe here: `run_result_collector_tick` never accumulates
    findings FROM the messages - it only uses them to learn which scan_ids to
    look at, then reads each engine's blob from the blob store by name. A
    duplicate message re-runs a decide attempt that the `scan_job.state`
    single-flight guard turns into a no-op.
    """
    _cursor, messages, _deleted = await redis.xautoclaim(
        RESULTS_STREAM, ORCHESTRATORS_GROUP, consumer, min_idle_time=min_idle_ms, start_id="0"
    )
    return _parse_results(messages)


def _parse_results(messages: Any) -> list[ResultMessage]:
    """The ONE place a results-stream entry becomes a `ResultMessage`.

    Deliberately shared by `claim_results` and `reclaim_stale_results`: they had
    byte-identical inline copies of this, and the reclaim path is the one nobody
    exercises until a collector has already crashed - exactly the copy that
    would have been left behind when a field was added to the other.
    """
    results: list[ResultMessage] = []
    for message_id, fields in messages:
        decoded = _decode_fields(fields)
        results.append(
            ResultMessage(
                message_id=_decode(message_id),
                scan_id=decoded["scan_id"],
                findings_key=decoded["findings_key"],
                engine=decoded["engine"],
                status=decoded["status"],
                analyze_duration_ms=_parse_analyze_duration_ms(decoded),
            )
        )
    return results


def _parse_analyze_duration_ms(decoded: dict[str, str]) -> int | None:
    """Absent or unusable timing reads as `None` - never as a number.

    Two deliberate asymmetries with the fields above it:

    1. It uses `.get`, not `[...]`. A pre-Task-7 producer writes no such field
       and its messages must keep flowing; the alternative (a default of 0)
       would record "this engine finished instantly" for every engine on the
       not-yet-upgraded side, i.e. it would silently poison the exact dataset
       this field exists to collect. Mutation-tested.

    2. A malformed value degrades to `None` instead of raising, unlike
       `scan_id`/`findings_key`/`status`, whose absence SHOULD blow up. Those
       are load-bearing: without them the message cannot be acted on at all.
       This one is telemetry. Raising here would abort the parse of the whole
       XREADGROUP batch, so one corrupt field would stall the results stream
       for every scan in it - fail-stuck across the board to protect a number
       nobody scores on. Logged at WARNING so it is not silent.
    """
    raw = decoded.get(ANALYZE_DURATION_MS_FIELD)
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError:
        _logger.warning(
            "results-stream message carried an unparseable analyze_duration_ms - ignoring it",
            extra={"context": {"engine": decoded.get("engine"), "raw_length": len(raw)}},
        )
        return None
    if value < 0:
        _logger.warning(
            "results-stream message carried a negative analyze_duration_ms - ignoring it",
            extra={"context": {"engine": decoded.get("engine"), "value": value}},
        )
        return None
    return value


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


def monotonic_now() -> float:
    """Start reading for a DURATION measurement - never for a deadline.

    SECURITY/CORRECTNESS: `now_epoch` (wall clock) and this (an arbitrary-origin
    uptime counter) are not interchangeable and this codebase has already paid
    for mixing them - `engine_runner/adapters/base.py` carries the post-mortem:
    comparing an epoch `deadline` against `time.monotonic()` produced a
    `remaining` of tens of years, so the shared scan budget constrained nothing
    and every engine silently fell back to its own fixed timeout. Deadlines are
    absolute and cross process boundaries, so they must stay on `now_epoch`.
    Durations are local and must not be distorted by an NTP step or a leap
    second, so they belong here.
    """
    return time.monotonic()


def elapsed_ms(started: float) -> int:
    """Whole milliseconds since a `monotonic_now()` reading.

    Floored at 0: a monotonic clock cannot legitimately run backwards, but a
    negative duration would be indistinguishable from a bug downstream, and
    `_parse_analyze_duration_ms` rejects negatives on the wire anyway. Both
    dispatch loops go through this rather than doing their own arithmetic, so
    the monolith's floor engines and the sandbox runner's engines cannot end up
    reporting the same interval in different units.
    """
    return max(0, round((time.monotonic() - started) * 1000))
