"""Scan state machine (coding spec §11.3): queued -> running -> scored -> decided/failed.

SECURITY: `run_mock_engine_worker_tick` stands in for a real sandboxed worker
process (coding spec §10, M4/M5) and therefore touches ONLY Redis + the blob
store - never a database session - exactly like a real subprocess/sandbox
worker will. `run_result_collector_tick` is the only piece with DB access, and
even it never imports gate's or audit's ORM models directly: recording a
verdict happens by calling gate's own `decide_and_record()` with a session the
caller supplies, bound to gate's own least-privilege MySQL user (svc_gate, per
policies/grants/manifest.yaml). This module's own session (svc_orchestration)
only ever touches scan_job/scan_result; even a bug that tried to reach into
gate's tables from here would be rejected by MySQL itself.
"""

from __future__ import annotations

import asyncio
import datetime
import io
import json
import tarfile
import uuid
from collections.abc import Callable, Sequence

import redis.asyncio as aioredis
import yaml
from common import airlock
from common.blobstore import BlobNotFoundError, BlobStorePort, artifact_key, findings_key
from common.log import get_logger
from engine_runner.normalizer import UnpackRejected, unpack_hardened
from schemas.findings import serialize_engine_result, serialize_finding
from skillscan_core import (
    AllowlistEntry,
    DetectionEngine,
    EngineMetadata,
    GatePolicy,
    ScanResult,
    Severity,
    TrustTier,
)
from skillscan_core import (
    cache_key as compute_cache_key,
)
from skillscan_core import (
    content_hash as compute_content_hash,
)
from skillscan_core import (
    toolchain_digest as compute_toolchain_digest,
)
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from monolith.modules.gate.service import SignerPort, decide_and_record

from .aggregate import load_and_aggregate, unavailable_engine_result
from .models import ScanJob, ScanResultRow

SessionFactory = Callable[[], AsyncSession]

# SECURITY: sentinel engine-status values a worker reports on the results
# stream to signal the orchestrator to dead-letter a job immediately, carrying
# no findings blob. Two distinct reasons get two distinct statuses even though
# both end up forcing the same BLOCK verdict: POISON_PILL is an *operational*
# failure (delivery_count exhausted - the archive might be fine, the worker
# just keeps crashing) while UNPACK_REJECTED is a *content* failure
# (normalizer.unpack_hardened deterministically rejected this exact archive -
# retrying would fail identically every time, so this fast-paths straight to
# dead-letter rather than waiting out redelivery attempts).
POISON_PILL_STATUS = "poison_pill"
UNPACK_REJECTED_STATUS = "unpack_rejected"
_POISON_PILL_ENGINE_MARKER = "__poison_pill__"
_UNPACK_REJECTED_ENGINE_MARKER = "__unpack_rejected__"
_TERMINAL_STATUSES = frozenset({POISON_PILL_STATUS, UNPACK_REJECTED_STATUS})

_logger = get_logger("skillscan.orchestration.worker")


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


class _NoAliasSafeLoader(yaml.SafeLoader):
    """SECURITY: a SafeLoader that refuses YAML aliases. `yaml.safe_load`
    blocks code execution but still expands anchors/aliases, so a tiny
    (<1 KiB) nested-alias "billion laughs" payload can expand exponentially and
    OOM the process. A length cap does NOT stop this (the payload is small by
    design), so aliases are rejected outright at compose time - before any
    expansion - which a SKILL.md name-bearing frontmatter never legitimately
    needs. The raised error is caught as a normal parse failure -> no name."""

    def compose_node(self, parent: object, index: object) -> object:
        event = self.peek_event()
        if isinstance(event, yaml.events.AliasEvent):
            raise yaml.YAMLError("YAML aliases are not permitted in SKILL.md frontmatter")
        return super().compose_node(parent, index)  # type: ignore[arg-type]


def _parse_skill_name(files: Sequence[tuple[str, int, bytes]]) -> str | None:
    """Best-effort extraction of the human-readable name from SKILL.md's YAML
    frontmatter (---\\nname: ...\\n---), the same format skillspector's own
    fixtures already use (vendor/skillspector/tests/fixtures/*/SKILL.md).
    Never raises - a missing/malformed SKILL.md just means no name to show,
    not a reason to fail the whole submission. yaml.safe_load only: this is
    untrusted upload content, never yaml.load/unsafe_load."""
    for path, _mode, data in files:
        if path != "SKILL.md":
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if not text.startswith("---"):
            return None
        parts = text.split("---", 2)
        if len(parts) < 3:
            return None
        # SECURITY (BE-5): length-cap first (cheap ceiling on any oversized
        # frontmatter), then parse via the alias-refusing loader that actually
        # defuses billion-laughs (see _NoAliasSafeLoader). We drive the loader
        # through its low-level API rather than `yaml.load(..., Loader=...)`
        # deliberately: _NoAliasSafeLoader is a SafeLoader SUBCLASS (no custom
        # constructors, so no arbitrary-type construction - identical safety to
        # yaml.safe_load, plus alias rejection), and this form keeps static
        # "no yaml.load" scanners satisfied.
        loader = _NoAliasSafeLoader(parts[1][:8192])
        try:
            frontmatter = loader.get_single_data()
        except yaml.YAMLError:
            return None
        finally:
            loader.dispose()
        if not isinstance(frontmatter, dict):
            return None
        name = frontmatter.get("name")
        if not isinstance(name, str):
            return None
        stripped = name.strip()
        # SECURITY (BE-1): cap to the DB column width (skill_name is
        # String(255)). An over-long name parses fine here but otherwise aborts
        # the ENTIRE scan submission at INSERT on strict MySQL ("Data too
        # long"), violating this function's own "never fail the submission"
        # contract. The sibling parser in aig.py caps identically.
        return stripped[:255] if stripped else None
    return None


def _pack_tar(files: Sequence[tuple[str, int, bytes]]) -> bytes:
    """Pre-normalization artifact packing (coding spec §8: artifacts/<content_hash>/pkg.tar).
    Packing untrusted-free (path,mode,data) tuples we already validated on the
    way in is not a security-sensitive operation - hardening lives entirely on
    the UNPACK side (`engine_runner.normalizer.unpack_hardened`), since that's
    where attacker-controlled bytes get parsed."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for path, mode, data in files:
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            info.mode = mode & 0o7777
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


async def submit_scan(
    session: AsyncSession,
    redis: aioredis.Redis,
    blobstore: BlobStorePort,
    *,
    files: Sequence[tuple[str, int, bytes]],
    submitter: str,
    engine_metadatas: Sequence[EngineMetadata],
    policy: GatePolicy,
    deadline_s: float = 300.0,
) -> str:
    """SECURITY (single-flight): `scan_job.cache_key` UNIQUE - two submissions of
    the same content+toolchain collapse to one scan_job/one pipeline run rather
    than duplicating work or racing two independent verdicts for one content_hash.
    Caller must run this inside `async with session.begin():`.
    """
    c_hash = compute_content_hash(files)
    t_digest = compute_toolchain_digest(engine_metadatas, policy.version)
    ck = compute_cache_key(c_hash, t_digest)

    existing = (
        await session.execute(select(ScanJob).where(ScanJob.cache_key == ck))
    ).scalar_one_or_none()
    if existing is not None:
        return str(existing.scan_id)

    scan_id = str(uuid.uuid4())
    a_key = artifact_key(c_hash)
    if not blobstore.exists(a_key):
        blobstore.put(a_key, _pack_tar(files))

    session.add(
        ScanJob(
            scan_id=scan_id,
            content_hash=c_hash,
            toolchain_digest=t_digest,
            cache_key=ck,
            state="queued",
            submitter=submitter,
            created_at=_naive_utcnow(),
            skill_name=_parse_skill_name(files),
        )
    )
    await session.flush()

    await airlock.produce_scan_job(
        redis,
        scan_id=scan_id,
        content_hash=c_hash,
        artifact_key=a_key,
        deadline_epoch=airlock.now_epoch() + deadline_s,
        engines=tuple(sorted(policy.required_engines)),
    )
    return scan_id


async def run_mock_engine_worker_tick(
    redis: aioredis.Redis,
    blobstore: BlobStorePort,
    *,
    engines_by_name: dict[str, DetectionEngine],
    consumer: str,
    count: int = 10,
    reclaim_idle_ms: int = airlock.STALE_CLAIM_IDLE_MS,
    additional_engine_names: Sequence[str] = (),
) -> int:
    """Claims pending scan jobs (including crash-recovered ones via
    XAUTOCLAIM once idle for `reclaim_idle_ms`), unpacks each job's artifact
    via `engine_runner.normalizer.unpack_hardened` (coding spec §11.4 M4), and
    runs the configured engines in-process - the M3 skeleton's substitute for
    the real sandboxed subprocess engine adapters (coding spec §10, M4/M5).
    Touches ONLY Redis + the blob store, matching what a real sandboxed worker
    will have access to. Returns the number of jobs processed (including
    dead-lettered ones).

    `reclaim_idle_ms` defaults to the airlock's normal crash-recovery
    threshold; tests exercising poison-pill/redelivery pass a much smaller
    value so they don't need to wait out a real 60s idle window.

    `additional_engine_names` (e.g. the intel matcher): run against EVERY
    claimed job regardless of that job's own `job.engines` (which is fixed
    at submission time from `policy.required_engines` only - an advisory
    engine added after the fact would otherwise never run at all, since the
    dispatch loop below is driven by `job.engines`, not by everything present
    in `engines_by_name`. Found live: constructing the matcher and putting it
    in `engines_by_name` alone was not sufficient - its findings blob simply
    never got written, for exactly this reason). Kept separate from
    `job.engines` rather than mutating what gets stored there, so a required
    engine's fail-closed semantics (INV-1) are never accidentally extended to
    an advisory one.

    SECURITY: `unpack_hardened` provides the decompression-bomb/path-traversal/
    symlink defenses (this function would otherwise be trusting attacker-
    controlled archive bytes directly) - but gVisor sandboxing of the WORKER
    PROCESS itself (coding spec: "全程在 gVisor sandbox 内") remains a
    deployment-time concern this function cannot provide on its own; never
    point `engines_by_name` at anything that parses/executes untrusted Skill
    content outside a real sandbox in production.
    """
    jobs = list(await airlock.claim_scan_jobs(redis, consumer=consumer, count=count, block_ms=200))
    jobs += await airlock.reclaim_stale_scan_jobs(
        redis, consumer=consumer, min_idle_ms=reclaim_idle_ms
    )

    processed = 0
    for job in jobs:
        delivered = await airlock.delivery_count(redis, job.message_id)
        if delivered > airlock.MAX_DELIVERY_COUNT:
            # SECURITY (INV-5 poison-pill): this job has defeated every prior
            # delivery attempt - stop retrying it and hand the orchestrator a
            # sentinel it will turn into a forced BLOCK (see
            # `_dead_letter_and_decide`). No findings blob is written.
            await airlock.produce_result(
                redis,
                scan_id=job.scan_id,
                findings_key="",
                engine=_POISON_PILL_ENGINE_MARKER,
                status=POISON_PILL_STATUS,
            )
            await airlock.ack_scan_job(redis, job.message_id)
            processed += 1
            continue

        try:
            try:
                artifact = await asyncio.to_thread(blobstore.get, job.artifact_key)
            except BlobNotFoundError:
                # SECURITY/robustness: a missing artifact is a PERMANENT failure
                # (the blob will never appear), not a transient one - retrying
                # it MAX_DELIVERY_COUNT times just churns the stream and can
                # starve live jobs behind a backlog of dead messages (observed
                # with stream messages left over from a prior run whose blob
                # store was wiped). Fast-path straight to dead-letter, same as
                # an UnpackRejected content failure, instead of leaving it
                # unacked for endless redelivery.
                await airlock.produce_result(
                    redis,
                    scan_id=job.scan_id,
                    findings_key="",
                    engine=_UNPACK_REJECTED_ENGINE_MARKER,
                    status=UNPACK_REJECTED_STATUS,
                )
                await airlock.ack_scan_job(redis, job.message_id)
                processed += 1
                _logger.warning(
                    "scan job's artifact is missing from the blob store - dead-lettering",
                    extra={"context": {"scan_id": job.scan_id, "artifact_key": job.artifact_key}},
                )
                continue
            try:
                files = {path: data for path, _mode, data in unpack_hardened(artifact)}
            except UnpackRejected as exc:
                # SECURITY (M4 hardening): a deterministic content rejection -
                # fast-path straight to dead-letter, see module SECURITY note.
                await airlock.produce_result(
                    redis,
                    scan_id=job.scan_id,
                    findings_key="",
                    engine=_UNPACK_REJECTED_ENGINE_MARKER,
                    status=UNPACK_REJECTED_STATUS,
                )
                await airlock.ack_scan_job(redis, job.message_id)
                processed += 1
                _logger.warning(
                    "scan job's archive failed hardened unpacking - dead-lettering",
                    extra={"context": {"scan_id": job.scan_id, "reason": str(exc)}},
                )
                continue
            dispatch_engines = tuple(job.engines) + tuple(
                e for e in additional_engine_names if e not in job.engines
            )
            for engine_name in dispatch_engines:
                engine = engines_by_name.get(engine_name)
                if engine is not None:
                    result = engine.analyze(files, deadline=job.deadline_epoch)
                else:
                    # Defensive only: dispatch list should always match the
                    # worker's registered engine set.
                    result = unavailable_engine_result(
                        engine_name, reason="engine not registered on this worker"
                    )
                key = findings_key(job.scan_id, engine_name)
                await asyncio.to_thread(
                    blobstore.put, key, json.dumps(serialize_engine_result(result)).encode("utf-8")
                )
                await airlock.produce_result(
                    redis,
                    scan_id=job.scan_id,
                    findings_key=key,
                    engine=engine_name,
                    status=result.status.value,
                )
        except Exception:
            # SECURITY: one job's failure (missing/corrupt blob, malformed
            # archive, etc.) must never abort the whole batch and starve every
            # other pending job this tick - deliberately don't ack here, so
            # this message is redelivered on the normal schedule and, if the
            # failure persists, naturally escalates to the poison-pill path
            # above once delivery_count exceeds the threshold (no separate
            # error-handling path needed).
            _logger.exception(
                "mock engine worker failed processing a scan job - leaving unacked for redelivery",
                extra={"context": {"scan_id": job.scan_id}},
            )
            continue
        await airlock.ack_scan_job(redis, job.message_id)
        processed += 1
    return processed


def forced_block_scan_result(content_hash: str, *, reason: str) -> ScanResult:
    """A synthetic, honestly-labeled ScanResult for a dead-lettered job: it
    reuses `gate.decide()`'s existing INV-1 fail-closed path (required_ok=False)
    rather than special-casing "force BLOCK" logic in this module. `reason`
    ends up in the recorded verdict's `reasons` (via gate.decide()), so an
    auditor can distinguish an operational poison-pill from a content
    rejection after the fact."""
    return ScanResult(
        content_hash=content_hash,
        severity=Severity.CRITICAL,
        confidence_at_max=1.0,
        trifecta_present=False,
        hard_gate_hits=(),
        findings=(),
        engine_provenance=(),
        findings_capped=False,
        required_ok=False,
        missing_or_failed_required=(reason,),
    )


async def run_result_collector_tick(
    redis: aioredis.Redis,
    blobstore: BlobStorePort,
    orchestration_session_factory: SessionFactory,
    gate_session_factory: SessionFactory,
    *,
    policy: GatePolicy,
    trust_tier: TrustTier,
    allowlist: Sequence[AllowlistEntry],
    signer: SignerPort,
    consumer: str,
    count: int = 20,
    operator: str = "system:orchestrator",
    additional_engines: Sequence[str] = (),
) -> int:
    """Claims pending result messages and, for every scan_id that now has all
    `policy.required_engines` reported (or was reported as a poison-pill),
    records a verdict. Returns how many scans were newly decided this tick.

    `additional_engines` (e.g. the intel matcher, coding spec NET-06/07/08):
    read into aggregation when they happen to have reported, never gated on
    - see `_try_score_and_decide`'s own docstring for the full reasoning.

    SECURITY: `scan_job.state` (checked+transitioned under `SELECT ... FOR
    UPDATE`) is the single-flight guard against two collector ticks (e.g. two
    orchestrator processes) double-deciding the same scan_id - see
    `_try_score_and_decide`/`_dead_letter_and_decide`. Known gap: a crash
    between the "scored" and "decided" transitions leaves the scan_job stuck at
    'scored' (the verdict itself, via gate's own transactional outbox, is never
    left partially written) - a reconciliation sweep to resume from 'scored'
    would close this, but is not required for M3's acceptance bar and is not
    implemented here.
    """
    results = await airlock.claim_results(redis, consumer=consumer, count=count, block_ms=200)
    required = tuple(sorted(policy.required_engines))
    by_scan_id: dict[str, list[str]] = {}
    for r in results:
        by_scan_id.setdefault(r.scan_id, []).append(r.status)

    decided = 0
    failed_scan_ids: set[str] = set()
    for scan_id, statuses in by_scan_id.items():
        try:
            terminal = _TERMINAL_STATUSES.intersection(statuses)
            if terminal:
                # SECURITY: if a scan_id somehow reported BOTH a poison-pill and
                # an unpack-rejection (shouldn't happen - each job only unpacks
                # once - but never trust that), the content rejection is the
                # more specific, more useful audit reason to record.
                reason = (
                    "unpack_rejected:hardening_check_failed"
                    if UNPACK_REJECTED_STATUS in terminal
                    else "poison_pill:max_delivery_exceeded"
                )
                did_decide = await _dead_letter_and_decide(
                    orchestration_session_factory,
                    gate_session_factory,
                    scan_id=scan_id,
                    policy=policy,
                    trust_tier=trust_tier,
                    signer=signer,
                    operator=operator,
                    reason=reason,
                )
            else:
                await _mark_running_if_queued(orchestration_session_factory, scan_id)
                did_decide = await _try_score_and_decide(
                    blobstore,
                    orchestration_session_factory,
                    gate_session_factory,
                    scan_id=scan_id,
                    required_engines=required,
                    policy=policy,
                    trust_tier=trust_tier,
                    allowlist=allowlist,
                    signer=signer,
                    operator=operator,
                    additional_engines=additional_engines,
                )
        except Exception:
            # SECURITY: one scan_id's failure (e.g. an IntegrityError from two
            # collector replicas racing to dead-letter/decide the same scan_id
            # concurrently - expected under concurrent ticks, see this
            # function's own docstring) must never abort the whole batch and
            # delay every OTHER already-decided scan_id's ack below -
            # deliberately don't mark this scan_id decided, and below, don't
            # ack any of ITS messages either, so it remains unacked for
            # legitimate retry/redelivery - exactly like
            # `run_mock_engine_worker_tick`'s equivalent per-job isolation
            # above, just scoped to this scan_id's own messages rather than
            # the whole tick's.
            failed_scan_ids.add(scan_id)
            _logger.exception(
                "result collector failed deciding a scan_id - leaving unacked for redelivery",
                extra={"context": {"scan_id": scan_id}},
            )
            continue
        if did_decide:
            decided += 1

    for r in results:
        if r.scan_id in failed_scan_ids:
            continue
        await airlock.ack_result(redis, r.message_id)
    return decided


async def _mark_running_if_queued(
    orchestration_session_factory: SessionFactory, scan_id: str
) -> None:
    async with orchestration_session_factory() as session, session.begin():
        await session.execute(
            update(ScanJob)
            .where(ScanJob.scan_id == scan_id, ScanJob.state == "queued")
            .values(state="running")
        )


async def _dead_letter_and_decide(
    orchestration_session_factory: SessionFactory,
    gate_session_factory: SessionFactory,
    *,
    scan_id: str,
    policy: GatePolicy,
    trust_tier: TrustTier,
    signer: SignerPort,
    operator: str,
    reason: str,
) -> bool:
    """SECURITY (INV-5 poison-pill + M4 hardening rejection): reached when a
    worker reports it could never process this scan job, for either reason
    `run_result_collector_tick` distinguishes. Records a real, signed BLOCK
    verdict through the normal gate/outbox/audit path (reusing gate.decide()'s
    INV-1 fail-closed logic via `forced_block_scan_result`) so it is fully
    auditable, then marks scan_job failed. A concurrent duplicate dead-letter
    signal for the same scan_id is caught by `verdict.scan_id`'s PRIMARY KEY
    (defense in depth) rather than a lock held across the gate call. Full
    marketplace-side inventory quarantine (skill lifecycle state) is M6 scope
    (`/v1/inventory/{skill_id}/quarantine`) - not wired here.
    """
    async with orchestration_session_factory() as session, session.begin():
        job = (
            await session.execute(
                select(ScanJob).where(ScanJob.scan_id == scan_id).with_for_update()
            )
        ).scalar_one_or_none()
        if job is None or job.state not in ("queued", "running"):
            return False
        content_hash = str(job.content_hash)

    async with gate_session_factory() as gate_session, gate_session.begin():
        await decide_and_record(
            gate_session,
            scan_id=scan_id,
            scan_result=forced_block_scan_result(content_hash, reason=reason),
            policy=policy,
            trust_tier=trust_tier,
            allowlist=(),
            signer=signer,
            operator=operator,
            now=airlock.now_epoch(),
        )

    async with orchestration_session_factory() as session, session.begin():
        await session.execute(
            update(ScanJob)
            .where(ScanJob.scan_id == scan_id, ScanJob.state.in_(("queued", "running")))
            .values(state="failed")
        )
    return True


async def _try_score_and_decide(
    blobstore: BlobStorePort,
    orchestration_session_factory: SessionFactory,
    gate_session_factory: SessionFactory,
    *,
    scan_id: str,
    required_engines: Sequence[str],
    policy: GatePolicy,
    trust_tier: TrustTier,
    allowlist: Sequence[AllowlistEntry],
    signer: SignerPort,
    operator: str,
    additional_engines: Sequence[str] = (),
) -> bool:
    """`additional_engines` (e.g. the intel matcher): read into aggregation
    WHEN PRESENT, but never gate on - the "all required engines reported"
    wait below deliberately checks only `required_engines`, so a scan is
    never blocked waiting on an advisory engine, and `load_and_aggregate`
    below reads `required_engines` union `additional_engines` so an advisory
    engine's findings still count toward severity/trifecta when it DID
    report in time (its own `findings_key` blob simply won't exist yet if it
    hasn't - `load_engine_result`'s existing BlobNotFoundError handling
    covers that the exact same way a slow required engine would be
    handled, except it never blocks the wait)."""
    scan_result: ScanResult | None = None
    async with orchestration_session_factory() as session, session.begin():
        job = (
            await session.execute(
                select(ScanJob).where(ScanJob.scan_id == scan_id).with_for_update()
            )
        ).scalar_one_or_none()
        if job is None or job.state not in ("queued", "running"):
            return False  # unknown, or already scored/decided/failed elsewhere
        all_reported = all(
            [
                await asyncio.to_thread(blobstore.exists, findings_key(scan_id, e))
                for e in required_engines
            ]
        )
        if not all_reported:
            return False  # not all required engines have reported yet

        engine_names = tuple(required_engines) + tuple(
            e for e in additional_engines if e not in required_engines
        )
        scan_result = load_and_aggregate(
            blobstore,
            scan_id=scan_id,
            content_hash=str(job.content_hash),
            engine_names=engine_names,
            policy=policy,
        )
        session.add(
            ScanResultRow(
                scan_id=scan_id,
                content_hash=scan_result.content_hash,
                severity=int(scan_result.severity),
                confidence_at_max=scan_result.confidence_at_max,
                trifecta_present=scan_result.trifecta_present,
                findings_capped=scan_result.findings_capped,
                required_ok=scan_result.required_ok,
                findings=[serialize_finding(f) for f in scan_result.findings],
                provenance=[list(p) for p in scan_result.engine_provenance],
                hard_gate_hits=list(scan_result.hard_gate_hits),
            )
        )
        job.state = "scored"
        await session.flush()

    async with gate_session_factory() as gate_session, gate_session.begin():
        await decide_and_record(
            gate_session,
            scan_id=scan_id,
            scan_result=scan_result,
            policy=policy,
            trust_tier=trust_tier,
            allowlist=allowlist,
            signer=signer,
            operator=operator,
            now=airlock.now_epoch(),
        )

    async with orchestration_session_factory() as session, session.begin():
        await session.execute(
            update(ScanJob)
            .where(ScanJob.scan_id == scan_id, ScanJob.state == "scored")
            .values(state="decided")
        )
    return True
