"""Scan state machine (coding spec §11.3): queued -> running -> scored -> decided/failed.

This sentence is a description; `SCAN_STATES` below is the definition. Anything
that needs the full set of states reads that constant - never this prose.

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
import enum
import io
import json
import tarfile
import uuid
from collections.abc import Callable, Sequence
from typing import Any

import redis.asyncio as aioredis
from common import airlock
from common.blobstore import BlobNotFoundError, BlobStorePort, artifact_key, findings_key
from common.frontmatter import parse_frontmatter
from common.log import get_logger
from common.skill_package import root_skill_md_path
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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from monolith.modules.gate.service import SignerPort, decide_and_record

from .aggregate import load_and_aggregate, unavailable_engine_result
from .models import ScanEngineHealthRow, ScanJob, ScanResultRow, ScanSubmitterRow

SessionFactory = Callable[[], AsyncSession]

# The scan state machine (coding spec §11.3), as a CONSTANT this module's own
# writers use - not as prose in the module docstring.
#
# CONTRACT: `SCAN_STATES` is the single source of truth for "which states a
# `scan_job` row can be in", and every consumer that must cover the whole
# machine reads it from here. `marketplace_api.views._STATUS_PROJECTION` is one
# such consumer: an internal state with no external projection makes
# `project_status` raise, which 500s every marketplace poll of such a scan.
# test_marketplace_views.py's guard reads THIS set, so adding a state below
# without mapping it there fails that test - the previous guard parsed the
# docstring prose with a regex that enumerated the five states it was meant to
# discover, and therefore could never see a sixth one (review 2026-07-28).
STATE_QUEUED = "queued"
STATE_RUNNING = "running"
STATE_SCORED = "scored"
STATE_DECIDED = "decided"
STATE_FAILED = "failed"
SCAN_STATES: frozenset[str] = frozenset(
    {STATE_QUEUED, STATE_RUNNING, STATE_SCORED, STATE_DECIDED, STATE_FAILED}
)
# The two non-terminal states: a job here has not been scored yet, so it is
# still claimable by the collector, the dead-letter path and the sweeps.
_UNSCORED_STATES: tuple[str, ...] = (STATE_QUEUED, STATE_RUNNING)


class SubmissionChannel(enum.StrEnum):
    """Which door one submission arrived through (里程碑 F Task 12).

    Persisted per `scan_submitter` row, ASSIGNED AT INSERT TIME. It is a known
    fact at that moment - the handler that calls `submit_scan` IS the channel -
    and this enum exists so it gets stored rather than reconstructed later.

    SECURITY: never derive this from the submitter STRING. "service accounts
    are named with such-and-such a prefix" is a shape check standing in for a
    membership check, and this repository has already paid for that once: a
    catalog audit that validated finding ids against `[A-Z]{3,7}-\\d{2}` but
    never against the 62-item catalog let the nonexistent id `SUP-01` through.
    The only other place the distinction exists at all is
    `SessionContext.is_machine`, which is per-request auth state that dies with
    the request - which is exactly why milestone F Task 2 could not produce
    this field without a schema change.

    Lives HERE rather than on `models.py` so `marketplace_api.router` can name
    its own channel without importing orchestration's ORM classes - the same
    plain-values-cross-the-boundary rule `is_scan_submitter` documents
    (scripts/check_import_boundaries.py).
    """

    CONSOLE = "console"
    MARKETPLACE = "marketplace"


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

# SECURITY (INV-5 poison-pill, 2026-07-29 milestone C correctness review N-1):
# the RESULTS stream's own dead-letter reason, the mirror of the SCANS stream's
# "poison_pill:max_delivery_exceeded" above.
#
# WHAT WAS MISSING. The scans stream has capped redelivery since M3; the
# results stream never did. `run_result_collector_tick` leaves a scan_id's
# messages unacked when deciding it raises (deliberately - so a transient
# failure retries), `reclaim_stale_results` hands them straight back, and a
# DETERMINISTIC failure inside `_try_score_and_decide` therefore retries
# forever: the scan never gets a verdict and the stream never drains.
#
# Milestone C Task 8 made that reachable rather than theoretical. It added 15
# `scan_engine_health` INSERTs, four CHECK constraints and a new GRANT into
# that same transaction, so a missing grant, a violated CHECK or an
# out-of-range value now fails identically on every attempt.
#
# WHY A FORCED BLOCK AND NOT AN ACK-AND-DROP. Both ends of the obvious choice
# are wrong: leaving it unacked churns the stream forever, and acking it away
# leaves the scan with no verdict, silently. So this takes the SAME exit the
# scans stream takes - a real, signed, audited fail-closed BLOCK through
# `_dead_letter_and_decide` - and only then acks. An operator sees a BLOCK
# verdict carrying this reason, `scan_job.state = 'failed'`, and an ERROR log
# naming the scan_id and the delivery count; nothing is silently dropped and
# nothing keeps churning.
#
# A distinct reason string from the scans stream's, deliberately: the two say
# very different things about where to look. "The worker could never process
# this artifact" is a content/worker problem; this one is "the monolith could
# never finish scoring a result it had already received", which points at the
# database, the grants or the policy - not at the submitted package.
RESULT_POISON_PILL_REASON = "result_poison_pill:max_delivery_exceeded"

# Grace on top of the configured wait before the sweep forces a decision - see
# sweep_sandbox_wait_timeouts' docstring for why it is not zero.
_SWEEP_GRACE_S = 30.0
_SWEEP_BATCH = 50

_logger = get_logger("skillscan.orchestration.worker")


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


def _parse_skill_name(files: Sequence[tuple[str, int, bytes]]) -> str | None:
    """Best-effort display name from SKILL.md's frontmatter. Parsing is shared
    with the permissions detector - see `common.frontmatter`.

    SECURITY/CORRECTNESS: root path only, never basename-anywhere. This name
    is written to `ScanJob.skill_name` and shown on the scan list - an
    Agent Skill's manifest is the one SKILL.md at the package root, so a
    bundled example (`examples/SKILL.md`) must never supply the displayed
    name for the whole package.

    2026-07-27 (final review, F-5): "root" is not the literal string
    "SKILL.md" - a conventionally packed `tar czf skill.tgz my-skill/` wraps
    every member in a directory the normalizer does not strip, which left the
    scan list showing "not registered" for such packages. Resolved through
    `common.skill_package.root_skill_md_path`, the one shared implementation
    (also used by the permissions detector and by gateway's declared_perms
    write) - do not add a fourth spelling."""
    root_skill_md = root_skill_md_path(path for path, _mode, _data in files)
    for path, _mode, data in files:
        if path != root_skill_md:
            continue
        frontmatter = parse_frontmatter(data)
        if frontmatter is None:
            return None
        name = frontmatter.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()[:255]
        return None
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
    trust_tier: TrustTier,
    source: SubmissionChannel,
    requested_trust_tier: TrustTier,
    deadline_s: float = 300.0,
) -> str:
    """SECURITY (single-flight): `scan_job.cache_key` UNIQUE - two submissions of
    the same content+toolchain collapse to one scan_job/one pipeline run rather
    than duplicating work or racing two independent verdicts for one content_hash.
    Caller must run this inside `async with session.begin():`.

    SECURITY (2026-07-28, milestone B' Task 4): `trust_tier` is REQUIRED, not
    defaulted - a default would let a missed call site silently fall back to
    some tier, which is exactly the failure mode this parameter exists to
    eliminate (every verdict used to be judged at a single process-wide
    `runtime.default_trust_tier` regardless of who submitted, since
    `session.tier` was never threaded any further than a whoami diagnostic).
    Recorded onto `ScanJob.trust_tier` here, at submit time, because the
    worker decides asynchronously - long after this request/session is gone -
    so the tier has to travel with the scan rather than through a request
    context. See `ScanJob.trust_tier` and this column's migration for the
    full history.

    SECURITY (2026-07-28, milestone B' review C2): BOTH paths out of this
    function record `submitter` in `scan_submitter`. On the dedup path the
    caller is handed someone else's existing scan_job, and every object-level
    authorization check in the system reads that association table - without
    the append, the second submitter is told 404 for a scan_id it was just
    given, permanently (the next submission returns the same id). The tier is
    NOT re-derived for a later submitter: the adjudication already happened, at
    the first submitter's tier, and re-tiering it would mean claiming a decision
    that was never made. `views.project_scan.judged_at_tier` is what makes that
    visible externally rather than silently assumed.

    SECURITY (2026-07-29, milestone F Task 12): `source` is REQUIRED with no
    default, for the same reason `trust_tier` above is - a default is exactly
    what lets a missed call site silently record a channel nobody verified,
    and the point of this parameter is that the CALLER is the channel. It is
    recorded onto the `scan_submitter` row rather than onto `scan_job`: the
    dedup path appends a second submitter who may well have arrived through
    the OTHER door, and a scan-level column could only keep one of the two.

    SECURITY (2026-07-29, milestone F Task 14): `requested_trust_tier` is the
    tier THIS caller asked for, recorded on THIS caller's `scan_submitter` row
    on BOTH paths out of this function. `trust_tier` above is a different fact
    with a different fate: it reaches `ScanJob.trust_tier` only when this call
    actually creates the scan, and is deliberately dropped on the dedup path
    (see the paragraph above - re-tiering an existing adjudication would claim
    a decision nobody made). That asymmetry is exactly the hole: a later
    submitter's request was recorded nowhere, so `GET /v1/scans/{scan_id}` had
    one column to answer two questions and printed it twice under two labels.

    Because `public` is the STRICTEST tier (`policies/gate/v1.yaml` blocks it
    at HIGH, every other tier only at CRITICAL), the case that matters is a
    caller asking for `public` and being handed a verdict adjudicated at
    `internal` - a MORE PERMISSIVE ruleset than they asked for. Nothing here
    changes the verdict; the point is that the divergence becomes visible
    instead of indistinguishable from agreement.

    Required with no default, same reasoning as the two parameters above. Both
    current callers pass the same value they pass as `trust_tier`: the RESOLVED
    tier this submission would have been judged at, never a raw caller-supplied
    form field (see `gateway.router.create_scan`, where a resubmission's tier
    comes from the registered skill and the form field is overridden on
    purpose). Recording the raw field instead would flag that deliberate
    override as a divergence and give an untrusted input a display surface.
    """
    c_hash = compute_content_hash(files)
    # `cache_policy_version`, NOT `version` (milestone C Tasks 5 and 11, INV-7):
    # the policy's `category_weights` change the persisted `verdict.score` and
    # its thresholds (`block_on_severity`, `tier_block_overrides`, ...) change
    # the persisted VERDICT, neither of which changes the version string - so an
    # in-place policy edit that forgot the bump would let this cache_key serve
    # the adjudication computed under the old policy. Must
    # stay identical to `ScanRuntime.current_toolchain_digest`, which decides
    # whether an ALREADY-published skill is stale - the two disagreeing would
    # mean every skill reads as permanently stale.
    t_digest = compute_toolchain_digest(engine_metadatas, policy.cache_policy_version)
    ck = compute_cache_key(c_hash, t_digest)

    existing = (
        await session.execute(select(ScanJob).where(ScanJob.cache_key == ck))
    ).scalar_one_or_none()
    if existing is not None:
        # THE case Task 14 exists for: `trust_tier` is discarded here (the
        # verdict is not re-adjudicated) but `requested_trust_tier` is not -
        # this caller's own request is recorded on their own row even though
        # the answer they are about to receive was reached at someone else's
        # tier. Without this line the two are indistinguishable downstream.
        await _associate_submitter(
            session,
            scan_id=str(existing.scan_id),
            submitter=submitter,
            source=source,
            requested_trust_tier=requested_trust_tier,
        )
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
            state=STATE_QUEUED,
            submitter=submitter,
            created_at=_naive_utcnow(),
            skill_name=_parse_skill_name(files),
            trust_tier=trust_tier.value,
        )
    )
    await session.flush()
    await _associate_submitter(
        session,
        scan_id=scan_id,
        submitter=submitter,
        source=source,
        requested_trust_tier=requested_trust_tier,
    )

    await airlock.produce_scan_job(
        redis,
        scan_id=scan_id,
        content_hash=c_hash,
        artifact_key=a_key,
        deadline_epoch=airlock.now_epoch() + deadline_s,
        engines=tuple(sorted(policy.required_engines)),
    )
    return scan_id


async def _associate_submitter(
    session: AsyncSession,
    *,
    scan_id: str,
    submitter: str,
    source: SubmissionChannel,
    requested_trust_tier: TrustTier,
) -> None:
    """Idempotently record that `submitter` submitted `scan_id` (C2), through
    `source` (里程碑 F Task 12), asking for `requested_trust_tier`
    (里程碑 F Task 14).

    Read-then-insert rather than `INSERT ... ON DUPLICATE KEY UPDATE`: the
    latter needs the UPDATE privilege even for a no-op update, and
    `scan_submitter` is granted INSERT+SELECT only on purpose (an UPDATE here
    could silently re-attribute a scan). The SAVEPOINT covers the race two
    concurrent submissions of the same content leave open between the SELECT
    and the INSERT - same idiom, and same reason, as
    `reeval.controller.trigger_rescans`: a duplicate is the expected benign
    outcome, so it rolls back only this statement and not the caller's
    transaction.

    `source` and `requested_trust_tier` are both written on the INSERT and
    never on the early return: an existing (scan_id, submitter) row already
    records the channel and the tier that pair's submission actually came in
    with, and rewriting either would (a) need an UPDATE grant this table
    deliberately does not have and (b) re-attribute a recorded fact. A
    DIFFERENT submitter arriving through a different channel, or asking for a
    different tier, gets its OWN row - which is why both channels and both
    requests stay visible after dedup.
    """
    already = (
        await session.execute(
            select(ScanSubmitterRow.scan_id).where(
                ScanSubmitterRow.scan_id == scan_id, ScanSubmitterRow.submitter == submitter
            )
        )
    ).scalar_one_or_none()
    if already is not None:
        return
    try:
        async with session.begin_nested():
            session.add(
                ScanSubmitterRow(
                    scan_id=scan_id,
                    submitter=submitter,
                    source=source.value,
                    requested_trust_tier=requested_trust_tier.value,
                )
            )
            await session.flush()
    except IntegrityError:
        # A concurrent submission of the same content by the same subject won
        # the race. The association exists either way, which is all that is
        # being asserted here.
        pass


async def submitter_attribution(
    session: AsyncSession, *, scan_ids: Sequence[str]
) -> dict[str, dict[str, Any]]:
    """Who submitted each of `scan_ids`, through which channel, asking for which
    tier - keyed by scan_id (里程碑 F Task 16).

    THE ONE IMPLEMENTATION of this response shape. `GET /v1/scans/{scan_id}`,
    `GET /v1/scans` and `GET /v1/reviews` all serve the same concept, and three
    hand-rolled `select()`s would drift: the detail endpoint carried full
    attribution while both LISTS still showed the scalar `ScanJob.submitter` -
    the FIRST submitter only - so a deduplicated scan displayed a stranger's
    name on the list page and the right names one click away. One concept with
    two shapes across two endpoints is a reliable source of consumer bugs, so
    the shape is produced here and nowhere else.

    ARCHITECTURE (scripts/check_import_boundaries.py): plain values cross the
    module boundary, never an ORM row and never this module's session - the
    same posture `is_scan_submitter` above documents. That is what lets
    `gate.reviews_router` serve this shape without reaching into orchestration's
    ORM.

    Per scan_id: `submitters` (every rightful reader, sorted), `submitter_sources`
    (per-name channel and requested tier), and `source` (the sorted set of
    channels the scan actually arrived through).

    `source` and `requested_trust_tier` are `null` when that row records nothing
    - written before those columns existed - and are passed through verbatim. A
    null channel contributes NOTHING to the aggregate `source` list rather than
    a guessed "console": the honest rendering of "we do not know" is absence.

    Always lists, even for a single submitter, and a scan with no association
    rows is simply ABSENT from the result rather than present with empty lists -
    callers decide what an unattributed scan should render as. A response whose
    shape changes with the data is what consumers silently mis-parse.

    BATCHED: one query for the whole page. The callers are list endpoints over
    up to 200 rows, and a query per row is how a list becomes N+1.
    """
    if not scan_ids:
        return {}
    rows = sorted(
        (
            await session.execute(
                select(
                    ScanSubmitterRow.scan_id,
                    ScanSubmitterRow.submitter,
                    ScanSubmitterRow.source,
                    ScanSubmitterRow.requested_trust_tier,
                ).where(ScanSubmitterRow.scan_id.in_(list(scan_ids)))
            )
        ).all(),
        key=lambda r: (r.scan_id, r.submitter),
    )
    attribution: dict[str, dict[str, Any]] = {}
    for row in rows:
        entry = attribution.setdefault(
            row.scan_id, {"submitters": [], "submitter_sources": [], "source": []}
        )
        entry["submitters"].append(row.submitter)
        entry["submitter_sources"].append(
            {
                "submitter": row.submitter,
                "source": row.source,
                "requested_trust_tier": row.requested_trust_tier,
            }
        )
    for entry in attribution.values():
        entry["source"] = sorted(
            {e["source"] for e in entry["submitter_sources"] if e["source"] is not None}
        )
    return attribution


async def is_scan_submitter(session: AsyncSession, *, scan_id: str, subject: str) -> bool:
    """Did `subject` submit `scan_id`? (object-level authorization, C2)

    ARCHITECTURE (scripts/check_import_boundaries.py): this exists so a
    consumer OUTSIDE orchestration - `marketplace_api.router` - can make its
    authorization decision without importing orchestration's ORM classes and
    issuing its own `select()`. Same posture as
    `gate.service.list_issued_verdicts`: plain values cross the module
    boundary, never an ORM row and never this module's session.

    SECURITY: this is deliberately SEPARATE from `get_scan_state_and_tier`
    below, rather than one accessor that filters internally and returns None
    for both "no such scan" and "not yours". Those two cases must stay
    distinguishable to a caller that legitimately needs to tell them apart -
    the console's reviewer roles may read any scan, so it needs "does this
    exist" independently of "is it yours". Callers that must NOT distinguish
    them (the marketplace, spec §6.2) collapse both to 404 themselves.

    Membership in `scan_submitter`, not equality against `ScanJob.submitter`:
    single-flight dedup means one scan can have several rightful submitters.
    """
    row = (
        await session.execute(
            select(ScanSubmitterRow.scan_id).where(
                ScanSubmitterRow.scan_id == scan_id, ScanSubmitterRow.submitter == subject
            )
        )
    ).scalar_one_or_none()
    return row is not None


async def get_scan_state_and_tier(
    session: AsyncSession, *, scan_id: str
) -> tuple[str, str | None] | None:
    """`(state, trust_tier)` for one scan, or None when no such scan exists.

    Same cross-module-boundary rationale as `is_scan_submitter` above.

    `trust_tier` is the tier this scan's verdict was actually adjudicated at
    (`ScanJob.trust_tier`, recorded at submit time). It is surfaced to the
    marketplace as `judged_at_tier` because of dedup: a caller whose submission
    collapsed onto an existing scan_job receives a verdict decided at the FIRST
    submitter's tier, and would otherwise reasonably assume it was judged at
    its own. None means the row records no tier (see `ScanJob.trust_tier`).
    """
    job = (
        await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
    ).scalar_one_or_none()
    if job is None:
        return None
    return job.state, job.trust_tier


async def get_scan_result_view(session: AsyncSession, *, scan_id: str) -> dict[str, Any] | None:
    """The projection-relevant `scan_result` columns as a plain dict, or None
    when this scan has no result row.

    None is meaningful, not merely "empty": a scan that was decided WITHOUT a
    result row is the fail-closed signature (`_dead_letter_and_decide` signs a
    BLOCK verdict but writes no findings blob), and
    `marketplace_api.views.project_scan` derives `fail_closed` from exactly
    this None. Returning `{}` here instead would silently turn every
    fail-closed BLOCK into an ordinary one.

    Same cross-module-boundary rationale as `is_scan_submitter` above. The key
    names are the ones `marketplace_api.views` reads; only the columns the
    external projection actually needs are included, so a new internal column
    does not become externally reachable by default.
    """
    row = (
        await session.execute(select(ScanResultRow).where(ScanResultRow.scan_id == scan_id))
    ).scalar_one_or_none()
    if row is None:
        return None
    return {
        "findings": row.findings,
        "findings_capped": row.findings_capped,
        "findings_total": row.findings_total,
    }


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
                # Milestone C Task 7: same bracket, same units and the same
                # helper as the sandbox runner's loop
                # (`engine_runner/worker.py`), so a floor engine's timing and a
                # sandbox engine's timing mean the same thing when the console
                # puts them in one table. Stays None on the branch below -
                # nothing ran, and "0ms" would read as a working engine.
                analyze_duration_ms: int | None = None
                if engine is not None:
                    started = airlock.monotonic_now()
                    result = engine.analyze(files, deadline=job.deadline_epoch)
                    analyze_duration_ms = airlock.elapsed_ms(started)
                else:
                    # Defensive only: dispatch list should always match the
                    # worker's registered engine set.
                    result = unavailable_engine_result(
                        engine_name, reason="engine not registered on this worker"
                    )
                key = findings_key(job.scan_id, engine_name)
                await asyncio.to_thread(
                    blobstore.put,
                    key,
                    json.dumps(
                        serialize_engine_result(result, analyze_duration_ms=analyze_duration_ms)
                    ).encode("utf-8"),
                )
                await airlock.produce_result(
                    redis,
                    scan_id=job.scan_id,
                    findings_key=key,
                    engine=engine_name,
                    status=result.status.value,
                    analyze_duration_ms=analyze_duration_ms,
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
        findings_total=0,
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
    default_trust_tier: TrustTier,
    allowlist: Sequence[AllowlistEntry],
    signer: SignerPort,
    consumer: str,
    count: int = 20,
    operator: str = "system:orchestrator",
    additional_engines: Sequence[str] = (),
    waited_advisory_engines: Sequence[str] = (),
    reclaim_idle_ms: int = airlock.STALE_CLAIM_IDLE_MS,
) -> int:
    """Claims pending result messages and, for every scan_id that now has all
    `policy.required_engines` reported (or was reported as a poison-pill),
    records a verdict. Returns how many scans were newly decided this tick.

    `default_trust_tier` (2026-07-28, milestone B' Task 4 - renamed from
    `trust_tier`): every scan is judged at ITS OWN `job.trust_tier`, recorded
    by `submit_scan` at submission time - never this parameter directly. This
    is only the fallback `_dead_letter_and_decide`/`_try_score_and_decide` use
    for a `job.trust_tier` that is NULL, i.e. a row that carries no recorded
    tier at all. Passing a single process-wide value here is correct ONLY as
    that fallback; it must never again become the tier a live submission is
    actually judged at.

    2026-07-28 (C3 correction): this docstring used to claim NULL was "only
    possible for a row written before the trust_tier column existed". That was
    FALSE and it mattered - `reeval.controller.build_rescan_job` did not map the
    column, so every reeval-triggered rescan inserted NULL and was silently
    re-decided at this permissive default. That path is fixed; both production
    writers (`submit_scan` and `build_rescan_job`) now always record a tier, so
    NULL means "written before the column existed, never backfilled" and
    nothing else. Do not restate that as an invariant of the schema - it is a
    property of the two writers, and it holds only as long as both keep it.

    `additional_engines` (e.g. the intel matcher, coding spec INTEL-01/02/03,
    corrected 2026-07-27 from the previously mislabelled NET-06/07/08): read
    into aggregation when they happen to have reported, never gated on
    - see `_try_score_and_decide`'s own docstring for the full reasoning.

    `waited_advisory_engines` (D2, 2026-07-27 - the sandbox engines) differ
    from `additional_engines` in exactly one way: they ARE waited for (a scan
    isn't decided here until they've reported too, same as `required_engines`),
    just never fail-closed BLOCK on absence the way `required_engines` does.
    A wait that times out is forced through by `sweep_sandbox_wait_timeouts`
    instead - this function alone never forces one.

    SECURITY: `scan_job.state` (checked+transitioned under `SELECT ... FOR
    UPDATE`) is the single-flight guard against two collector ticks (e.g. two
    orchestrator processes) double-deciding the same scan_id - see
    `_try_score_and_decide`/`_dead_letter_and_decide`. Known gap: a crash
    between the "scored" and "decided" transitions leaves the scan_job stuck at
    'scored' (the verdict itself, via gate's own transactional outbox, is never
    left partially written) - a reconciliation sweep to resume from 'scored'
    would close this, but is not required for M3's acceptance bar and is not
    implemented here.

    SECURITY (INV-5, 2026-07-29): a scan whose messages have been redelivered
    past `airlock.MAX_DELIVERY_COUNT` is dead-lettered to a forced BLOCK
    instead of being retried again - the results stream's counterpart to the
    scans stream's own cap. See `RESULT_POISON_PILL_REASON` for why the
    unacked-forever behaviour it replaces was reachable, and why the exit is a
    signed verdict rather than an ack-and-drop.
    """
    results = await airlock.claim_results(redis, consumer=consumer, count=count, block_ms=200)
    # SECURITY (2026-07-28, VM re-review N-2): also take over messages an
    # earlier collector claimed and never ACKed. Without this the results
    # stream has no recovery path at all - a crash between XREADGROUP and
    # ack_result strands that message forever, and with it the scan, because
    # nothing else ever re-triggers `_try_score_and_decide` for a scan whose
    # blobs are already written. See `airlock.reclaim_stale_results` for why
    # redelivery is idempotent here.
    results += await airlock.reclaim_stale_results(
        redis, consumer=consumer, min_idle_ms=reclaim_idle_ms
    )
    required = tuple(sorted(policy.required_engines))
    by_scan_id: dict[str, list[str]] = {}
    message_ids_by_scan_id: dict[str, list[str]] = {}
    for r in results:
        by_scan_id.setdefault(r.scan_id, []).append(r.status)
        message_ids_by_scan_id.setdefault(r.scan_id, []).append(r.message_id)

    decided = 0
    failed_scan_ids: set[str] = set()
    for scan_id, statuses in by_scan_id.items():
        try:
            # SECURITY (INV-5): how many times the results stream has already
            # handed us this scan's messages. The MAX across them, not a sum:
            # a scan's engines each produce their own message and they are
            # redelivered independently, so summing would trip the cap on a
            # busy healthy scan while the max only rises when the SAME message
            # keeps coming back - which is exactly the poison-pill signature.
            # See `RESULT_POISON_PILL_REASON` for why this exists at all.
            deliveries = [
                await airlock.result_delivery_count(redis, message_id)
                for message_id in message_ids_by_scan_id[scan_id]
            ]
            exhausted = max(deliveries, default=0) > airlock.MAX_DELIVERY_COUNT

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
                    default_trust_tier=default_trust_tier,
                    signer=signer,
                    operator=operator,
                    reason=reason,
                )
            elif exhausted:
                # SECURITY (INV-5): every prior attempt to score this scan has
                # failed, so the next one will fail the same way. Take the
                # fail-closed exit rather than retrying forever - see
                # `RESULT_POISON_PILL_REASON`. Checked AFTER `terminal` on
                # purpose: both land in `_dead_letter_and_decide`, and a
                # terminal marker names the more specific cause.
                _logger.error(
                    "results-stream message exceeded MAX_DELIVERY_COUNT - "
                    "dead-lettering this scan to a forced BLOCK",
                    extra={
                        "context": {
                            "scan_id": scan_id,
                            "deliveries": max(deliveries, default=0),
                            "max_delivery_count": airlock.MAX_DELIVERY_COUNT,
                        }
                    },
                )
                did_decide = await _dead_letter_and_decide(
                    orchestration_session_factory,
                    gate_session_factory,
                    scan_id=scan_id,
                    policy=policy,
                    default_trust_tier=default_trust_tier,
                    signer=signer,
                    operator=operator,
                    reason=RESULT_POISON_PILL_REASON,
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
                    default_trust_tier=default_trust_tier,
                    allowlist=allowlist,
                    signer=signer,
                    operator=operator,
                    additional_engines=additional_engines,
                    waited_advisory_engines=waited_advisory_engines,
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


async def sweep_sandbox_wait_timeouts(
    blobstore: BlobStorePort,
    orchestration_session_factory: SessionFactory,
    gate_session_factory: SessionFactory,
    *,
    policy: GatePolicy,
    default_trust_tier: TrustTier,
    allowlist: Sequence[AllowlistEntry],
    signer: SignerPort,
    waited_advisory_engines: Sequence[str],
    wait_timeout_s: float,
    operator: str = "system:orchestrator",
    additional_engines: Sequence[str] = (),
) -> int:
    """Decide scans that have waited past `wait_timeout_s` for a sandbox engine.

    `default_trust_tier` (2026-07-28, milestone B' Task 4): same fallback-only
    role as `run_result_collector_tick`'s parameter of the same name - each
    scan is judged at its own `job.trust_tier`; this is only what
    `_try_score_and_decide` falls back to for a `job.trust_tier` that is NULL,
    i.e. a row with no recorded tier.

    WHY THIS EXISTS: `run_result_collector_tick` is message-driven - it only
    tries to decide a scan when a result message arrives. The moment a wait
    times out is precisely the moment no further message will arrive, so
    without this sweep a timed-out scan sits in queued/running forever. Same
    shape as `sweep_queued_jobs_to_airlock`: read the DB for stuck rows, push
    them forward.

    The cutoff adds `_SWEEP_GRACE_S` on top of `wait_timeout_s` because the
    sandbox subprocesses are themselves bounded by `deadline_epoch`
    (created_at + scan_deadline_s, 300s by default - the SAME value as the
    wait timeout). Sweeping exactly at the timeout would race the engine's own
    TIMEOUT blob write and discard the more informative outcome: an engine
    that reports "I timed out" tells an operator more than our guess that it
    never arrived.

    SECURITY (Critical, 2026-07-27 final review F-2): the cutoff is measured
    against `sandbox_wait_started_at`, NOT `created_at`. `created_at` answers
    "how old is this submission"; this sweep needs "how long have we been
    waiting for the sandbox", and the two differ by the entire queue backlog.
    With `created_at`, the failure fits inside a single `worker_tick`: after a
    worker outage longer than the wait budget (a rolling restart, a deploy,
    SKILLSCAN_WORKER_ENABLED=false) `sweep_queued_jobs_to_airlock` re-produces
    the backlog, the floor engines run and write all 9 required blobs, the
    collector declines to decide because the sandbox blobs have not landed yet
    - and then THIS sweep selected those same scans, because their `created_at`
    was already ~10 minutes old, and force-decided them from floor findings
    alone. A package whose only HIGH finding comes from bandit got PASS instead
    of REVIEW. The `sandbox_wait_timeout:` reason made it auditable, but D2's
    entire purpose was defeated for exactly the backlog case it exists for.

    NULL `sandbox_wait_started_at` means "has never started waiting" and is
    never swept. That also keeps scans whose required engines were never
    dispatched at all out of this sweep entirely, rather than relying on
    `_try_score_and_decide`'s required-engines check to reject them afterwards.
    """
    cutoff = _naive_utcnow() - datetime.timedelta(seconds=wait_timeout_s + _SWEEP_GRACE_S)
    async with orchestration_session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(ScanJob.scan_id)
                    .where(ScanJob.state.in_(_UNSCORED_STATES))
                    .where(ScanJob.sandbox_wait_started_at.is_not(None))
                    .where(ScanJob.sandbox_wait_started_at < cutoff)
                    # SECURITY/Minor (2026-07-27 review): oldest-first, not
                    # unordered - an unordered LIMIT window means a cluster of
                    # rows that keeps raising (caught below, per-scan isolated)
                    # could occupy the whole batch every tick and starve
                    # everything behind it. Same ordering `sweep_queued_jobs_
                    # to_airlock` gets implicitly (it has no LIMIT at all).
                    # Ordered by the same column the cutoff filters on, so
                    # "oldest" means "waiting longest", not "submitted first".
                    .order_by(ScanJob.sandbox_wait_started_at)
                    .limit(_SWEEP_BATCH)
                )
            )
            .scalars()
            .all()
        )

    decided = 0
    for scan_id in rows:
        try:
            if await _try_score_and_decide(
                blobstore,
                orchestration_session_factory,
                gate_session_factory,
                scan_id=str(scan_id),
                required_engines=tuple(sorted(policy.required_engines)),
                policy=policy,
                default_trust_tier=default_trust_tier,
                allowlist=allowlist,
                signer=signer,
                operator=operator,
                additional_engines=additional_engines,
                waited_advisory_engines=waited_advisory_engines,
                force_decide=True,
            ):
                decided += 1
        except Exception:
            # Same per-scan isolation as run_result_collector_tick: one stuck
            # scan must not stop the rest of the batch.
            _logger.exception(
                "sandbox-wait sweep failed for a scan", extra={"context": {"scan_id": str(scan_id)}}
            )
    return decided


async def _mark_running_if_queued(
    orchestration_session_factory: SessionFactory, scan_id: str
) -> None:
    async with orchestration_session_factory() as session, session.begin():
        await session.execute(
            update(ScanJob)
            .where(ScanJob.scan_id == scan_id, ScanJob.state == STATE_QUEUED)
            .values(state=STATE_RUNNING)
        )


async def _dead_letter_and_decide(
    orchestration_session_factory: SessionFactory,
    gate_session_factory: SessionFactory,
    *,
    scan_id: str,
    policy: GatePolicy,
    default_trust_tier: TrustTier,
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
        if job is None or job.state not in _UNSCORED_STATES:
            return False
        content_hash = str(job.content_hash)
        # SECURITY (2026-07-28, milestone B' Task 4): judge this scan at its
        # OWN submission-time tier, not the process-wide default - see
        # `run_result_collector_tick`'s `default_trust_tier` docstring.
        # A NULL `job.trust_tier` means this row records no tier and falls back
        # to `default_trust_tier` (C3 correction: that is NOT the same claim as
        # "only pre-column rows can be NULL" - reeval used to produce NULL rows
        # continuously; see the docstring above).
        job_trust_tier = job.trust_tier

    effective_trust_tier = (
        TrustTier(job_trust_tier) if job_trust_tier is not None else default_trust_tier
    )
    async with gate_session_factory() as gate_session, gate_session.begin():
        await decide_and_record(
            gate_session,
            scan_id=scan_id,
            scan_result=forced_block_scan_result(content_hash, reason=reason),
            policy=policy,
            trust_tier=effective_trust_tier,
            allowlist=(),
            signer=signer,
            operator=operator,
            now=airlock.now_epoch(),
        )

    async with orchestration_session_factory() as session, session.begin():
        await session.execute(
            update(ScanJob)
            .where(ScanJob.scan_id == scan_id, ScanJob.state.in_(_UNSCORED_STATES))
            .values(state=STATE_FAILED)
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
    default_trust_tier: TrustTier,
    allowlist: Sequence[AllowlistEntry],
    signer: SignerPort,
    operator: str,
    additional_engines: Sequence[str] = (),
    waited_advisory_engines: Sequence[str] = (),
    force_decide: bool = False,
) -> bool:
    """`waited_advisory_engines` (the sandbox engines) ARE waited for, but are
    NOT in `required_engines`: a missing one degrades to an advisory absence
    (load_and_aggregate's existing BlobNotFoundError -> EngineStatus.ERROR
    path) rather than a fail-closed BLOCK, so one crashed engine cannot block
    every scan. `force_decide` is what the wait-timeout sweep passes to stop
    waiting - see `sweep_sandbox_wait_timeouts`.

    `default_trust_tier` (2026-07-28, milestone B' Task 4 - renamed from
    `trust_tier`): this scan is judged at its OWN `job.trust_tier`, read below
    under the same `SELECT ... FOR UPDATE` that already loads `job` - this
    parameter is only the fallback for a `job.trust_tier` that is NULL, i.e. a
    row that records no tier at all (see `run_result_collector_tick`'s own
    docstring for why "NULL == pre-column row" is a claim about the writers,
    not about the schema, and was false for reeval's rescans until C3).

    `force_decide` ONLY ever bypasses the `waited_advisory_engines` wait - it
    NEVER bypasses the `required_engines` presence check. `required_engines`
    is checked unconditionally, before `force_decide` is even consulted: the
    sweep that passes `force_decide=True` cannot distinguish "waited 330s for
    a sandbox engine" from "sat in queued/running 330s because a required
    floor engine was never dispatched at all" (worker outage, Redis
    interruption, a reeval batch bigger than one dispatch tick's claim count)
    - skipping the required-engines check under `force_decide` would let the
    sweep force a signed, unrevisable fail-closed BLOCK on scans that were
    never actually stuck on a sandbox engine.

    `additional_engines` (e.g. the intel matcher) remain read-when-present and
    never waited for."""
    scan_result: ScanResult | None = None
    extra_reasons: tuple[str, ...] = ()
    async with orchestration_session_factory() as session, session.begin():
        job = (
            await session.execute(
                select(ScanJob).where(ScanJob.scan_id == scan_id).with_for_update()
            )
        ).scalar_one_or_none()
        if job is None or job.state not in _UNSCORED_STATES:
            return False  # unknown, or already scored/decided/failed elsewhere

        # SECURITY (2026-07-28, milestone B' Task 4): captured now, while `job`
        # is still in scope under the row lock, for use after this session
        # block closes below - see `default_trust_tier`'s docstring above for
        # what a NULL here means and what it deliberately no longer claims.
        job_trust_tier = job.trust_tier

        # SECURITY (Critical, 2026-07-27 review): this check is UNCONDITIONAL -
        # never skipped by `force_decide`. If it were skipped, a forced decide
        # would take a scan whose FLOOR engines never ran straight to
        # `load_and_aggregate` with zero required blobs -> `required_ok=False`
        # -> `policy.fail_closed_verdict` (BLOCK), signed and unrevisable, on a
        # scan that was never actually stuck waiting on anything
        # sandbox-related (worker outage, Redis interruption, or a
        # `reeval.controller.trigger_rescans` batch bigger than one dispatch
        # tick's claim count).
        #
        # 2026-07-28: the ORIGINAL wording of this comment justified the check
        # by saying the sweep "selects rows purely by `state in
        # ('queued','running') AND created_at < cutoff`" and therefore could
        # not tell the two cases apart. That is no longer true - F-2 moved the
        # sweep onto `sandbox_wait_started_at`, which is NULL for exactly those
        # never-dispatched scans, so they are not selected in the first place.
        # The check stays regardless: it is the last line of defence, and it
        # must not depend on the sweep being the only caller that can pass
        # `force_decide`.
        # `force_decide` only ever bypasses the sandbox-advisory wait below.
        all_reported = all(
            [
                await asyncio.to_thread(blobstore.exists, findings_key(scan_id, e))
                for e in required_engines
            ]
        )
        if not all_reported:
            return False  # not all required engines have reported yet

        missing_advisory: tuple[str, ...] = ()
        if not force_decide:
            waited_missing = [
                e
                for e in waited_advisory_engines
                if not await asyncio.to_thread(blobstore.exists, findings_key(scan_id, e))
            ]
            if waited_missing:
                # SECURITY (2026-07-27 final review, F-2): THIS is the moment
                # the wait actually begins - every required engine has
                # reported and only a sandbox engine is outstanding. Recording
                # it here is what lets `sweep_sandbox_wait_timeouts` measure
                # the wait instead of the submission's age; see that
                # function's docstring for the PASS-instead-of-REVIEW failure
                # the old `created_at` clock produced after a worker outage.
                #
                # Set once and never refreshed: a later tick that finds the
                # same engine still missing must not push the deadline out
                # forever. The row is already held under `SELECT ... FOR
                # UPDATE` above, so the read-modify-write is safe against a
                # second collector.
                if job.sandbox_wait_started_at is None:
                    job.sandbox_wait_started_at = _naive_utcnow()
                return False  # sandbox engines still running; the sweep will force us on
        else:
            # NOTE: list comprehension, not a bare generator expression - a
            # generator expression containing `await` inside an `async def`
            # becomes an async generator per PEP 530, which `tuple()` cannot
            # consume synchronously (mypy catches this as an arg-type error;
            # at runtime it would raise, never actually calling `exists` at
            # all). Same pattern `waited_missing`/`all_reported` above already
            # use correctly.
            missing_advisory = tuple(
                [
                    e
                    for e in waited_advisory_engines
                    if not await asyncio.to_thread(blobstore.exists, findings_key(scan_id, e))
                ]
            )

        if missing_advisory:
            # Visible in GET /v1/scans/{id}.reasons: this verdict was made
            # with fewer engines than usual. A silent downgrade would be
            # worse than the latency this wait costs.
            extra_reasons = (f"sandbox_wait_timeout:{','.join(sorted(missing_advisory))}",)

        # NOTE: deduplicated (dict.fromkeys, order-preserving) rather than the
        # naive concat-then-filter-against-required_engines-only one might
        # first reach for - `waited_advisory_engines` and `additional_engines`
        # legitimately overlap in production (worker.py passes
        # SANDBOX_WAITED_ENGINE_NAMES as the former and a superset including
        # it as the latter, so aig-mcp-scan - waited-excluded but still
        # aggregation-eligible - is reachable through additional_engines).
        # Without dedup, an overlapping name's blob would be loaded twice by
        # `load_and_aggregate`, doubling its findings into `core_aggregate`
        # and manufacturing a fake dedup collision on its own rule_id(s) - the
        # same bug class as the fixed 2026-07-06 "dedup collision silently
        # dropped trifecta signal" incident, just self-inflicted this time.
        engine_names = tuple(
            dict.fromkeys(
                tuple(required_engines) + tuple(waited_advisory_engines) + tuple(additional_engines)
            )
        )
        aggregated = load_and_aggregate(
            blobstore,
            scan_id=scan_id,
            content_hash=str(job.content_hash),
            engine_names=engine_names,
            policy=policy,
        )
        scan_result = aggregated.scan_result
        # Milestone C Task 8: the per-engine telemetry that reached this
        # process and was discarded here until now - status, error text and
        # (Task 7) the analyze() duration. Written in the SAME transaction as
        # the ScanResultRow above, so "this scan was scored" and "here is what
        # each engine did on it" can never disagree, and a health row can never
        # outlive a rolled-back decide.
        #
        # One timestamp for the whole set, taken once: these observations were
        # all made in the same read-back pass, and a per-row `now()` would
        # imply an ordering between engines that this loop does not have.
        recorded_at = _naive_utcnow()
        session.add_all(
            [
                ScanEngineHealthRow(
                    scan_id=scan_id,
                    engine_name=health.engine_name,
                    report_state=health.report_state.value,
                    engine_status=(
                        None if health.engine_status is None else health.engine_status.value
                    ),
                    analyze_duration_ms=health.analyze_duration_ms,
                    finding_count=health.finding_count,
                    error=health.error,
                    recorded_at=recorded_at,
                )
                for health in aggregated.engine_health
            ]
        )
        session.add(
            ScanResultRow(
                scan_id=scan_id,
                content_hash=scan_result.content_hash,
                severity=int(scan_result.severity),
                confidence_at_max=scan_result.confidence_at_max,
                trifecta_present=scan_result.trifecta_present,
                findings_capped=scan_result.findings_capped,
                findings_total=scan_result.findings_total,
                required_ok=scan_result.required_ok,
                findings=[serialize_finding(f) for f in scan_result.findings],
                provenance=[list(p) for p in scan_result.engine_provenance],
                hard_gate_hits=list(scan_result.hard_gate_hits),
            )
        )
        job.state = STATE_SCORED
        await session.flush()

    effective_trust_tier = (
        TrustTier(job_trust_tier) if job_trust_tier is not None else default_trust_tier
    )
    async with gate_session_factory() as gate_session, gate_session.begin():
        await decide_and_record(
            gate_session,
            scan_id=scan_id,
            scan_result=scan_result,
            policy=policy,
            trust_tier=effective_trust_tier,
            allowlist=allowlist,
            signer=signer,
            operator=operator,
            now=airlock.now_epoch(),
            extra_reasons=extra_reasons,
        )

    async with orchestration_session_factory() as session, session.begin():
        await session.execute(
            update(ScanJob)
            .where(ScanJob.scan_id == scan_id, ScanJob.state == STATE_SCORED)
            .values(state=STATE_DECIDED)
        )
    return True
