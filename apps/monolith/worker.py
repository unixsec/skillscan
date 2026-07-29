"""Background processing loop - the live process the M3-M8 milestones built
components for but nothing ever invoked (docs/MAINTENANCE_GUIDE.md §3 gap 1).

One `worker_tick()` drives, in order:

1. policy hot-reload   - latest APPROVED policy_proposal becomes the active
                         GatePolicy (admin "approve" finally has a real effect,
                         and it survives restarts + propagates across replicas)
2. queued-job sweep    - scan_job rows stuck in 'queued' with no live airlock
                         message (reeval-triggered rescans are DB-INSERT-only;
                         crash-lost messages too) get (re)produced to Redis
3. engine execution    - orchestration.service.run_mock_engine_worker_tick
                         (in-process floor engines - the M3 skeleton's honest
                         stand-in for the real sandboxed M4/M5 adapters -
                         plus a freshly-snapshotted IntelMatcher, IOC
                         matching against `threat_indicator`, added here
                         rather than to `floor_engines()` itself since it
                         needs a DB read to construct and floor engines must
                         stay zero-arg-constructible; not `required_engines`,
                         same advisory-not-fail-closed reasoning as the
                         sandboxed OSS engines - a transient intel-DB hiccup
                         degrades to floor-only rather than blocking every
                         scan)
4. score + decide      - orchestration.service.run_result_collector_tick with
                         a LIVE allowlist read (closes the startup-snapshot
                         gap: MAINTENANCE_GUIDE §3 gap 2); the gate now WAITS
                         for the sandbox engines too (D2, 2026-07-27) before
                         deciding, so orchestration.service.
                         sweep_sandbox_wait_timeouts runs right after it to
                         force through anything that waited past
                         ScanRuntime.sandbox_wait_timeout_s - see
                         SANDBOX_WAITED_ENGINE_NAMES below for what's waited
                         on, and _active_sandbox_waited_engines for what a
                         given deployment drops from that set
5. lifecycle sync      - verdicts drive the §16.2 skill state machine
                         (scanning→published on PASS, scanning→review_pending
                         on REVIEW; review-approved skills →published). A
                         publish here carries a fresh signed verdict for that
                         exact content_hash, so it ADVANCES the SUPPLY-06
                         drift baseline onto that content (inventory.service.
                         advance_baseline_on_publish, same transaction) -
                         shipping a v2 through the pipeline is the intended
                         path, not drift. The publish is then still checked
                         against orchestration.drift.check_drift(), which now
                         only fires for a baseline an admin pinned out of band
                         to content this skill never published; that goes to
                         quarantined (coding spec SUPPLY-06: "content_hash 对
                         比 baseline, 不一致 → 隔离", FR-REV-020)
6. toolchain advance   - a version that has now actually been re-scanned under
                         the current toolchain stops reading as stale
                         (advance_scanned_toolchain_digests). Nothing else in
                         the tree writes skill_version.toolchain_digest after
                         submission, so without this step `reeval` re-queues a
                         rescan of the same content forever; and this is the
                         only place all three modules involved can be read with
                         their own least-privilege credentials
7. audit chain drain   - audit.service.drain_pending_intents
8. outbox drain        - integration_relay.service.drain_pending_outbox
                         (marketplace writeback + SIEM, both optional)
9. report schedules    - fire due cron schedules (POST /v1/reports/schedule
                         finally executes; delivery = SIEM event when
                         configured, always audited via the generation itself)
10. health retention   - orchestration.retention.sweep_engine_health_retention,
                         behind an hourly Redis lease. THE ONLY RETENTION PATH
                         IN THIS SYSTEM (design §3.1: findings blobs have no
                         TTL and nothing prunes them). Last on purpose: it is
                         the least important responsibility here and must never
                         delay a decide - see `_HEALTH_RETENTION_LEASE_KEY`

SECURITY: this module composes other modules the same way routers do - each
step uses that module's OWN least-privilege session factory (svc_orchestration
never touches gate tables, svc_inventory never reads verdict directly - the
verdict read in step 5 goes through gate's own session). Default OFF
(SKILLSCAN_WORKER_ENABLED=false): the test suite drives these ticks explicitly
and must not race a background consumer; scripts/dev/run_local.py and the
docker-compose deployment turn it on.
"""

from __future__ import annotations

import asyncio
import datetime
from collections.abc import Sequence
from typing import Any, cast

import redis.asyncio as aioredis
import yaml
from common import airlock
from common.blobstore import artifact_key
from common.log import get_logger
from engine_runner.sandbox_engines import SANDBOX_ENGINE_NAMES, llm_gated_engine_names
from skillscan_core import GatePolicy
from sqlalchemy import CursorResult, or_, select, update
from sqlalchemy.exc import SQLAlchemyError

from monolith.modules.admin.engine_registry import list_disabled_engines
from monolith.modules.audit.service import count_unchained_intents, drain_pending_intents
from monolith.modules.gate.models import PolicyProposalRow, VerdictRow
from monolith.modules.gate.policy import GatePolicyLoadError, parse_gate_policy
from monolith.modules.gate.service import list_active_allowlist_entries
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.integration_relay.service import drain_pending_outbox
from monolith.modules.intel.matcher import IntelMatcher, load_known_iocs
from monolith.modules.inventory.lifecycle import InvalidTransitionError
from monolith.modules.inventory.models import SkillLifecycleEventRow, SkillVersionRow
from monolith.modules.inventory.service import advance_baseline_on_publish, transition_skill
from monolith.modules.orchestration.drift import check_drift
from monolith.modules.orchestration.floor import floor_engines
from monolith.modules.orchestration.models import ScanJob
from monolith.modules.orchestration.retention import sweep_engine_health_retention
from monolith.modules.orchestration.service import (
    POISON_PILL_STATUS,
    STATE_DECIDED,
    STATE_QUEUED,
    run_mock_engine_worker_tick,
    run_result_collector_tick,
    sweep_sandbox_wait_timeouts,
)
from monolith.modules.reporting import service as reporting_service
from monolith.modules.reporting.models import ReportScheduleRow

_logger = get_logger("skillscan.monolith.worker")

_WORKER_OPERATOR = "system:worker"
# Names of the engines run by the separate engine-runner service (never by this
# process - INV-15 subprocess/license isolation). This process has no adapter
# instance for any of these to dispatch; they're aggregation-only, so their
# finding blob (when the engine-runner already wrote it) counts toward
# severity/trifecta the same advisory, never-gates-the-wait way the intel
# matcher does. Sourced from `engine_runner.sandbox_engines.SANDBOX_ENGINE_NAMES`
# - the single source of truth for "every engine name that service can ever
# produce a finding blob for" - rather than a second, independently-maintained
# copy of the list: a previous hardcoded copy here drifted out of sync and
# silently dropped aig-mcp-scan (computed and blob-written by engine-runner,
# never aggregated into any verdict here) until this alias replaced it.
SANDBOX_ADVISORY_ENGINE_NAMES: tuple[str, ...] = SANDBOX_ENGINE_NAMES
# The sandbox engines the gate WAITS for (D2, 2026-07-27). Now the WHOLE tier:
# aig-mcp-scan used to be subtracted here by name, for two reasons, both of
# which milestone C Task 4 (2026-07-29) closed.
#
# The first was its timeout. Every static adapter shared one 60s constant and
# aig alone escaped it via a single-engine environment variable, so its 240s
# could only be traded against the whole tier's budget by moving the global
# value - this comment used to say the fix "needs per-engine timeouts, not a
# bigger global one". `engine_runner.timeouts` is that, and the engine-runner
# now warns at startup when the configured per-engine timeouts cannot all fit
# inside one job's `scan_deadline_s`. Waiting is safe regardless of how those
# are tuned: `adapters/base.py` clamps every engine's timeout down to the
# budget remaining on the job's shared `deadline_epoch`, so each engine reports
# SOMETHING - OK, ERROR or TIMEOUT - before the deadline the wait is measured
# against, and `sweep_sandbox_wait_timeouts`' own grace exists to let that last
# report win the race.
#
# The second was deployment shape, and it is NOT solved by a name-keyed
# exclusion in a constant: an engine the local engine-runner never constructs
# can never report, so waiting for it burns the entire budget on every scan.
# That is a property of the deployment, not of the tier, so it belongs with the
# admin-disable filter in `worker_tick` rather than here - see
# `_active_sandbox_waited_engines`.
SANDBOX_WAITED_ENGINE_NAMES: tuple[str, ...] = SANDBOX_ADVISORY_ENGINE_NAMES
# Engine marker for the sweep's "artifact vanished from the blob store"
# dead-letter (audit-distinguishable from a real worker's poison-pill; the
# collector keys off status, the engine field is informational).
UNRUNNABLE_ENGINE_MARKER = "__artifact_missing__"
# Redis key prefix for per-schedule-per-minute dedup (multi-replica safe:
# SET NX means exactly one worker fires a given schedule for a given minute).
_SCHEDULE_FIRED_PREFIX = "skillscan:reporting:schedule_fired:"
# A queued scan_job younger than this is assumed to still have its original
# airlock message in flight; older ones get (re)produced. Duplicate messages
# are harmless: the collector's state check under FOR UPDATE makes the second
# decide a no-op, and engine re-runs just overwrite the same findings blobs.
REQUEUE_QUEUED_AFTER_S = 60.0
# Milestone C Task 9. The retention sweep must be DRIVEN, and the only live
# driver this process has is `worker_tick` - observed on the VM at a 1.0 s
# interval (Task 1, 1bfd580). A sweep on every tick would issue a DELETE per
# second against the table the scoring transaction is inserting into, so the
# tick calls it behind a lease instead: SET NX EX means the first replica to
# arrive in a given hour runs it and every other tick, on every replica, is a
# single Redis round trip that returns immediately. Same mechanism
# `run_due_report_schedules` uses for its per-minute cross-replica dedup.
#
# ONE HOUR, chosen against the per-pass budget rather than against timeliness -
# nothing observes a health row's deletion, so being an hour late costs
# nothing. One pass removes up to 20,000 rows (1,333 scans, 2.8x the busiest
# day this deployment has ever had), so 24 passes/day drain 67x the peak
# observed production rate and a sweep outage of a full day is caught up by the
# first pass after it. A longer interval would also mean a longer wait before
# an operator could notice the counter is stuck at zero.
_HEALTH_RETENTION_LEASE_KEY = "skillscan:orchestration:health_retention_lease"
_HEALTH_RETENTION_INTERVAL_S = 3600


def _active_sandbox_waited_engines(
    *, disabled_engines: frozenset[str], sandbox_llm_configured: bool
) -> tuple[str, ...]:
    """`SANDBOX_WAITED_ENGINE_NAMES` minus the engines that cannot report on
    THIS deployment right now. Waiting on one of those is not a slow decision,
    it is the full `sandbox_wait_timeout_s` budget spent on every scan for
    evidence that was never going to arrive.

    Two ways an engine cannot report, and both are runtime facts rather than
    tier membership, which is why they are filtered here instead of being
    subtracted from the constant:

    - ADMIN-DISABLED (Important 2, 2026-07-27 review). `engine_runner.worker`
      skips a disabled engine with a bare `continue` - no blob, no result
      message, ever. Read live each tick from the same Redis key the admin API
      writes and the dashboard reads, so a re-enable takes effect on the next
      tick exactly as the disable did.
    - NOT CONSTRUCTED BY THIS DEPLOYMENT'S ENGINE-RUNNER. `sandbox_engines()`
      omits its LLM-gated engines entirely when no internal endpoint is
      configured (aig-mcp-scan has no static-only mode - see that function's
      docstring), and `SKILLSCAN_VLLM_BASE_URL` is one ConfigMap key both
      deployables consume, so `runtime.sandbox_llm_configured` answers for the
      engine-runner too. The NAMES come from `llm_gated_engine_names()`, which
      derives them from that same config gate rather than restating "aig" here
      - this filter must not become the name-keyed special case it replaced.

    Fail-safe direction: `sandbox_llm_configured` defaults to False, so a caller
    that never wires it waits for less and decides sooner. The cost of guessing
    wrong that way is a verdict that may miss an advisory engine's findings
    (recorded in `reasons`); guessing wrong the other way stalls every scan for
    the whole budget."""
    llm_gated = llm_gated_engine_names()
    return tuple(
        name
        for name in SANDBOX_WAITED_ENGINE_NAMES
        if name not in disabled_engines and (sandbox_llm_configured or name not in llm_gated)
    )


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


def _parse_policy_candidate(runtime: ScanRuntime, row: PolicyProposalRow) -> GatePolicy | None:
    """Parses a proposal's YAML into a GatePolicy, with two fail-closed guards:
    unparseable YAML is refused, and a policy whose required_engines name an
    engine this deployment doesn't have is refused (scans would wait forever
    for findings that can never arrive). Refusals keep the current policy and
    log loudly - never a silent no-op."""
    try:
        raw = yaml.safe_load(str(row.proposed_policy_yaml))
        if not isinstance(raw, dict):
            raise GatePolicyLoadError("policy YAML is not a mapping")
        candidate = parse_gate_policy(raw)
    except (yaml.YAMLError, GatePolicyLoadError, ValueError) as exc:
        _logger.error(
            "policy proposal failed to parse - keeping current policy",
            extra={"context": {"proposal_id": row.id, "error": str(exc)}},
        )
        return None
    if not candidate.required_engines:
        # SECURITY (INV-1 floor backstop): a policy with NO required engines
        # can never produce a decideable scan - the worker runs zero engines,
        # zero result messages are emitted, and every scan under it sits
        # unqueued/undecided forever (observed live with a test-residue
        # `required_engines: []` proposal that had been applied). The floor
        # engine set is mandatory; refuse the policy and keep the current one.
        _logger.error(
            "refusing to apply policy: required_engines is empty (violates INV-1 floor backstop)",
            extra={"context": {"proposal_id": row.id, "policy_version": candidate.version}},
        )
        return None
    available = {m.name for m in runtime.engine_metadatas}
    missing = set(candidate.required_engines) - available
    if missing:
        _logger.error(
            "refusing to apply policy: required_engines not available in this deployment",
            extra={
                "context": {
                    "proposal_id": row.id,
                    "policy_version": candidate.version,
                    "missing_engines": sorted(missing),
                }
            },
        )
        return None
    return candidate


async def promote_approved_policy(runtime: ScanRuntime, *, proposal_id: int) -> bool:
    """Called by the admin approve endpoint: applies THIS approved proposal to
    the running gate and marks it `applied` so restarts and other replicas
    (via `reload_policy_if_changed` below) converge on it.

    SECURITY: activation is a deliberate, per-proposal act - only proposals a
    live approve action promoted to `applied` ever become policy. Historic
    rows that sit at `approved` (including everything approved before this
    apply path existed, e.g. accumulated test data) stay inert forever; a
    fail-closed parse/guard refusal also leaves the row at `approved`, never
    half-applied."""
    async with runtime.gate_session_factory() as session, session.begin():
        row = await session.get(PolicyProposalRow, proposal_id)
        if row is None or str(row.status) != "approved":
            return False
        candidate = _parse_policy_candidate(runtime, row)
        if candidate is None:
            return False
        row.status = "applied"
        await session.flush()
    runtime.policy = candidate
    _logger.info(
        "gate policy applied via approval",
        extra={"context": {"proposal_id": proposal_id, "new_version": candidate.version}},
    )
    return True


async def reload_policy_if_changed(runtime: ScanRuntime) -> bool:
    """Re-applies the newest APPLIED policy proposal (worker tick + startup):
    what makes an approve-time apply durable across restarts and convergent
    across replicas. Version-string comparison keeps it idempotent."""
    async with runtime.gate_session_factory() as session:
        row = (
            await session.execute(
                select(PolicyProposalRow)
                .where(PolicyProposalRow.status == "applied")
                .order_by(PolicyProposalRow.id.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
    if row is None:
        return False
    candidate = _parse_policy_candidate(runtime, row)
    if candidate is None or candidate.version == runtime.policy.version:
        return False
    old_version = runtime.policy.version
    runtime.policy = candidate
    _logger.info(
        "reloaded applied gate policy",
        extra={
            "context": {
                "proposal_id": row.id,
                "old_version": old_version,
                "new_version": candidate.version,
            }
        },
    )
    return True


async def _floor_engines_with_intel(runtime: ScanRuntime) -> dict[str, Any]:
    """`floor_engines()` plus a freshly-snapshotted `IntelMatcher` (coding
    spec INTEL-01/02/03, corrected 2026-07-27 from the previously mislabelled
    NET-06/07/08) - not itself a floor engine (see module docstring's
    step-3 note: it needs a DB read to construct, floor engines don't), and
    deliberately not `required_engines` (an intel-DB hiccup degrades to
    floor-only findings rather than fail-closed BLOCKing every scan, same
    reasoning as the sandboxed OSS engine tier)."""
    engines = dict(floor_engines())
    if runtime.intel_session_factory is None:
        return engines
    try:
        async with runtime.intel_session_factory() as session:
            known_iocs = await load_known_iocs(session)
    except Exception:
        _logger.exception("intel matcher snapshot load failed - continuing with floor engines only")
        return engines
    matcher = IntelMatcher(known_iocs=known_iocs)
    engines[matcher.metadata.name] = matcher
    return engines


async def sweep_queued_jobs_to_airlock(
    runtime: ScanRuntime, *, requeue_after_s: float = REQUEUE_QUEUED_AFTER_S
) -> int:
    """(Re)produces an airlock message for scan_job rows stuck in 'queued'.

    Covers two real cases: reeval-triggered rescans (reeval.controller.
    trigger_rescans INSERTs scan_job only - it has no Redis access by design)
    and messages lost to a crash between the DB insert and the XADD."""
    cutoff = _naive_utcnow() - datetime.timedelta(seconds=requeue_after_s)
    async with runtime.orchestration_session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(ScanJob).where(
                        ScanJob.state == STATE_QUEUED, ScanJob.created_at < cutoff
                    )
                )
            )
            .scalars()
            .all()
        )
    swept = 0
    for job in rows:
        a_key = artifact_key(str(job.content_hash))
        if not runtime.blobstore.exists(a_key):
            # SECURITY (INV-5 fail-closed): a queued job whose artifact is
            # gone can NEVER run - report it onto the results stream as
            # operationally unrunnable so the collector dead-letters it
            # through the normal path (signed BLOCK verdict + state=failed,
            # fully audited), instead of leaving it stuck at 'queued' forever
            # and re-warning every tick.
            _logger.warning(
                "queued scan_job has no artifact in the blob store - dead-lettering",
                extra={"context": {"scan_id": str(job.scan_id), "artifact_key": a_key}},
            )
            await airlock.produce_result(
                runtime.redis,
                scan_id=str(job.scan_id),
                findings_key="",
                engine=UNRUNNABLE_ENGINE_MARKER,
                status=POISON_PILL_STATUS,
            )
            continue
        await airlock.produce_scan_job(
            runtime.redis,
            scan_id=str(job.scan_id),
            content_hash=str(job.content_hash),
            artifact_key=a_key,
            # Use the configured deadline, not a hardcoded 300s. This sweep
            # covers reeval-triggered rescans (a normal recurring path), so
            # hardcoding here silently ignored SKILLSCAN_SCAN_DEADLINE_S for
            # every reeval scan while the submit path (router.py) honored it -
            # the two must raise together (a slow LLM backend needs the budget
            # on rescans too, not just first submissions).
            deadline_epoch=airlock.now_epoch() + runtime.scan_deadline_s,
            engines=tuple(sorted(runtime.policy.required_engines)),
        )
        swept += 1
    return swept


# verdict string -> target lifecycle state, per coding spec §16.2.
# BLOCK used to have deliberately NO entry here, on the theory that "the
# verdict itself is visible and signed" was enough. In practice this left a
# blocked skill permanently indistinguishable from one still scanning on the
# inventory page - visible verdict is not the same thing as a readable state.
_VERDICT_TARGET_STATE = {"PASS": "published", "REVIEW": "review_pending", "BLOCK": "blocked"}
# The states in which a skill is waiting for a verdict to move it. Exactly the
# two `sync_lifecycle_tick` acts on, and the same pair `inventory.lifecycle`
# names in REVIEW_ACTIONABLE_STATE's comment - one spelling, so the tick's
# pending filter and its stranded-verdict check can never disagree about which
# states "waiting" means.
_WAITING_STATES = ("scanning", "review_pending")
# Redis key prefix for stranded-verdict report dedup (C1) - see
# `_report_stranded_verdicts`.
_STRANDED_VERDICT_PREFIX = "skillscan:lifecycle:stranded_verdict:"
# How many recently-decided scans `advance_scanned_toolchain_digests` inspects
# per tick. Same order as `_UNOWNED_MAX_LIMIT`/`GET /v1/scans`' own clamp: a
# bound that a single second's scan volume cannot realistically overflow, so
# freshly decided work is always inside the window.
_TOOLCHAIN_ADVANCE_BATCH = 200


async def _quarantine_if_drifted(runtime: ScanRuntime, *, skill_id: str, content_hash: str) -> None:
    """SUPPLY-06 (coding spec, FR-REV-020): "content_hash 对比 baseline, 不一致 →
    隔离". `inventory.lifecycle`'s own transition graph only allows
    'quarantined' FROM 'published' (confirmed: `scanning -> quarantined` is
    not a legal edge) - so this runs as a follow-up AFTER a skill has just
    published, matching the spec's own "published→quarantined" wording,
    rather than trying to redirect the publish transition itself. A skill
    with no baseline set yet is never drift, by `is_drift`'s own definition -
    nothing happens for the vast majority of publishes.

    WHAT THIS STILL CATCHES, after C3 (2026-07-29). Its caller now runs
    `inventory.service.advance_baseline_on_publish` first, so a publish that
    is the next link in the skill's own published chain has already moved the
    baseline onto this content and finds no drift here. What remains, and it
    is the only case that was ever a real signal: a baseline an ADMIN pinned
    out of band (`POST /v1/inventory/{skill_id}/baseline`) to content this
    skill has never published. That pin is a human statement of "the approved
    content is X"; a pipeline publish of anything else contradicts it, is
    refused adoption, and lands here - quarantined, for a human to settle.

    WHAT IT NEVER CAUGHT, and must not be mistaken for: content swapped in
    the marketplace WITHOUT passing through us. That produces no lifecycle
    event at all, so this function - reachable only from a `-> published`
    transition we ourselves made - could never observe it. The control for
    that is `reeval.service.run_poll_reconciliation`, which enumerates the
    marketplace's published set independently and auto-quarantines an ORPHAN/
    MISMATCH without consulting `baseline` at all."""
    if runtime.orchestration_session_factory is None or runtime.inventory_session_factory is None:
        return
    async with runtime.orchestration_session_factory() as drift_session:
        drift = await check_drift(drift_session, skill_id=skill_id, content_hash=content_hash)
    if not (drift.has_baseline and drift.drifted):
        return
    try:
        async with runtime.inventory_session_factory() as inv_session, inv_session.begin():
            await transition_skill(
                inv_session,
                skill_id=skill_id,
                to_state="quarantined",
                reason=(
                    # FROZEN literal, not a spec citation: `reeval/router.py`'s
                    # _DRIFT_REASON_PREFIX matches historical rows against this
                    # exact prefix. The catalog renumbered SUP-05 -> SUPPLY-06
                    # (2026-07-28) and the comments around here followed, but
                    # changing THIS string would make every drift event written
                    # before the rename invisible on the reeval page. See that
                    # constant's comment for the full reasoning.
                    f"drift detected (SUP-05): baseline={drift.baseline_content_hash} "
                    f"!= current={content_hash}"
                ),
                actor=_WORKER_OPERATOR,
                content_hash=content_hash,
            )
    except (InvalidTransitionError, ValueError) as exc:
        _logger.warning(
            "drift-triggered quarantine skipped",
            extra={"context": {"skill_id": skill_id, "error": str(exc)}},
        )


async def sync_lifecycle_tick(runtime: ScanRuntime) -> int:
    """Drives the §16.2 skill lifecycle from issued verdicts.

    For every skill whose LATEST lifecycle state is 'scanning' or
    'review_pending', looks up THAT EVENT'S OWN verdict (via gate's own
    session - svc_inventory has no verdict grant, deliberately) and applies
    the mapped transition. Idempotent: already-transitioned skills no longer
    match the state filter.

    SECURITY (2026-07-29, milestones E+F review finding C1) - "that event's
    own verdict" is the fix. This used to take the NEWEST verdict for the
    event's `content_hash`, with nothing tying it to the scan the event named
    (the scan_id lived only in the free-text `reason`) and no check that it
    even post-dated the event. Since a3f26e4 (finding I1) made a resubmission
    of UNCHANGED bytes write real lifecycle events, that was live:

      publish at hash H under toolchain T1 -> detection content or policy
      changes (T2) -> the owner resubmits the same bytes, which is exactly the
      case I1 exists to serve -> cache_key = f(H, T2) misses so a real new scan
      is enqueued -> the lifecycle commits published -> submitted -> scanning
      -> this tick fires within ~1s (`run_worker_loop(interval_s=1.0)`), finds
      the T1 PASS as newest-for-H and publishes -> seconds later the T2 scan
      issues BLOCK, to a skill that has already left `scanning` and is no
      longer in `pending`. Dropped, permanently.

    The mirror case is worse: a `blocked` skill resubmitted under a RELAXED
    ruleset was instantly re-blocked on its own stale BLOCK, so I1's stated
    purpose could not work at all. And nothing recovered either -
    `register_skill_version` deliberately never advances
    `skill_version.toolchain_digest`, so `reeval` keeps re-queueing rescans
    whose verdicts hit the same dead end.

    RESOLUTION ORDER, per pending event:

      1. `event.scan_id` (`SkillLifecycleEventRow.scan_id`, added by
         7f2ad4c9e1b3) -> a point lookup of `verdict` by its PRIMARY KEY. The
         one verdict this event is waiting for; "newest for this content hash"
         - a set that legitimately holds several rows once the same bytes are
         scanned under several toolchains - is not consulted at all.
      2. NULL scan_id -> LEGACY ROWS ONLY (written before that column existed;
         the admin routes never leave a skill in a waiting state). Falls back
         to the newest verdict for the content hash whose `issued_at` is not
         BEFORE the event - the time-based shape the reviewer offered as the
         other option, kept here strictly as a fallback so a migrated
         deployment's in-flight scans still settle instead of sticking in
         `scanning` forever. It is a heuristic across two modules' clocks
         (inventory writes `occurred_at`, gate writes `issued_at`), which is
         why it is not the primary path.

    A VERDICT THE LIFECYCLE CANNOT ACT ON IS NEVER SILENTLY DROPPED. Resolving
    by scan_id removes the drop this finding is about - the event waits for its
    own scan, and `scanning -> submitted` is not a legal edge, so nothing can
    move the skill on underneath an in-flight scan. What remains is an admin
    moving a skill out of a waiting state (retire/quarantine) while its scan is
    still running: legal, deliberate, and the verdict that lands afterwards has
    nowhere to go. `_report_stranded_verdicts` below finds exactly those and
    logs them at WARNING with the scan_id, deduped in Redis so a permanently
    stranded verdict costs one line a day rather than one a second.
    Deliberately a report and not an automatic transition: the state machine
    refuses `published -> blocked` on purpose (lifting or imposing a block goes
    through a fresh scan or an admin), so the honest answer is to surface it
    for a human, not to invent an edge for the worker."""
    if runtime.inventory_session_factory is None:
        return 0

    async with runtime.inventory_session_factory() as inv_session:
        events = (
            (
                await inv_session.execute(
                    select(SkillLifecycleEventRow).order_by(SkillLifecycleEventRow.id.desc())
                )
            )
            .scalars()
            .all()
        )
    latest_by_skill: dict[str, SkillLifecycleEventRow] = {}
    for event in events:  # newest first - first hit per skill wins
        latest_by_skill.setdefault(str(event.skill_id), event)

    pending = {
        skill_id: event
        for skill_id, event in latest_by_skill.items()
        if event.to_state in _WAITING_STATES and event.content_hash
    }
    if not pending:
        # C1: NOT a bare `return 0`. A stranded verdict is by definition one
        # whose skill is no longer waiting for anything, so "nothing is
        # pending" is the very state in which it has to still be reported -
        # returning early here would have made the report unreachable in
        # exactly the case it exists for.
        await _report_stranded_verdicts(runtime, events=events, pending=pending)
        return 0

    # C1: the scans the pending events actually name, and - only for legacy
    # rows that carry no scan_id - their content hashes. Both sets are read in
    # ONE gate query; `scan_id` is `verdict`'s primary key, so the first half is
    # a point lookup per event rather than a scan of every verdict ever issued
    # for that content.
    awaited_scan_ids = {str(e.scan_id) for e in pending.values() if e.scan_id}
    legacy_hashes = {str(e.content_hash) for e in pending.values() if not e.scan_id}
    verdict_by_scan: dict[str, str] = {}
    legacy_candidates: list[VerdictRow] = []
    # Built as a list rather than a fixed two-armed OR: with no legacy rows in
    # play - the steady state once a deployment has been migrated for a while -
    # the content_hash arm is not in the query at all, instead of being present
    # as an `IN ('')` that can never match but still has to be planned.
    verdict_filters = []
    if awaited_scan_ids:
        verdict_filters.append(VerdictRow.scan_id.in_(awaited_scan_ids))
    if legacy_hashes:
        verdict_filters.append(VerdictRow.content_hash.in_(legacy_hashes))
    if verdict_filters:
        async with runtime.gate_session_factory() as gate_session:
            verdict_rows = (
                (
                    await gate_session.execute(
                        select(VerdictRow)
                        .where(or_(*verdict_filters))
                        .order_by(VerdictRow.issued_at.desc())
                    )
                )
                .scalars()
                .all()
            )
        for v in verdict_rows:
            if str(v.scan_id) in awaited_scan_ids:
                verdict_by_scan[str(v.scan_id)] = str(v.verdict)
            if str(v.content_hash) in legacy_hashes:
                legacy_candidates.append(v)  # already ordered newest-first

    transitioned = 0
    for skill_id, event in pending.items():
        verdict = _resolve_event_verdict(event, verdict_by_scan, legacy_candidates)
        if verdict is None:
            continue  # not decided yet
        target = _VERDICT_TARGET_STATE.get(verdict)
        if target is None or target == event.to_state:
            continue  # unmapped verdict, or already there
        try:
            async with runtime.inventory_session_factory() as inv_session, inv_session.begin():
                if target == "published":
                    # C3 (2026-07-29): THIS publish is the approval - the
                    # content just got its own fresh, signed verdict - so it
                    # becomes the drift baseline, in the same transaction as
                    # the transition and BEFORE it (the helper reads the
                    # skill's prior published event; see its docstring for
                    # both requirements, and for the one case it declines).
                    # Without this, `_quarantine_if_drifted` below quarantined
                    # every v2 of a baselined skill, since a new version has a
                    # different content_hash by definition.
                    await advance_baseline_on_publish(
                        inv_session,
                        skill_id=skill_id,
                        content_hash=str(event.content_hash),
                        actor=_WORKER_OPERATOR,
                    )
                await transition_skill(
                    inv_session,
                    skill_id=skill_id,
                    to_state=target,
                    reason=f"verdict {verdict}",
                    actor=_WORKER_OPERATOR,
                    content_hash=str(event.content_hash),
                    # C1: carry the link FORWARD, do not drop it here. The
                    # `scanning -> review_pending` hop is written by this very
                    # loop, and the `review_pending -> published` hop that
                    # follows a human approval has to resolve the SAME scan's
                    # verdict (the review decision rewrites that row in place,
                    # keyed by scan_id). Dropping it would put every reviewed
                    # skill back on the newest-for-content-hash path this whole
                    # fix exists to remove. It is also what makes
                    # `_report_stranded_verdicts` able to tell "this scan's
                    # verdict was acted on" from "the skill moved on without
                    # it".
                    scan_id=str(event.scan_id) if event.scan_id else None,
                )
            transitioned += 1
            if target == "published":
                await _quarantine_if_drifted(
                    runtime, skill_id=skill_id, content_hash=str(event.content_hash)
                )
        except (InvalidTransitionError, ValueError) as exc:
            # e.g. review_pending + a later REVIEW verdict maps to its own
            # current state, or a concurrent admin action moved it first -
            # never let one skill's surprise stall the rest of the tick.
            _logger.warning(
                "lifecycle transition skipped",
                extra={"context": {"skill_id": skill_id, "target": target, "error": str(exc)}},
            )

    await _report_stranded_verdicts(runtime, events=events, pending=pending)
    return transitioned


def _resolve_event_verdict(
    event: SkillLifecycleEventRow,
    verdict_by_scan: dict[str, str],
    legacy_candidates: list[VerdictRow],
) -> str | None:
    """The verdict THIS lifecycle event is waiting for, or None if it has not
    been decided yet. See `sync_lifecycle_tick`'s docstring for the resolution
    order and for the finding (C1) that made an explicit link necessary."""
    if event.scan_id:
        return verdict_by_scan.get(str(event.scan_id))
    # LEGACY ROWS ONLY - see `sync_lifecycle_tick`. `legacy_candidates` is
    # ordered newest-first, so the first match is the newest verdict for this
    # content that is not OLDER than the event. The `>=` is what keeps a
    # pre-existing verdict for the same bytes (the exact stale-verdict shape
    # C1 is about) from resolving a freshly re-entered scan.
    for v in legacy_candidates:
        if str(v.content_hash) == str(event.content_hash) and v.issued_at >= event.occurred_at:
            return str(v.verdict)
    return None


async def _report_stranded_verdicts(
    runtime: ScanRuntime,
    *,
    events: Sequence[SkillLifecycleEventRow],
    pending: dict[str, SkillLifecycleEventRow],
) -> None:
    """Reports verdicts that were issued for a scan the lifecycle named and
    then never acted on, because the skill had already moved on.

    SECURITY/OBSERVABILITY (2026-07-29, milestones E+F review finding C1): "a
    verdict that arrives for a skill that has already moved on must not be
    silently dropped." Resolving by scan_id removes the drop the finding is
    about - a `scanning` event now waits for its OWN scan, and `scanning ->
    submitted` is not a legal edge, so no resubmission can move the skill out
    from under an in-flight verdict. What remains is an admin retiring - or
    quarantining a `review_pending` skill - while its scan is still running:
    legal, deliberate, and the verdict that lands afterwards has nowhere to go.

    ITS SCOPE, STATED PLAINLY: this reports scans the LIFECYCLE NAMED and did
    not act on. `reeval.controller.build_rescan_job` INSERTs a `scan_job`
    directly and writes no lifecycle event at all, so its verdicts carry no
    `scan_id` any event ever referenced and are OUTSIDE this report - they have
    never driven a transition and still do not. That is a real remaining gap
    and it is deliberately not papered over here: closing it means giving
    reeval rescans a lifecycle identity, which is a design change to `reeval`,
    not a filter in this function.

    WHAT IT DOES, AND WHY NOT MORE: it logs, at WARNING, with the scan_id, the
    skill, the verdict and where the skill actually stands. It does NOT
    transition anything. `lifecycle.VALID_TRANSITIONS` refuses `published ->
    blocked` on purpose (a block is imposed by a fresh scan, or an admin
    quarantines), and inventing an edge here so the worker could apply a late
    BLOCK would route around the human gate those refusals exist to force. The
    honest behaviour is to make the drop LOUD and let an operator decide.

    HOW "acted on" is decided, without a second table: every transition this
    worker writes OFF a waiting state carries the same `scan_id` forward, so a
    scan whose verdict reached the lifecycle always appears on some event with
    `from_state` in ('scanning', 'review_pending'). Anything in a waiting
    event's `scan_id` but never in an exiting event's - and not still legitim-
    ately awaited by the current `pending` set - is stranded.

    Redis SET NX dedup (24h) keeps a permanently stranded verdict to one line a
    day instead of one a second, and is multi-replica safe - the same idiom
    `run_due_report_schedules` uses. A Redis failure degrades to logging
    nothing extra; it must never break the lifecycle tick.
    """
    awaited = {str(e.scan_id) for e in pending.values() if e.scan_id}
    entered_waiting = {
        str(e.scan_id) for e in events if e.scan_id and e.to_state in _WAITING_STATES
    }
    left_waiting = {str(e.scan_id) for e in events if e.scan_id and e.from_state in _WAITING_STATES}
    candidates = entered_waiting - left_waiting - awaited
    if not candidates:
        return
    try:
        async with runtime.gate_session_factory() as gate_session:
            stranded = (
                (
                    await gate_session.execute(
                        select(VerdictRow).where(VerdictRow.scan_id.in_(candidates))
                    )
                )
                .scalars()
                .all()
            )
    except SQLAlchemyError:
        _logger.exception("stranded-verdict check failed to read verdicts")
        return
    if not stranded:
        return
    latest_state = {
        str(e.skill_id): str(e.to_state)
        for e in reversed(list(events))  # events arrive newest-first
    }
    by_scan = {str(e.scan_id): e for e in events if e.scan_id}
    for v in stranded:
        event = by_scan.get(str(v.scan_id))
        skill_id = str(event.skill_id) if event is not None else None
        try:
            fresh = await runtime.redis.set(
                f"{_STRANDED_VERDICT_PREFIX}{v.scan_id}", "1", nx=True, ex=86400
            )
        except (aioredis.RedisError, OSError):
            _logger.exception("stranded-verdict dedup failed - reporting anyway")
            fresh = True
        if not fresh:
            continue
        _logger.warning(
            "verdict issued for a skill that had already left the waiting state - "
            "no lifecycle transition was applied",
            extra={
                "context": {
                    "scan_id": str(v.scan_id),
                    "skill_id": skill_id,
                    "verdict": str(v.verdict),
                    "content_hash": str(v.content_hash),
                    "skill_state": latest_state.get(skill_id or "", "unknown"),
                }
            },
        )


async def advance_scanned_toolchain_digests(
    runtime: ScanRuntime, *, limit: int = _TOOLCHAIN_ADVANCE_BATCH
) -> int:
    """Advances `skill_version.toolchain_digest` onto the CURRENT toolchain for
    every version that has actually been re-scanned under it. Returns how many
    rows moved.

    THE FINDING (2026-07-29, milestones E+F residual triage). Nothing advanced
    that column after the first submission, so `reeval` re-offered - and
    re-queued - a rescan for versions it had already re-evaluated, forever.
    `register_skill_version` is right to leave it alone (see its docstring:
    writing it at SUBMIT time would claim "scanned by the current toolchain"
    before any verdict exists, a fail-open write to the very signal reeval
    reads), but nothing picked it up after the verdict landed either. Waste
    rather than incorrectness - until `1b4b1f5` those rescans resolved to
    nothing anyway; now that they resolve properly the churn is real work.

    WHY HERE AND NOT AT THE DECIDE SITE. `gate.service.decide_and_record` (via
    `orchestration._try_score_and_decide`) is where all three facts hold at
    once and it is where I first looked: the `scan_job` row in hand carries
    both `content_hash` and `toolchain_digest`, and the verdict is being
    written in that same transaction. It cannot write this column: `skill_version`
    belongs to inventory, and `svc_orchestration`/`svc_gate` hold no grant on it
    (policies/grants/manifest.yaml) - by design, not by omission. `reeval` is
    likewise SELECT-only there, deliberately. The worker is this codebase's
    composition point for exactly this shape: it holds each module's OWN
    least-privilege factory and calls across them without any module reaching
    into another's tables, the same way `sync_lifecycle_tick` reads gate's
    verdicts through gate's own session.

    NOT FOLDED INTO `sync_lifecycle_tick`, which already resolves a verdict per
    skill and looks like the cheaper home: it only ever sees scans a LIFECYCLE
    EVENT named, and `reeval.controller.build_rescan_job` INSERTs its scan_job
    directly and writes no lifecycle event at all (see
    `_report_stranded_verdicts` on that same gap). Reeval rescans are precisely
    the churn this function exists to stop, so putting it there would have
    fixed the case that was not broken.

    THE INVARIANT, CHECKED RATHER THAN ARGUED. A row is advanced only when all
    three hold, each read from the row that carries it:

      1. a verdict EXISTS - the `verdict` row is selected through gate's own
         session and its absence disqualifies the job. `scan_job.state ==
         'decided'` is checked too, but is not trusted as a proxy: it is set by
         a different module in a different transaction from the verdict write.
      2. it is FOR THIS CONTENT - `verdict.content_hash == scan_job.content_hash`
         and that hash is one this sweep looked up in `skill_version`. Not
         inferred from the cache_key the job was found by, even though that key
         is a hash of exactly this pair.
      3. it was produced by the toolchain BEING RECORDED - `scan_job.
         toolchain_digest == current`, re-read off the job rather than assumed
         from the `cache_key` filter that selected it.

    Anything that fails one of the three is left alone: an honest stale digest
    costs a redundant rescan, a dishonest fresh one silently suppresses a real
    one.

    BOUNDED, NEWEST FIRST. The driving query is the newest `limit` scan_jobs
    decided under the current digest, not the whole staleness list. New work
    always enters that window at the top, so a rescan decided a second ago is
    always in it; and because the filter is `toolchain_digest = current`, the
    set empties itself on every policy hot-reload / engine change rather than
    growing with history. Idempotent - the UPDATE re-asserts `!= current`, so a
    row that is already advanced is not rewritten and does not count.
    """
    if runtime.inventory_session_factory is None:
        return 0
    current_digest = await runtime.current_toolchain_digest()
    async with runtime.orchestration_session_factory() as orch_session:
        jobs = (
            (
                await orch_session.execute(
                    select(ScanJob)
                    .where(
                        ScanJob.toolchain_digest == current_digest,
                        ScanJob.state == STATE_DECIDED,
                    )
                    .order_by(ScanJob.created_at.desc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
    if not jobs:
        return 0
    # Which of those scans' packages are registered versions at all - most
    # scans never register a skill_id. A primary-key IN over at most `limit`
    # hashes, so this stays a point lookup per candidate.
    candidate_hashes = {str(job.content_hash) for job in jobs}
    async with runtime.inventory_session_factory() as inv_session:
        stale_hashes = set(
            (
                await inv_session.execute(
                    select(SkillVersionRow.content_hash).where(
                        SkillVersionRow.content_hash.in_(candidate_hashes),
                        SkillVersionRow.toolchain_digest != current_digest,
                    )
                )
            )
            .scalars()
            .all()
        )
    pending = [
        job
        for job in jobs
        if str(job.content_hash) in stale_hashes and str(job.toolchain_digest) == current_digest
    ]
    if not pending:
        return 0
    async with runtime.gate_session_factory() as gate_session:
        verdict_rows = (
            await gate_session.execute(
                select(VerdictRow.scan_id, VerdictRow.content_hash).where(
                    VerdictRow.scan_id.in_([str(job.scan_id) for job in pending])
                )
            )
        ).all()
    verdict_content = {str(row.scan_id): str(row.content_hash) for row in verdict_rows}
    confirmed = {
        str(job.content_hash)
        for job in pending
        if verdict_content.get(str(job.scan_id)) == str(job.content_hash)
    }
    if not confirmed:
        return 0
    async with runtime.inventory_session_factory() as inv_session, inv_session.begin():
        # An UPDATE's execute() always returns a CursorResult at runtime (unlike
        # the generic Result[Any] a SELECT gives) - the cast narrows to what
        # .rowcount needs, the same idiom `intel_sync.sync._apply_rows` uses.
        # `rowcount`, not `len(confirmed)`: the WHERE re-asserts staleness, so
        # this reports the rows that actually MOVED rather than the rows we
        # intended to move.
        result = cast(
            CursorResult[Any],
            await inv_session.execute(
                update(SkillVersionRow)
                .where(
                    SkillVersionRow.content_hash.in_(confirmed),
                    SkillVersionRow.toolchain_digest != current_digest,
                )
                .values(toolchain_digest=current_digest)
            ),
        )
    return int(result.rowcount or 0)


async def run_due_report_schedules(
    runtime: ScanRuntime, *, now: datetime.datetime | None = None
) -> int:
    """Fires report schedules whose cron matches the current minute.

    Delivery: the generated report's summary goes to the SIEM notifier when
    one is configured (coding spec §16.2: "推送计划(cron → SIEM/邮件内网)");
    without one the generation is still logged. Email delivery needs SMTP
    infrastructure this codebase has never had - honestly logged as skipped,
    not silently pretended. Per-minute dedup via Redis SET NX keeps this
    exactly-once across replicas."""
    if runtime.reporting_session_factory is None:
        return 0
    at = now if now is not None else datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
    async with runtime.reporting_session_factory() as session:
        schedules = (await session.execute(select(ReportScheduleRow))).scalars().all()

    fired = 0
    for schedule in schedules:
        try:
            if not reporting_service.cron_matches(str(schedule.cron), at):
                continue
        except reporting_service.InvalidCronError:
            _logger.warning(
                "report schedule has an unfireable cron expression - skipping",
                extra={"context": {"schedule_id": schedule.id, "cron": str(schedule.cron)}},
            )
            continue
        minute_stamp = at.strftime("%Y%m%d%H%M")
        dedup_key = f"{_SCHEDULE_FIRED_PREFIX}{schedule.id}:{minute_stamp}"
        if not await runtime.redis.set(dedup_key, "1", nx=True, ex=120):
            continue  # another replica already fired this schedule this minute
        try:
            async with runtime.reporting_session_factory() as session:
                report = await reporting_service.generate_report(
                    str(schedule.template), session=session, redis=runtime.redis
                )
        except Exception:
            _logger.exception(
                "scheduled report generation failed",
                extra={"context": {"schedule_id": schedule.id, "template": str(schedule.template)}},
            )
            continue
        event: dict[str, Any] = {
            "event_type": "scheduled_report",
            "schedule_id": schedule.id,
            "template": report.template,
            "targets": list(schedule.targets or []),
            "summary": dict(report.summary),
        }
        if runtime.siem_notifier is not None:
            await runtime.siem_notifier.emit(event)
        else:
            _logger.info(
                "scheduled report generated (no SIEM notifier configured - log-only delivery)",
                extra={"context": event},
            )
        fired += 1
    return fired


async def run_engine_health_retention(
    runtime: ScanRuntime, *, interval_s: int = _HEALTH_RETENTION_INTERVAL_S
) -> int:
    """Drive `scan_engine_health` retention, at most once per `interval_s` per
    cluster. Returns rows deleted (0 when another tick already holds the lease).

    THIS FUNCTION IS THE ANSWER TO "WHERE DOES THE SWEEP RUN". `worker_tick`
    is the only live driver in this deployment - one background asyncio task in
    the single monolith pod, ticking at 1.0 s, confirmed by observation on the
    VM (Task 1, 1bfd580) rather than inferred from the source. Anything else
    would have needed a scheduler this system does not have, and a sweep with
    no scheduler is the "real code, no live caller" defect this milestone has
    already found four times.

    THE LEASE, not a timestamp column and not a per-process clock. `SET NX EX`
    is the same primitive `run_due_report_schedules` uses, and it is correct
    across replicas for the same reason: whichever pod gets there first runs
    the pass, the rest see the key and return. A process-local "last run at"
    would restart with the process, so a crash-looping pod would sweep on every
    restart, and two replicas would each keep their own.

    A Redis failure means the pass is SKIPPED, never that it runs unleased -
    the failure mode of an unleased sweep is every replica deleting
    concurrently, which is exactly the contention this design exists to avoid.
    It is logged rather than raised: retention is the least important thing in
    the tick and must not cost the steps ordered after it.
    """
    try:
        acquired = await runtime.redis.set(_HEALTH_RETENTION_LEASE_KEY, "1", nx=True, ex=interval_s)
    except (aioredis.RedisError, OSError):
        _logger.exception(
            "could not take the engine-health retention lease - skipping this pass",
        )
        return 0
    if not acquired:
        return 0
    return await sweep_engine_health_retention(runtime.orchestration_session_factory)


async def worker_tick(runtime: ScanRuntime, *, consumer: str = "monolith-worker") -> dict[str, int]:
    """One full pass over every background responsibility. Each step is
    independently useful and independently fallible - a step's failure is
    logged and the remaining steps still run this tick."""
    counts = {
        "policy_reloaded": 0,
        "swept": 0,
        "engine_jobs": 0,
        "decided": 0,
        # 2026-07-27 review (Minor): named "swept", not "timeouts" -
        # sweep_sandbox_wait_timeouts returns how many scans IT decided (any
        # queued/running row older than the cutoff it force-decided, whether
        # or not a sandbox engine was actually still missing at that point -
        # _try_score_and_decide returns True for every row it successfully
        # scores), not a count of genuine sandbox timeouts. The per-verdict
        # `sandbox_wait_timeout:<engines>` reason is the accurate signal for
        # "this specific verdict was missing a sandbox engine"; this counter
        # is only ever "how much work did the sweep do this tick."
        "sandbox_swept": 0,
        "lifecycle": 0,
        "toolchain_advanced": 0,
        "audit_chained": 0,
        # Task 13: the backlog LEFT after this tick's drain, not work done -
        # reported alongside the counters so a caller reading `counts` sees
        # the same number `/metrics` reports for `audit_intent_unchained`,
        # rather than having to scrape to find out.
        "audit_unchained": 0,
        "outbox_dispatched": 0,
        "reports_fired": 0,
        # Task 9: `scan_engine_health` rows deleted by this tick. Almost always
        # 0 - the lease lets one tick an hour do the work - so the number that
        # carries information is its SUM over a day, not its value on a tick.
        "health_rows_pruned": 0,
    }

    if await reload_policy_if_changed(runtime):
        counts["policy_reloaded"] = 1

    counts["swept"] = await sweep_queued_jobs_to_airlock(runtime)

    # Read once per tick, before anything that must respect it. The sandbox
    # waited-set below reads the same value; this used to be fetched only there.
    disabled_engines = await list_disabled_engines(runtime.redis)

    tick_engines = await _floor_engines_with_intel(runtime)
    # Everything in `tick_engines` beyond the floor set (currently just the
    # intel matcher, when its DB read succeeded) is advisory: passed to BOTH
    # the dispatch tick (as `additional_engine_names`, so it actually runs -
    # `job.engines` alone never includes it, see run_mock_engine_worker_tick's
    # own docstring) and the collector tick (as `additional_engines`, so its
    # finding counts toward severity/trifecta when present, without ever
    # gating the "all required engines present" wait).
    floor_names = frozenset(floor_engines().keys())
    # SECURITY/HONESTY (2026-07-29, milestone C Task 2): the admin toggle now
    # LISTS the intel matcher and accepts a PATCH for it, so this tick has to
    # honour it - the same "write-only toggle" the sandbox engines suffered
    # until 2026-07-13 (recorded in Redis, read by nobody, engine kept running)
    # would otherwise be reintroduced on the one tier that had just been made
    # visible. Only NON-floor entries are droppable: a floor engine can never
    # be in `disabled_engines` (the admin endpoint 409s on INV-1 before it can
    # be written), and filtering the floor here would silently defeat the
    # backstop if that guard ever regressed, so the floor is excluded from this
    # filter by construction rather than by trusting the writer.
    tick_engines = {
        name: engine
        for name, engine in tick_engines.items()
        if name in floor_names or name not in disabled_engines
    }
    dispatchable_advisory_engines = tuple(name for name in tick_engines if name not in floor_names)
    # SANDBOX_ADVISORY_ENGINE_NAMES are NEVER added to `dispatchable_advisory_engines`/
    # `additional_engine_names` above - they run only in the separate engine-runner
    # service (INV-15 subprocess/license isolation), and this process has no adapter
    # instance for them to dispatch. They're aggregation-only: when the
    # engine-runner has already written a finding blob for one, it counts toward
    # severity/trifecta (same advisory, never-fail-closed treatment as the intel
    # matcher - see `_try_score_and_decide`'s docstring). Before this fix their
    # blobs were written but silently never read at all; after it, but before D2
    # (2026-07-27), they were read only when they happened to already be written
    # by the time this tick's collector ran - the floor tick usually decides
    # within the same synchronous tick it dispatches in, while the sandbox
    # engines are real subprocesses on their own poll interval in a different
    # process, so a verdict was routinely signed before their first subprocess
    # had even exited.
    #
    # DECIDED (D2): the gate now WAITS for SANDBOX_WAITED_ENGINE_NAMES (below)
    # before `run_result_collector_tick` will decide a scan at all - they are
    # passed as `waited_advisory_engines`, not just `additional_engines`. They
    # stay advisory, never `required_engines`: a missing one degrades to an
    # advisory absence rather than a fail-closed BLOCK, so one crashed engine
    # (or engine-runner outage) cannot block every scan. A wait that runs past
    # `runtime.sandbox_wait_timeout_s` is forced through by
    # `sweep_sandbox_wait_timeouts` below - see that function's own docstring
    # for why the sweep's cutoff isn't exactly `sandbox_wait_timeout_s`. On a
    # forced timeout, `reasons` gains `sandbox_wait_timeout:<engines>` so the
    # downgrade is visible via `GET /v1/scans/{id}`, never silent.
    #
    # The AGGREGATED set stays the whole tier unconditionally: aggregating a
    # blob that happens to exist costs nothing and is what makes a findings
    # record complete, whereas WAITING for one is a promise about time. The two
    # sets are therefore filtered differently on purpose - see
    # `_active_sandbox_waited_engines` for what can make an engine unwaitable
    # on a given deployment (an admin disable, or an LLM-gated engine this
    # deployment's engine-runner never constructs), and why neither is a
    # property of the tier itself.
    aggregation_advisory_engines = dispatchable_advisory_engines + SANDBOX_ADVISORY_ENGINE_NAMES
    active_sandbox_waited_engines = _active_sandbox_waited_engines(
        disabled_engines=disabled_engines,
        sandbox_llm_configured=runtime.sandbox_llm_configured,
    )
    counts["engine_jobs"] = await run_mock_engine_worker_tick(
        runtime.redis,
        runtime.blobstore,
        engines_by_name=tick_engines,
        consumer=consumer,
        additional_engine_names=dispatchable_advisory_engines,
    )

    async with runtime.gate_session_factory() as gate_session:
        allowlist = await list_active_allowlist_entries(gate_session, now=airlock.now_epoch())
    # SECURITY (2026-07-28, milestone B' Task 4): `runtime.default_trust_tier`
    # is no longer the tier every scan is judged at - each scan carries its
    # own `ScanJob.trust_tier`, recorded by `submit_scan` at submission time,
    # and `run_result_collector_tick`/`sweep_sandbox_wait_timeouts` read that
    # per-scan value internally. What's passed here is only the fallback for a
    # scan_job row written before that column existed (NULL, no backfill).
    counts["decided"] = await run_result_collector_tick(
        runtime.redis,
        runtime.blobstore,
        runtime.orchestration_session_factory,
        runtime.gate_session_factory,
        policy=runtime.policy,
        default_trust_tier=runtime.default_trust_tier,
        allowlist=allowlist,
        signer=runtime.signer,
        consumer=consumer,
        operator=_WORKER_OPERATOR,
        additional_engines=aggregation_advisory_engines,
        waited_advisory_engines=active_sandbox_waited_engines,
    )
    counts["sandbox_swept"] = await sweep_sandbox_wait_timeouts(
        runtime.blobstore,
        runtime.orchestration_session_factory,
        runtime.gate_session_factory,
        policy=runtime.policy,
        default_trust_tier=runtime.default_trust_tier,
        allowlist=allowlist,
        signer=runtime.signer,
        waited_advisory_engines=active_sandbox_waited_engines,
        wait_timeout_s=runtime.sandbox_wait_timeout_s,
        additional_engines=aggregation_advisory_engines,
    )

    counts["lifecycle"] = await sync_lifecycle_tick(runtime)

    # Step 6: runs AFTER the lifecycle sync only because both read the same
    # verdicts and this one is the cheaper of the two to repeat - it is not
    # ordered relative to it. It deliberately does NOT read lifecycle events at
    # all; reeval's own rescans never write one (see its docstring).
    counts["toolchain_advanced"] = await advance_scanned_toolchain_digests(runtime)

    if runtime.audit_session_factory is not None:
        counts["audit_chained"] = len(await drain_pending_intents(runtime.audit_session_factory))
        # Task 13 (2026-07-29): `audit_intent_unchained` (coding spec §11.7),
        # observed AFTER the drain, not before - the number that matters is
        # the backlog this tick could not clear, not the queue depth it
        # started with. A steady 0 means the drain is keeping up; anything
        # that stays nonzero across ticks means business events are sitting
        # in `audit_intent` without a hash chaining them, which is the
        # condition INV-12's tamper-evidence does not yet cover.
        #
        # Its own session, deliberately outside `drain_pending_intents`'s
        # short transactions - a read that could contend with the drainer it
        # is measuring would be an observation that changes the thing
        # observed. Failure here must never cost the tick: the gauge is
        # worth less than the drain, and the remaining steps below still
        # need to run (same poison-pill isolation as every other step here).
        try:
            async with runtime.audit_session_factory() as audit_session:
                counts["audit_unchained"] = await count_unchained_intents(audit_session)
        except Exception:
            _logger.exception(
                "audit_intent_unchained gauge read failed - gauge left at its previous value"
            )
        else:
            runtime.security_metrics.audit_intent_unchained.set(counts["audit_unchained"])

    if runtime.relay_session_factory is not None:
        counts["outbox_dispatched"] = await drain_pending_outbox(
            runtime.relay_session_factory,
            marketplace=runtime.marketplace,
            notifier=runtime.siem_notifier,
        )

    counts["reports_fired"] = await run_due_report_schedules(runtime)

    # LAST, and deliberately so. Everything above moves a scan forward or
    # records what happened to one; this only deletes telemetry that is 26 days
    # old. Ordering it here means a slow or failing retention pass cannot delay
    # a decide, a lifecycle transition or an audit chaining - and it can never
    # touch a row this tick just wrote, since the cutoff is weeks in the past.
    counts["health_rows_pruned"] = await run_engine_health_retention(runtime)
    return counts


async def run_worker_loop(
    runtime: ScanRuntime,
    *,
    interval_s: float = 1.0,
    consumer: str = "monolith-worker",
    stop_event: asyncio.Event | None = None,
) -> None:
    """The long-running loop `create_app()`'s lifespan starts when
    SKILLSCAN_WORKER_ENABLED=true. One failed tick never kills the loop."""
    # SECURITY/robustness: create the Redis consumer groups the worker consumes
    # from before the first tick. Previously these were only ever created by
    # test fixtures (airlock.ensure_groups in conftest), so a real fresh
    # deployment's worker failed every tick with NOGROUP and no scan ever left
    # 'queued' - found live on first VM deploy against a clean Redis. Idempotent
    # (BUSYGROUP-tolerant), so it is safe on every start and to re-run after a
    # Redis-side infra error (which is where a flushed/restarted Redis would
    # drop the groups mid-run).
    try:
        await airlock.ensure_groups(runtime.redis)
    except (aioredis.RedisError, OSError):
        _logger.exception("failed to ensure Redis consumer groups at worker start - will retry")
    _logger.info(
        "background worker started",
        extra={"context": {"interval_s": interval_s, "consumer": consumer}},
    )
    while stop_event is None or not stop_event.is_set():
        try:
            await worker_tick(runtime, consumer=consumer)
        except asyncio.CancelledError:
            # NOT counted: this is shutdown, the one way out of this loop that
            # is supposed to happen. Counting it would put a guaranteed
            # increment on every clean stop and make the metric's baseline
            # nonzero by design.
            raise
        except (aioredis.RedisError, OSError):
            # Task 13 (2026-07-29): `worker_failures_total` (coding spec
            # §11.7's "worker 失败"). Counted at TICK level, in both handlers -
            # the meaning is "a whole background tick died", not "a step
            # degraded". Steps that swallow their own exception and carry on
            # (the intel-matcher snapshot, a report schedule, one outbox row)
            # deliberately do NOT count here: folding those in would mix a
            # routine, self-healing degradation into the same unlabeled
            # counter as a dead tick, and no consumer could then tell which
            # had happened. See this module's own per-step handlers.
            runtime.security_metrics.worker_failures_total.inc()
            _logger.exception("worker tick failed on infrastructure error - will retry")
            # A NOGROUP (Redis flushed/restarted mid-run) surfaces here - re-
            # ensure the groups so the loop self-heals instead of spinning.
            try:
                await airlock.ensure_groups(runtime.redis)
            except (aioredis.RedisError, OSError):
                pass
        except Exception:
            runtime.security_metrics.worker_failures_total.inc()
            _logger.exception("worker tick failed unexpectedly - will retry")
        try:
            if stop_event is not None:
                await asyncio.wait_for(stop_event.wait(), timeout=interval_s)
            else:
                await asyncio.sleep(interval_s)
        except TimeoutError:
            pass
