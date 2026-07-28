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
                         on and why aig-mcp-scan is excluded
5. lifecycle sync      - verdicts drive the §16.2 skill state machine
                         (scanning→published on PASS, scanning→review_pending
                         on REVIEW; review-approved skills →published) - a
                         PASS that would publish is first checked against
                         orchestration.drift.check_drift(); if the skill
                         already has an approved baseline (inventory.service.
                         set_baseline, a separate admin action) and this
                         content_hash doesn't match it, the transition goes
                         to quarantined instead (coding spec SUPPLY-06:
                         "content_hash 对比 baseline, 不一致 → 隔离",
                         FR-REV-020) - closes "drift.py exists, is tested,
                         has no live caller"
6. audit chain drain   - audit.service.drain_pending_intents
7. outbox drain        - integration_relay.service.drain_pending_outbox
                         (marketplace writeback + SIEM, both optional)
8. report schedules    - fire due cron schedules (POST /v1/reports/schedule
                         finally executes; delivery = SIEM event when
                         configured, always audited via the generation itself)

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
from typing import Any

import redis.asyncio as aioredis
import yaml
from common import airlock
from common.blobstore import artifact_key
from common.log import get_logger
from engine_runner.sandbox_engines import SANDBOX_ENGINE_NAMES
from skillscan_core import GatePolicy
from sqlalchemy import select

from monolith.modules.admin.engine_registry import list_disabled_engines
from monolith.modules.audit.service import drain_pending_intents
from monolith.modules.gate.models import PolicyProposalRow, VerdictRow
from monolith.modules.gate.policy import GatePolicyLoadError, parse_gate_policy
from monolith.modules.gate.service import list_active_allowlist_entries
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.integration_relay.service import drain_pending_outbox
from monolith.modules.intel.matcher import IntelMatcher, load_known_iocs
from monolith.modules.inventory.lifecycle import InvalidTransitionError
from monolith.modules.inventory.models import SkillLifecycleEventRow
from monolith.modules.inventory.service import transition_skill
from monolith.modules.orchestration.drift import check_drift
from monolith.modules.orchestration.floor import floor_engines
from monolith.modules.orchestration.models import ScanJob
from monolith.modules.orchestration.service import (
    POISON_PILL_STATUS,
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
# The sandbox engines the gate WAITS for (D2, 2026-07-27). aig-mcp-scan is
# excluded unconditionally: it is only constructed when vllm_base_url is set
# (sandbox_engines.py:137), so on a default deployment it never reports at all,
# and even when enabled its 240s subprocess timeout would consume almost the
# entire 300s wait window on its own - starving the other four. Its findings
# therefore remain probabilistically visible; fixing that needs per-engine
# timeouts, not a bigger global one.
SANDBOX_WAITED_ENGINE_NAMES: tuple[str, ...] = tuple(
    n for n in SANDBOX_ADVISORY_ENGINE_NAMES if n != "aig-mcp-scan"
)
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


# verdict string -> target lifecycle state, per coding spec §16.2. BLOCK has
# deliberately NO entry: the state machine defines no 'blocked' state - a
# blocked skill stays where it is with its (visible, signed) BLOCK verdict;
# publish simply never happens.
_VERDICT_TARGET_STATE = {"PASS": "published", "REVIEW": "review_pending"}


async def _quarantine_if_drifted(runtime: ScanRuntime, *, skill_id: str, content_hash: str) -> None:
    """SUPPLY-06 (coding spec, FR-REV-020): "content_hash 对比 baseline, 不一致 →
    隔离". `inventory.lifecycle`'s own transition graph only allows
    'quarantined' FROM 'published' (confirmed: `scanning -> quarantined` is
    not a legal edge) - so this runs as a follow-up AFTER a skill has just
    published, matching the spec's own "published→quarantined" wording,
    rather than trying to redirect the publish transition itself. A skill
    with no baseline set yet (the common case - baselines are a separate,
    deliberate admin action via `inventory.service.set_baseline`) is never
    drift, by `is_drift`'s own definition - nothing happens for the vast
    majority of publishes."""
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
    'review_pending', looks up the newest verdict for that event's
    content_hash (via gate's own session - svc_inventory has no verdict
    grant, deliberately) and applies the mapped transition. Idempotent:
    already-transitioned skills no longer match the state filter."""
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
        if event.to_state in ("scanning", "review_pending") and event.content_hash
    }
    if not pending:
        return 0

    hashes = {str(e.content_hash) for e in pending.values()}
    async with runtime.gate_session_factory() as gate_session:
        verdict_rows = (
            (
                await gate_session.execute(
                    select(VerdictRow)
                    .where(VerdictRow.content_hash.in_(hashes))
                    .order_by(VerdictRow.issued_at.desc())
                )
            )
            .scalars()
            .all()
        )
    latest_verdict: dict[str, str] = {}
    for v in verdict_rows:  # newest first per content_hash
        latest_verdict.setdefault(str(v.content_hash), str(v.verdict))

    transitioned = 0
    for skill_id, event in pending.items():
        verdict = latest_verdict.get(str(event.content_hash))
        if verdict is None:
            continue  # not decided yet
        target = _VERDICT_TARGET_STATE.get(verdict)
        if target is None or target == event.to_state:
            continue  # BLOCK (no state change), or already there
        try:
            async with runtime.inventory_session_factory() as inv_session, inv_session.begin():
                await transition_skill(
                    inv_session,
                    skill_id=skill_id,
                    to_state=target,
                    reason=f"verdict {verdict}",
                    actor=_WORKER_OPERATOR,
                    content_hash=str(event.content_hash),
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
    return transitioned


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
        "audit_chained": 0,
        "outbox_dispatched": 0,
        "reports_fired": 0,
    }

    if await reload_policy_if_changed(runtime):
        counts["policy_reloaded"] = 1

    counts["swept"] = await sweep_queued_jobs_to_airlock(runtime)

    tick_engines = await _floor_engines_with_intel(runtime)
    # Everything in `tick_engines` beyond the floor set (currently just the
    # intel matcher, when its DB read succeeded) is advisory: passed to BOTH
    # the dispatch tick (as `additional_engine_names`, so it actually runs -
    # `job.engines` alone never includes it, see run_mock_engine_worker_tick's
    # own docstring) and the collector tick (as `additional_engines`, so its
    # finding counts toward severity/trifecta when present, without ever
    # gating the "all required engines present" wait).
    floor_names = frozenset(floor_engines().keys())
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
    # aig-mcp-scan is excluded from the WAITED set (SANDBOX_WAITED_ENGINE_NAMES)
    # but stays in the AGGREGATED set below: it is only constructed when
    # `vllm_base_url` is set, so a default deployment would otherwise wait the
    # full budget for an engine that can never report, and even when enabled
    # its 240s subprocess timeout would consume nearly the whole 300s window on
    # its own, starving the other four. Its findings remain probabilistically
    # visible - counted when it happens to have reported by decide time, same
    # as before D2 - rather than reliably waited-for.
    aggregation_advisory_engines = dispatchable_advisory_engines + SANDBOX_ADVISORY_ENGINE_NAMES
    # SECURITY/operability (Important 2, 2026-07-27 review): SANDBOX_WAITED_
    # ENGINE_NAMES is a static constant - it never reflects the admin
    # enable/disable toggle (PATCH /v1/admin/engines/{name}, gated only by
    # `engine_registry.is_disableable`, which allows disabling any of these
    # four since none is in `required_engines`). The engine-runner service
    # skips a disabled engine with a bare `continue` (services/engine_runner/
    # worker.py) - no blob, no result message, ever. Waiting on a name that
    # can structurally never report would silently turn a routine admin
    # disable into a 330s decision delay on EVERY scan from then on (still
    # recorded in `reasons`, so not silent in the audit sense - but a steep,
    # surprising operability cliff for one legitimate admin action). Read live
    # each tick (same Redis key `list_disabled_engines` reads for the
    # dashboard at reporting/service.py:359 and engine-runner's own dispatch
    # gate) so a re-enable takes effect on the very next tick, same as the
    # disable did.
    disabled_engines = await list_disabled_engines(runtime.redis)
    active_sandbox_waited_engines = tuple(
        n for n in SANDBOX_WAITED_ENGINE_NAMES if n not in disabled_engines
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

    if runtime.audit_session_factory is not None:
        counts["audit_chained"] = len(await drain_pending_intents(runtime.audit_session_factory))

    if runtime.relay_session_factory is not None:
        counts["outbox_dispatched"] = await drain_pending_outbox(
            runtime.relay_session_factory,
            marketplace=runtime.marketplace,
            notifier=runtime.siem_notifier,
        )

    counts["reports_fired"] = await run_due_report_schedules(runtime)
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
            raise
        except (aioredis.RedisError, OSError):
            _logger.exception("worker tick failed on infrastructure error - will retry")
            # A NOGROUP (Redis flushed/restarted mid-run) surfaces here - re-
            # ensure the groups so the loop self-heals instead of spinning.
            try:
                await airlock.ensure_groups(runtime.redis)
            except (aioredis.RedisError, OSError):
                pass
        except Exception:
            _logger.exception("worker tick failed unexpectedly - will retry")
        try:
            if stop_event is not None:
                await asyncio.wait_for(stop_event.wait(), timeout=interval_s)
            else:
                await asyncio.sleep(interval_s)
        except TimeoutError:
            pass
