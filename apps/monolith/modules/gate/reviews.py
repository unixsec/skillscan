"""Manual review decision for a REVIEW-verdict scan (coding spec §9
`POST /v1/reviews/{scan_id}`: "SoD 强制 approver≠submitter").

This is a composition-root-level orchestrator (like `reeval.service`'s
reconciliation functions) that legitimately holds THREE modules' sessions at
once: `orchestration_session` (read-only, to learn who submitted the scan -
gate has no grant on `scan_job`), `gate_session` (to read/update the verdict
itself) and `inventory_session` (read-only, to learn whether the skill has
already moved past the content this review covers - see
`SupersededReviewError`). SECURITY: `scan_id` is the PRIMARY KEY on `verdict`, so a
reviewed scan's row is UPDATED in place (there is no way to keep both the
original automated REVIEW verdict AND a final one as separate rows under the
current schema) - the original decision's reasons are preserved inside the
new `reasons` list, and the full history survives regardless in audit_entry
(action="review_decided"), which is never overwritten.
"""

from __future__ import annotations

import datetime

import jwt as pyjwt
from schemas.findings import deserialize_finding
from skillscan_core import CategoryWeights, Verdict
from skillscan_core.scoring import security_score
from sqlalchemy.ext.asyncio import AsyncSession

from monolith.modules.inventory.lifecycle import pending_review_is_superseded
from monolith.modules.inventory.service import lifecycle_position_for_content
from monolith.modules.orchestration.models import ScanJob, ScanResultRow
from monolith.modules.orchestration.service import is_scan_submitter

from .models import AuditIntentInsertOnly, GateOutboxRow, VerdictRow
from .service import SignerPort


class ReviewDecisionError(ValueError):
    pass


class InvalidDecisionError(ReviewDecisionError):
    """SECURITY: a malformed `decision` value - a client input error (400),
    distinct from every other failure mode below so the router can map each
    to the right status code without fragile message-text matching."""


class ReviewNotFoundError(ReviewDecisionError):
    """Unknown scan_id, or the scan has no recorded verdict yet - 404."""


class SodViolationError(ReviewDecisionError):
    """SECURITY: a same-person SoD violation is an authorization failure
    (403), never a 400/404 - those would tell an attacker whether the
    scan_id merely doesn't exist vs. exists but they're not allowed to
    decide it."""


class NotPendingReviewError(ReviewDecisionError):
    """The scan exists but its verdict isn't REVIEW (already decided, or
    never needed review) - a conflict with the resource's current state
    (409), not a missing-resource 404."""


class SupersededReviewError(ReviewDecisionError):
    """The verdict is still REVIEW, but the SKILL has moved past the content
    it covers - a newer version was submitted, or an admin retired/quarantined
    it (409, same "conflict with current state" family as
    `NotPendingReviewError`).

    SECURITY/UX (2026-07-29, milestone F Task 11 follow-up I3): without this,
    the decision was accepted, the verdict row was rewritten and signed, and
    then `worker.sync_lifecycle_tick` silently discarded it - it only
    transitions skills whose latest state is `scanning` or `review_pending`.
    The approver's sign-off vanished with no feedback, and the audit trail
    recorded a `review_decided` intent that never moved anything. Refusing is
    the honest answer: the queue entry is stale, and the current version has
    its own review to come.
    """


_DECISION_TO_VERDICT = {"approve": "PASS", "reject": "BLOCK"}


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


async def submit_review_decision(
    *,
    orchestration_session: AsyncSession,
    gate_session: AsyncSession,
    inventory_session: AsyncSession | None,
    scan_id: str,
    decision: str,
    reviewer: str,
    reason: str,
    signer: SignerPort,
) -> VerdictRow:
    """SECURITY: caller must run `gate_session` inside `async with
    gate_session.begin():` - the verdict update/outbox/audit rows commit
    atomically (INV-12), same as `gate.service.decide_and_record`.

    `inventory_session` is a REQUIRED keyword with no default (same posture as
    `inventory.service.register_skill_version`'s `actor_is_admin`): a new call
    site that has not thought about supersession is then a type error, not a
    silently accepted decision that the worker will throw away. `None` means
    this deployment has no inventory module wired at all - the same condition
    `reviews_router` already tests before enriching the queue - in which case
    no lifecycle exists to supersede anything and every REVIEW is decidable.
    """
    if decision not in _DECISION_TO_VERDICT:
        raise InvalidDecisionError(f"decision must be one of {sorted(_DECISION_TO_VERDICT)}")

    job = await orchestration_session.get(ScanJob, scan_id)
    if job is None:
        raise ReviewNotFoundError(f"scan {scan_id!r} not found")
    # SECURITY (SoD, coding spec §9): the whole point of this endpoint.
    #
    # 2026-07-29 (milestone F Task 18): the check used to be `reviewer ==
    # job.submitter` ALONE, and `ScanJob.submitter` is the FIRST submitter
    # only. `submit_scan` is single-flight on `cache_key`, so a second person
    # submitting byte-identical content is handed the first person's scan_job
    # and recorded in `scan_submitter` - a legitimate co-submitter whose name
    # the scalar column never mentions. Every other object-level authorization
    # in this system was converted to that association table by milestone B'
    # review C2 (see `ScanSubmitterRow`'s docstring); the review path was
    # missed, so Bob could approve content Bob himself submitted whenever
    # Alice happened to submit it first.
    #
    # `is_scan_submitter` rather than `submitter_attribution`: this is an
    # authorization decision, and that is the accessor C2 built for
    # authorization decisions (`gateway.router.get_scan`, `.get_scan_sarif`,
    # `marketplace_api.router.get_marketplace_scan`) - not a fourth query
    # shape. `submitter_attribution` is the one producer of a RESPONSE shape
    # for three endpoints; deciding authorization by testing membership in a
    # display projection would make any later change to that projection
    # (redaction, truncation) a silent change to who may approve.
    #
    # BOTH conditions, not a replacement - and the union is the safe direction
    # here specifically because SoD is a DENY rule: widening the set of people
    # refused can only refuse more. For anything `submit_scan` created the
    # scalar is already a member of the table, so the two agree; they diverge
    # only for a scan_job written by some OTHER producer that never appends an
    # association row - `reeval.controller.build_rescan_job` does exactly that
    # today. Dropping the scalar would silently disarm SoD on every such scan.
    if reviewer == job.submitter or await is_scan_submitter(
        orchestration_session, scan_id=scan_id, subject=reviewer
    ):
        raise SodViolationError("reviewer must differ from the scan's submitter (SoD)")

    verdict_row = await gate_session.get(VerdictRow, scan_id)
    if verdict_row is None:
        raise ReviewNotFoundError(f"scan {scan_id!r} has no recorded verdict yet")
    if verdict_row.verdict != "REVIEW":
        raise NotPendingReviewError(
            f"scan {scan_id!r} is not pending review (current verdict: {verdict_row.verdict!r})"
        )

    if inventory_session is not None:
        # I3: checked BEFORE anything is signed or written. A superseded entry
        # must not leave a rewritten verdict, an outbox event or a
        # `review_decided` audit intent behind - those would all record a
        # decision that never took effect.
        position = await lifecycle_position_for_content(
            inventory_session, content_hash=verdict_row.content_hash
        )
        if pending_review_is_superseded(position, review_content_hash=verdict_row.content_hash):
            # The message names the skill's own current state and nothing
            # else - same FR-API-060 posture as the sibling errors above.
            state = position.state if position is not None else "unknown"
            raise SupersededReviewError(
                f"scan {scan_id!r} reviews content this skill has already moved past "
                f"(skill is now {state!r}) - decide the current version's review instead"
            )

    new_verdict = _DECISION_TO_VERDICT[decision]
    new_reasons = [*verdict_row.reasons, f"manual review by {reviewer}: {decision} - {reason}"]

    # SECURITY (score/verdict consistency, 2026-07-26 final-review fix): a
    # manual review decision changes the verdict's band, so score must be
    # recomputed against the NEW band - otherwise a REVIEW-band score (e.g.
    # 57) would survive into a PASS/BLOCK verdict, violating the "score never
    # contradicts verdict" invariant (2026-07-24 scoring design doc) on every
    # normal review-queue decision, not just an edge case.
    #
    # pin_to_floor=False below depends on gate.decide()'s hard-gate
    # branch (gate.py's `combined_hard_gate` check) always forcing BLOCK
    # unconditionally - true today, and this function's own REVIEW-only
    # precondition (checked above) means that branch can be ruled out. It
    # does NOT rule out the separate required-engine fail-closed branch
    # (gate.py, `not scan_result.required_ok`), whose verdict is
    # policy.fail_closed_verdict - GatePolicy only forbids that being PASS
    # (models.py), so a future policy change setting it to REVIEW (every
    # deployed policy sets it to BLOCK today, incl. policies/gate/v1.yaml)
    # could reach this function with an unrecorded hard-gate hit. The score
    # would still land in-band regardless (security_score's own clamp), so
    # this is a documentation/robustness note, not a live gap - flagged by
    # the fix's own code review (2026-07-26), not fixed further since no
    # policy in this codebase configures fail_closed_verdict=REVIEW.
    result_row = await orchestration_session.get(ScanResultRow, scan_id)
    if result_row is None:
        # Not fully unreachable (see note above) but still expected to be
        # rare/never under every policy configuration this codebase actually
        # ships: every path that can produce a REVIEW verdict under the
        # standard flow (orchestration.service._try_score_and_decide) writes
        # ScanResultRow before ever calling decide_and_record; the only
        # verdict-producing path that skips it (_dead_letter_and_decide)
        # forces BLOCK under every policy shipped in this codebase today.
        # Fail loudly rather than silently scoring against zero findings if
        # this invariant is ever violated.
        raise RuntimeError(
            f"scan {scan_id!r} has a REVIEW verdict but no recorded ScanResultRow "
            "- cannot recompute score for the review decision"
        )
    findings = [deserialize_finding(f) for f in result_row.findings]
    new_score = security_score(
        Verdict[new_verdict], findings, pin_to_floor=False, weights=CategoryWeights()
    )

    jws = await signer.sign_verdict(
        {
            "content_hash": verdict_row.content_hash,
            "verdict": new_verdict,
            "policy_version": verdict_row.policy_version,
            "effective_severity": verdict_row.effective_severity,
            "score": new_score,
        }
    )
    unverified_claims = pyjwt.decode(jws, options={"verify_signature": False})

    verdict_row.verdict = new_verdict
    verdict_row.score = new_score
    verdict_row.jti = unverified_claims["jti"]
    verdict_row.jws_signature = jws
    verdict_row.reasons = new_reasons
    verdict_row.issued_at = _naive_utcnow()

    gate_session.add(
        GateOutboxRow(
            aggregate_id=scan_id,
            event_type="verdict_issued",
            payload={
                "scan_id": scan_id,
                "content_hash": verdict_row.content_hash,
                "verdict": new_verdict,
                "jti": unverified_claims["jti"],
                "jws": jws,
            },
            dispatched=False,
            created_at=_naive_utcnow(),
        )
    )
    gate_session.add(
        AuditIntentInsertOnly(
            operator=reviewer,
            action="review_decided",
            payload={
                "scan_id": scan_id,
                "decision": decision,
                "new_verdict": new_verdict,
                "reason": reason,
            },
        )
    )
    await gate_session.flush()
    return verdict_row
