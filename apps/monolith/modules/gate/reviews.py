"""Manual review decision for a REVIEW-verdict scan (coding spec §9
`POST /v1/reviews/{scan_id}`: "SoD 强制 approver≠submitter").

This is a composition-root-level orchestrator (like `reeval.service`'s
reconciliation functions) that legitimately holds TWO modules' sessions at
once: `orchestration_session` (read-only, to learn who submitted the scan -
gate has no grant on `scan_job`) and `gate_session` (to read/update the
verdict itself). SECURITY: `scan_id` is the PRIMARY KEY on `verdict`, so a
reviewed scan's row is UPDATED in place (there is no way to keep both the
original automated REVIEW verdict AND a final one as separate rows under the
current schema) - the original decision's reasons are preserved inside the
new `reasons` list, and the full history survives regardless in audit_entry
(action="review_decided"), which is never overwritten.
"""

from __future__ import annotations

import datetime

import jwt as pyjwt
from sqlalchemy.ext.asyncio import AsyncSession

from monolith.modules.orchestration.models import ScanJob

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


_DECISION_TO_VERDICT = {"approve": "PASS", "reject": "BLOCK"}


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


async def submit_review_decision(
    *,
    orchestration_session: AsyncSession,
    gate_session: AsyncSession,
    scan_id: str,
    decision: str,
    reviewer: str,
    reason: str,
    signer: SignerPort,
) -> VerdictRow:
    """SECURITY: caller must run `gate_session` inside `async with
    gate_session.begin():` - the verdict update/outbox/audit rows commit
    atomically (INV-12), same as `gate.service.decide_and_record`."""
    if decision not in _DECISION_TO_VERDICT:
        raise InvalidDecisionError(f"decision must be one of {sorted(_DECISION_TO_VERDICT)}")

    job = await orchestration_session.get(ScanJob, scan_id)
    if job is None:
        raise ReviewNotFoundError(f"scan {scan_id!r} not found")
    if reviewer == job.submitter:
        # SECURITY (SoD, coding spec §9): the whole point of this endpoint.
        raise SodViolationError("reviewer must differ from the scan's submitter (SoD)")

    verdict_row = await gate_session.get(VerdictRow, scan_id)
    if verdict_row is None:
        raise ReviewNotFoundError(f"scan {scan_id!r} has no recorded verdict yet")
    if verdict_row.verdict != "REVIEW":
        raise NotPendingReviewError(
            f"scan {scan_id!r} is not pending review (current verdict: {verdict_row.verdict!r})"
        )

    new_verdict = _DECISION_TO_VERDICT[decision]
    new_reasons = [*verdict_row.reasons, f"manual review by {reviewer}: {decision} - {reason}"]

    jws = await signer.sign_verdict(
        {
            "content_hash": verdict_row.content_hash,
            "verdict": new_verdict,
            "policy_version": verdict_row.policy_version,
            "effective_severity": verdict_row.effective_severity,
        }
    )
    unverified_claims = pyjwt.decode(jws, options={"verify_signature": False})

    verdict_row.verdict = new_verdict
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
