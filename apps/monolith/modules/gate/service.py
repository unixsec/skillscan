"""Gate decision + transactional outbox (coding spec §11.3, INV-12/INV-13).

SECURITY: `verdict`, `gate_outbox`, and `audit_intent` are written in ONE
database transaction - either all three commit or none do. This is what makes
the outbox pattern safe: a crash between "decide" and "notify
integration_relay" can never leave a signed verdict recorded without a
corresponding audit trail or outbox event to drive downstream notification.
"""

from __future__ import annotations

import datetime
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import jwt as pyjwt
from ports import SignerPort
from skillscan_core import AllowlistEntry, GatePolicy, ScanResult, TrustTier, VerdictResult, decide
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AllowlistRow, AuditIntentInsertOnly, GateOutboxRow, VerdictRow

# SignerPort now lives in libs/ports/signer.py (coding spec §6) - re-exported
# here so this used to be its home and every existing `from .service import
# SignerPort` import site keeps working unchanged.
__all__ = ["AllowlistError", "SignerPort"]


class AllowlistError(ValueError):
    pass


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


async def decide_and_record(
    session: AsyncSession,
    *,
    scan_id: str,
    scan_result: ScanResult,
    policy: GatePolicy,
    trust_tier: TrustTier,
    allowlist: Sequence[AllowlistEntry],
    signer: SignerPort,
    operator: str,
    now: float,
    extra_reasons: Sequence[str] = (),
) -> VerdictResult:
    """SECURITY: caller must invoke this within `async with session.begin():` (or
    equivalent) - the atomicity guarantee is the caller's transaction boundary,
    not something this function creates on its own, so it composes correctly
    with whatever else the calling request handler needs in the same transaction.
    `scan_id` is the orchestration-assigned UUID for this scan (coding spec §7.1
    scan_job.scan_id) - always supplied by the caller, never derived here.

    `extra_reasons` (D2, 2026-07-27): appended to the recorded `VerdictRow.reasons`
    (and the audit intent's mirrored `reasons`) alongside whatever `gate.decide()`
    itself produced - orchestration's sandbox-wait sweep uses this to record
    `sandbox_wait_timeout:<engines>` when a verdict is forced through without
    every sandbox engine reporting. Deliberately NOT threaded into `decide()`'s
    own pure-function signature (that would pollute the kernel with an
    orchestration-layer concern); NOT part of the signed JWS payload either -
    only `reasons` gains it, exactly like any other post-decide bookkeeping.
    """
    verdict_result = decide(scan_result, policy, trust_tier, allowlist, now=now)
    reasons = list(verdict_result.reasons) + list(extra_reasons)

    jws = await signer.sign_verdict(
        {
            "content_hash": scan_result.content_hash,
            "verdict": verdict_result.verdict.name,
            "policy_version": verdict_result.policy_version,
            "effective_severity": int(verdict_result.effective_severity),
            "score": verdict_result.score,
        }
    )
    # SECURITY: decode-without-verify is safe here specifically because we just
    # produced this token ourselves in the line above - this is not accepting an
    # externally-supplied token, only reading back our own signer's jti/exp for
    # local bookkeeping.
    unverified_claims = pyjwt.decode(jws, options={"verify_signature": False})

    session.add(
        VerdictRow(
            scan_id=scan_id,
            content_hash=scan_result.content_hash,
            verdict=verdict_result.verdict.name,
            policy_version=verdict_result.policy_version,
            jti=unverified_claims["jti"],
            jws_signature=jws,
            effective_severity=int(verdict_result.effective_severity),
            score=verdict_result.score,
            reasons=reasons,
            # SECURITY (2026-07-30): the gate's OWN answer, persisted, rather
            # than something a reader reconstructs from which other rows happen
            # to exist. See `VerdictRow.fail_closed`.
            fail_closed=verdict_result.fail_closed,
            issued_at=_naive_utcnow(),
        )
    )
    session.add(
        GateOutboxRow(
            aggregate_id=scan_id,
            event_type="verdict_issued",
            payload={
                "scan_id": scan_id,
                "content_hash": scan_result.content_hash,
                "verdict": verdict_result.verdict.name,
                "jti": unverified_claims["jti"],
                # SECURITY: svc_relay has NO grant on `verdict` (policies/grants/
                # manifest.yaml §7.2: "仅排空, 不碰 verdict") - the outbox payload
                # must carry the actual JWS itself, since relay has no other way
                # to obtain it for MarketplacePort.write_verdict.
                "jws": jws,
            },
            dispatched=False,
            created_at=_naive_utcnow(),
        )
    )
    session.add(
        AuditIntentInsertOnly(
            operator=operator,
            action="verdict_issued",
            payload={
                "scan_id": scan_id,
                "content_hash": scan_result.content_hash,
                "verdict": verdict_result.verdict.name,
                "policy_version": verdict_result.policy_version,
                "reasons": reasons,
            },
        )
    )
    await session.flush()
    return verdict_result


@dataclass(frozen=True, slots=True)
class IssuedVerdict:
    """Plain-data projection of `VerdictRow` (coding spec §11.6 reconciliation).
    SECURITY: `svc_reeval` has no GRANT on `verdict` at all (policies/grants/
    manifest.yaml §7.2) - reconciliation never reads this table directly.
    Whatever orchestrates a reconciliation pass must call
    `list_issued_verdicts` using a session opened with GATE's own credentials,
    then hand these plain values (not ORM rows, not the session) across the
    module boundary into `reeval.reconciliation.reconcile`.

    SECURITY (2026-07-29, milestone F Task 11 follow-up I4): `issued_at`
    carries because `verdict`'s primary key is `scan_id`, NOT `content_hash` -
    one package can and does accumulate several verdicts (a reeval-triggered
    rescan under a new toolchain_digest is a second scan_job over the same
    bytes). `reconcile` needs to know which of them is CURRENT; without this
    field it could only take whichever row the driver happened to yield last,
    and a stale BLOCK beating a current PASS produces a spurious MISMATCH and,
    on the poll path, an automatic quarantine of a legitimately published
    skill. Required, no default: a call site that cannot say when a verdict
    was issued cannot participate in that ordering, and a default would let it
    silently pretend otherwise."""

    content_hash: str
    verdict: str
    issued_at: datetime.datetime


async def list_issued_verdicts(session: AsyncSession) -> Sequence[IssuedVerdict]:
    """Every issued verdict, newest first. NOT one row per content_hash -
    the full ledger is what reconciliation's ORPHAN detection is defined
    against, and collapsing it here would hide the duplicates rather than
    order them. `reconcile` picks the current verdict per hash from this; the
    ordering is here so the rows arrive in the order that choice is about,
    rather than in whatever order the driver happens to yield."""
    result = await session.execute(
        select(VerdictRow.content_hash, VerdictRow.verdict, VerdictRow.issued_at).order_by(
            VerdictRow.issued_at.desc()
        )
    )
    return tuple(
        IssuedVerdict(content_hash=row.content_hash, verdict=row.verdict, issued_at=row.issued_at)
        for row in result
    )


def _allowlist_row_to_entry(row: AllowlistRow) -> AllowlistEntry:
    return AllowlistEntry(
        scope_type=row.scope_type,
        scope_value=row.scope_value,
        rule_id=row.rule_id,
        expires_at=row.expires_at.replace(tzinfo=datetime.UTC).timestamp(),
        approved_by=row.approved_by,
        requested_by=row.requested_by,
        reason=row.reason or "",
    )


async def list_active_allowlist_rows(
    session: AsyncSession, *, now: float
) -> Sequence[AllowlistRow]:
    """SECURITY (INV-8): "active" means not yet expired - an expired row is
    excluded here rather than deleted, preserving it for audit/history until
    an explicit revoke removes it. Returns the raw ORM rows (with `id`) for
    admin-listing/revoke use cases - see `list_active_allowlist_entries` for
    the core-domain-type projection `decide()` actually consumes (which has
    no `id` field at all, since the gate's decision logic never needs one)."""
    now_dt = datetime.datetime.fromtimestamp(now, tz=datetime.UTC).replace(tzinfo=None)
    result = await session.execute(select(AllowlistRow).where(AllowlistRow.expires_at > now_dt))
    return result.scalars().all()


async def list_active_allowlist_entries(
    session: AsyncSession, *, now: float
) -> Sequence[AllowlistEntry]:
    rows = await list_active_allowlist_rows(session, now=now)
    return tuple(_allowlist_row_to_entry(row) for row in rows)


async def grant_allowlist_entry(
    session: AsyncSession,
    *,
    scope_type: str,
    scope_value: str,
    rule_id: str,
    expires_at: float,
    approved_by: str,
    requested_by: str,
    reason: str = "",
) -> AllowlistRow:
    """SECURITY (INV-8 four-eyes + mandatory expiry): validated by
    constructing a real `AllowlistEntry` first - its own `__post_init__`
    already enforces approved_by != requested_by, expires_at > 0, and valid
    scope_type/non-empty scope_value/rule_id (skillscan_core.models), so this
    reuses that invariant rather than re-implementing it. Caller must run
    inside `async with session.begin():` - audited in the SAME transaction
    (INV-12), same pattern as gate.policy_workflow."""
    try:
        AllowlistEntry(
            scope_type=scope_type,
            scope_value=scope_value,
            rule_id=rule_id,
            expires_at=expires_at,
            approved_by=approved_by,
            requested_by=requested_by,
            reason=reason,
        )
    except ValueError as exc:
        raise AllowlistError(str(exc)) from exc

    row = AllowlistRow(
        id=str(uuid.uuid4()),
        scope_type=scope_type,
        scope_value=scope_value,
        rule_id=rule_id,
        expires_at=datetime.datetime.fromtimestamp(expires_at, tz=datetime.UTC).replace(
            tzinfo=None
        ),
        approved_by=approved_by,
        requested_by=requested_by,
        reason=reason,
    )
    session.add(row)
    session.add(
        AuditIntentInsertOnly(
            operator=approved_by,
            action="allowlist_granted",
            payload={
                "allowlist_id": row.id,
                "scope_type": scope_type,
                "scope_value": scope_value,
                "rule_id": rule_id,
                "requested_by": requested_by,
            },
        )
    )
    await session.flush()
    return row


async def revoke_allowlist_entry(session: AsyncSession, *, allowlist_id: str, actor: str) -> None:
    """SECURITY: caller must run inside `async with session.begin():`. Raises
    `AllowlistError` for an unknown id - never a silent no-op, so a caller
    can't mistake "already gone" for "just revoked"."""
    row = await session.get(AllowlistRow, allowlist_id)
    if row is None:
        raise AllowlistError(f"allowlist entry {allowlist_id!r} not found")
    await session.delete(row)
    session.add(
        AuditIntentInsertOnly(
            operator=actor,
            action="allowlist_revoked",
            payload={
                "allowlist_id": allowlist_id,
                "scope_type": row.scope_type,
                "scope_value": row.scope_value,
                "rule_id": row.rule_id,
            },
        )
    )
    await session.flush()


async def get_verdict_view(session: AsyncSession, *, scan_id: str) -> dict[str, Any] | None:
    """The externally-projectable fields of one verdict as a plain dict, or
    None when this scan has no verdict yet.

    ARCHITECTURE (scripts/check_import_boundaries.py): same posture as
    `list_issued_verdicts` above - `marketplace_api.router` needs a verdict to
    project, and gets plain values rather than a `VerdictRow` and rather than
    a licence to `select()` against gate's private table itself.

    The key names are the ones `marketplace_api.views.project_skill_verdict`
    reads.
    `issued_at` is serialized here (naive-UTC `.isoformat()`, the convention
    every other router in this codebase uses) because `views` is a pure
    function with no clock and no I/O - handing it a `datetime` would push a
    serialization decision into the projection layer.

    Deliberately NOT included: `jti`, `content_hash`, `effective_severity`,
    `reasons`. They are internal adjudication detail (spec §5.3) - anything
    returned here is one `views` change away from being part of the external
    contract, so the narrow set is the safe default.

    `fail_closed` IS included (2026-07-30). It is not adjudication detail but a
    fact about the answer being handed over - "this BLOCK means we could not
    complete the scan", which the external surface already published as a field
    and, until this column existed, published WRONGLY: it was inferred from the
    absence of a `ScanResultRow`, a signature only the dead-letter path has.
    """
    row = (
        await session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
    ).scalar_one_or_none()
    if row is None:
        return None
    return {
        "verdict": row.verdict,
        "score": row.score,
        "policy_version": row.policy_version,
        "issued_at": row.issued_at.isoformat(),
        "jws_signature": row.jws_signature,
        "fail_closed": bool(row.fail_closed),
    }


async def list_pending_reviews(session: AsyncSession) -> Sequence[VerdictRow]:
    """SECURITY (coding spec §9 `GET /v1/reviews`): the review queue is
    exactly the scans whose CURRENT verdict is REVIEW - once a decision is
    submitted (`gate.reviews.submit_review_decision`), the row's verdict is
    updated in place and it naturally drops out of this query."""
    result = await session.execute(select(VerdictRow).where(VerdictRow.verdict == "REVIEW"))
    return result.scalars().all()
