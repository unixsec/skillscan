"""Reconciliation pass orchestration (coding spec §11.6, SAD §4.3).

This is the ONE place that legitimately holds sessions from TWO different
modules at once (`gate_session` + `reeval_session`) - a composition-root-
level orchestrator, not either module's own repository code. SECURITY:
`gate_session` must be opened with GATE's own credentials (svc_gate) and
`reeval_session` with REEVAL's own (svc_reeval) - `svc_reeval` has no DB
grant on `verdict` at all (policies/grants/manifest.yaml §7.2), so this
cross-module read only ever happens via `gate.service.list_issued_verdicts`
called with a gate-credentialed session, never by reeval reading the table
itself.

Idempotent-by-design: poll reconciliation re-derives every outcome from
scratch each pass, so a quarantine call that fails (or a crash before it
runs) is naturally retried on the NEXT poll pass, which will rediscover the
same ORPHAN/MISMATCH - no separate outbox/retry bookkeeping is needed here
the way gate_outbox's dispatch does, since "detect it again" already IS the
retry mechanism. A quarantine-call failure for one outcome must never abort
processing the REST of a batch (same poison-pill-isolation lesson as the M4
airlock worker-tick and this milestone's own outbox-drain fix).
"""

from __future__ import annotations

import datetime
from collections.abc import Sequence

from common.log import get_logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from monolith.modules.gate.service import list_issued_verdicts
from monolith.modules.integration_relay.marketplace import MarketplacePort

from .models import ReconciliationRow
from .quarantine import decide_quarantine_action
from .reconciliation import (
    MarketplacePublishedEntry,
    ReconciliationOutcome,
    ReconciliationSource,
    reconcile,
)

_MAX_RECONCILIATION_LIST_LIMIT = 500

_logger = get_logger("skillscan.reeval")


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


def _parse_published_entries(
    raw: Sequence[dict[str, object]],
) -> tuple[MarketplacePublishedEntry, ...]:
    return tuple(
        MarketplacePublishedEntry(
            content_hash=str(item["content_hash"]), skill_id=str(item["skill_id"])
        )
        for item in raw
    )


async def run_poll_reconciliation(
    *,
    gate_session: AsyncSession,
    reeval_session: AsyncSession,
    marketplace: MarketplacePort,
    push_auto_quarantine_enabled: bool = False,
) -> tuple[ReconciliationOutcome, ...]:
    """SAD §4.3: poll independently enumerates the marketplace's FULL
    published set and compares it against our own issued-verdict ledger -
    this is what can actually detect an ORPHAN."""
    published_raw = await marketplace.list_published()
    published = _parse_published_entries(published_raw)
    issued_verdicts = await list_issued_verdicts(gate_session)
    outcomes = reconcile(published, issued_verdicts, source=ReconciliationSource.POLL)

    await _persist_and_act(
        outcomes,
        reeval_session=reeval_session,
        marketplace=marketplace,
        push_auto_quarantine_enabled=push_auto_quarantine_enabled,
    )
    return outcomes


async def apply_push_event(
    entry: MarketplacePublishedEntry,
    *,
    gate_session: AsyncSession,
    reeval_session: AsyncSession,
    marketplace: MarketplacePort,
    push_auto_quarantine_enabled: bool = False,
) -> ReconciliationOutcome:
    """A single push-sourced event (already signature/replay-verified by the
    caller - see `reconciliation.verify_push_event_signature`) reconciled the
    same way a poll entry would be, just scoped to one entry and tagged
    `source=PUSH` so the asymmetric correction-side defaults apply."""
    issued_verdicts = await list_issued_verdicts(gate_session)
    outcomes = reconcile((entry,), issued_verdicts, source=ReconciliationSource.PUSH)
    await _persist_and_act(
        outcomes,
        reeval_session=reeval_session,
        marketplace=marketplace,
        push_auto_quarantine_enabled=push_auto_quarantine_enabled,
    )
    return outcomes[0]


async def _persist_and_act(
    outcomes: Sequence[ReconciliationOutcome],
    *,
    reeval_session: AsyncSession,
    marketplace: MarketplacePort,
    push_auto_quarantine_enabled: bool,
) -> None:
    for outcome in outcomes:
        reeval_session.add(
            ReconciliationRow(
                content_hash=outcome.content_hash,
                skill_id=outcome.skill_id,
                result=outcome.result.value,
                source=outcome.source.value,
                detected_at=_naive_utcnow(),
            )
        )
        decision = decide_quarantine_action(
            outcome, push_auto_quarantine_enabled=push_auto_quarantine_enabled
        )
        if decision.should_alert:
            _logger.warning(
                "reconciliation outcome requires attention",
                extra={
                    "context": {
                        "content_hash": outcome.content_hash,
                        "skill_id": outcome.skill_id,
                        "result": outcome.result.value,
                        "source": outcome.source.value,
                        "reason": decision.reason,
                    }
                },
            )
        if decision.should_quarantine:
            try:
                await marketplace.quarantine(
                    outcome.skill_id, decision.reason or "reconciliation mismatch"
                )
            except Exception:  # noqa: BLE001 - one failed quarantine call must not abort the batch
                _logger.exception(
                    "marketplace quarantine call failed - will retry on next reconciliation pass",
                    extra={"context": {"skill_id": outcome.skill_id}},
                )
    await reeval_session.flush()


async def list_reconciliation_outcomes(
    session: AsyncSession, *, limit: int = 100
) -> Sequence[ReconciliationRow]:
    """Most-recent-first (coding spec §9 `GET /v1/reconciliation`) - a plain
    ascending scan would return the OLDEST outcomes once this table has
    accumulated any real history, which is useless for an "ORPHAN/MISMATCH
    alerts" view (same ordering mistake caught and fixed in audit.router)."""
    bounded_limit = max(1, min(limit, _MAX_RECONCILIATION_LIST_LIMIT))
    result = await session.execute(
        select(ReconciliationRow).order_by(ReconciliationRow.id.desc()).limit(bounded_limit)
    )
    return result.scalars().all()
