"""Gate outbox drain (coding spec §11.3/§11.6): `verdict_issued` events are
dispatched to the marketplace (idempotent writeback) AND, when configured, a
SIEM (coding spec §13/§16.2, `integration_relay.siem.SyslogSiemAdapter` -
2026-07-06 spec-compliance audit fix); any other event_type still just logs
(M3's original skeleton behavior, unchanged - no other producer exists yet).

SECURITY: the SIEM notifier is fire-and-forget ALONGSIDE the marketplace
writeback, not a gate on it - `notifier.emit()` never raises (see
`SyslogSiemAdapter`'s own fail-soft design note) and its outcome never affects
whether this row gets marked `dispatched` or retried. Marketplace writeback
success/failure is the only thing `dispatched`/retry logic depends on, exactly
as before this change - a missing or unreachable SIEM must never turn an
otherwise-successful marketplace dispatch into a retry loop.

SECURITY: `dispatched` is only set TRUE after the dispatch action itself
succeeds - a crash (or a marketplace-write failure) between reading and
marking dispatched leaves the row eligible for a safe, idempotent retry
(re-sending an already-applied verdict writeback is a non-issue per
`MarketplacePort.write_verdict`'s idempotency; silently dropping one would
not be). Each row is drained in its own short transaction, matching
audit.service's drain pattern (coding spec §7.3: short transactions, no
leader election).

A marketplace dispatch failure for ONE row must never abort the WHOLE batch
(same poison-pill-isolation lesson as the M4 airlock worker-tick: a single
job's failure previously could crash an entire tick) - `drain_pending_outbox`
excludes rows that just failed from re-selection for the REST of that same
batch call, so one persistently-failing event can't starve every other
pending event of the batch's attempts; it still gets retried on the next
call to `drain_pending_outbox` (e.g. the next scheduled tick).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from common.log import get_logger
from ports import NotificationPort
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .marketplace import MarketplacePort
from .models import GateOutboxReadWrite

SessionFactory = Callable[[], AsyncSession]

_logger = get_logger("skillscan.integration_relay")


@dataclass(frozen=True, slots=True)
class DrainAttempt:
    row_id: int | None  # None = no undispatched (and not-yet-excluded) row was found
    succeeded: bool  # only meaningful when row_id is not None


async def drain_one(
    session: AsyncSession,
    *,
    marketplace: MarketplacePort | None = None,
    notifier: NotificationPort | None = None,
    exclude_ids: frozenset[int] = frozenset(),
) -> DrainAttempt:
    """Drains at most one undispatched outbox row. SECURITY: caller must run
    this inside `async with session.begin():` - the row lock (`FOR UPDATE`)
    only excludes concurrent drainers for the duration of this transaction."""
    row = (
        await session.execute(
            select(GateOutboxReadWrite)
            .where(
                GateOutboxReadWrite.dispatched.is_(False),
                GateOutboxReadWrite.id.notin_(exclude_ids),
            )
            .order_by(GateOutboxReadWrite.id.asc())
            .limit(1)
            .with_for_update(skip_locked=True)
        )
    ).scalar_one_or_none()
    if row is None:
        return DrainAttempt(row_id=None, succeeded=False)

    if row.event_type == "verdict_issued" and marketplace is not None:
        try:
            await marketplace.write_verdict(
                jws=row.payload["jws"], content_hash=row.payload["content_hash"]
            )
        except Exception:  # noqa: BLE001 - any dispatch failure must retry-later, never crash the batch
            _logger.exception(
                "marketplace write_verdict failed - leaving outbox row undispatched for retry",
                extra={"context": {"outbox_id": row.id, "aggregate_id": row.aggregate_id}},
            )
            return DrainAttempt(row_id=row.id, succeeded=False)
        if notifier is not None:
            # SECURITY: fire-and-forget, never gates dispatched/retry status -
            # see this module's own docstring. SyslogSiemAdapter.emit() itself
            # never raises, but this codebase's convention elsewhere is that a
            # notification/observability sink NEVER gets to influence the
            # security-relevant control flow around it, so the same
            # broad-except-and-continue guard is applied here too rather than
            # trusting a specific adapter's own internal fail-soft promise.
            try:
                await notifier.emit({"event_type": row.event_type, "payload": row.payload})
            except Exception:  # noqa: BLE001 - SIEM delivery must never affect outbox dispatch state
                _logger.exception(
                    "SIEM notifier.emit failed - marketplace dispatch already succeeded, "
                    "outbox row still marked dispatched",
                    extra={"context": {"outbox_id": row.id, "aggregate_id": row.aggregate_id}},
                )
    else:
        # M3's original log-only relay target - still exercised for any
        # event_type this module doesn't have a real downstream target for.
        _logger.info(
            "gate_outbox event dispatched (log-only)",
            extra={
                "context": {
                    "outbox_id": row.id,
                    "aggregate_id": row.aggregate_id,
                    "event_type": row.event_type,
                    "payload": row.payload,
                }
            },
        )

    row.dispatched = True
    await session.flush()
    return DrainAttempt(row_id=row.id, succeeded=True)


async def drain_pending_outbox(
    session_factory: SessionFactory,
    *,
    batch_size: int = 50,
    marketplace: MarketplacePort | None = None,
    notifier: NotificationPort | None = None,
) -> int:
    """Drains up to `batch_size` undispatched gate_outbox rows, one per short
    transaction. Returns the number actually dispatched (rows that failed
    dispatch and were left undispatched-for-retry do NOT count, even though
    they consumed one of this call's attempts)."""
    drained = 0
    failed_ids: set[int] = set()
    for _ in range(batch_size):
        async with session_factory() as session, session.begin():
            attempt = await drain_one(
                session,
                marketplace=marketplace,
                notifier=notifier,
                exclude_ids=frozenset(failed_ids),
            )
        if attempt.row_id is None:
            break
        if attempt.succeeded:
            drained += 1
        else:
            failed_ids.add(attempt.row_id)
    return drained
