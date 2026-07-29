"""Retention for `scan_engine_health` (milestone C Task 9, design §3.1).

Task 8 shipped the table; design §3.1 records that retention "不存在" for any
of this telemetry, and that is still true of everything else here - findings
blobs have no TTL and no pruning job exists anywhere (`blobstore.py`'s TTL
serves only the unrelated share probe, :271-331). This module is the first
retention path in the system, and it covers exactly one table.

WHY THIS TABLE FIRST, and an honest correction to the premise. Health rows are
15 per scan against `scan_result`'s 1, so the ROW count grows 15x faster than
anything else. In BYTES it does not: measured on the dev VM (2026-07-29,
MySQL 8.0.46), a `scan_engine_health` row costs 334 B (116 B data + 218 B in
the two secondary indexes - the indexes cost 1.9x the data), so one scan's 15
rows cost 5.0 KB, while that same scan's single `scan_result` row costs 7.6 KB
(4,734,976 B + 65,536 B over 632 rows). The health table is CHEAPER per scan
than the row it annotates. Retention here is therefore not a disk-space rescue;
it is a bound on a telemetry table that Task 10 will scan by `engine_name`, and
the point at which this system acquires a retention mechanism at all.


THE WINDOW: 26 DAYS, AND WHERE THE NUMBER COMES FROM
====================================================

Measured on the dev VM, 2026-07-29. 860 scans spanning 2026-07-22 05:42:30 to
2026-07-29 01:45:52 (6.836 days, 125.8 scans/day; heavily bursty - a 481-skill
bulk import produced 266/474/95 on three consecutive days, then a trickle of
1/0/2/17/5).

The window is the smallest value that satisfies every question a read path
actually asks. Each floor below is a MEASUREMENT, not a preference:

  R1  "Is this engine healthy now" must never have zero observations to answer
      from. The longest observed gap between two consecutive scans on this
      deployment is 45.49 h.                                     -> >  1.90 d

  R2  "Did this engine change when the toolchain changed" must be answerable
      at the moment of a rotation, so the window must hold the whole previous
      toolchain generation. `scan_job` shows 5 distinct `toolchain_digest`
      values with inter-rotation intervals of 0.41 / 1.61 / 3.34 / 0.08 days;
      the longest is 3.34 d, and answering across one needs two.
                                                                 -> >= 6.68 d

  R3  "Has osv-scanner degraded since we upgraded it" must be answerable after
      an engine version bump, so the window must hold the whole previous
      ENGINE version. `vendor/engines.lock.yaml` has three revisions
      (2026-07-07 00:41, 2026-07-09 22:16, 2026-07-22 22:34) - intervals of
      2.90 d and 13.01 d. Longest is 13.01 d, and answering across one needs
      two.                                                       -> >= 26.02 d

  R4  The slowest configured periodic consumer. `report_schedule` is empty on
      the VM, so nothing binds here today.                        -> no floor

R3 binds. **26 days.**

WHAT IT COSTS, so the choice is priced rather than assumed. At 334 B/row and
15 rows/scan: 5.0 KB per scan.

    window   at 125.8 scans/day (observed mean)   at 474 scans/day (peak day)
    ------   ---------------------------------   ---------------------------
      7 d                    4.4 MB                        16.6 MB
     26 d                   16.4 MB                        61.7 MB
     90 d                   56.7 MB                       213.7 MB
    365 d                  230.0 MB                       866.6 MB

Cost does not bind at any window under a year. That matters for how the number
was chosen: it means 26 is the read path's answer and not a budget's, and it
means the knob below can be raised a long way without a capacity conversation.
What cost DOES rule out is "keep forever", which is unbounded index growth on
the one column Task 10 will range-scan.

HONESTY ABOUT THE SAMPLE. R3's 13.01 d comes from three lock-file revisions
over 22 days of repository history. That is a short sample and it almost
certainly UNDERSTATES a steady-state upgrade cadence (a deployment that re-pins
OSV/semgrep/bandit quarterly has a 90-day interval, and would want 180). The
derivation is written down here precisely so it can be redone against real
numbers rather than re-argued, and the value is an env knob so redoing it needs
no migration and no rebuild.


HEALTH ROWS MUST NOT OUTLIVE THE SCAN THEY DESCRIBE
===================================================

The intended relationship is containment, in one direction only:

    lifetime(health rows for scan S)  <=  lifetime(S)

A health row is keyed on `scan_id` and says nothing interpretable without the
scan: "aig-mcp-scan never reported" is a fact ABOUT a submission, and an
orphan carries no content hash, no submitter, no verdict, nothing to join to.

Today the containment holds trivially and vacuously - nothing anywhere deletes
a `scan_job`, so scans are immortal and these rows expire at 26 days. The
question becomes real the moment scan retention is built, and the obligation
then falls on THAT code, not on this sweep: deleting a scan must delete its
health rows in the same transaction. This sweep cannot enforce it (a scan
pruned at 10 days would leave 16 days of orphans behind), and there is no FK to
enforce it either - `d5a1c07f9e42` explains why this repo adds FKs only within
a module's owned set.

No orphan sweep is implemented here, deliberately. Nothing produces an orphan,
so such a sweep would be code with no live trigger - the failure mode this
milestone has already found four times over.
"""

from __future__ import annotations

import datetime
import os
from collections.abc import Callable
from typing import Any, cast

from common.log import get_logger
from sqlalchemy import CursorResult, Delete, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from .models import ScanEngineHealthRow

# Same shape as `service.SessionFactory`, spelled again here rather than
# imported from it: `service` is where a future caller of this sweep would most
# naturally live, and importing it from there would make that a circular import
# instead of a one-line edit. Nothing about a `Callable[[], AsyncSession]` is a
# registry that could drift.
SessionFactory = Callable[[], AsyncSession]

_logger = get_logger("skillscan.orchestration.retention")

RETENTION_DAYS_ENV = "SKILLSCAN_ENGINE_HEALTH_RETENTION_DAYS"

# See the module docstring for the four measured requirements this satisfies.
# R3 (2 x the longest observed interval between `vendor/engines.lock.yaml`
# revisions, 13.01 d) is the binding one. Deliberately not a round number: a
# round number would have to be justified after the fact, and this one is
# reproducible from `git log -- vendor/engines.lock.yaml`.
DEFAULT_RETENTION_DAYS = 26.0

# A deployment may shorten the window, but not to zero. `retention_days=0`
# means "delete every health row the instant it is written", which silently
# empties the table Task 10 reads; a negative value puts the cutoff in the
# FUTURE and deletes rows a scan currently being decided just wrote. Neither is
# ever what someone meant to type, so both are refused in favour of the default.
MINIMUM_RETENTION_DAYS = 1.0

# Rows deleted per statement. MEASURED on the VM against 150,000 seeded rows:
# LIMIT 1000 -> 5.6 ms, LIMIT 5000 -> 25 ms, LIMIT 20000 -> 108 ms. 1000 keeps
# a single statement's lock hold in the single-digit milliseconds.
RETENTION_BATCH = 1000

# Statements per pass. 20 x 1000 = 20,000 rows = 1,333 scans' worth, which is
# 2.8x the busiest day ever observed on this deployment (474 scans), for about
# 110 ms of database time. One hourly pass therefore absorbs a multi-day
# backlog, and 24 passes/day drain 67x the peak observed production rate.
RETENTION_MAX_BATCHES = 20

# SECURITY/CONCURRENCY - the whole reason this sweep does not fight the writer.
# MEASURED on the VM, 2026-07-29, MySQL 8.0.46, default REPEATABLE READ:
#
#   isolation          delete             concurrent INSERT at recorded_at=NOW()
#   ----------------   ----------------   --------------------------------------
#   REPEATABLE READ    unbounded (109k)   ER_LOCK_WAIT_TIMEOUT (1205), then 1.54 s
#   REPEATABLE READ    LIMIT 1000         ~1.0 ms
#   READ COMMITTED     unbounded (109k)   ~1.7 ms
#   READ COMMITTED     LIMIT 1000         ~1.0 ms
#
# Under REPEATABLE READ, InnoDB takes NEXT-KEY locks: `performance_schema.
# data_locks` shows the bounded delete holding 1000 `X,REC_NOT_GAP` locks on
# the clustered index plus 1005 `X` (record+gap) locks on
# `idx_engine_health_recorded`. `scan_id` is a random UUID, so the gaps a
# delete locks in the clustered index are scattered across the whole key space,
# and a writer inserting a fresh random `scan_id` lands inside one of them with
# probability proportional to the fraction of the table being deleted. An
# unbounded delete locks ~73% of it and the writer stops - and that writer is
# the SCORING TRANSACTION, so a lock-wait timeout there aborts the whole decide,
# not merely the telemetry insert.
#
# READ COMMITTED takes no gap locks at all, so the conflict is not made
# unlikely, it is made impossible: the sweep locks only rows it is deleting,
# which are 26 days old, and the writer only ever inserts rows at NOW(). The
# batch limit is still applied, for statement duration / undo / binlog size -
# but correctness no longer depends on picking the batch size correctly, which
# is the difference between a mitigation and a fix.
#
# Set as a SQLAlchemy execution option rather than a bare `SET SESSION ...`, so
# SQLAlchemy restores the connection's isolation level on checkin instead of
# leaking READ COMMITTED to whatever borrows that pooled connection next.
RETENTION_ISOLATION_LEVEL = "READ COMMITTED"


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


def retention_days() -> float:
    """The configured window, read from the environment ON EVERY CALL.

    Deliberately a function and not `float(os.environ.get(...))` evaluated at
    import into a module constant. `gateway.auth.middleware.session_ttl_from_env`
    records what that costs here: a guard asserted against a constant the
    implementation itself reads can only ever compare a value to itself, and a
    test that sets the variable observes nothing.

    A value that is unparseable or below `MINIMUM_RETENTION_DAYS` falls back to
    the default and logs a WARNING naming the variable and the value. Not a
    raise, unlike `session_ttl_from_env`: that one guards a security ceiling
    where refusing to start is the safe outcome, whereas refusing to start over
    a typo in a telemetry-retention knob would take the entire scanner down.
    Not a silent clamp either - the operator asked for something and must be
    told they did not get it.
    """
    raw = os.environ.get(RETENTION_DAYS_ENV)
    if raw is None:
        return DEFAULT_RETENTION_DAYS
    try:
        days = float(raw)
    except ValueError:
        _logger.warning(
            "engine-health retention window is not a number - using the default",
            extra={"context": {"variable": RETENTION_DAYS_ENV, "value": raw}},
        )
        return DEFAULT_RETENTION_DAYS
    if days < MINIMUM_RETENTION_DAYS:
        _logger.warning(
            "engine-health retention window is below the minimum - using the default",
            extra={
                "context": {
                    "variable": RETENTION_DAYS_ENV,
                    "value": raw,
                    "minimum_days": MINIMUM_RETENTION_DAYS,
                    "default_days": DEFAULT_RETENTION_DAYS,
                }
            },
        )
        return DEFAULT_RETENTION_DAYS
    return days


def retention_cutoff(now: datetime.datetime, *, days: float) -> datetime.datetime:
    """Rows with `recorded_at` STRICTLY BEFORE this are eligible for deletion.

    `recorded_at`, never `scan_job.created_at`: the two differ by the whole
    queue backlog (that difference is F-2, the 2026-07-27 review finding that
    made `sweep_sandbox_wait_timeouts` sign floor-only verdicts), and this table
    has its own timestamp and its own index on it for exactly this reason.
    """
    return now - datetime.timedelta(days=days)


def retention_delete_stmt(cutoff: datetime.datetime, *, limit: int) -> Delete:
    """One bounded delete statement.

    Exposed as a builder so a test can compile it and assert on the SQL without
    a database - the `LIMIT` and the strict `<` are the two properties that
    matter and both are invisible in the Python call site.

    `<`, not `<=`: a row recorded exactly at the cutoff is inside the window.
    The boundary is arbitrary either way at microsecond resolution, but it has
    to be asserted somewhere or a later edit flips it unnoticed.

    NO `SELECT ... ORDER BY ... LIMIT 1 ... FOR UPDATE` PRECEDES THIS, and none
    ever should. That shape forked silently under concurrency in this
    repository's audit chain (2026-07 incident, saved to memory): two workers
    read the same "next" row and both proceeded. A single `DELETE ... LIMIT` has
    no read-then-act window to fork in, and the sweep is indifferent to WHICH
    rows a batch takes because every eligible row is going anyway.
    """
    return (
        delete(ScanEngineHealthRow)
        .where(ScanEngineHealthRow.recorded_at < cutoff)
        .with_dialect_options(mysql_limit=limit)
    )


async def sweep_engine_health_retention(
    orchestration_session_factory: SessionFactory,
    *,
    now: datetime.datetime | None = None,
    days: float | None = None,
    batch_size: int = RETENTION_BATCH,
    max_batches: int = RETENTION_MAX_BATCHES,
) -> int:
    """Delete `scan_engine_health` rows older than the retention window.

    Returns the number of rows deleted this pass.

    BOUNDED, in three independent ways, because an unbounded pass is the
    failure mode measured above:

      1. `batch_size` per statement (1000 rows, ~6 ms of lock hold),
      2. `max_batches` per pass (20, so a pass is ~110 ms of database time
         whatever the backlog is), and
      3. the cutoff is computed ONCE at the top of the pass, so a long pass
         cannot walk forward into rows that came inside the window while it ran.

    WHAT HAPPENS WHEN A PASS OVERLAPS A BURST OF SCANS. Nothing contends: the
    burst writes rows at `recorded_at = NOW()` and this deletes rows 26 days
    older, and READ COMMITTED means the delete holds no gap locks that a fresh
    insert could land in (see `RETENTION_ISOLATION_LEVEL`). If the burst is
    large enough that the backlog exceeds one pass's budget, the pass simply
    stops at the budget and the next pass continues - the sweep is idempotent
    and convergent, it never needs to finish in one go, and it never grows its
    own footprint to catch up. A pass that exhausts its budget logs a WARNING,
    because a backlog that persists across passes is the signal that the budget
    or the sweep interval is wrong.

    NEVER RAISES. This runs inside `worker_tick`, which has no per-step
    try/except - a raise here would abort every step ordered after it. Nothing
    in this system is more important than deciding scans, and retention is the
    least important thing in it, so a database error is logged and the pass
    reports what it managed to delete.
    """
    window_days = days if days is not None else retention_days()
    cutoff = retention_cutoff(now if now is not None else _naive_utcnow(), days=window_days)

    deleted = 0
    for _ in range(max_batches):
        try:
            async with orchestration_session_factory() as session:
                # Applied to the connection BEFORE the transaction opens -
                # InnoDB fixes the isolation level at transaction start, and
                # `session.connection()` is the documented way to get one
                # transaction's worth of a different level. See
                # RETENTION_ISOLATION_LEVEL for why it is not the default here.
                await session.connection(
                    execution_options={"isolation_level": RETENTION_ISOLATION_LEVEL}
                )
                # `cast` for the same reason `worker.advance_scanned_toolchain_
                # digests` does it: `AsyncSession.execute` is typed as
                # returning `Result`, which has no `.rowcount`, and rowcount is
                # the whole answer here - it reports the rows that actually
                # WENT, not the batch we asked for.
                result = cast(
                    CursorResult[Any],
                    await session.execute(retention_delete_stmt(cutoff, limit=batch_size)),
                )
                batch = int(result.rowcount or 0)
                await session.commit()
        except SQLAlchemyError:
            _logger.exception(
                "engine-health retention sweep failed - will retry on the next pass",
                extra={"context": {"cutoff": cutoff.isoformat(), "deleted_so_far": deleted}},
            )
            return deleted
        deleted += batch
        if batch < batch_size:
            # The last batch came back short, so nothing eligible is left. Stop
            # rather than spend the remaining budget on empty statements.
            break
    else:
        _logger.warning(
            "engine-health retention sweep exhausted its per-pass budget - "
            "a backlog remains and will be taken up by the next pass",
            extra={
                "context": {
                    "cutoff": cutoff.isoformat(),
                    "deleted": deleted,
                    "batch_size": batch_size,
                    "max_batches": max_batches,
                }
            },
        )

    if deleted:
        _logger.info(
            "engine-health retention sweep deleted expired rows",
            extra={
                "context": {
                    "cutoff": cutoff.isoformat(),
                    "deleted": deleted,
                    "retention_days": window_days,
                }
            },
        )
    return deleted
