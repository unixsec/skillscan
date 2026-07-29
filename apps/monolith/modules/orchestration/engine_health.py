"""Read path for `scan_engine_health` (milestone C Task 10, design §3 + §9.7/§9.8).

WHICH QUESTION THIS ANSWERS, and why the shape follows from it. Task 8's table
is per-(scan, engine): one row per engine per scored scan. Task 12 drew the
boundary explicitly in `common/observability.py` - the Prometheus registry holds
process-wide, unlabeled, unretained aggregates; THIS is the per-scan, queryable,
retained side. So an "engine health" read that silently folded every row ever
stored into one number would be answering the metrics question with the health
table's data, and would answer it badly: the totals would drift with retention
and with deployment age rather than with engine behaviour.

The window is therefore counted in SCANS, not in days, and it is the N most
recent scans THAT STILL HAVE ROWS:

  * Task 9 is choosing a retention window concurrently. When the sweep deletes
    older rows, a scan-counted window simply contains fewer scans and says so
    (`EngineHealthWindow.observed_scans`) - it never turns "we stopped keeping
    the history" into "the engine stopped reporting". A day-counted window
    would have made those two indistinguishable the moment retention was
    shorter than the window.
  * `observed_scans == 0` is its own answer ("nothing is retained"), NOT an
    engine-level statement about anything.

READ-ONLY, and deliberately no `FOR UPDATE` anywhere: the writer holds the
scoring transaction (`service.aggregate_and_decide`) and Task 9's sweep deletes
by `recorded_at`. A read path that took row locks here would contend with both,
and this repository already has one post-mortem about a `SELECT ... ORDER BY
... LIMIT 1 ... FOR UPDATE` forking under concurrency.

WHAT THIS MODULE REFUSES TO DO: it does not explain `not_reported`. That value
is one bucket for five causes (never dispatched, still running past the wait,
crashed before writing, admin-disabled, never constructed on this deployment) -
`aggregate.EngineReportState`'s own docstring says so and says a reader must
JOIN an authoritative source rather than guess. Two of the five are knowable
authoritatively, and both live outside orchestration (Redis' disabled set; the
engine-runner's LLM gate), so the join happens in `admin.engine_registry`
alongside those sources. Guessing here would produce a value that reads exactly
like an observation.
"""

from __future__ import annotations

import dataclasses
import datetime
from collections.abc import Iterable, Sequence

from skillscan_core import EngineStatus
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .aggregate import EngineReportState
from .models import ScanEngineHealthRow

#: How many recent scans a read covers when the caller does not say. 50 is
#: chosen against the write rate, not against a duration: ~15 rows per scan, so
#: this reads ~750 rows - small enough to aggregate in Python (which keeps the
#: whole summary testable with no database at all) and long enough that one
#: unlucky scan does not define an engine's row in the console.
DEFAULT_WINDOW_SCANS = 50

#: Hard ceiling on `requested_scans`. Bounds the row fetch (~3000 rows) so this
#: endpoint cannot be turned into a full-table read by a query parameter.
MAX_WINDOW_SCANS = 200

#: The `EngineStatus` values that mean the engine itself reported a failure.
#: `PARTIAL` is deliberately NOT here: a partial result is a degraded success
#: that still contributed findings, and folding it into the failure count would
#: overstate breakage. It gets its own counter instead.
FAILED_ENGINE_STATUSES = frozenset({EngineStatus.ERROR.value, EngineStatus.TIMEOUT.value})


@dataclasses.dataclass(frozen=True, slots=True)
class EngineHealthObservation:
    """One `scan_engine_health` row as read back.

    A plain dataclass rather than the ORM row so `summarize_engine_health`
    below is a pure function over values: every aggregation rule in this module
    is then testable without MySQL, which matters because the tests that DO
    need MySQL can only run on the dev VM.
    """

    scan_id: str
    engine_name: str
    report_state: str
    engine_status: str | None
    analyze_duration_ms: int | None
    finding_count: int | None
    error: str | None
    recorded_at: datetime.datetime


@dataclasses.dataclass(frozen=True, slots=True)
class EngineHealthCounts:
    """How the window's rows for one engine break down.

    EXHAUSTIVE over (report_state x engine_status) by construction - the five
    fields sum to `EngineHealthSummary.observed_scans`, and a test asserts that
    - so a status this module has not been taught cannot be silently dropped
    into an existing bucket. `not_reported` and `error` are separate fields for
    the same reason they are separate columns: that distinction is acceptance
    criterion 8.
    """

    ok: int = 0
    partial: int = 0
    error: int = 0
    not_reported: int = 0
    unreadable: int = 0

    @property
    def total(self) -> int:
        return self.ok + self.partial + self.error + self.not_reported + self.unreadable

    @property
    def reported(self) -> int:
        """Rows where the engine-runner actually delivered a result, whatever
        the result said.

        This is EVIDENCE, and it is the only evidence the monolith has about
        what the engine-runner really constructs. Everything else the console
        says on that subject is inference from the monolith's own environment -
        see `admin.engine_registry.not_reported_attribution`, which uses this
        to refuse to contradict it.

        Derived from the three `reported` buckets rather than counted
        separately, so an engine_status the aggregation grows later cannot make
        this number and `_count`'s disagree."""
        return self.ok + self.partial + self.error


@dataclasses.dataclass(frozen=True, slots=True)
class EngineHealthSummary:
    """One engine's behaviour across the window, plus its most recent row verbatim.

    BOTH, not one or the other. The counts answer "is this engine reliable";
    the `last_*` fields answer "what happened the last time we looked", which
    is the question an operator has while a scan is stuck. Reporting only the
    counts would hide a currently-broken engine behind 49 good scans; reporting
    only the last row would make one flake look like an outage.

    `last_analyze_duration_ms` carries Task 7's THREE states unchanged - an
    integer (measured), `0` (also measured: in-process floor engines really do
    finish in under half a millisecond, since `airlock.elapsed_ms` rounds), and
    `None` (NOT measured - a blob written by an engine-runner image older than
    Task 7, or a row for an engine we never heard from). Collapsing `0` and
    `None` at any layer destroys the distinction two prior tasks preserved on
    purpose, so nothing in this module substitutes a default for `None`.
    """

    engine_name: str
    observed_scans: int
    counts: EngineHealthCounts
    last_scan_id: str
    last_recorded_at: datetime.datetime
    last_report_state: str
    last_engine_status: str | None
    last_analyze_duration_ms: int | None
    last_finding_count: int | None
    last_error: str | None
    #: How many rows in the window carried a duration at all. `0` alongside a
    #: non-zero `observed_scans` is the honest way to say "this engine reports,
    #: but nothing has ever timed it here" - which is what an un-upgraded
    #: engine-runner image looks like from the read side.
    measured_duration_count: int
    #: The slowest MEASURED run in the window, or None if none was measured.
    #: This is the number Task 4's open question needs (the SUM of per-engine
    #: worst cases against the scan deadline), which is why it is a max rather
    #: than a mean.
    max_analyze_duration_ms: int | None


@dataclasses.dataclass(frozen=True, slots=True)
class EngineHealthWindow:
    """What the numbers above are actually computed over - reported alongside
    them, never implied. The console renders this as a caption; without it a
    reader cannot tell "0 failures in 50 scans" from "0 failures in 0 scans"."""

    requested_scans: int
    observed_scans: int
    started_at: datetime.datetime | None
    ended_at: datetime.datetime | None


@dataclasses.dataclass(frozen=True, slots=True)
class EngineHealthReport:
    window: EngineHealthWindow
    engines: tuple[EngineHealthSummary, ...]


def _recency_key(observation: EngineHealthObservation) -> tuple[datetime.datetime, str]:
    """Total order over rows. `recorded_at` alone is not one: every engine of a
    single scan shares one timestamp (`service.aggregate_and_decide` takes it
    once for the whole set), and two scans decided inside the same clock tick
    would otherwise pick a winner by dict iteration order."""
    return (observation.recorded_at, observation.scan_id)


def summarize_engine_health(
    observations: Iterable[EngineHealthObservation], *, requested_scans: int
) -> EngineHealthReport:
    """Fold rows into one summary per engine. PURE - no session, no clock.

    Engines are returned sorted by name; only engines that actually have rows
    in the window appear. An engine the deployment knows about but that has no
    row here is NOT represented as a zeroed entry, because "we have no
    observation of this engine" and "we observed this engine not reporting"
    are different facts and this repository has already paid for merging that
    exact pair once (`unavailable_engine_result`'s fabricated ERROR). The
    caller joins against its own engine universe and renders the absence.
    """
    rows = sorted(observations, key=_recency_key)
    by_engine: dict[str, list[EngineHealthObservation]] = {}
    for row in rows:
        by_engine.setdefault(row.engine_name, []).append(row)

    summaries: list[EngineHealthSummary] = []
    for engine_name in sorted(by_engine):
        engine_rows = by_engine[engine_name]
        last = engine_rows[-1]  # `rows` is ascending by `_recency_key`
        # `is not None`, never a truthiness test: `0` is a real measurement and
        # `if r.analyze_duration_ms` would drop every floor engine's timing.
        durations = [
            r.analyze_duration_ms for r in engine_rows if r.analyze_duration_ms is not None
        ]
        summaries.append(
            EngineHealthSummary(
                engine_name=engine_name,
                observed_scans=len(engine_rows),
                counts=_count(engine_rows),
                last_scan_id=last.scan_id,
                last_recorded_at=last.recorded_at,
                last_report_state=last.report_state,
                last_engine_status=last.engine_status,
                last_analyze_duration_ms=last.analyze_duration_ms,
                last_finding_count=last.finding_count,
                last_error=last.error,
                measured_duration_count=len(durations),
                max_analyze_duration_ms=max(durations) if durations else None,
            )
        )

    scan_ids = {row.scan_id for row in rows}
    window = EngineHealthWindow(
        requested_scans=requested_scans,
        observed_scans=len(scan_ids),
        started_at=rows[0].recorded_at if rows else None,
        ended_at=rows[-1].recorded_at if rows else None,
    )
    return EngineHealthReport(window=window, engines=tuple(summaries))


def _count(engine_rows: Sequence[EngineHealthObservation]) -> EngineHealthCounts:
    """SECURITY/HONESTY: an unrecognised `report_state` or `engine_status` falls
    into no bucket, so the counts stop summing to `observed_scans` and the
    exhaustiveness test goes red. Deliberately not an `else: error += 1`
    fallback, which would report a value nobody has interpreted as a failure."""
    ok = partial = error = not_reported = unreadable = 0
    for row in engine_rows:
        if row.report_state == EngineReportState.NOT_REPORTED.value:
            not_reported += 1
        elif row.report_state == EngineReportState.UNREADABLE.value:
            unreadable += 1
        elif row.report_state == EngineReportState.REPORTED.value:
            if row.engine_status in FAILED_ENGINE_STATUSES:
                error += 1
            elif row.engine_status == EngineStatus.PARTIAL.value:
                partial += 1
            elif row.engine_status == EngineStatus.OK.value:
                ok += 1
    return EngineHealthCounts(
        ok=ok, partial=partial, error=error, not_reported=not_reported, unreadable=unreadable
    )


def _observation(row: ScanEngineHealthRow) -> EngineHealthObservation:
    return EngineHealthObservation(
        scan_id=row.scan_id,
        engine_name=row.engine_name,
        report_state=row.report_state,
        engine_status=row.engine_status,
        analyze_duration_ms=row.analyze_duration_ms,
        finding_count=row.finding_count,
        error=row.error,
        recorded_at=row.recorded_at,
    )


def clamp_window_scans(requested_scans: int) -> int:
    return max(1, min(requested_scans, MAX_WINDOW_SCANS))


async def load_recent_engine_health(
    session: AsyncSession, *, requested_scans: int = DEFAULT_WINDOW_SCANS
) -> EngineHealthReport:
    """The N most recent scans that still have health rows, summarized per engine.

    TWO statements, not one, and not a window function: the first picks the
    scan ids (so the window is a count of SCANS - fifteen engines of one scan
    are one unit of history, not fifteen), the second fetches those scans' rows
    whole. A `GROUP BY engine_name` with a per-group latest row would need
    either a window function or a correlated subquery, and would still have to
    come back for `last_error`; folding a few hundred rows in Python instead
    keeps every aggregation rule in `summarize_engine_health`, where it is
    testable without a database. `ONLY_FULL_GROUP_BY` (on by default in MySQL
    8) also rejects the naive single-statement version outright.
    """
    limit = clamp_window_scans(requested_scans)
    last_recorded = func.max(ScanEngineHealthRow.recorded_at).label("last_recorded_at")
    recent_scans = (
        select(ScanEngineHealthRow.scan_id, last_recorded)
        .group_by(ScanEngineHealthRow.scan_id)
        # `scan_id` breaks ties deterministically: one worker tick can score
        # several scans, and `recorded_at` has second-or-better resolution but
        # is not unique. Without it, LIMIT would pick an arbitrary member of a
        # tied group and the window could differ between two identical calls.
        .order_by(last_recorded.desc(), ScanEngineHealthRow.scan_id.desc())
        .limit(limit)
    )
    scan_ids = [str(row[0]) for row in (await session.execute(recent_scans)).all()]
    if not scan_ids:
        return summarize_engine_health((), requested_scans=limit)
    rows = (
        (
            await session.execute(
                select(ScanEngineHealthRow).where(ScanEngineHealthRow.scan_id.in_(scan_ids))
            )
        )
        .scalars()
        .all()
    )
    return summarize_engine_health([_observation(row) for row in rows], requested_scans=limit)
