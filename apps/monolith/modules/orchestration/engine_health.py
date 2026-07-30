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
from enum import StrEnum

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


# --------------------------------------------------------------------------- #
# PER-SCAN COVERAGE (2026-07-30, owner decision after the 290-scan run)
# --------------------------------------------------------------------------- #
#
# WHAT THIS ANSWERS, and why it is a different read from everything above. The
# window summary answers "is this engine reliable"; this answers "was the
# verdict on THIS scan reached on complete evidence". Same table, opposite axis:
# one row per engine of ONE scan instead of one summary per engine across many.
#
# WHY IT HAD TO EXIST. `GatePolicy.required_engines` fails closed - a floor
# engine that does not deliver turns into a signed conservative BLOCK, and a
# 290-scan real-world run confirmed that path works (18 BLOCKs, 17 of them
# exactly this). EVERY OTHER ENGINE FAILS OPEN: its absence discards its
# findings and the verdict is computed on what remains, as though it had found
# nothing. On that same run, scans with complete evidence and scans without it
# were 60% vs 29% REVIEW and 38% vs 57% PASS - under load the effective ruleset
# shrinks and the scanner gets MORE permissive, and nothing anywhere said so.
#
# The owner's decision was explicitly NOT to change verdict semantics. Nothing
# in this section is read by the gate; it exists so a consumer can see that the
# evidence was incomplete and judge for itself.

#: The engine self-reports that mean findings actually reached the aggregator.
#:
#: MEASURED, not assumed. The obvious definition of coverage is
#: `report_state == 'reported'` - we heard from the engine - and on the 290-scan
#: corpus that definition is WORTHLESS: it reads 14.0 engines on the scans with
#: timeouts and 14.0 on the scans without. Every timeout in that corpus is
#: (`reported`, `timeout`): the engine-runner's airlock times `analyze()` out and
#: writes a perfectly valid findings blob carrying `EngineStatus.TIMEOUT` and
#: zero findings. So the blob arrives, `report_state` says `reported`, and the
#: findings are gone anyway. Splitting on THIS axis instead reads 14.0 vs 9.3,
#: which is the number that was invisible.
#:
#: `PARTIAL` is on the delivered side deliberately: a partial result is a
#: degraded success that still contributed findings (the same call
#: `FAILED_ENGINE_STATUSES` above makes, for the same reason). On the corpus that
#: is not a rounding decision - osv-scanner reports PARTIAL on 161 of 290 scans,
#: so putting it on the missing side would mark more than half of all scans
#: incomplete and train every reader to ignore the flag.
DELIVERED_ENGINE_STATUSES = frozenset({EngineStatus.OK.value, EngineStatus.PARTIAL.value})


class EngineCoverageClass(StrEnum):
    """How one engine's row on one scan bears on that scan's evidence."""

    #: The engine delivered a usable result - `reported` plus a status in
    #: `DELIVERED_ENGINE_STATUSES`. Whatever it found is in the verdict.
    REPORTED = "reported"
    #: Its findings are NOT in the verdict, and no authority explains that away.
    #: Covers both halves of the gap: nothing arrived (`not_reported`,
    #: `unreadable`) and something arrived saying the run failed (`error`,
    #: `timeout`). One bucket, because the consequence is identical - the
    #: verdict was computed as if this engine had found nothing.
    MISSING = "missing"
    #: This deployment does not run this engine at all, per a source that can be
    #: joined rather than guessed. Excluded from `expected` entirely, NOT counted
    #: as a gap - see `summarize_scan_coverage` for why that exclusion is the
    #: difference between a signal and noise.
    NOT_APPLICABLE = "not_applicable"


def classify_engine_coverage(
    observation: EngineHealthObservation, *, structurally_absent: frozenset[str]
) -> EngineCoverageClass:
    """Exactly one class per row. TOTAL over the enums by construction - every
    `(report_state, engine_status)` pair lands somewhere, and the unrecognised
    ones land in `MISSING`, the conservative direction ("we cannot show this
    engine's findings in the verdict").

    That is a deliberate departure from `_count` above, which leaves unknown
    values in no bucket so an exhaustiveness test breaks. The two are answering
    different questions: `_count` publishes a breakdown, where a silently
    reclassified value is a lie, whereas this publishes a completeness claim,
    where the only safe default is "not complete". A test enumerates both enums
    and pins the class of every member, so a NEW enum value still forces a
    deliberate decision here rather than sliding into `MISSING` unnoticed.

    EVIDENCE OUTRANKS INFERENCE, the same rule
    `admin.engine_registry.not_reported_attribution` was rewritten to follow.
    `structurally_absent` is read from configuration NOW; a blob is proof about
    THIS scan. So the exclusion applies only to `not_reported` - the state in
    which genuinely nothing arrived:

      * a `reported` row proves the engine ran here, so config cannot explain it
        away. An engine disabled after the scan still shows its real timeout.
      * an `unreadable` row proves SOMETHING wrote to that key, which is an
        incident and never a structural absence.
    """
    if observation.report_state == EngineReportState.REPORTED.value:
        if observation.engine_status in DELIVERED_ENGINE_STATUSES:
            return EngineCoverageClass.REPORTED
        return EngineCoverageClass.MISSING
    if (
        observation.report_state == EngineReportState.NOT_REPORTED.value
        and observation.engine_name in structurally_absent
    ):
        return EngineCoverageClass.NOT_APPLICABLE
    return EngineCoverageClass.MISSING


@dataclasses.dataclass(frozen=True, slots=True)
class EngineCoverageEntry:
    """One engine that did not deliver on this scan, as the console renders it.

    Carries the SAME two fields the window summary does - `report_state` and
    `engine_status`, never merged - so `web/src/engineHealth.ts` renders this
    with the state machine it already has instead of growing a fourth spelling
    of the same six states.

    `error` is deliberately NOT here. `ScanEngineHealthRow.error` carries an
    engine's own message, which can quote the scanned bytes; the window summary
    publishes it on an ADMIN-only endpoint, whereas per-scan coverage is served
    to every authorized reader of a scan (`_submitter_or_above`, which includes
    reviewers reading somebody else's package). The state answers "which engines
    did not report"; the message is available to admins who need it.
    """

    engine_name: str
    report_state: str
    engine_status: str | None
    #: Task 7's three states, unchanged: an int is measured, `0` is ALSO
    #: measured, `None` is not-measured. A timed-out engine legitimately has a
    #: measured duration (the airlock timed the run it cut short), and on the
    #: corpus those range from 0 to 3218 ms - so this column is not redundant
    #: with the state.
    analyze_duration_ms: int | None
    coverage: EngineCoverageClass
    #: What today's configuration would predict, or None. Filled in by the
    #: caller from `admin.engine_registry.not_reported_attribution`, which owns
    #: the join to the two authorities and the refusal to guess the other three
    #: causes. Never derived here.
    not_reported_attribution: str | None = None
    not_reported_attribution_basis: str | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class ScanEngineCoverage:
    """Whether one scan's verdict was reached on every engine's evidence.

    `observed` is the field that keeps this honest. A scan with no rows at all
    is NOT complete coverage and it is NOT missing coverage - it is no record,
    and there are three ordinary ways to get one: `_dead_letter_and_decide`
    never aggregates (so it writes none, deliberately - see
    `ScanEngineHealthRow`), Task 9's retention sweep deletes old ones, and a
    scan scored before milestone C never had any. `complete` is therefore
    `None` in that case, never `True` - "0 of 0 engines missing" would publish
    the strongest possible claim about the weakest possible evidence, which is
    the fabricated-field mistake `fail_closed` shipped hours before this was
    written (a structural inference that read `false` for 17 of 18 real
    fail-closed BLOCKs).
    """

    #: Engines whose evidence this scan's verdict was supposed to include:
    #: `reported + missing`. Excludes `not_applicable`.
    expected: int
    #: Of `expected`, how many delivered.
    reported: int
    #: Engines excluded from `expected` because this deployment does not run
    #: them. Published rather than silently subtracted: without it, `expected`
    #: shrinking from 15 to 14 between two deployments has no accounting.
    not_applicable: int
    #: Every engine that did NOT deliver - `missing` AND `not_applicable`, in
    #: name order. The delivering ones are not listed: the question is which
    #: engines are absent from the evidence, and a full listing on every scan
    #: buries the answer. Each entry carries its own `coverage` class so the two
    #: kinds are never rendered as one.
    entries: tuple[EngineCoverageEntry, ...]
    #: Whether this scan has any per-engine record at all.
    observed: bool

    @property
    def missing(self) -> int:
        return self.expected - self.reported

    @property
    def complete(self) -> bool | None:
        """`None` when nothing was observed - see the class docstring.

        A property, not a stored field, and read by BOTH the marketplace
        projection and the console: the two surfaces of this feature cannot
        drift into two definitions of "complete", which is precisely the defect
        shape this repository hit five times in one milestone (a second registry
        that was never updated)."""
        if not self.observed:
            return None
        return self.reported == self.expected


#: The qualifier that travels with any coverage answer, for the same reason
#: `engine_registry.ATTRIBUTION_BASIS_CURRENT_CONFIG` exists: `expected` is
#: computed by subtracting engines that TODAY'S configuration says this
#: deployment does not run, and nothing recorded the configuration the scan
#: actually ran under. An engine disabled this morning would make last week's
#: scans read complete. That caveat has to be on the wire, not only in a
#: console's translation strings, because the marketplace surface has no
#: console.
COVERAGE_BASIS_CURRENT_CONFIG = "current_config"


def summarize_scan_coverage(
    observations: Iterable[EngineHealthObservation],
    *,
    structurally_absent: frozenset[str] = frozenset(),
) -> ScanEngineCoverage:
    """Fold one scan's rows into a coverage answer. PURE - no session, no clock.

    `structurally_absent` is the join to authority, and passing it in is what
    keeps this function pure AND keeps the two authorities in one place:
    `admin.engine_registry.structurally_absent_engine_names` builds it from the
    Redis disabled set and the engine-runner's own LLM gate. Empty (the default)
    means "explain nothing away", which is the conservative reading and the one
    every pure test uses.

    WHY THE EXCLUSION IS NOT OPTIONAL. On every deployment without an internal
    LLM endpoint - which includes the one this feature was measured on -
    `aig-mcp-scan` has a `not_reported` row on EVERY scan: 290 of 290 in the
    corpus, no exceptions. Counting it as a gap would publish
    `complete: false` on every scan the system has ever run, forever. A flag
    that is always on is not a signal; it teaches operators that coverage
    warnings mean nothing, which is strictly worse than publishing no coverage
    at all. So a structurally-absent engine is reported as such - present in
    `entries` with `coverage: not_applicable` and its attribution, visible but
    not a fault - and an engine that WAS expected and did not arrive is the only
    thing that moves `complete`.
    """
    rows = sorted(observations, key=lambda o: o.engine_name)
    reported = missing = not_applicable = 0
    entries: list[EngineCoverageEntry] = []
    for row in rows:
        coverage = classify_engine_coverage(row, structurally_absent=structurally_absent)
        if coverage is EngineCoverageClass.REPORTED:
            reported += 1
            continue
        if coverage is EngineCoverageClass.MISSING:
            missing += 1
        else:
            not_applicable += 1
        entries.append(
            EngineCoverageEntry(
                engine_name=row.engine_name,
                report_state=row.report_state,
                engine_status=row.engine_status,
                analyze_duration_ms=row.analyze_duration_ms,
                coverage=coverage,
            )
        )
    return ScanEngineCoverage(
        expected=reported + missing,
        reported=reported,
        not_applicable=not_applicable,
        entries=tuple(entries),
        observed=bool(rows),
    )


async def load_scan_engine_coverage(
    session: AsyncSession,
    *,
    scan_id: str,
    structurally_absent: frozenset[str] = frozenset(),
) -> ScanEngineCoverage:
    """One scan's coverage, read from `scan_engine_health` and never inferred.

    THE FIELD THIS DOES NOT BECOME. Hours before this was written, the
    marketplace contract's `fail_closed` was found to be a structural inference
    ("a verdict with no result row") that reported `false` for 17 of 18 real
    fail-closed BLOCKs, because the ordinary collector path DOES write a result
    row. The lesson is not "that inference was subtly wrong", it is "do not
    publish a derived field when an authoritative one exists". `scan_engine_
    health` is that authority - one row per engine per scored scan, written in
    the same transaction as the verdict - so this reads it, and returns
    `observed=False` rather than guessing when it is empty.

    `scan_id` is the leading column of the table's composite primary key, so
    this is an index prefix lookup, not a scan. No `FOR UPDATE`, same reason as
    `load_recent_engine_health`.
    """
    rows = (
        (
            await session.execute(
                select(ScanEngineHealthRow).where(ScanEngineHealthRow.scan_id == scan_id)
            )
        )
        .scalars()
        .all()
    )
    return summarize_scan_coverage(
        [_observation(row) for row in rows], structurally_absent=structurally_absent
    )
