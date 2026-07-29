"""Retention for `scan_engine_health` (milestone C Task 9, design §3.1).

NO INFRASTRUCTURE. Everything here reads real source, real constants and the
real SQL the sweep compiles - no MySQL, no Redis, no mocked session. The
deletion behaviour itself (which rows go, which stay, what a bounded pass
leaves behind) needs a real database and lives in
`test_orchestration_pipeline.py::TestEngineHealthRetention` and
`test_worker.py::TestEngineHealthRetentionIsDriven`, both of which issue real
SQL against real InnoDB and therefore run only on the dev VM.

WHAT THIS FILE IS FOR, and why it is not just "unit tests for a sweep". Three
properties of this feature are invisible at the Python call site and each one
fails silently if it regresses:

  1. The sweep is DRIVEN. A retention sweep nothing schedules is the fifth
     "real code, no live caller" defect this milestone has found. The guard
     below reads `worker.py` and fails if the call disappears from
     `worker_tick`.
  2. The DELETE is BOUNDED and the comparison is STRICT. `LIMIT` and `<` live
     inside a SQLAlchemy expression; the compiled SQL is the only place they
     are visible, so that is what gets asserted.
  3. The sweep runs at READ COMMITTED. This is the difference between "a
     concurrent scoring transaction is unlikely to block" and "it cannot
     block" (measured: under the default REPEATABLE READ an unbounded delete
     took the writer's INSERT to ER_LOCK_WAIT_TIMEOUT). Delete the execution
     option and every test that does not run a real concurrent writer still
     passes.

The window itself is pinned too, because 26 is a derived number and a later
reader will be tempted to round it.
"""

from __future__ import annotations

import ast
import datetime
import logging
from pathlib import Path

import pytest
from sqlalchemy.dialects import mysql

from monolith.modules.orchestration.retention import (
    DEFAULT_RETENTION_DAYS,
    MINIMUM_RETENTION_DAYS,
    RETENTION_BATCH,
    RETENTION_DAYS_ENV,
    RETENTION_ISOLATION_LEVEL,
    RETENTION_MAX_BATCHES,
    retention_cutoff,
    retention_days,
    retention_delete_stmt,
)

_WORKER_SOURCE = Path(__file__).resolve().parents[1] / "worker.py"

# The busiest day this deployment has ever had, measured on the dev VM
# 2026-07-29: 474 scans on 2026-07-23, at 15 health rows per scan.
_PEAK_OBSERVED_ROWS_PER_DAY = 474 * 15


def _compiled(cutoff: datetime.datetime, *, limit: int) -> str:
    return str(
        retention_delete_stmt(cutoff, limit=limit).compile(
            dialect=mysql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )


def _calls_in(func_name: str, source: str) -> set[str]:
    """Every function name called anywhere inside `func_name`'s body.

    Deliberately name-based and not import-following: the property under test
    is "the call site still exists", and a call site that has been renamed out
    from under the sweep is exactly the regression this catches.
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef) and node.name == func_name:
            called: set[str] = set()
            for call in ast.walk(node):
                if not isinstance(call, ast.Call):
                    continue
                target = call.func
                if isinstance(target, ast.Name):
                    called.add(target.id)
                elif isinstance(target, ast.Attribute):
                    called.add(target.attr)
            return called
    raise AssertionError(f"{func_name} not found in the source under test")


class TestTheSweepIsActuallyDriven:
    """THE failure this project keeps producing: real code, no live caller.

    `worker_tick` is the one live driver in this deployment - a single
    background asyncio task in the single monolith pod, ticking at 1.0 s,
    established by observation on the VM in Task 1 (1bfd580) rather than read
    out of the source. These tests fail if the sweep stops being reachable
    from it. They do NOT prove the tick itself runs; that is a deployment
    fact, proved by `test_worker.py::TestEngineHealthRetentionIsDriven`
    against real MySQL and by the VM checklist's live-pod check.
    """

    def test_worker_tick_calls_the_retention_driver(self) -> None:
        assert "run_engine_health_retention" in _calls_in(
            "worker_tick", _WORKER_SOURCE.read_text(encoding="utf-8")
        ), (
            "worker_tick no longer calls run_engine_health_retention. "
            "scan_engine_health then grows without bound, silently: nothing "
            "else in this system schedules anything."
        )

    def test_the_driver_calls_the_sweep(self) -> None:
        calls = _calls_in("run_engine_health_retention", _WORKER_SOURCE.read_text(encoding="utf-8"))
        assert "sweep_engine_health_retention" in calls

    def test_the_driver_takes_the_lease_with_nx_and_an_expiry(self) -> None:
        """SET NX EX, not SET. Without NX every replica sweeps concurrently -
        which is the contention this whole design exists to avoid - and without
        EX a crashed pod holds the lease forever and retention stops."""
        tree = ast.parse(_WORKER_SOURCE.read_text(encoding="utf-8"))
        keywords: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            if node.name != "run_engine_health_retention":
                continue
            for call in ast.walk(node):
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute):
                    if call.func.attr == "set":
                        keywords |= {kw.arg for kw in call.keywords if kw.arg}
        assert "nx" in keywords, "the retention lease must be SET NX or replicas sweep in parallel"
        assert "ex" in keywords, "the retention lease must expire or a crash stops retention"

    def test_the_guard_can_fail(self) -> None:
        """Guards-the-guard. `_calls_in` returning an empty/permissive set for
        everything would make all three tests above vacuously green."""
        calls = _calls_in("worker_tick", _WORKER_SOURCE.read_text(encoding="utf-8"))
        assert calls, "the extractor found no calls at all in worker_tick"
        assert "a_function_that_does_not_exist" not in calls
        with pytest.raises(AssertionError):
            _calls_in("no_such_function_anywhere", _WORKER_SOURCE.read_text(encoding="utf-8"))


class TestTheDeleteIsBoundedAndStrict:
    def test_the_statement_carries_a_limit(self) -> None:
        """The bound is what keeps one pass from locking the table out from
        under the scoring transaction. It is a MySQL dialect option, so it is
        invisible in the Python and only appears once compiled."""
        sql = _compiled(datetime.datetime(2026, 7, 1), limit=RETENTION_BATCH)
        assert f"LIMIT {RETENTION_BATCH}" in sql, sql

    def test_the_limit_is_the_one_passed(self) -> None:
        assert "LIMIT 7" in _compiled(datetime.datetime(2026, 7, 1), limit=7)

    def test_the_comparison_is_strict(self) -> None:
        """`<`, not `<=`: a row recorded exactly at the cutoff is inside the
        window. Arbitrary at microsecond resolution, but it must be asserted
        somewhere or a later edit flips it with nothing to notice."""
        sql = _compiled(datetime.datetime(2026, 7, 1), limit=RETENTION_BATCH)
        assert "recorded_at <" in sql
        assert "recorded_at <=" not in sql

    def test_it_deletes_from_the_health_table_and_nothing_else(self) -> None:
        sql = _compiled(datetime.datetime(2026, 7, 1), limit=RETENTION_BATCH)
        assert sql.startswith("DELETE FROM scan_engine_health")
        for other in ("scan_job", "scan_result", "verdict", "scan_submitter"):
            assert other not in sql, f"the retention delete must never reach {other}"

    def test_there_is_no_select_for_update_before_the_delete(self) -> None:
        """This repository has a recorded incident where `SELECT ... ORDER BY
        ... LIMIT 1 ... FOR UPDATE` forked silently under concurrency. A single
        `DELETE ... LIMIT` has no read-then-act window to fork in, and the
        sweep does not care which rows a batch takes - every eligible row is
        going anyway."""
        sql = _compiled(datetime.datetime(2026, 7, 1), limit=RETENTION_BATCH)
        assert "SELECT" not in sql.upper()
        assert "FOR UPDATE" not in sql.upper()

    def test_the_sweep_sets_read_committed_on_the_connection(self) -> None:
        """MEASURED, VM, MySQL 8.0.46: under the default REPEATABLE READ an
        unbounded delete on this table drove a concurrent INSERT at
        recorded_at=NOW() to ER_LOCK_WAIT_TIMEOUT, because InnoDB's next-key
        locks cover gaps a random-UUID scan_id insert lands in. That INSERT is
        inside the SCORING transaction, so the casualty is a whole decide.
        READ COMMITTED takes no gap locks, which turns "unlikely to collide"
        into "cannot collide" - and deleting this one line reverts that with
        no other test able to see it."""
        assert RETENTION_ISOLATION_LEVEL == "READ COMMITTED"
        source = (
            Path(__file__).resolve().parents[1] / "modules" / "orchestration" / "retention.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        found = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            if node.name != "sweep_engine_health_retention":
                continue
            for call in ast.walk(node):
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and call.func.attr == "connection"
                    and any(kw.arg == "execution_options" for kw in call.keywords)
                ):
                    found = True
        assert found, (
            "sweep_engine_health_retention no longer sets an isolation level on its "
            "connection; it is back on REPEATABLE READ and can now abort a decide"
        )


class TestTheWindow:
    def test_the_default_is_the_derived_value(self) -> None:
        """26 days = 2 x the longest observed interval between
        `vendor/engines.lock.yaml` revisions (13.01 d), so the window always
        holds a full previous-engine-version baseline. See retention.py's
        module docstring for all four measured requirements and the cost
        table. This assertion exists because 26 looks like a typo for 30."""
        assert DEFAULT_RETENTION_DAYS == 26.0

    def test_the_cutoff_is_now_minus_the_window(self) -> None:
        now = datetime.datetime(2026, 7, 29, 12, 0, 0)
        assert retention_cutoff(now, days=26.0) == datetime.datetime(2026, 7, 3, 12, 0, 0)

    def test_a_fractional_window_is_honoured(self) -> None:
        now = datetime.datetime(2026, 7, 29, 12, 0, 0)
        assert retention_cutoff(now, days=0.5) == datetime.datetime(2026, 7, 29, 0, 0, 0)

    def test_one_pass_can_absorb_the_busiest_day_ever_observed(self) -> None:
        """The per-pass budget and the hourly lease are one decision, not two:
        an hourly sweep whose budget is smaller than a day's production can
        never catch up after an outage. 20 x 1000 is 2.8x the peak day."""
        assert RETENTION_BATCH * RETENTION_MAX_BATCHES > _PEAK_OBSERVED_ROWS_PER_DAY

    def test_the_minimum_is_below_the_default(self) -> None:
        assert MINIMUM_RETENTION_DAYS < DEFAULT_RETENTION_DAYS


class TestTheWindowIsReadFromTheEnvironmentAtCallTime:
    """`gateway.auth.middleware.session_ttl_from_env`'s recorded lesson: a
    knob evaluated at import into a module constant makes every test that
    asserts against that constant compare a value to itself. These tests set
    the variable and observe the RETURN, so an import-time regression fails
    them."""

    def test_absent_gives_the_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(RETENTION_DAYS_ENV, raising=False)
        assert retention_days() == DEFAULT_RETENTION_DAYS

    def test_a_valid_override_is_honoured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(RETENTION_DAYS_ENV, "90")
        assert retention_days() == 90.0

    def test_it_is_re_read_between_calls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(RETENTION_DAYS_ENV, "40")
        first = retention_days()
        monkeypatch.setenv(RETENTION_DAYS_ENV, "50")
        assert (first, retention_days()) == (40.0, 50.0)

    def test_the_minimum_is_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(RETENTION_DAYS_ENV, str(MINIMUM_RETENTION_DAYS))
        assert retention_days() == MINIMUM_RETENTION_DAYS

    @pytest.mark.parametrize("value", ["0", "-1", "0.5", ""])
    def test_a_window_below_the_minimum_falls_back_and_says_so(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, value: str
    ) -> None:
        """A zero window deletes rows the instant they are written; a negative
        one puts the cutoff in the FUTURE and would delete rows the scoring
        transaction just wrote. Both fall back - refusing to start would turn a
        typo in a telemetry knob into a scanner outage - but neither is
        silent."""
        monkeypatch.setenv(RETENTION_DAYS_ENV, value)
        with caplog.at_level(logging.WARNING, logger="skillscan.orchestration.retention"):
            assert retention_days() == DEFAULT_RETENTION_DAYS
        assert any(RETENTION_DAYS_ENV in str(r.__dict__.get("context", "")) for r in caplog.records)

    def test_an_unparseable_window_falls_back_and_says_so(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv(RETENTION_DAYS_ENV, "forever")
        with caplog.at_level(logging.WARNING, logger="skillscan.orchestration.retention"):
            assert retention_days() == DEFAULT_RETENTION_DAYS
        assert caplog.records
