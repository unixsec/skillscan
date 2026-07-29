"""add scan_engine_health

Milestone C Task 8 (design §3, acceptance criterion 8). Per-engine runtime
health was measured, logged and streamed, and then dropped: `ScanResultRow`
persists only `provenance` = (name, version, ruleset_digest), and
`orchestration.aggregate.load_and_aggregate` discarded everything outside
findings/usability. Status, error text and (Task 7) the `analyze()` duration
all reached the monolith and died there.

THE DISTINCTION THIS SCHEMA EXISTS TO CARRY. `aggregate.unavailable_engine_result`
turns a MISSING findings blob into `EngineStatus.ERROR` so the gate fails
closed. That is correct for adjudication and destroys the telemetry: stored as
a single status column, "the engine returned ERROR" and "the engine never
reported at all" become the same byte. On an LLM-less deployment
`aig-mcp-scan` is never even constructed by the engine-runner, so it is the
standing example - it would have read as a permanently failing engine.

Hence TWO columns, plus a CHECK that makes the pairing unforgeable:

  report_state='reported',     engine_status='error'  -> the engine failed
  report_state='not_reported', engine_status=NULL     -> we never heard from it
  report_state='unreadable',   engine_status=NULL     -> something wrote garbage

`report_state`'s value domain IS constrained here; `engine_status`'s is NOT,
deliberately. `EngineReportState` is owned by `orchestration.aggregate` and
grows only when this module decides it should. `EngineStatus` is a
`skillscan_core` domain enum - constraining it here would mean that adding a
status to the core model makes every decide abort at the DB on a column this
table only records, turning a recorded value into a fail-stuck.

`analyze_duration_ms` is nullable because NULL means NOT MEASURED (a blob from
a pre-Task-7 engine-runner image). `0` is a real measurement - the monolith's
in-process floor engines genuinely complete in under a millisecond - so a
NOT NULL DEFAULT 0 would have recorded every unmeasured engine as instant,
poisoning the one dataset this table exists to create.

NO BACKFILL, and unlike 3c7e1b40d95a's there is no honest one available:
nothing anywhere retains what each engine did on a past scan. `provenance`
lists only the engines that produced a usable result, so reconstructing rows
from it would assert every historical engine reported successfully - which is
exactly the false claim this table exists to make impossible. Scans decided
before this migration simply have no rows here, which reads as "no health data
recorded", not as "all healthy".

No FK to scan_job, matching 3c7e1b40d95a's reasoning: this repo adds FKs only
within a module's own owned set, and these rows are inserted in the same
transaction that scores the scan_job, so the application path cannot orphan
one.

Revision ID: d5a1c07f9e42
Revises: 7f2ad4c9e1b3
Create Date: 2026-07-29 14:20:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d5a1c07f9e42"
down_revision: str | Sequence[str] | None = "7f2ad4c9e1b3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # -- orchestration module (written by the result collector, in the same
    # -- transaction as scan_result; INV-10 forbids the engine-runner that
    # -- measures this from holding a DB session at all).
    op.execute("""
        CREATE TABLE scan_engine_health (
          scan_id             VARCHAR(36) NOT NULL,
          engine_name         VARCHAR(64) NOT NULL,
          report_state        VARCHAR(16) NOT NULL,
          engine_status       VARCHAR(16) NULL,
          analyze_duration_ms INT NULL,
          finding_count       INT NULL,
          error               VARCHAR(1024) NULL,
          recorded_at         DATETIME NOT NULL,
          PRIMARY KEY (scan_id, engine_name),
          CONSTRAINT chk_engine_health_report_state CHECK (
            report_state IN ('reported', 'not_reported', 'unreadable')
          ),
          CONSTRAINT chk_engine_health_status_iff_reported CHECK (
            (report_state = 'reported' AND engine_status IS NOT NULL)
            OR (report_state <> 'reported' AND engine_status IS NULL)
          ),
          CONSTRAINT chk_engine_health_duration_needs_a_report CHECK (
            report_state = 'reported' OR analyze_duration_ms IS NULL
          ),
          CONSTRAINT chk_engine_health_duration_nonnegative CHECK (
            analyze_duration_ms IS NULL OR analyze_duration_ms >= 0
          )
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)
    # The PK (scan_id first) already serves "every engine on this scan". These
    # two serve the other two known readers - same "idx_*" naming as the rest
    # of the schema (idx_fetch_scan, idx_sandbox_wait, ...).
    #
    # Per-engine history: "how has osv-scanner been doing lately", which the
    # scan_id-leading PK cannot answer at all.
    op.execute(
        sa.text(
            "CREATE INDEX idx_engine_health_engine ON scan_engine_health (engine_name, recorded_at)"
        )
    )
    # Retention: this table grows ~15 rows per scan and design §3.1 records
    # that no retention path exists yet for any of this telemetry. Whatever
    # sweeps it will filter on recorded_at alone.
    op.execute(
        sa.text("CREATE INDEX idx_engine_health_recorded ON scan_engine_health (recorded_at)")
    )


def downgrade() -> None:
    op.execute(sa.text("DROP INDEX idx_engine_health_recorded ON scan_engine_health"))
    op.execute(sa.text("DROP INDEX idx_engine_health_engine ON scan_engine_health"))
    op.execute(sa.text("DROP TABLE IF EXISTS scan_engine_health"))
