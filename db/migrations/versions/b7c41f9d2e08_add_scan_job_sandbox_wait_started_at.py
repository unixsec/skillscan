"""add scan_job.sandbox_wait_started_at

2026-07-27 (milestone D final review, F-2): `sweep_sandbox_wait_timeouts`
measured the sandbox wait from `created_at`, the only timestamp scan_job had -
i.e. "how old is this submission" rather than "how long have we been waiting
for the sandbox". Those differ by the entire queue backlog, and the gap is
exploitable by ordinary operations: after a worker outage longer than the wait
budget, a backlogged scan's floor blobs land, the collector declines to decide
because the sandbox blobs have not arrived yet, and the sweep then force-
decides that same scan in the SAME tick because its created_at is already ~10
minutes old. The verdict is signed from floor findings only, so a package
whose only HIGH finding comes from bandit gets PASS instead of REVIEW.

This column records the moment the wait actually begins: the first time
`_try_score_and_decide` observes every required engine reported but a
waited-advisory (sandbox) engine still missing. NULL means "has never started
waiting" and is never swept, which also keeps never-dispatched scans out of the
sweep entirely.

Nullable with no backfill on purpose: every pre-existing row genuinely has no
"waiting since" instant, and NULL is exactly the right answer for them. In
flight scans simply record it on the next collector tick that observes the
wait.

Revision ID: b7c41f9d2e08
Revises: f19c2a7e5b3d
Create Date: 2026-07-27 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision: str = "b7c41f9d2e08"
down_revision: str | Sequence[str] | None = "f19c2a7e5b3d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # DATETIME(6), matching scan_job.created_at - the sweep compares this
    # against a Python-generated cutoff, and a second-precision column would
    # silently round the stored value.
    op.add_column(
        "scan_job",
        sa.Column("sandbox_wait_started_at", mysql.DATETIME(fsp=6), nullable=True),
    )
    # The sweep selects `state IN ('queued','running') AND
    # sandbox_wait_started_at < cutoff ORDER BY sandbox_wait_started_at`; this
    # index keeps that a range scan rather than a full table scan as scan_job
    # grows. Same `idx_*` naming as the rest of this schema.
    op.execute(
        sa.text("CREATE INDEX idx_sandbox_wait ON scan_job (state, sandbox_wait_started_at)")
    )


def downgrade() -> None:
    op.execute(sa.text("DROP INDEX idx_sandbox_wait ON scan_job"))
    op.drop_column("scan_job", "sandbox_wait_started_at")
