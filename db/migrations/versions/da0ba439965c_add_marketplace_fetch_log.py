"""add marketplace_fetch_log

里程碑 B'(marketplace pull integration) spec §7: the pull model gives us no
confirmed endpoint on the marketplace's side to poll for their published list,
so classic ORPHAN reconciliation (a published skill we never scored) is
structurally undetectable here - there is nothing on our side to compare
against. This table is the achievable dual instead: a row per actual fetch,
so we can (a) prove what we told the marketplace and when (non-repudiation)
and (b) find verdicts that were issued but never collected (a scan_job in
`decided` state with no matching `scan_id` in this table) - the closest
analogue of ORPHAN detection a pull-only model allows, plus real polling data
for tuning `poll_after_ms`.

`fetched_at` is DATETIME(6), matching every other audit-shaped timestamp in
this schema (audit_entry, scan_job.created_at) - a second-precision column
would blur the ordering of two fetches inside the same request burst.

No FK to scan_job: this table is written by the marketplace-facing module,
which per policies/grants/manifest.yaml owns no other table and is granted no
access to orchestration's. A cross-module FK would require a grant this
module deliberately does not have; the scan_id linkage is enforced at the
application layer instead (mirrors gate_outbox/audit_intent's own FK-less,
grant-bounded cross-module seams).

Revision ID: da0ba439965c
Revises: c22ba961a06e
Create Date: 2026-07-28 02:37:59.352814

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision: str = "da0ba439965c"
down_revision: str | Sequence[str] | None = "c22ba961a06e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "marketplace_fetch_log",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("service_account", sa.String(length=255), nullable=False),
        sa.Column("fetched_at", mysql.DATETIME(fsp=6), nullable=False),
        sa.Column("status_shown", sa.String(length=16), nullable=False),
        sa.Column("verdict_shown", sa.String(length=16), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    # Every reverse-gap / non-repudiation query filters by scan_id first (see
    # this migration's docstring) - same "idx_*" naming as the rest of the
    # schema (idx_sandbox_wait, idx_state, ...).
    op.execute(sa.text("CREATE INDEX idx_fetch_scan ON marketplace_fetch_log (scan_id)"))


def downgrade() -> None:
    op.execute(sa.text("DROP INDEX idx_fetch_scan ON marketplace_fetch_log"))
    op.drop_table("marketplace_fetch_log")
