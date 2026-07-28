"""add scan_submitter

里程碑 B' 全分支 review 的 C2: `submit_scan` is single-flight on
`cache_key` (content_hash + toolchain_digest). When a second caller submits
byte-identical content under the same toolchain, it gets back the EXISTING
scan_job - which keeps its original `submitter`. Authorization on both the
console (`GET /v1/scans/{scan_id}`) and the marketplace poll
(`GET /v1/market/scans/{scan_id}`) compared that single column against the
requesting subject, so the second submitter got a 404 for a scan it had just
been handed the id of - permanently, since re-submitting returns the same id
again. Per spec §6.2 that 404 is deliberately indistinguishable from "no such
scan", so the marketplace could not even diagnose it.

"The console and the marketplace scan the same skills" is this product's
normal case, not an edge case: the very first package both sides look at
triggers it.

One row per (scan, subject-that-submitted-it), so a deduplicated submission
appends rather than overwrites. Deliberately NOT a column change on scan_job:
`scan_job.submitter` remains the FIRST submitter (it is what the scan list
displays, and the tier the verdict was judged at belongs to that submission -
see below), and a scan legitimately has N submitters.

**Backfilled**, unlike `scan_job.trust_tier` (9a8bb2a8a332) - and the contrast
is the point. There, the value was never captured and inventing one would have
fabricated the basis of a past decision. Here the value IS on record:
`scan_job.submitter` is, for every existing row, exactly the one subject
authorized to read that scan. Copying it across is lossless and preserves
existing access; skipping the backfill would revoke every historical scan from
the person who submitted it.

Composite PK (scan_id, submitter) makes the association naturally idempotent -
re-submitting is a duplicate-key no-op, never a second row. The extra index on
`submitter` serves the other direction, `GET /v1/scans`'s "list my scans".

No FK to scan_job despite both tables belonging to orchestration: the codebase
adds FKs only within a module's own owned set (fk_sv_skill, fk_sle_skill) and
this row is written in the same transaction that inserts/loads the scan_job, so
an orphan cannot be produced by the application path. Left out to keep the
delete-order coupling absent from a table that is only ever appended to.

Revision ID: 3c7e1b40d95a
Revises: 9a8bb2a8a332
Create Date: 2026-07-28 11:05:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "3c7e1b40d95a"
down_revision: str | Sequence[str] | None = "9a8bb2a8a332"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_submitter",
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("submitter", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("scan_id", "submitter"),
    )
    # "list the scans I submitted" filters on submitter alone, which the
    # scan_id-leading PK cannot serve. Same idx_* naming as the rest of the
    # schema (idx_fetch_scan, idx_sandbox_wait, ...).
    op.execute(sa.text("CREATE INDEX idx_submitter ON scan_submitter (submitter)"))
    # Backfill - see this migration's docstring for why this one is honest and
    # 9a8bb2a8a332's deliberate non-backfill was too. INSERT IGNORE only to be
    # re-runnable; scan_job.scan_id is a PK so no duplicate pair can arise.
    op.execute(
        sa.text(
            "INSERT IGNORE INTO scan_submitter (scan_id, submitter) "
            "SELECT scan_id, submitter FROM scan_job"
        )
    )


def downgrade() -> None:
    op.execute(sa.text("DROP INDEX idx_submitter ON scan_submitter"))
    op.drop_table("scan_submitter")
