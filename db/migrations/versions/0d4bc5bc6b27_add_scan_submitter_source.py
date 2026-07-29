"""add scan_submitter.source

里程碑 F Task 12 - the column milestone F Task 2 reported BLOCKED on.

The console detail response needs to say which channel a submission arrived
through ("console" vs "marketplace"). Before this column that fact was stored
NOWHERE: `scan_submitter` held only (scan_id, submitter), and the sole other
carrier of the distinction is `SessionContext.is_machine`, a per-request auth
fact that dies with the request. So it is recorded at INSERT time by whichever
handler took the submission, which is the one moment it is known.

Deliberately NOT derived at read time from the submitter STRING ("service
accounts are named with such-and-such a prefix"). That is a shape check
standing in for a membership check - the same fragility that let the
nonexistent finding id `SUP-01` pass a catalog audit which validated
`[A-Z]{3,7}-\\d{2}` but never checked the 62-item catalog. The channel is a
known fact at write time; known facts get persisted.

ON `scan_submitter`, NOT on `scan_job`. `submit_scan` is single-flight on
cache_key, so a scan legitimately has N submitters, and "the console and the
marketplace scan the same skill" is this product's normal case (see
3c7e1b40d95a, the migration that created this table for exactly that reason).
A scan-level column could hold only one channel, so the moment both doors are
involved - the case this field exists to make visible - it would silently drop
one of them. Per submitter, both survive.

**Not backfilled**, and the contrast with 3c7e1b40d95a (which DID backfill) is
the point. There, the value was genuinely on record: `scan_job.submitter` was,
for every existing row, exactly the subject authorized to read that scan, so
copying it across was lossless. Here nothing anywhere records the channel of a
past submission; any backfill would have to guess from the submitter's name,
which is precisely what this design refuses. NULL is the honest value for
pre-existing rows and means "this row records no channel" - the same posture as
9a8bb2a8a332 (`scan_job.trust_tier`) and `scan_result.findings_total`.
`gateway.router.get_scan` surfaces NULL verbatim in `submitter_sources` and
omits it from the aggregate `source` list; it never defaults to "console".

Nullable with no server default on purpose: a DEFAULT would let a future writer
that forgets the column record a channel nobody verified. `submit_scan` takes
`source` as a required keyword argument instead, so a missed call site is a
type error, not a silently wrong provenance record.

No GRANT change: `policies/grants/manifest.yaml` gives svc_orchestration
INSERT+SELECT on this table, and MySQL table-level grants cover all columns
present and future. This table stays append-only - the column is assigned once
on INSERT and never updated, so no UPDATE privilege is needed or wanted (an
UPDATE here could silently re-attribute someone else's scan).

Operationally this is an ADD COLUMN at the end of a narrow table, which MySQL 8
performs with ALGORITHM=INSTANT - no table rebuild, no long metadata lock, and
therefore safe against a populated `scan_submitter` in the deployed database.

Revision ID: 0d4bc5bc6b27
Revises: 3c7e1b40d95a
Create Date: 2026-07-29 02:53:53.395170

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0d4bc5bc6b27"
down_revision: str | Sequence[str] | None = "3c7e1b40d95a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # String(16) matches `scan_job.trust_tier`'s width and comfortably holds
    # both `SubmissionChannel` values ("console", "marketplace").
    op.add_column(
        "scan_submitter",
        sa.Column("source", sa.String(length=16), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scan_submitter", "source")
