"""add scan_submitter.requested_trust_tier

里程碑 F Task 14 - the tier each submitter asked for, as opposed to the tier the
verdict was actually adjudicated at.

WHAT WAS MISSING. `scan_job.trust_tier` (9a8bb2a8a332) is the FIRST submitter's
tier and the tier the verdict was reached at. `submit_scan` is single-flight on
`cache_key`, so a later submitter of byte-identical content is handed that
existing scan_job and that existing verdict - correctly, since the adjudication
is not redone and re-tiering it would claim a decision nobody made. But nothing
recorded what the LATER submitter asked for. One column had to answer two
questions, so `GET /v1/scans/{scan_id}` printed the same value twice under two
labels ("trust_tier" and "judged_at_tier") and disclosed nothing. Task 7 found
this the hard way: it implemented "highlight when the two differ" and the
highlight could never fire.

WHY IT MATTERS, CONCRETELY. `policies/gate/v1.yaml` gives `public` a HIGH block
override while every other tier blocks only at CRITICAL, so **`public` is the
STRICTEST tier and `internal` the most permissive** (`TrustTier`'s declaration
order INTERNAL/PARTNER/PUBLIC runs loose-to-strict). A caller asking for
`public` whose content was already scanned at `internal` receives a verdict
reached under a MORE PERMISSIVE ruleset than they asked for: a HIGH finding that
would have blocked for them reads PASS. This is the marketplace's ordinary case,
not a contrivance - an unconfigured service account is granted PUBLIC while the
console routinely submits at `internal`. The reverse direction (asking
`internal`, getting a `public` verdict) is the safe side, only over-blocking,
and is disclosed too rather than hidden.

ON `scan_submitter`, NOT on `scan_job`, and per submitter rather than per scan -
same reasoning as `source` (0d4bc5bc6b27). Dedup means one scan legitimately has
N submitters who may have asked for N different tiers; a scan-level column could
keep only one, and would drop the others precisely in the case this column
exists to expose.

**Not backfilled.** Copying `scan_job.trust_tier` into it would be the single
worst thing this migration could do: it would assert that every past submitter
asked for the tier they were judged at, which is exactly the unverified
assumption the column exists to stop making, and it would erase the divergences
already sitting in the deployed data. Contrast 3c7e1b40d95a, whose backfill was
honest because `scan_job.submitter` genuinely held the value being copied. NULL
means "this row records no request" and is surfaced as unknown - the same
posture as `scan_submitter.source`, `scan_job.trust_tier` and
`scan_result.findings_total`.

Nullable with no server default on purpose: a DEFAULT would let a future writer
that forgets the column record a request nobody made. `submit_scan` takes
`requested_trust_tier` as a required keyword argument instead, so a missed call
site is a type error. That check was run rather than assumed - making the
parameter required produced 24 mypy errors, exactly 2 of them in production code
(`gateway/router.py`'s `create_scan`, `marketplace_api/router.py`'s
`submit_marketplace_scan`) and 22 in tests. The same two write paths Task 12
found by the same method.

No GRANT change. `db/setup_grants.py` issues table-level grants, so
`scan_submitter: [INSERT, SELECT]` in `policies/grants/manifest.yaml` already
covers a new column, present and future. The table stays append-only - the value
is assigned once on INSERT and never updated, so no UPDATE privilege is needed
or wanted (an UPDATE here could silently re-attribute a request to the wrong
submitter).

Operationally an ADD COLUMN at the end of a narrow table, which MySQL 8 performs
with ALGORITHM=INSTANT - no rebuild, no long metadata lock - so a populated
`scan_submitter` in the deployed database is not an availability concern.

Revision ID: ec971a98d1b6
Revises: b888bb0d0635
Create Date: 2026-07-29 05:24:35.226435

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "ec971a98d1b6"
down_revision: str | Sequence[str] | None = "b888bb0d0635"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # String(16) matches `scan_job.trust_tier` and `scan_submitter.source`, and
    # comfortably holds every `TrustTier` value ("internal"/"partner"/"public").
    op.add_column(
        "scan_submitter",
        sa.Column("requested_trust_tier", sa.String(length=16), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scan_submitter", "requested_trust_tier")
