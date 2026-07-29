"""add skill_lifecycle_event.scan_id

Security review of milestones E+F (2026-07-29, finding C1) - the explicit link
between a lifecycle event and the scan whose verdict is supposed to resolve it.

WHAT WAS BROKEN. `worker.sync_lifecycle_tick` resolved a `scanning` skill by
taking the NEWEST `verdict` row for that event's `content_hash`. Nothing tied
that verdict to the scan the event actually named - the scan_id lived only
inside the event's free-text `reason` ("scan <uuid> submitted") - and nothing
checked that the verdict even post-dated the event or came from the current
toolchain.

That was inert until a3f26e4 (finding I1) made an identical-content
resubmission write real lifecycle events. Afterwards:

  1. skill published at content hash H, PASS under toolchain T1
  2. detection content or policy changes -> toolchain T2
  3. the owner resubmits the SAME bytes (the case I1 exists to serve)
  4. cache_key = f(H, T2) misses, so a genuinely new scan is enqueued
  5. the lifecycle commits published -> submitted -> scanning immediately
  6. the worker tick (1s) finds the T1 PASS as newest-for-H and publishes
  7. seconds later the T2 scan issues BLOCK - and the skill has already left
     `scanning`, so the tick never looks at it again and that verdict is
     dropped forever

The mirror case is worse: a `blocked` skill resubmitted under a RELAXED ruleset
was instantly re-blocked on its own stale BLOCK, so the remediation path I1 was
built for could not work at all. Nothing recovered either case -
`register_skill_version` deliberately never advances `skill_version.
toolchain_digest`, so `reeval` keeps re-queueing rescans whose verdicts hit the
same dead end.

WHY A COLUMN RATHER THAN A TIME FILTER. The reviewer offered two shapes:
filter candidate verdicts to those issued AFTER the lifecycle event, or record
the scan_id and resolve by it. This is the second.

  - It is an explicit link, not a heuristic. `verdict.scan_id` is that table's
    PRIMARY KEY, so resolution becomes a point lookup of the one verdict this
    event is waiting for, and "newest for this content hash" - a set that
    legitimately contains several rows once the same bytes are scanned under
    several toolchains - stops being consulted at all.
  - It does not compare clocks written by two different modules (inventory
    writes `occurred_at`, gate writes `issued_at`) in a deployment that may run
    several replicas. A `>=` between them is right only to within clock skew,
    and both of its failure directions are bad: too early re-admits the stale
    verdict, too late strands the skill in `scanning` forever.
  - The value is already known where the event is written: `gateway/router.py`
    creates the scan BEFORE the transition and already interpolates the same
    scan_id into `reason`. This column stops that string being the only record.

NULLABLE, NOT BACKFILLED, no server default. NULL means "no scan is on record
for this event" and is the honest value for:

  - every row written before this column existed (a backfill would have to
    parse the `reason` text, which is exactly the un-typed coupling this
    column removes, and would have to guess for every reason wording that
    never carried one);
  - the admin quarantine/retire/restore routes and the drift-triggered
    quarantine, which record no scan because none is involved;
  - the genesis/re-entry `submitted` event, which `register_skill_version`
    writes without knowing the scan (the following `-> scanning` event carries
    it).

`worker.sync_lifecycle_tick` therefore keeps a documented, strictly narrower
fallback for NULL: newest verdict for the content hash whose `issued_at` is not
BEFORE the event - the time-based shape, restricted to legacy rows only, so a
migrated deployment's in-flight scans still settle instead of sticking in
`scanning` forever. New rows never take that path.

No GRANT change: `db/setup_grants.py` issues table-level grants and
`policies/grants/manifest.yaml` already gives svc_inventory ALL on
`skill_lifecycle_event`.

Operationally an ADD COLUMN at the end of a narrow, append-only table, which
MySQL 8 performs with ALGORITHM=INSTANT - no rebuild, no long metadata lock.

Revision ID: 7f2ad4c9e1b3
Revises: ec971a98d1b6
Create Date: 2026-07-29 11:02:14.775310

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "7f2ad4c9e1b3"
down_revision: str | Sequence[str] | None = "ec971a98d1b6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # String(36) matches `verdict.scan_id` and `scan_job.scan_id` - a UUID4 in
    # its canonical hyphenated form.
    op.add_column(
        "skill_lifecycle_event",
        sa.Column("scan_id", sa.String(length=36), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("skill_lifecycle_event", "scan_id")
