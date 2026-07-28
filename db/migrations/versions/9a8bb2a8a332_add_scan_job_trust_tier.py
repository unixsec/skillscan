"""add scan_job.trust_tier

2026-07-28 (milestone B' Task 4): `SessionContext.tier` (resolved per service
account) never reached `gate.decide()` - `session.tier` was read in exactly
one place in the whole monolith (gateway/router.py's whoami diagnostic), while
every verdict was judged against `runtime.default_trust_tier`, a process-wide
TrustTier.INTERNAL constant (the most permissive tier: BLOCK at CRITICAL,
versus `public`'s HIGH). A machine caller submitting third-party content was
therefore judged by the internal-content threshold regardless of its actual
identity.

The worker decides asynchronously (`orchestration.service.
run_result_collector_tick`/`sweep_sandbox_wait_timeouts`), long after the
submitting session/request context is gone - so the tier cannot be looked up
at decide time the way a synchronous request handler could; it has to travel
WITH the scan. This column is what carries it: `submit_scan` now records the
submitter's trust tier onto the row at submission time, and the decide path
reads it back per-scan instead of a global constant.

Nullable with no backfill, same reasoning as `b7c41f9d2e08` (sandbox_wait_
started_at): every row written before this column genuinely has no recorded
tier - the caller's identity/tier at submission time was never captured, and
there is no way to reconstruct it after the fact. Inventing a value (e.g.
defaulting every historical row to 'internal') would be fabricating the basis
of a past decision that was never actually made on a per-submission tier in
the first place. NULL is the honest answer, and the decide path falls back to
`runtime.default_trust_tier` for those NULL rows - which is precisely the
(process-wide, permissive-default) behaviour they were actually decided under.

⚠ 2026-07-28 CORRECTION (milestone B' review, C3): this docstring originally
went on to say NULL could ONLY occur for pre-column rows. That was false when
written. `reeval.controller.build_rescan_job` constructed its scan_job through
an ORM class that never mapped this column, so EVERY reeval-triggered rescan
inserted NULL long after the migration ran - and each one was then re-decided
at the permissive `default_trust_tier` instead of the skill's own tier. Fixed
by mapping the column in `reeval/models.py` and filling it from the skill's
recorded tier. NULL therefore means only "this row records no tier"; that both
production writers now always record one is a property of those two call sites,
not something this schema enforces.

Revision ID: 9a8bb2a8a332
Revises: da0ba439965c
Create Date: 2026-07-28 08:09:21.817579

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9a8bb2a8a332"
down_revision: str | Sequence[str] | None = "da0ba439965c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scan_job", sa.Column("trust_tier", sa.String(length=16), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_job", "trust_tier")
