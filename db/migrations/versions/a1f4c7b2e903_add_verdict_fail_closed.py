"""add verdict.fail_closed

2026-07-30. `fail_closed` was never a recorded fact - every consumer INFERRED it
structurally, from "a verdict row exists but a ScanResultRow does not"
(`marketplace_api.views.project_scan`). That inference is incomplete: only the
dead-letter path (`orchestration.service._dead_letter_and_decide`, via
`forced_block_scan_result`) omits the findings row. The ordinary result-collector
path WRITES a `scan_result` row - carrying `required_ok=False` - and then hands
`gate.decide()` a ScanResult whose required engines are missing or failed, so its
INV-1 fail-closed BLOCK looked, to every reader, exactly like an ordinary
content BLOCK.

That was not a rare corner. On a real 226-package corpus run (2026-07-29), 18 of
the scans BLOCKed and 17 of those were `fail_closed:required_engine_missing_or
_failed` - engine timeouts with zero findings - all of them reporting
`fail_closed: false`.

BACKFILLED, and the backfill is exact rather than a guess. `gate.decide()`'s
fail-closed branch is the only producer of a fail-closed verdict, and it always
writes the marker `"fail_closed:required_engine_missing_or_failed:<engines>"` as
the FIRST element of `VerdictResult.reasons`, which `decide_and_record` persists
verbatim into `verdict.reasons`. So this reads back gate's own written
declaration in gate's own table - it is not the `skill.owner` situation, where a
field written for AUDIT would have been promoted to an AUTHORIZATION field
retroactively (see `inventory.ownership.authorize_skill_write`, which records why
that backfill was refused). Nothing here changes what a column means.

Because the backfill is total, the column lands NOT NULL: a third "we never
recorded this" state would have to be handled by every reader forever, and there
is no row it would be the truth for.

Revision ID: a1f4c7b2e903
Revises: d5a1c07f9e42
Create Date: 2026-07-30 09:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1f4c7b2e903"
down_revision: str | Sequence[str] | None = "d5a1c07f9e42"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("verdict", sa.Column("fail_closed", sa.Boolean(), nullable=True))
    # `reasons` is a JSON column; CAST(... AS CHAR) gives its serialized text on
    # MySQL 8 (and is a no-op TEXT cast on SQLite), so one LIKE covers the
    # marker wherever gate put it in the array. Matching the PREFIX only, not
    # the engine list that follows it.
    op.execute(
        "UPDATE verdict SET fail_closed = 1 "
        "WHERE CAST(reasons AS CHAR) LIKE "
        "'%fail_closed:required_engine_missing_or_failed%'"
    )
    op.execute("UPDATE verdict SET fail_closed = 0 WHERE fail_closed IS NULL")
    op.alter_column("verdict", "fail_closed", existing_type=sa.Boolean(), nullable=False)


def downgrade() -> None:
    op.drop_column("verdict", "fail_closed")
