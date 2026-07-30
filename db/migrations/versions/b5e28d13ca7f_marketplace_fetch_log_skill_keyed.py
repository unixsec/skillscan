"""marketplace_fetch_log: skill-keyed, binary answer

2026-07-30. The marketplace contract was replaced outright: the poll key is now
`skill_id` (not `scan_id`) and the answer is a binary `is_safe` + an
`unsafe_reason` code (not a three-valued `verdict`). `marketplace_fetch_log`
exists for non-repudiation - "we can show what we told them and when" (design
spec §7) - so a record that still only holds the old key and the old answer
cannot do its one job.

Four columns added, all NULLABLE, none backfilled. Rows written under the
scan-keyed contract genuinely have no skill_id, no shown content_hash and no
is_safe; NULL says "this field predates the question", which is true, and any
default would assert something about a fetch that never happened that way.

`scan_id` becomes NULLABLE. A poll for a skill whose latest version has never
been scanned is a legitimate request that gets a legitimate answer
(`not_yet_scanned`), and there is no scan to name. Nothing else changes about it.

NOT RENAMED, deliberately: `verdict_shown` keeps its name and its data even
though the response no longer returns `verdict` verbatim - the model docstring
records that it is now the verdict the answer was DERIVED from. An audit table
whose column meanings shift silently underneath historical rows is worse than one
with a slightly dated name.

GRANTS: no change needed and none made. `policies/grants/manifest.yaml` grants
svc_marketplace `marketplace_fetch_log: [INSERT, SELECT]` at TABLE level, which
covers new columns, and the append-only posture (no UPDATE, no DELETE) is exactly
what must NOT be widened - reviewed and left alone. Note `db/setup_grants.py` is
additive with no REVOKE, so a stale dev grant can make a tamper test pass that
should fail; that check belongs on a fresh database, not here.

Revision ID: b5e28d13ca7f
Revises: a1f4c7b2e903
Create Date: 2026-07-30 09:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b5e28d13ca7f"
down_revision: str | Sequence[str] | None = "a1f4c7b2e903"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "marketplace_fetch_log", sa.Column("skill_id", sa.String(length=128), nullable=True)
    )
    op.create_index(
        "ix_marketplace_fetch_log_skill_id", "marketplace_fetch_log", ["skill_id"], unique=False
    )
    op.add_column(
        "marketplace_fetch_log",
        sa.Column("content_hash_shown", sa.String(length=64), nullable=True),
    )
    op.add_column("marketplace_fetch_log", sa.Column("is_safe_shown", sa.Boolean(), nullable=True))
    op.add_column(
        "marketplace_fetch_log",
        sa.Column("unsafe_reason_shown", sa.String(length=32), nullable=True),
    )
    op.alter_column(
        "marketplace_fetch_log",
        "scan_id",
        existing_type=sa.String(length=36),
        nullable=True,
    )


def downgrade() -> None:
    # `scan_id` back to NOT NULL first: any row written by the skill-keyed poll for
    # an unscanned skill has NULL there, and dropping the columns would leave those
    # rows unrepresentable. Deleting them silently is not an option for an audit
    # table, so this downgrade fails loudly if any exist - which is the correct
    # outcome: the operator must decide what to do with real audit records.
    op.alter_column(
        "marketplace_fetch_log",
        "scan_id",
        existing_type=sa.String(length=36),
        nullable=False,
    )
    op.drop_column("marketplace_fetch_log", "unsafe_reason_shown")
    op.drop_column("marketplace_fetch_log", "is_safe_shown")
    op.drop_column("marketplace_fetch_log", "content_hash_shown")
    op.drop_index("ix_marketplace_fetch_log_skill_id", table_name="marketplace_fetch_log")
    op.drop_column("marketplace_fetch_log", "skill_id")
