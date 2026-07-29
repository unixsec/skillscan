"""add verdict.score

2026-07-25: a 0-100 advisory score, deterministically derived from the
already-decided verdict + its findings and never an input to the decision
itself - `skillscan_core.scoring.security_score`, called from
`skillscan_core.gate.decide()` after the verdict is fixed. Existing
rows predate scoring and have no findings recorded to recompute a real score
from, so they're backfilled to the midpoint of their verdict's band
(BLOCK=20, REVIEW=57, PASS=87) rather than left NULL - the API always returns
an int for this field, never null, for a row that has a verdict at all.

Revision ID: f19c2a7e5b3d
Revises: a3d3501e06a3
Create Date: 2026-07-25 09:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f19c2a7e5b3d"
down_revision: str | Sequence[str] | None = "a3d3501e06a3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("verdict", sa.Column("score", sa.SmallInteger(), nullable=True))
    op.execute("UPDATE verdict SET score = 20 WHERE verdict = 'BLOCK'")
    op.execute("UPDATE verdict SET score = 57 WHERE verdict = 'REVIEW'")
    op.execute("UPDATE verdict SET score = 87 WHERE verdict = 'PASS'")
    op.alter_column("verdict", "score", existing_type=sa.SmallInteger(), nullable=False)


def downgrade() -> None:
    op.drop_column("verdict", "score")
