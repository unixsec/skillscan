"""add scan_result.findings_total

2026-07-28 (milestone B' Task 1 review, Critical): the marketplace projection's
`summary.total` (spec §5.3) is documented as "the real count even when the
findings array was capped", but `ScanResultRow` only ever recorded
`findings_capped: bool` - there was no column to hold the true pre-cap count.
Once `findings` itself is the post-cap (>= milestone A, 5000-item) list, any
`total` derived from `len(findings)` is not the real number for a capped scan;
it is just the cap. `scoring.py aggregate()` already preserves
`pre_cap_hard_gate_hits`/`pre_cap_trifecta_present` for exactly this reason
(a finding flood must not make information unrecoverable, only the full
findings list) - this column closes the same gap for the total count.

Nullable with no backfill on purpose: pre-existing rows never captured the
pre-cap count, and it cannot be reconstructed after the fact - the findings
that were truncated away are simply gone. NULL is the honest answer for those
rows, not 0 and not the post-cap `len(findings)` (see
`marketplace_api.views._summarize`, which falls back to `len(findings)` only
when this column is NULL and documents that fallback as a degraded-but-honest
answer for already-capped historical rows, and the correct answer for
un-capped ones).

Revision ID: c22ba961a06e
Revises: b7c41f9d2e08
Create Date: 2026-07-28 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c22ba961a06e"
down_revision: str | Sequence[str] | None = "b7c41f9d2e08"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scan_result",
        sa.Column("findings_total", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scan_result", "findings_total")
