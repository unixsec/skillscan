"""add 'applied' to policy_proposal.status enum

Policy approval previously had no operational effect: nothing ever turned an
approved proposal into the ACTIVE gate policy. The new apply path
(monolith.worker.promote_approved_policy, called by the admin approve
endpoint) marks the proposal 'applied' after swapping the live policy, and
the background worker's reload converges restarts/replicas on the newest
'applied' row. Rows that sit at 'approved' (everything approved before this
path existed) deliberately stay inert - activation is a per-proposal act,
never a retroactive sweep.

Revision ID: e4b8c31a90d2
Revises: def77a3f2f08
Create Date: 2026-07-06

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e4b8c31a90d2"
down_revision: str | Sequence[str] | None = "def77a3f2f08"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE policy_proposal MODIFY status "
        "ENUM('pending','approved','rejected','applied') NOT NULL DEFAULT 'pending'"
    )


def downgrade() -> None:
    # Any 'applied' rows must be representable after the enum shrinks - demote
    # them to 'approved' (loses only the applied marker, not the approval).
    op.execute("UPDATE policy_proposal SET status = 'approved' WHERE status = 'applied'")
    op.execute(
        "ALTER TABLE policy_proposal MODIFY status "
        "ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending'"
    )
