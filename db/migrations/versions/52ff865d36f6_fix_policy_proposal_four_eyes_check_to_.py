"""fix policy_proposal four eyes check to be conditional on hard gate changes

The original `chk_policy_proposal_four_eyes` constraint (a67ad93f6c55)
unconditionally required `approved_by <> proposed_by`, but the actual design
(gate.policy_workflow.propose_policy_change) deliberately self-approves a
proposal that does NOT touch `hard_gate_rules` (a single admin's judgment is
sufficient for non-hard-gate tuning per coding spec §16.1's own scoping of
the two-person requirement to hard-gate items specifically) - caught
immediately by a real DB constraint violation when a test actually exercised
the auto-approval path, not assumed correct from reading the code alone.

Revision ID: 52ff865d36f6
Revises: a67ad93f6c55
Create Date: 2026-07-05 20:47:44.883570

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "52ff865d36f6"
down_revision: str | Sequence[str] | None = "a67ad93f6c55"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE policy_proposal DROP CHECK chk_policy_proposal_four_eyes")
    op.execute("""
        ALTER TABLE policy_proposal ADD CONSTRAINT chk_policy_proposal_four_eyes CHECK (
          changes_hard_gate_rules = FALSE OR approved_by IS NULL OR approved_by <> proposed_by
        )
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE policy_proposal DROP CHECK chk_policy_proposal_four_eyes")
    op.execute(
        sa.text(
            "ALTER TABLE policy_proposal ADD CONSTRAINT chk_policy_proposal_four_eyes "
            "CHECK (approved_by IS NULL OR approved_by <> proposed_by)"
        )
    )
