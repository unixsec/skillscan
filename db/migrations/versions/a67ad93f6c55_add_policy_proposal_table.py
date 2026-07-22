"""add policy_proposal table

coding spec §9/§16.1: gate policy changes are config-as-code + PR-reviewed,
but hard-gate rule changes specifically need a two-person (four-eyes) sign-off
BEFORE the config-as-code PR is even opened (coding spec: "硬门禁项变更需二人
+ 审计" - hard-gate item changes need two people + audit). This table records
that approval workflow itself - it is NOT the live policy (policies/gate/
*.yaml on disk still is; an approved proposal is a precondition for someone
then opening the actual PR, not a runtime policy mutation).

Revision ID: a67ad93f6c55
Revises: 2307212254dd
Create Date: 2026-07-05 20:39:30.990855

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a67ad93f6c55"
down_revision: str | Sequence[str] | None = "2307212254dd"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # -- gate module (policy is gate's own domain concept, §9 admin·policy) -
    op.execute("""
        CREATE TABLE policy_proposal (
          id                      BIGINT AUTO_INCREMENT PRIMARY KEY,
          proposed_policy_yaml    TEXT NOT NULL,
          changes_hard_gate_rules BOOL NOT NULL,
          status                  ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
          proposed_by             VARCHAR(255) NOT NULL,
          approved_by             VARCHAR(255) NULL,
          reason                  TEXT NULL,
          created_at              DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
          decided_at              DATETIME(6) NULL,
          CONSTRAINT chk_policy_proposal_four_eyes CHECK (
            approved_by IS NULL OR approved_by <> proposed_by
          )
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS policy_proposal"))
