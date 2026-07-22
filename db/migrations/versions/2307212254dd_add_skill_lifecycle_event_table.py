"""add skill_lifecycle_event table

coding spec §16.2's skill lifecycle state machine (M8) needs somewhere to
record each transition - the original §7.1 DDL's `skill`/`skill_version`
tables have no status/state column at all (that DDL predates M8's own
detailed spec), so this is an ADDITIVE new table, not a change to the
already-applied initial migration. Append-only, mirroring `audit_entry`'s
own event-log pattern (coding spec §7.3) - "current state" is derived as
"the `to_state` of the most recent event for this skill_id", never updated
in place.

Revision ID: 2307212254dd
Revises: 1d6112d0e997
Create Date: 2026-07-05 20:29:59.868446

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "2307212254dd"
down_revision: str | Sequence[str] | None = "1d6112d0e997"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # -- inventory module (owns skill/skill_version/baseline too, §7.1) ----
    op.execute("""
        CREATE TABLE skill_lifecycle_event (
          id              BIGINT AUTO_INCREMENT PRIMARY KEY,
          skill_id        VARCHAR(128) NOT NULL,
          content_hash    CHAR(64) NULL,
          from_state      VARCHAR(32) NULL,
          to_state        VARCHAR(32) NOT NULL,
          reason          TEXT NULL,
          actor           VARCHAR(255) NOT NULL,
          occurred_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
          INDEX idx_skill_id (skill_id, id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS skill_lifecycle_event"))
