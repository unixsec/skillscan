"""add skill_lifecycle_event fk and verdict content_hash index

Two schema gaps found in review, both between the original §7.1 DDL
(1d6112d0e997) and the later M8 additive tables:

1. skill_lifecycle_event.skill_id (2307212254dd) has no FOREIGN KEY back to
   skill(skill_id), unlike skill_version - its sibling child table of skill,
   and the only other table inventory.service writes alongside it. Nothing
   in the DB currently rejects a lifecycle event for a skill_id that doesn't
   exist; add fk_sle_skill to match fk_sv_skill's precedent (1d6112d0e997).
   No pre-check/backfill here: a fresh or correctly-running deployment has
   no reason to hold orphaned rows (skill rows are never deleted - INV-12
   append-only posture - so there is no deletion race that could produce
   one either), and no other migration in this project's history does a
   pre-check before adding a constraint (see e.g. 52ff865d36f6, which just
   drops+re-adds a CHECK directly).

2. verdict.content_hash (1d6112d0e997) has no index, despite being the
   WHERE ... IN (...) filter monolith.worker.sync_lifecycle_tick issues on
   every tick (a hot path) - an unindexed scan on verdict, which is
   append-only and only grows. Add idx_content_hash to close the gap, same
   shape as skill_version's own idx_skill.

Revision ID: 02723a42c8e9
Revises: e4b8c31a90d2
Create Date: 2026-07-10

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "02723a42c8e9"
down_revision: str | Sequence[str] | None = "e4b8c31a90d2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # -- inventory module (skill_lifecycle_event child-of-skill FK, matching
    # skill_version's own fk_sv_skill precedent, 1d6112d0e997) --------------
    op.execute("""
        ALTER TABLE skill_lifecycle_event
        ADD CONSTRAINT fk_sle_skill FOREIGN KEY (skill_id) REFERENCES skill(skill_id)
    """)

    # -- gate module (verdict.content_hash is the hot-path lookup key for
    # monolith.worker.sync_lifecycle_tick's WHERE content_hash IN (...)) ----
    op.execute("""
        CREATE INDEX idx_content_hash ON verdict (content_hash)
    """)


def downgrade() -> None:
    op.execute(sa.text("DROP INDEX idx_content_hash ON verdict"))
    op.execute(sa.text("ALTER TABLE skill_lifecycle_event DROP FOREIGN KEY fk_sle_skill"))
