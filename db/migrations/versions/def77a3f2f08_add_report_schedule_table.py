"""add report_schedule table

coding spec §16.2's reporting module (FR-REP) needs somewhere to persist
`POST /v1/reports/schedule`'s `{template, cron, targets}` - not part of the
original §7.1 DDL (reporting was added later, in §16.2's "补"/supplement),
so this is an ADDITIVE new table owned by a new `svc_reporting` module, same
shape as `policy_proposal`/`skill_lifecycle_event` before it. `targets` is
JSON (a list of intranet-only SIEM/email destinations, coding spec §16.2:
"推送计划(cron → SIEM/邮件内网)") since a schedule may fan out to more than
one destination.

SECURITY: this table stores the DECLARATIVE schedule only ("what to send,
how often, where") - actually firing on the cron schedule and delivering to
those destinations requires a live background worker process this
environment cannot stand up or verify (same class of gap as M6's live
marketplace push / M7's live DR drill; see docs/stories/BACKLOG.md's S8
status note).

Revision ID: def77a3f2f08
Revises: 52ff865d36f6
Create Date: 2026-07-05 21:27:22.480145

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "def77a3f2f08"
down_revision: str | Sequence[str] | None = "52ff865d36f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # -- reporting module (new, coding spec §16.2 FR-REP) ------------------
    op.execute("""
        CREATE TABLE report_schedule (
          id              BIGINT AUTO_INCREMENT PRIMARY KEY,
          template        VARCHAR(64) NOT NULL,
          cron            VARCHAR(64) NOT NULL,
          targets         JSON NOT NULL,
          created_by      VARCHAR(255) NOT NULL,
          created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS report_schedule"))
