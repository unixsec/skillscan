"""add scan_job.skill_name

2026-07-14: Scans list page needs a human-readable name to distinguish scan
targets, distinct from skill_id (which is only present for scans explicitly
registered into inventory - most ad-hoc submissions show "not registered").
Parsed once at submission time from the uploaded package's SKILL.md YAML
frontmatter `name:` field (gateway/router.py's create_scan) and stored
directly on scan_job so every scan has it, registered or not - never derived
from skill_id/skill_version, which many scans don't have.

Revision ID: a3d3501e06a3
Revises: 772bfe6609de
Create Date: 2026-07-14 20:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a3d3501e06a3"
down_revision: str | Sequence[str] | None = "772bfe6609de"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scan_job", sa.Column("skill_name", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_job", "skill_name")
