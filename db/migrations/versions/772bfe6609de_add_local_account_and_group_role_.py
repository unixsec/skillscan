"""add local_account and group_role_mapping tables

2026-07-14 (item #13, admin console redesign): "user management" so far only
covered breakglass/local_auth (env-JSON-sourced, read-only after startup) and
group_role_map.yaml (git/PR-reviewed, read-only after startup) - neither
supports an admin actually managing accounts or role mappings at runtime.
Both become admin's own new, additive tables (svc_admin - the module's first
ever owned table; every prior admin/router.py write borrowed another
module's session/credentials for its own domain data), same "new module, new
table" shape as svc_reporting's report_schedule (def77a3f2f08) before it.

local_account: `status` (active/disabled) rather than DELETE, mirroring this
codebase's consistent revoke-not-delete posture (allowlist/breakglass) so a
disabled account's audit history (who created it, when) is never lost.

group_role_mapping: group_name is the PK (one role per IdP group, matching
rbac.load_group_role_map's existing "dict[str,str]" semantics exactly) - both
tables are seeded once from their pre-existing config sources
(SKILLSCAN_LOCAL_ACCOUNTS_JSON / policies/rbac/group_role_map.yaml) on first
boot if empty, then the DB is authoritative (apps/monolith/main.py's
_seed_admin_tables_if_empty).

Revision ID: 772bfe6609de
Revises: 02723a42c8e9
Create Date: 2026-07-14 09:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "772bfe6609de"
down_revision: str | Sequence[str] | None = "02723a42c8e9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # -- admin module (new, coding spec has no §-anchor - post-milestone item
    # #13, scoped/approved via the 2026-07-14 conversational punch-list, not
    # a formal spec section) -------------------------------------------------
    op.execute("""
        CREATE TABLE local_account (
          id              BIGINT AUTO_INCREMENT PRIMARY KEY,
          username        VARCHAR(255) NOT NULL,
          password_hash   VARCHAR(255) NOT NULL,
          role            VARCHAR(32) NOT NULL,
          status          VARCHAR(16) NOT NULL DEFAULT 'active',
          created_by      VARCHAR(255) NOT NULL,
          created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
          updated_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
          UNIQUE KEY uq_local_account_username (username)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)
    op.execute("""
        CREATE TABLE group_role_mapping (
          group_name      VARCHAR(255) NOT NULL PRIMARY KEY,
          role            VARCHAR(32) NOT NULL,
          updated_by      VARCHAR(255) NOT NULL,
          updated_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS group_role_mapping"))
    op.execute(sa.text("DROP TABLE IF EXISTS local_account"))
