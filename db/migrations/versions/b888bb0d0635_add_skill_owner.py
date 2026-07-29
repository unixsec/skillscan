"""add skill.owner

Milestone F Task 11 follow-up C1 - the column that makes "who may submit a new
version of this skill" answerable at all.

WHY. Task 11 fixed a real lockout: `"submitted"` appeared ZERO times as a
target state in `inventory.lifecycle.VALID_TRANSITIONS`, while
`register_skill_version` routes every already-known `skill_id` through a
validated `current_state -> "submitted"` transition - so no skill could ever
have a second version submitted, and every v2 release and every resubmission of
a fixed BLOCKed skill got a permanent 409. That always-failing transition had
been doing unintended double duty, though: a submission naming SOMEONE ELSE's
`skill_id` also hit that 409 and changed nothing. Removing the lockout removed
the accidental control, and `skill` had no owner column, so nothing on the
submission path knew who a skill belongs to. With `skill_id` AND `trust_tier`
both caller-supplied form fields on `POST /v1/scans`, any caller holding submit
rights could name any existing skill, knock it out of `published`, write their
own `skill_version` row, have it judged at a tier they chose, and on PASS leave
that skill published with their content. This column is where the answer lives.

OWNER = THE IDENTITY THAT FIRST REGISTERED THE SKILL. Written once, at genesis,
by `inventory.service.register_skill_version`, and never updated afterwards -
neither a resubmission nor an admin override transfers it. `inventory.
ownership.authorize_skill_write` is the single place the value is interpreted.

**NOT BACKFILLED, and NULL fails closed.** Every pre-existing row reads NULL,
which means "no owner is on record"; `authorize_skill_write` refuses a
non-admin write to such a skill rather than defaulting into permissiveness -
defaulting the other way would leave the hole wide open for exactly the rows an
attacker would most want (every skill that existed before the fix).

The backfill that LOOKS available was considered and deliberately rejected,
which is the opposite call from 3c7e1b40d95a (whose backfill was honest) and
the same call as 0d4bc5bc6b27 (which refused to guess). `skill_lifecycle_event`
does carry an `actor` on each skill's genesis (`from_state IS NULL`) event, and
that actor IS by construction whoever first registered the skill - so this
would not have been a guess, and that is worth stating plainly so nobody
"rediscovers" it later and assumes it was missed. It was rejected on blast
radius and on asymmetry of failure: that column was written as an AUDIT field,
and promoting it to an AUTHORIZATION field retroactively would confer real
ownership over every row in a populated deployment (~481 bulk-imported
real-world skills in the VM database alone) on the strength of a value nobody
recorded with authorization in mind. A wrong backfill silently grants authority
and is nearly undetectable; fail-closed NULL produces a loud 403 that an admin
can resolve deliberately. If the operator later decides genesis actors ARE the
rightful owners, that backfill is still available as its own reviewed
migration - the reverse is not.

Nullable with no server default, for the same reason 0d4bc5bc6b27 gives: a
DEFAULT would let a future writer that forgets the column record an owner
nobody verified. `register_skill_version` takes `actor_is_admin` as a required
keyword instead, so a submission path that has not considered authorization is
a type error at the call site rather than a silently unauthorized write.

No GRANT change: `policies/grants/manifest.yaml` already gives svc_inventory
ALL on `skill`, and MySQL table-level grants cover columns present and future.
The cross-module readers (svc_reeval, svc_reporting) hold `skill: [SELECT]`,
which likewise needs no amendment.

Operationally an ADD COLUMN at the end of a narrow table, which MySQL 8 does
with ALGORITHM=INSTANT - no table rebuild, no long metadata lock, so it is safe
against a populated `skill` in the deployed database.

Revision ID: b888bb0d0635
Revises: 0d4bc5bc6b27
Create Date: 2026-07-29 04:10:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b888bb0d0635"
down_revision: str | Sequence[str] | None = "0d4bc5bc6b27"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # VARCHAR(255) matches every other identity-subject column in the schema
    # (`skill_lifecycle_event.actor`, `audit_intent.operator`,
    # `scan_submitter.submitter`) - an owner is one of those same subjects.
    op.add_column("skill", sa.Column("owner", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("skill", "owner")
