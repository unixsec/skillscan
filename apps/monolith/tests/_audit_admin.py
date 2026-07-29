"""Out-of-band (privileged) writes to `audit_entry`, for audit tests only.

SECURITY (threat model): `audit_entry` is append-only to EVERY application user -
svc_audit has INSERT+SELECT and deliberately no UPDATE/DELETE (INV-12 immutability),
and `conftest.py`'s fixtures stay on those least-privilege credentials on purpose.
The hash-chain tests legitimately need two writes that NO app path is ever permitted
to make:

  1. simulating an attacker/DBA who bypasses the grants to mutate or delete a row -
     exactly the tampering the hash chain exists to DETECT, and something the
     least-privilege grants themselves cannot prevent;
  2. resetting the shared, ever-accumulating dev ledger back to its genesis anchor so
     a whole-chain assertion is deterministic even though other test files seed
     non-chaining dummy `audit_entry` rows into the same table.

Both therefore run over a separate privileged connection. Do NOT widen any grant in
`db/setup_grants.py` to make these easier - that file is additive (no REVOKE), so a
grant added "just for tests" silently survives into every dev database and can make a
tamper test pass that should have failed.
"""

from __future__ import annotations

import os

from common.db import make_engine
from sqlalchemy import text

_ADMIN_DB_URL = os.environ.get(
    "SKILLSCAN_TEST_ADMIN_DB_URL", "mysql+aiomysql://root@localhost/skillscan"
)


async def admin_exec(sql: str, params: dict[str, object] | None = None) -> None:
    engine = make_engine(_ADMIN_DB_URL)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql), params or {})
    finally:
        await engine.dispose()


async def wipe_entire_ledger() -> None:
    """Delete EVERY row, genesis included - the total-erasure attack, simulated.

    SECURITY (2026-07-29, milestones E+F review): `verify_chain` used to return
    True on an empty ledger, so `DELETE FROM audit_entry` reported "chain
    intact". Proving that is fixed requires actually emptying the table, which
    no application user may do and `reset_chain_to_genesis` deliberately does
    not (it keeps the anchor).

    ALWAYS pair this with `restore_genesis_row()` in a `finally` - this dev
    ledger is shared across the whole suite, and leaving it empty would break
    `append_one_intent` for every later test (and for the local dev backend).
    """
    await admin_exec("DELETE FROM audit_entry")


async def restore_genesis_row() -> None:
    """Put the anchor back, byte-identical to what the initial schema migration
    writes (1d6112d0e997_initial_core_schema.py) - same operator, action,
    payload and hashes, and explicitly at `seq = 1`.

    The explicit seq matters: InnoDB does not rewind AUTO_INCREMENT after a
    DELETE, so a re-inserted genesis would otherwise land at some large seq and
    `reset_chain_to_genesis()` ("delete everything above seq 1") would erase it
    on the next test that calls it, leaving the ledger permanently anchorless.
    """
    await admin_exec("""
        INSERT INTO audit_entry (seq, prev_hash, entry_hash, operator, action, payload)
        VALUES (
            1,
            REPEAT('0', 64),
            SHA2(CONCAT(REPEAT('0', 64), '{"action":"genesis"}'), 256),
            'system',
            'chain_genesis',
            JSON_OBJECT('note', 'audit hash-chain genesis entry')
        )
    """)


async def reset_chain_to_genesis() -> None:
    """Delete every non-genesis row so a whole-chain assertion is not polluted by the
    dummy/non-chaining `audit_entry` rows other test files seed into this shared,
    append-only ledger (see module note - this is an out-of-band admin write).

    NOTE: InnoDB's AUTO_INCREMENT counter is not rewound by a DELETE, so entries
    chained after this call keep the ledger's real (large) seq values and there is a
    wide gap above genesis. Nothing in `verify_chain` depends on seq contiguity.
    """
    await admin_exec("DELETE FROM audit_entry WHERE seq > 1")
