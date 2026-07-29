"""Audit intent drain + hash-chain append (coding spec §7.3, INV-12).

SECURITY: the chain is append-only and tamper-evident - each entry's hash binds
the previous entry's hash plus this entry's own canonical payload. Concurrent
appenders serialize on `SELECT ... FOR UPDATE` against the chain tail, so no two
processes can ever compute a hash from the same prev_hash and both commit.
`audit_intent` rows are written by the *business* transaction that generated
them (e.g. gate's verdict+outbox+intent insert, coding spec §12); this service
only drains unchained intents into the ledger - it does not create intents.

SECURITY (empirically discovered, not just theoretical): a naive
`SELECT ... ORDER BY seq DESC LIMIT 1 FOR UPDATE` against the tail is NOT
sufficient for correctness under real concurrency. Under real load-testing
against local MySQL 8, a second transaction blocked on that lock, once
unblocked by the first transaction's commit, can be handed back the row it
originally targeted (now stale - a newer row exists) rather than re-discovering
the new true max. This silently forks the chain (two entries both claiming the
same predecessor) without raising any error - `verify_chain` is the only thing
that notices, after the fact. `append_one_intent` defends against this
directly: after acquiring the tail lock, it re-checks for a newer row and
raises `_StaleTailDetected` (always retried by `_drain_one_with_retry`) rather
than trusting the locked row blindly.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditEntry, AuditIntent

SessionFactory = Callable[[], AsyncSession]

GENESIS_HASH = "0" * 64

# SECURITY: "SELECT ... ORDER BY seq DESC LIMIT 1 FOR UPDATE" against the chain
# tail is InnoDB's well-documented gap-lock deadlock pattern under concurrent
# appenders (each INSERT of a new max-seq row contends for the same
# next-key/gap lock) - MySQL error 1213 (deadlock) and 1205 (lock wait timeout)
# are the expected, transient result, not a bug. The standard mitigation is to
# retry the losing transaction, which `_drain_one_with_retry` below does.
_MYSQL_DEADLOCK_ERRNO = 1213
_MYSQL_LOCK_WAIT_TIMEOUT_ERRNO = 1205
# SECURITY: generous on purpose - chain append is a low-throughput background
# drain, not a latency-sensitive hot path, and each retry is cheap (a rolled-
# back transaction + a fresh query). Under sustained N-way concurrency, a
# losing transaction can plausibly need several retries (a stale-tail retry's
# fresh read can itself become the next blocked transaction's stale target);
# failing loudly after exhausting retries is still fail-closed and far better
# than silently forking the chain.
_MAX_APPEND_RETRIES = 50


def _is_retryable_lock_error(exc: OperationalError) -> bool:
    orig = exc.orig
    if orig is None or not orig.args:
        return False
    return orig.args[0] in (_MYSQL_DEADLOCK_ERRNO, _MYSQL_LOCK_WAIT_TIMEOUT_ERRNO)


class _StaleTailDetected(Exception):
    """Internal: the locked tail row was not actually the current max (see
    module SECURITY note) - always retried, never surfaced to callers."""


def canonical_json(payload: dict[str, Any]) -> str:
    """Deterministic serialization for hashing: sorted keys, no extra whitespace.
    SECURITY: must be used identically every time the same payload is hashed -
    any drift (key order, whitespace, float formatting) would make the chain
    unverifiable against re-computation."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_entry_hash(prev_hash: str, operator: str, action: str, payload: dict[str, Any]) -> str:
    intent_canonical = canonical_json({"operator": operator, "action": action, "payload": payload})
    return hashlib.sha256((prev_hash + intent_canonical).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ChainedEntry:
    seq: int
    prev_hash: str
    entry_hash: str


async def append_one_intent(session: AsyncSession, intent: AuditIntent) -> ChainedEntry:
    """Chains exactly one intent. SECURITY: caller must hold this within a
    transaction - the `FOR UPDATE` tail-lock is only serializing if the whole
    read-compute-insert-update sequence is one atomic unit. Raises
    `_StaleTailDetected` (see module SECURITY note) if the locked tail turns
    out not to be the true current max - callers must retry, never treat the
    computed hash as valid in that case."""
    tail = (
        await session.execute(
            select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1).with_for_update()
        )
    ).scalar_one_or_none()
    prev_hash = tail.entry_hash if tail is not None else GENESIS_HASH

    if tail is not None:
        # SECURITY: defends against the empirically-observed stale-tail case -
        # a plain (non-locking) check under this transaction's read view is
        # enough to detect it; the fix is to retry the whole operation, not to
        # somehow "fix up" this read.
        newer_exists = (
            await session.execute(select(AuditEntry.seq).where(AuditEntry.seq > tail.seq).limit(1))
        ).scalar_one_or_none()
        if newer_exists is not None:
            raise _StaleTailDetected(f"locked tail seq={tail.seq} is stale, newer entries exist")

    entry_hash = compute_entry_hash(prev_hash, intent.operator, intent.action, intent.payload)
    entry = AuditEntry(
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        operator=intent.operator,
        action=intent.action,
        payload=intent.payload,
        chained_at=datetime.now(UTC).replace(tzinfo=None),
    )
    session.add(entry)
    intent.chained = True
    await session.flush()
    return ChainedEntry(seq=entry.seq, prev_hash=prev_hash, entry_hash=entry_hash)


async def _drain_one_with_retry(session_factory: SessionFactory) -> ChainedEntry | None:
    """Claims and chains exactly one pending intent, retrying on a transient
    InnoDB deadlock/lock-wait-timeout or a detected stale tail read (see
    module-level SECURITY note). Returns None if there is currently no pending
    intent to claim."""
    for attempt in range(_MAX_APPEND_RETRIES):
        try:
            async with session_factory() as session:
                # SECURITY: READ COMMITTED avoids InnoDB's next-key gap-locking
                # for "ORDER BY seq DESC LIMIT 1 FOR UPDATE" against the chain
                # tail (append_one_intent) - this code's correctness comes from
                # the explicit FOR UPDATE row lock, not from repeatable-read
                # snapshot semantics, so relaxing phantom protection here is
                # safe and removes the standard root cause of this deadlock
                # pattern. NOTE: `session.connection(execution_options=...)`
                # itself autobegins the session's transaction, so we commit
                # explicitly below rather than nesting in `session.begin()`
                # (which would raise "a transaction is already begun").
                await session.connection(execution_options={"isolation_level": "READ COMMITTED"})
                pending = (
                    await session.execute(
                        select(AuditIntent)
                        .where(AuditIntent.chained.is_(False))
                        .order_by(AuditIntent.id.asc())
                        .limit(1)
                        .with_for_update(skip_locked=True)
                    )
                ).scalar_one_or_none()
                if pending is None:
                    return None
                result = await append_one_intent(session, pending)
                await session.commit()
                return result
        except _StaleTailDetected:
            if attempt == _MAX_APPEND_RETRIES - 1:
                raise
            continue
        except OperationalError as exc:
            if not _is_retryable_lock_error(exc) or attempt == _MAX_APPEND_RETRIES - 1:
                raise
    raise AssertionError("unreachable: loop always returns or raises")


async def drain_pending_intents(
    session_factory: SessionFactory, *, batch_size: int = 50
) -> list[ChainedEntry]:
    """Drains up to `batch_size` unchained intents, one at a time, each in its
    own short transaction (coding spec §7.3: "短事务 → FOR UPDATE 争用可忽略").
    Chaining one intent per transaction (rather than the whole batch in one
    transaction) keeps the tail-lock hold time minimal under concurrent
    appenders/drainers.

    SECURITY: the spec explicitly allows ANY replica to drain concurrently, no
    leader election (§7.3) - `SELECT ... FOR UPDATE SKIP LOCKED` on the pending
    intent itself (not just the chain tail in `append_one_intent`) is what
    makes that safe: two concurrent drainers racing for the same row never both
    pick it, so one business event can never be chained twice.
    """
    chained: list[ChainedEntry] = []
    while len(chained) < batch_size:
        entry = await _drain_one_with_retry(session_factory)
        if entry is None:
            break
        chained.append(entry)
    return chained


async def count_unchained_intents(session: AsyncSession) -> int:
    """How many `audit_intent` rows are still waiting to be chained, right now.

    SECURITY (Task 13, 2026-07-29): this is the read behind the
    `audit_intent_unchained` gauge (coding spec §11.7). A backlog that grows
    without bound means business events are being RECORDED but never made
    tamper-evident - the ledger's INV-12 guarantee covers only what has
    actually been chained, so an unchained intent is an audit record with no
    hash protecting it yet. Until this existed there was no query in the
    codebase that could answer the question at all: the only unchained-row
    predicate was `_drain_one_with_retry`'s `LIMIT 1` claim, which by
    construction can never distinguish "one pending" from "fifty thousand
    pending".

    Deliberately a plain COUNT with no `FOR UPDATE`, no isolation change and
    no participation in the drain's transaction: this is an observation, and
    it must never be able to block or deadlock the drainer it is observing.
    The count it returns is therefore a snapshot that may be stale the moment
    it is read, which is exactly the right semantics for a gauge. The initial
    migration already carries `INDEX idx_unchained (chained, id)`, so this is
    an index-only scan rather than a table scan of the whole intent history.
    """
    return int(
        (
            await session.execute(
                select(func.count()).select_from(AuditIntent).where(AuditIntent.chained.is_(False))
            )
        ).scalar_one()
    )


async def verify_chain(session: AsyncSession) -> bool:
    """Recomputes entry_hash for EVERY row from the genesis entry to the tail
    and checks it against the stored value and the next entry's prev_hash.
    `True` has exactly one meaning: the whole ledger is intact.

    SECURITY (milestone F Task 17): this deliberately takes no `since_seq` /
    cursor argument, and callers cannot ask for a cheaper answer. It used to
    accept one, and `since_seq > 0` ANCHORED the scan on the entry at the
    cursor - that entry's stored entry_hash was trusted as the starting point
    and every entry before it was never read at all. So a rewrite of an earlier
    entry (or of the anchor entry's own payload, which was never recomputed)
    was invisible to that scan, while the bool it returned was indistinguish-
    able from a whole-ledger result. `GET /v1/audit?since_seq=N` fed that bool
    straight to the console as "chain intact". A tamper-evidence primitive with
    a weaker mode one keyword argument away WILL be called in the weaker mode,
    and the weaker answer WILL be read as the strong one - this repo has
    already shipped one audit-verification defect of exactly that shape (the
    genesis hash was never verified, so `chain_valid` was permanently False and
    nobody noticed until the first VM deploy, because the return value was
    consumed as a conclusion and never asserted against a known-tampered
    chain). The fix is to delete the weaker mode, not to document it.

    COST: O(ledger), unconditionally. This is not new spend - it is exactly
    what the endpoint's default (unparameterized) call already did on every
    audit page load, so the whole-ledger scan was already the steady-state
    cost and only the *paged* calls were getting the cheap, misleading answer.
    Measured: re-hashing 3000 representative entries (the VM ledger's size)
    takes ~8 ms of CPU; the row fetch dominates, and only projected columns are
    read, not whole ORM entities. If the ledger ever grows to where this hurts,
    the answer is a *signed, periodically re-verified checkpoint* that makes an
    incremental scan trustworthy - not an unsigned caller-supplied cursor.
    """
    # Project only the columns the verification needs: no ORM identity-map
    # bookkeeping for a scan that touches every row and keeps none of them.
    rows = (
        await session.execute(
            select(
                AuditEntry.prev_hash,
                AuditEntry.entry_hash,
                AuditEntry.operator,
                AuditEntry.action,
                AuditEntry.payload,
            ).order_by(AuditEntry.seq.asc())
        )
    ).all()
    if not rows:
        # SECURITY (2026-07-29, milestones E+F review): FALSE, not True. This
        # used to read "an empty ledger has nothing to have been tampered
        # with", which is true of a table that was never created and false of
        # every deployment this code actually runs in: the genesis row is
        # INSERTed by the initial schema migration itself
        # (1d6112d0e997_initial_core_schema.py), so `audit_entry` is non-empty
        # from the moment the schema exists. An empty ledger therefore does not
        # mean "nothing happened yet" - it means THE LEDGER WAS DELETED, which
        # is the most complete form of the tampering every other path in this
        # function exists to detect. `DELETE FROM audit_entry` reported
        # `chain_valid: true` and the console printed "chain intact" over an
        # erased audit trail.
        #
        # Failing closed also costs nothing real: the only way to reach this
        # branch legitimately would be a database whose migrations have not
        # run, where every other audit operation is broken anyway.
        return False

    # SECURITY: the genesis row (seq=1) is the chain's ROOT OF TRUST and the
    # only entry whose stored hash is trusted rather than recomputed - verify it
    # carries the structural genesis marker (prev_hash == GENESIS_HASH), which
    # also catches a genesis row that was deleted outright (the lowest surviving
    # row would not carry the marker). The genesis entry_hash is a fixed
    # bootstrap value set by the initial schema migration and is deliberately
    # NOT derived via compute_entry_hash (nothing precedes genesis to derive it
    # from), so recomputing it here would always mismatch and make every real
    # chain report tampered - which it did for GET /v1/audit until that was
    # fixed. Every NON-genesis entry is fully hash-verified below.
    genesis_prev_hash, expected_prev, _, _, _ = rows[0]
    if genesis_prev_hash != GENESIS_HASH:
        return False

    for prev_hash, entry_hash, operator, action, payload in rows[1:]:
        if prev_hash != expected_prev:
            return False
        if compute_entry_hash(prev_hash, operator, action, payload) != entry_hash:
            return False
        expected_prev = entry_hash
    return True
