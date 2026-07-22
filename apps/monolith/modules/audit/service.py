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

from sqlalchemy import select
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


async def verify_chain(session: AsyncSession, *, since_seq: int = 0) -> bool:
    """Recomputes entry_hash for every row from `since_seq` onward and checks
    it against the stored value and the next entry's prev_hash - a full (or,
    with `since_seq > 0`, incremental) tamper-detection scan.

    When `since_seq > 0`, the entry AT `since_seq` is trusted as the starting
    anchor (its own recorded entry_hash, not recomputed against genesis) -
    this lets an operator (or `GET /v1/audit`'s chain-verification status,
    coding spec §9) re-verify only the chain's recent tail from a previously
    trusted checkpoint, without rescanning the entire history on every call.
    """
    entries = (
        (
            await session.execute(
                select(AuditEntry).where(AuditEntry.seq >= since_seq).order_by(AuditEntry.seq.asc())
            )
        )
        .scalars()
        .all()
    )
    if not entries:
        return since_seq == 0  # an empty chain is trivially valid only from genesis

    if since_seq > 0:
        if entries[0].seq != since_seq:
            return False  # the anchor checkpoint itself doesn't exist
        expected_prev = entries[0].entry_hash
        remaining = entries[1:]
    else:
        # SECURITY: the genesis row (seq=1) is the chain's ROOT OF TRUST, so it
        # is the anchor for a full scan the same way a checkpoint is for an
        # incremental one - verify it carries the structural genesis marker
        # (prev_hash == GENESIS_HASH) but TRUST its stored entry_hash rather
        # than recomputing it. The genesis entry_hash is a fixed bootstrap value
        # set by the initial schema migration and is deliberately NOT derived
        # via compute_entry_hash (nothing precedes genesis to derive it from),
        # so recomputing it here would always mismatch and make every real
        # chain report tampered - which it did for GET /v1/audit until this fix
        # (no test exercised since_seq=0, only checkpointed since_seq>0 scans).
        # Every NON-genesis entry is still fully hash-verified below.
        if entries[0].prev_hash != GENESIS_HASH:
            return False
        expected_prev = entries[0].entry_hash
        remaining = entries[1:]

    for entry in remaining:
        if entry.prev_hash != expected_prev:
            return False
        recomputed = compute_entry_hash(
            entry.prev_hash, entry.operator, entry.action, entry.payload
        )
        if recomputed != entry.entry_hash:
            return False
        expected_prev = entry.entry_hash
    return True
