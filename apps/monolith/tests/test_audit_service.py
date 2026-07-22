"""Tests for `audit.service` (coding spec §7.3, INV-12) against the real local
MySQL instance - hash-chain append, drain, and (the M3 acceptance bar) that
concurrent drainers never fork or double-chain the ledger.

SECURITY: intents are seeded via `gate`'s own INSERT-only ORM class
(`AuditIntentInsertOnly`) through a real `svc_gate` session, exactly mirroring
how gate is the only real producer of audit_intent rows in production
(policies/grants/manifest.yaml: svc_audit has no INSERT on audit_intent).

NOTE: this local dev MySQL instance is a long-lived, shared, ever-accumulating
fixture across many test runs (audit_entry is append-only by design, and
audit_intent rows are never deleted). Every test below uses a per-invocation
unique `action` string (uuid-suffixed) so its own count-based assertions are
never polluted by rows any other run left behind.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid

import pytest
from common.db import make_engine
from sqlalchemy import func, select, text

from monolith.modules.audit.models import AuditEntry, AuditIntent
from monolith.modules.audit.service import (
    append_one_intent,
    canonical_json,
    compute_entry_hash,
    drain_pending_intents,
    verify_chain,
)
from monolith.modules.gate.models import AuditIntentInsertOnly
from monolith.tests.conftest import SessionmakerFixture

# SECURITY (threat model): audit_entry is append-only to EVERY application user -
# svc_audit has INSERT+SELECT and deliberately no UPDATE/DELETE (INV-12 immutability).
# A couple of the whole-chain tests below legitimately need writes that NO app path
# is ever permitted to make: (1) resetting the shared, ever-accumulating ledger back
# to its genesis anchor so a `verify_chain(since_seq=0)` assertion is deterministic
# even though other test files seed non-chaining dummy audit_entry rows into the same
# table, and (2) simulating an attacker/DBA who bypasses the grants to mutate a row -
# exactly the out-of-band tampering the hash chain exists to DETECT. Doing either via
# svc_audit would be denied by MySQL (correctly) - so these use a privileged admin
# connection, which also keeps the test honest about what the chain actually defends
# against (a compromise the least-privilege grants can't themselves prevent).
_ADMIN_DB_URL = os.environ.get(
    "SKILLSCAN_TEST_ADMIN_DB_URL", "mysql+aiomysql://root@localhost/skillscan"
)


async def _admin_exec(sql: str, params: dict | None = None) -> None:
    engine = make_engine(_ADMIN_DB_URL)
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql), params or {})
    finally:
        await engine.dispose()


async def _reset_chain_to_genesis() -> None:
    """Delete every non-genesis row so a since_seq=0 whole-chain assertion is not
    polluted by dummy/non-chaining audit_entry rows other test files seed into this
    shared, append-only ledger (see module note - this is an out-of-band admin write)."""
    await _admin_exec("DELETE FROM audit_entry WHERE seq > 1")


def _unique_action(label: str) -> str:
    return f"{label}_{uuid.uuid4().hex[:12]}"


async def _seed_intents(gate_sessionmaker: SessionmakerFixture, *, action: str, count: int) -> None:
    async with gate_sessionmaker() as session, session.begin():
        for i in range(count):
            session.add(
                AuditIntentInsertOnly(
                    operator="tester",
                    action=action,
                    payload={"seed_index": i, "action": action},
                )
            )


async def _current_tail_seq(audit_sessionmaker: SessionmakerFixture) -> int:
    """A checkpoint for `verify_chain(session, since_seq=...)` - see module note."""
    async with audit_sessionmaker() as session:
        tail = (
            await session.execute(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1))
        ).scalar_one_or_none()
        return tail.seq if tail is not None else 0


class TestCanonicalJsonAndHash:
    def test_canonical_json_is_order_independent(self) -> None:
        a = canonical_json({"b": 1, "a": 2})
        b = canonical_json({"a": 2, "b": 1})
        assert a == b

    def test_compute_entry_hash_changes_with_any_field(self) -> None:
        base = compute_entry_hash("0" * 64, "alice", "verdict_issued", {"x": 1})
        assert base != compute_entry_hash("1" * 64, "alice", "verdict_issued", {"x": 1})
        assert base != compute_entry_hash("0" * 64, "bob", "verdict_issued", {"x": 1})
        assert base != compute_entry_hash("0" * 64, "alice", "other_action", {"x": 1})
        assert base != compute_entry_hash("0" * 64, "alice", "verdict_issued", {"x": 2})


class TestAppendAndDrain:
    @pytest.mark.asyncio
    async def test_append_one_intent_links_to_current_tail(
        self, audit_sessionmaker: SessionmakerFixture, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        action = _unique_action("test_append_single")
        await _seed_intents(gate_sessionmaker, action=action, count=1)

        async with audit_sessionmaker() as session, session.begin():
            tail_before = (
                await session.execute(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1))
            ).scalar_one_or_none()
            expected_prev = tail_before.entry_hash if tail_before is not None else "0" * 64

            pending = (
                await session.execute(
                    select(AuditIntent)
                    .where(AuditIntent.chained.is_(False), AuditIntent.action == action)
                    .limit(1)
                )
            ).scalar_one()
            result = await append_one_intent(session, pending)

        assert result.prev_hash == expected_prev
        assert result.entry_hash == compute_entry_hash(
            expected_prev, "tester", action, {"seed_index": 0, "action": action}
        )

    @pytest.mark.asyncio
    async def test_drain_pending_intents_chains_all_and_marks_chained(
        self, audit_sessionmaker: SessionmakerFixture, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        action = _unique_action("test_drain_batch")
        await _seed_intents(gate_sessionmaker, action=action, count=5)

        chained = await drain_pending_intents(audit_sessionmaker, batch_size=100)
        assert len(chained) >= 5  # other tests may have left unrelated pending rows too

        async with audit_sessionmaker() as session:
            remaining = (
                await session.execute(
                    select(func.count())
                    .select_from(AuditIntent)
                    .where(AuditIntent.action == action, AuditIntent.chained.is_(False))
                )
            ).scalar_one()
        assert remaining == 0

    @pytest.mark.asyncio
    async def test_verify_chain_is_true_after_draining(
        self, audit_sessionmaker: SessionmakerFixture, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        action = _unique_action("test_verify_chain")
        checkpoint = await _current_tail_seq(audit_sessionmaker)
        await _seed_intents(gate_sessionmaker, action=action, count=3)
        await drain_pending_intents(audit_sessionmaker, batch_size=100)

        async with audit_sessionmaker() as session:
            assert await verify_chain(session, since_seq=checkpoint) is True

    @pytest.mark.asyncio
    async def test_full_chain_from_genesis_verifies(
        self, audit_sessionmaker: SessionmakerFixture, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        """Regression (found on first VM deploy): verify_chain(since_seq=0) -
        the exact call GET /v1/audit makes - must return True on a real
        migrated chain. The genesis row's entry_hash is a fixed bootstrap value
        (initial migration) that is NOT derived via compute_entry_hash, so the
        verifier must trust it as the root anchor rather than recomputing it;
        before the fix, every deployment reported chain_valid=False. No prior
        test exercised since_seq=0 (all used checkpointed since_seq>0), which
        is why this shipped undetected."""
        # Own the ledger state: other test files seed non-chaining dummy rows into
        # this shared table, and a since_seq=0 scan legitimately fails on those - so
        # reset to the genesis anchor first, then build a real chain to verify.
        await _reset_chain_to_genesis()
        action = _unique_action("test_full_chain")
        await _seed_intents(gate_sessionmaker, action=action, count=3)
        await drain_pending_intents(audit_sessionmaker, batch_size=100)
        async with audit_sessionmaker() as session:
            assert await verify_chain(session, since_seq=0) is True

    @pytest.mark.asyncio
    async def test_full_chain_detects_non_genesis_tamper(
        self, audit_sessionmaker: SessionmakerFixture, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        """The genesis-as-anchor fix must NOT weaken tamper detection for real
        entries: a mutated payload on any non-genesis row still fails a full
        since_seq=0 scan (its recomputed hash no longer matches)."""
        await _reset_chain_to_genesis()
        action = _unique_action("test_tamper")
        await _seed_intents(gate_sessionmaker, action=action, count=3)
        await drain_pending_intents(audit_sessionmaker, batch_size=100)
        async with audit_sessionmaker() as session:
            tail = (
                await session.execute(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1))
            ).scalar_one()
            tail_seq = tail.seq
            original_payload = tail.payload
        try:
            # SECURITY (threat model): tamper via an out-of-band admin write, NOT an
            # app user - svc_audit has no UPDATE on audit_entry by design (the hash
            # chain exists precisely to detect writes that bypass those grants).
            await _admin_exec(
                "UPDATE audit_entry SET payload = :p WHERE seq = :s",
                {"p": json.dumps({**(original_payload or {}), "tampered": True}), "s": tail_seq},
            )
            async with audit_sessionmaker() as session:
                assert await verify_chain(session, since_seq=0) is False
        finally:
            # Restore the row so the shared chain stays valid for later tests.
            await _admin_exec(
                "UPDATE audit_entry SET payload = :p WHERE seq = :s",
                {"p": json.dumps(original_payload), "s": tail_seq},
            )


class TestConcurrentDrainProducesAConsistentChain:
    @pytest.mark.asyncio
    async def test_concurrent_drainers_never_fork_or_double_chain(
        self, audit_sessionmaker: SessionmakerFixture, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        """SECURITY (M3 acceptance bar): 'concurrent audit append -> chain
        consistent (no forks/double-chaining)'. The spec explicitly allows any
        replica to drain with no leader election (§7.3), so N concurrent
        drainers racing for the same pending intents must still produce
        exactly one audit_entry per audit_intent and a fully verifiable chain.
        """
        action = _unique_action("test_concurrent_drain")
        n_intents = 20
        checkpoint = await _current_tail_seq(audit_sessionmaker)
        await _seed_intents(gate_sessionmaker, action=action, count=n_intents)

        # 6 concurrent "replicas" all draining from the same shared pending pool.
        results = await asyncio.gather(
            *(drain_pending_intents(audit_sessionmaker, batch_size=n_intents) for _ in range(6))
        )
        total_chained = sum(len(r) for r in results)
        assert total_chained >= n_intents  # SKIP LOCKED: no double-claims, none dropped

        async with audit_sessionmaker() as session:
            assert await verify_chain(session, since_seq=checkpoint) is True

            entry_count_for_action = (
                await session.execute(
                    select(func.count()).select_from(AuditEntry).where(AuditEntry.action == action)
                )
            ).scalar_one()
            # SECURITY: exactly one audit_entry per seeded intent - if the
            # missing FOR UPDATE SKIP LOCKED fix were reverted, two drainers
            # could both claim + chain the same intent, and this count would
            # exceed n_intents even though verify_chain() alone would still
            # report True (each duplicate entry is still internally
            # hash-consistent with its own position in the chain).
            assert entry_count_for_action == n_intents

            no_longer_pending = (
                await session.execute(
                    select(func.count())
                    .select_from(AuditIntent)
                    .where(AuditIntent.action == action, AuditIntent.chained.is_(False))
                )
            ).scalar_one()
            assert no_longer_pending == 0
