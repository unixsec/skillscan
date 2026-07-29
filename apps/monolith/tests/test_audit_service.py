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
never polluted by rows any other run left behind. `verify_chain` is a
whole-ledger claim with no cursor to scope it (see its docstring, and
`test_tamper_before_a_page_cursor_is_still_detected` below), so any test that
asserts on it first resets the ledger to its genesis anchor - other test files
seed non-chaining dummy audit_entry rows into this same table, and a
genesis-rooted scan correctly rejects those.

The privileged out-of-band writes those two things need (reset, tamper) live in
`monolith.tests._audit_admin` - see that module for why they must not become a
grant in db/setup_grants.py.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import uuid

import pytest
from sqlalchemy import func, select

from monolith.modules.audit.models import AuditEntry, AuditIntent
from monolith.modules.audit.service import (
    append_one_intent,
    canonical_json,
    compute_entry_hash,
    drain_pending_intents,
    verify_chain,
)
from monolith.modules.gate.models import AuditIntentInsertOnly
from monolith.tests._audit_admin import (
    admin_exec,
    reset_chain_to_genesis,
    restore_genesis_row,
    wipe_entire_ledger,
)
from monolith.tests.conftest import SessionmakerFixture


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


async def _chained_seqs(audit_sessionmaker: SessionmakerFixture, *, action: str) -> list[int]:
    async with audit_sessionmaker() as session:
        return list(
            (
                await session.execute(
                    select(AuditEntry.seq)
                    .where(AuditEntry.action == action)
                    .order_by(AuditEntry.seq.asc())
                )
            )
            .scalars()
            .all()
        )


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

        # Drain to EXHAUSTION, not to a fixed batch size. `audit_intent` is
        # shared across every test file, and a single `batch_size=100` call is
        # only enough if fewer than ~95 foreign pending rows happen to be
        # queued ahead of these 5 - `drain_pending_intents` walks the backlog
        # oldest-first, so a large enough backlog fills the batch entirely with
        # other files' rows and chains none of this test's. Measured on the VM
        # 2026-07-29: `test_inventory_service.py` alone leaves 120 unchained
        # intents behind, and re-running this file after it failed with
        # `assert 5 == 0`. It passes inside a full-suite run purely because
        # `test_audit_*` sorts before `test_inventory_*`, which makes it an
        # ordering accident rather than isolation.
        chained: list[object] = []
        while True:
            batch = await drain_pending_intents(audit_sessionmaker, batch_size=100)
            if not batch:
                break
            chained.extend(batch)
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
        # Own the ledger state: other test files seed non-chaining dummy rows into
        # this shared table and verify_chain is a whole-ledger claim, so reset to the
        # genesis anchor first, then build a real chain to verify.
        await reset_chain_to_genesis()
        action = _unique_action("test_verify_chain")
        await _seed_intents(gate_sessionmaker, action=action, count=3)
        await drain_pending_intents(audit_sessionmaker, batch_size=100)

        async with audit_sessionmaker() as session:
            assert await verify_chain(session) is True

    @pytest.mark.asyncio
    async def test_full_chain_from_genesis_verifies(
        self, audit_sessionmaker: SessionmakerFixture, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        """Regression (found on first VM deploy): verify_chain() - the exact
        call GET /v1/audit makes - must return True on a real migrated chain.
        The genesis row's entry_hash is a fixed bootstrap value (initial
        migration) that is NOT derived via compute_entry_hash, so the verifier
        must trust it as the root anchor rather than recomputing it; before the
        fix, every deployment reported chain_valid=False. No test exercised the
        genesis-rooted scan at all (they all used a checkpointed `since_seq>0`
        scan, which skipped genesis), which is why this shipped undetected."""
        await reset_chain_to_genesis()
        action = _unique_action("test_full_chain")
        await _seed_intents(gate_sessionmaker, action=action, count=3)
        await drain_pending_intents(audit_sessionmaker, batch_size=100)
        async with audit_sessionmaker() as session:
            assert await verify_chain(session) is True

    @pytest.mark.asyncio
    async def test_full_chain_detects_non_genesis_tamper(
        self, audit_sessionmaker: SessionmakerFixture, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        """The genesis-as-anchor fix must NOT weaken tamper detection for real
        entries: a mutated payload on any non-genesis row still fails the scan
        (its recomputed hash no longer matches)."""
        await reset_chain_to_genesis()
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
            await admin_exec(
                "UPDATE audit_entry SET payload = :p WHERE seq = :s",
                {"p": json.dumps({**(original_payload or {}), "tampered": True}), "s": tail_seq},
            )
            async with audit_sessionmaker() as session:
                assert await verify_chain(session) is False
        finally:
            # Restore the row so the shared chain stays valid for later tests.
            await admin_exec(
                "UPDATE audit_entry SET payload = :p WHERE seq = :s",
                {"p": json.dumps(original_payload), "s": tail_seq},
            )

    @pytest.mark.asyncio
    async def test_tamper_before_a_page_cursor_is_still_detected(
        self, audit_sessionmaker: SessionmakerFixture, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        """SECURITY (milestone F Task 17) - the regression test for the anchor bug.

        `verify_chain` used to take a `since_seq` cursor and, when given one,
        anchor on the entry AT the cursor: it trusted that entry's stored hash
        and never read a single entry before it. `GET /v1/audit?since_seq=N`
        passed the page cursor straight through, so rewriting an entry OLDER
        than the page under view produced `chain_valid: true` - the console
        told an auditor the log was intact while looking away from exactly the
        rows an attacker would rewrite. Measured before the fix: True.

        This asserts the whole-ledger claim directly. Delete the "always scan
        from genesis" behaviour (e.g. reintroduce a cursor and skip ahead to
        it) and this test fails, because the mutated row is not just outside
        the page - it is outside the window the old code would have read.
        """
        await reset_chain_to_genesis()
        action = _unique_action("test_pre_cursor_tamper")
        await _seed_intents(gate_sessionmaker, action=action, count=6)
        await drain_pending_intents(audit_sessionmaker, batch_size=100)
        seqs = await _chained_seqs(audit_sessionmaker, action=action)
        assert len(seqs) == 6
        victim_seq, cursor_seq = seqs[0], seqs[-1]
        # The point of the test: the row we mutate is strictly older than the
        # cursor a paging client would have supplied.
        assert victim_seq < cursor_seq

        async with audit_sessionmaker() as session:
            original_payload = (
                await session.execute(
                    select(AuditEntry.payload).where(AuditEntry.seq == victim_seq)
                )
            ).scalar_one()
            # Positive control: the ledger really is intact right now, so a False
            # below can only have come from the tamper and not from ambient
            # pollution of this shared dev ledger.
            assert await verify_chain(session) is True
        try:
            await admin_exec(
                "UPDATE audit_entry SET payload = :p WHERE seq = :s",
                {
                    "p": json.dumps({**(original_payload or {}), "tampered": True}),
                    "s": victim_seq,
                },
            )
            async with audit_sessionmaker() as session:
                assert await verify_chain(session) is False
        finally:
            await admin_exec(
                "UPDATE audit_entry SET payload = :p WHERE seq = :s",
                {"p": json.dumps(original_payload), "s": victim_seq},
            )

    def test_verify_chain_takes_no_cursor_argument(self) -> None:
        """A cheaper, weaker answer must not be one keyword argument away. If a
        `since_seq`-style parameter is ever reintroduced, callers will pass their
        page cursor into it again (that is exactly how the bug above happened) -
        so the absence of the parameter is itself part of the fix and is asserted."""
        params = list(inspect.signature(verify_chain).parameters)
        assert params == ["session"]

    @pytest.mark.asyncio
    async def test_a_wiped_ledger_does_not_verify_as_intact(
        self, audit_sessionmaker: SessionmakerFixture
    ) -> None:
        """SECURITY REGRESSION LOCK (2026-07-29, milestones E+F review): an
        EMPTY `audit_entry` is a deleted ledger, and must fail verification.

        `verify_chain` opened with `if not rows: return True  # an empty ledger
        has nothing to have been tampered with`. That reasoning holds only for
        a table that was never created. In any migrated deployment the genesis
        row is INSERTed by the initial schema migration itself
        (1d6112d0e997_initial_core_schema.py), so the ledger is non-empty from
        the moment the schema exists - and an empty one therefore means the
        whole thing was DELETED. That is the most complete form of the
        tampering Task 17 hardened every other path in this function against,
        and it was the one input that reported `chain_valid: true`.

        Measured before the fix: `DELETE FROM audit_entry` -> True; delete
        all-but-genesis -> True (correct, that is a legitimately intact
        one-row ledger, and it is the positive control below); delete genesis
        alone -> False (already correct - the lowest surviving row does not
        carry the `prev_hash == GENESIS_HASH` marker).

        The wipe is an out-of-band admin write (see `_audit_admin`): no
        application user may DELETE from this table, which is exactly why the
        hash chain has to be the thing that notices.
        """
        # Positive control: a ledger holding only its genesis anchor IS intact,
        # so the False below can only come from the wipe itself.
        await reset_chain_to_genesis()
        async with audit_sessionmaker() as session:
            assert await verify_chain(session) is True

        try:
            await wipe_entire_ledger()
            async with audit_sessionmaker() as session:
                assert await verify_chain(session) is False, (
                    "an erased audit ledger verified as intact - the console "
                    "would print 'chain intact' over a deleted audit trail"
                )
        finally:
            # Non-negotiable: this dev ledger is shared with every other test
            # and with the local dev backend, and `append_one_intent` reads its
            # tail. Leaving it empty would break both.
            await restore_genesis_row()
        async with audit_sessionmaker() as session:
            assert await verify_chain(session) is True


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
        await reset_chain_to_genesis()  # verify_chain below is a whole-ledger claim
        action = _unique_action("test_concurrent_drain")
        n_intents = 20
        await _seed_intents(gate_sessionmaker, action=action, count=n_intents)

        # 6 concurrent "replicas" all draining from the same shared pending pool.
        results = await asyncio.gather(
            *(drain_pending_intents(audit_sessionmaker, batch_size=n_intents) for _ in range(6))
        )
        total_chained = sum(len(r) for r in results)
        assert total_chained >= n_intents  # SKIP LOCKED: no double-claims, none dropped

        async with audit_sessionmaker() as session:
            assert await verify_chain(session) is True

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
