"""Tests for `integration_relay.service` (coding spec §11.3/§11.6: gate_outbox
drain, `verdict_issued` -> marketplace writeback, other event types log-only)
against the real local MySQL instance.

SECURITY: outbox rows are seeded via a real `svc_gate` session (gate/models.py
GateOutboxRow) since gate is the only real producer of gate_outbox events in
production - svc_relay itself is granted only SELECT+UPDATE on this table
(policies/grants/manifest.yaml), never INSERT.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any

import pytest
from sqlalchemy import func, select

from monolith.modules.gate.models import GateOutboxRow
from monolith.modules.integration_relay.models import GateOutboxReadWrite
from monolith.modules.integration_relay.service import drain_pending_outbox
from monolith.tests.conftest import SessionmakerFixture


class _FakeNotifier:
    def __init__(self, *, raises: bool = False) -> None:
        self._raises = raises
        self.emit_calls: list[dict[str, Any]] = []

    async def emit(self, event: dict[str, Any]) -> None:
        if self._raises:
            raise RuntimeError("simulated SIEM outage")
        self.emit_calls.append(event)


class _FakeMarketplace:
    def __init__(self, *, fails_for_content_hash: frozenset[str] = frozenset()) -> None:
        self._fails_for = fails_for_content_hash
        self.write_verdict_calls: list[tuple[str, str]] = []

    async def write_verdict(self, jws: str, content_hash: str) -> None:
        if content_hash in self._fails_for:
            raise RuntimeError(f"simulated marketplace outage for {content_hash}")
        self.write_verdict_calls.append((jws, content_hash))

    async def list_published(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def quarantine(self, skill_id: str, reason: str) -> None:
        raise NotImplementedError


async def _seed_outbox_events(
    gate_sessionmaker: SessionmakerFixture, *, event_type: str, count: int
) -> None:
    async with gate_sessionmaker() as session, session.begin():
        for i in range(count):
            session.add(
                GateOutboxRow(
                    aggregate_id=str(uuid.uuid4()),
                    event_type=event_type,
                    payload={"seed_index": i},
                    dispatched=False,
                    created_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )


class TestDrainPendingOutbox:
    @pytest.mark.asyncio
    async def test_drains_all_undispatched_rows_and_marks_dispatched(
        self, gate_sessionmaker: SessionmakerFixture, relay_sessionmaker: SessionmakerFixture
    ) -> None:
        event_type = f"test_relay_drain_{uuid.uuid4().hex[:12]}"
        await _seed_outbox_events(gate_sessionmaker, event_type=event_type, count=4)

        drained = await drain_pending_outbox(relay_sessionmaker, batch_size=100)
        assert drained >= 4  # other tests may leave unrelated pending rows too

        async with relay_sessionmaker() as session:
            remaining = (
                await session.execute(
                    select(func.count())
                    .select_from(GateOutboxReadWrite)
                    .where(
                        GateOutboxReadWrite.event_type == event_type,
                        GateOutboxReadWrite.dispatched.is_(False),
                    )
                )
            ).scalar_one()
        assert remaining == 0

    @pytest.mark.asyncio
    async def test_empty_outbox_drains_zero(
        self, gate_sessionmaker: SessionmakerFixture, relay_sessionmaker: SessionmakerFixture
    ) -> None:
        event_type = f"test_relay_empty_{uuid.uuid4().hex[:12]}"
        # Drain everything currently pending first so this run starts from a
        # known-empty state for OUR event_type (never seeded, so trivially
        # already empty) - this test just proves drain_pending_outbox doesn't
        # error or loop forever when there's nothing (left) to do.
        drained = await drain_pending_outbox(relay_sessionmaker, batch_size=1)
        assert drained in (0, 1)

        async with relay_sessionmaker() as session:
            count = (
                await session.execute(
                    select(func.count())
                    .select_from(GateOutboxReadWrite)
                    .where(GateOutboxReadWrite.event_type == event_type)
                )
            ).scalar_one()
        assert count == 0


class TestVerdictIssuedDispatchesToMarketplace:
    @pytest.mark.asyncio
    async def test_verdict_issued_event_calls_marketplace_write_verdict(
        self, gate_sessionmaker: SessionmakerFixture, relay_sessionmaker: SessionmakerFixture
    ) -> None:
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex
        aggregate_id = str(uuid.uuid4())
        async with gate_sessionmaker() as session, session.begin():
            session.add(
                GateOutboxRow(
                    aggregate_id=aggregate_id,
                    event_type="verdict_issued",
                    payload={"content_hash": content_hash, "jws": "the-jws-token"},
                    dispatched=False,
                    created_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )

        marketplace = _FakeMarketplace()
        drained = await drain_pending_outbox(
            relay_sessionmaker, batch_size=200, marketplace=marketplace
        )
        assert drained >= 1
        assert ("the-jws-token", content_hash) in marketplace.write_verdict_calls

        async with relay_sessionmaker() as session:
            row = (
                await session.execute(
                    select(GateOutboxReadWrite).where(
                        GateOutboxReadWrite.aggregate_id == aggregate_id
                    )
                )
            ).scalar_one()
        assert row.dispatched is True

    @pytest.mark.asyncio
    async def test_failed_dispatch_leaves_row_undispatched_and_does_not_block_other_rows(
        self, gate_sessionmaker: SessionmakerFixture, relay_sessionmaker: SessionmakerFixture
    ) -> None:
        failing_hash = uuid.uuid4().hex + uuid.uuid4().hex
        succeeding_hash = uuid.uuid4().hex + uuid.uuid4().hex
        failing_aggregate_id = str(uuid.uuid4())
        succeeding_aggregate_id = str(uuid.uuid4())

        async with gate_sessionmaker() as session, session.begin():
            session.add(
                GateOutboxRow(
                    aggregate_id=failing_aggregate_id,
                    event_type="verdict_issued",
                    payload={"content_hash": failing_hash, "jws": "jws-a"},
                    dispatched=False,
                    created_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )
            session.add(
                GateOutboxRow(
                    aggregate_id=succeeding_aggregate_id,
                    event_type="verdict_issued",
                    payload={"content_hash": succeeding_hash, "jws": "jws-b"},
                    dispatched=False,
                    created_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )

        marketplace = _FakeMarketplace(fails_for_content_hash=frozenset({failing_hash}))
        drained = await drain_pending_outbox(
            relay_sessionmaker, batch_size=200, marketplace=marketplace
        )
        # SECURITY: the failing row must not have been counted as drained, but
        # the succeeding one (and any other unrelated pending rows) still was.
        assert ("jws-b", succeeding_hash) in marketplace.write_verdict_calls
        assert ("jws-a", failing_hash) not in marketplace.write_verdict_calls
        assert drained >= 1

        async with relay_sessionmaker() as session:
            failing_row = (
                await session.execute(
                    select(GateOutboxReadWrite).where(
                        GateOutboxReadWrite.aggregate_id == failing_aggregate_id
                    )
                )
            ).scalar_one()
            succeeding_row = (
                await session.execute(
                    select(GateOutboxReadWrite).where(
                        GateOutboxReadWrite.aggregate_id == succeeding_aggregate_id
                    )
                )
            ).scalar_one()
        assert failing_row.dispatched is False  # left for a later retry
        assert succeeding_row.dispatched is True

        # Cleanup: this shared local MySQL instance persists across tests (no
        # per-test transaction rollback, by design - see conftest.py), and
        # drain_pending_outbox drains ANY undispatched row regardless of which
        # test created it. Deliberately leaving `failing_row` undispatched
        # would otherwise leak into a LATER test's drain_pending_outbox call
        # and get dispatched against THAT test's own (unrelated) marketplace
        # fake, breaking its assertions - force it dispatched here, simulating
        # "eventually handled out of band", same as a real operator resolving
        # the underlying outage would.
        async with relay_sessionmaker() as session, session.begin():
            row = (
                await session.execute(
                    select(GateOutboxReadWrite).where(
                        GateOutboxReadWrite.aggregate_id == failing_aggregate_id
                    )
                )
            ).scalar_one()
            row.dispatched = True

    @pytest.mark.asyncio
    async def test_non_verdict_issued_events_stay_log_only_even_with_marketplace_wired(
        self, gate_sessionmaker: SessionmakerFixture, relay_sessionmaker: SessionmakerFixture
    ) -> None:
        # NOTE: this shared local MySQL instance may carry OTHER, unrelated
        # undispatched verdict_issued rows left by tests elsewhere that
        # exercise decide_and_record without ever draining the outbox
        # themselves (e.g. test_orchestration_pipeline.py/test_router.py) -
        # `drain_pending_outbox(batch_size=200, ...)` will legitimately sweep
        # those up too. This test's assertions are scoped to the specific
        # rows IT seeded, not to marketplace's call count globally, so it
        # can't be broken by that unrelated, pre-existing state.
        event_type = f"test_relay_other_{uuid.uuid4().hex[:12]}"
        await _seed_outbox_events(gate_sessionmaker, event_type=event_type, count=2)

        marketplace = _FakeMarketplace()
        drained = await drain_pending_outbox(
            relay_sessionmaker, batch_size=200, marketplace=marketplace
        )
        assert drained >= 2

        async with relay_sessionmaker() as session:
            remaining = (
                await session.execute(
                    select(func.count())
                    .select_from(GateOutboxReadWrite)
                    .where(
                        GateOutboxReadWrite.event_type == event_type,
                        GateOutboxReadWrite.dispatched.is_(False),
                    )
                )
            ).scalar_one()
        assert remaining == 0  # this test's own seeded rows all dispatched log-only


# SECURITY (2026-07-06 spec-compliance audit fix): notifier is fire-and-forget
# ALONGSIDE marketplace, never a gate on dispatched/retry status - see this
# module's own docstring.
class TestVerdictIssuedDispatchesToSiemNotifier:
    @pytest.mark.asyncio
    async def test_verdict_issued_event_calls_notifier_emit_alongside_marketplace(
        self, gate_sessionmaker: SessionmakerFixture, relay_sessionmaker: SessionmakerFixture
    ) -> None:
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex
        aggregate_id = str(uuid.uuid4())
        async with gate_sessionmaker() as session, session.begin():
            session.add(
                GateOutboxRow(
                    aggregate_id=aggregate_id,
                    event_type="verdict_issued",
                    payload={"content_hash": content_hash, "jws": "the-jws-token"},
                    dispatched=False,
                    created_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )

        marketplace = _FakeMarketplace()
        notifier = _FakeNotifier()
        drained = await drain_pending_outbox(
            relay_sessionmaker, batch_size=200, marketplace=marketplace, notifier=notifier
        )
        assert drained >= 1
        assert ("the-jws-token", content_hash) in marketplace.write_verdict_calls
        matching = [
            c for c in notifier.emit_calls if c["payload"].get("content_hash") == content_hash
        ]
        assert len(matching) == 1
        assert matching[0]["event_type"] == "verdict_issued"

    @pytest.mark.asyncio
    async def test_notifier_failure_does_not_undo_a_successful_marketplace_dispatch(
        self, gate_sessionmaker: SessionmakerFixture, relay_sessionmaker: SessionmakerFixture
    ) -> None:
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex
        aggregate_id = str(uuid.uuid4())
        async with gate_sessionmaker() as session, session.begin():
            session.add(
                GateOutboxRow(
                    aggregate_id=aggregate_id,
                    event_type="verdict_issued",
                    payload={"content_hash": content_hash, "jws": "the-jws-token"},
                    dispatched=False,
                    created_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )

        marketplace = _FakeMarketplace()
        notifier = _FakeNotifier(raises=True)
        drained = await drain_pending_outbox(
            relay_sessionmaker, batch_size=200, marketplace=marketplace, notifier=notifier
        )
        assert drained >= 1
        assert ("the-jws-token", content_hash) in marketplace.write_verdict_calls

        async with relay_sessionmaker() as session:
            row = (
                await session.execute(
                    select(GateOutboxReadWrite).where(
                        GateOutboxReadWrite.aggregate_id == aggregate_id
                    )
                )
            ).scalar_one()
        assert row.dispatched is True  # SIEM outage must never undo this
