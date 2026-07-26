"""Tests for `reeval.service` (coding spec §11.6) against the REAL local
MySQL instance - `gate_sessionmaker` (svc_gate) and `reeval_sessionmaker`
(svc_reeval) are genuinely separate, least-privilege DB users (policies/
grants/manifest.yaml), proving `run_poll_reconciliation`/`apply_push_event`
compose the two correctly (gate for reading issued verdicts, reeval for
persisting ReconciliationRow) rather than needing a single shared connection.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any

import pytest
from sqlalchemy import select

from monolith.modules.gate.models import VerdictRow
from monolith.modules.reeval.models import ReconciliationRow
from monolith.modules.reeval.reconciliation import MarketplacePublishedEntry, ReconciliationResult
from monolith.modules.reeval.service import apply_push_event, run_poll_reconciliation
from monolith.tests.conftest import SessionmakerFixture


class _FakeMarketplace:
    def __init__(
        self, published: list[dict[str, Any]], *, quarantine_fails_for: frozenset[str] = frozenset()
    ) -> None:
        self._published = published
        self._quarantine_fails_for = quarantine_fails_for
        self.quarantine_calls: list[tuple[str, str]] = []

    async def write_verdict(self, jws: str, content_hash: str) -> None:
        raise NotImplementedError("not exercised by reconciliation tests")

    async def list_published(self) -> list[dict[str, Any]]:
        return self._published

    async def quarantine(self, skill_id: str, reason: str) -> None:
        if skill_id in self._quarantine_fails_for:
            raise RuntimeError(f"simulated marketplace outage for {skill_id}")
        self.quarantine_calls.append((skill_id, reason))


async def _seed_verdict(
    gate_sessionmaker: SessionmakerFixture, *, content_hash: str, verdict: str
) -> None:
    async with gate_sessionmaker() as session, session.begin():
        session.add(
            VerdictRow(
                scan_id=str(uuid.uuid4()),
                content_hash=content_hash,
                verdict=verdict,
                score={"PASS": 87, "REVIEW": 57, "BLOCK": 20}[verdict],
                policy_version="test-policy-v1",
                jti=str(uuid.uuid4()),
                jws_signature="test-jws-signature",
                effective_severity=0,
                reasons=[],
                issued_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
            )
        )


async def _reconciliation_rows_for(
    reeval_sessionmaker: SessionmakerFixture, *, content_hash: str
) -> list[ReconciliationRow]:
    async with reeval_sessionmaker() as session:
        result = await session.execute(
            select(ReconciliationRow).where(ReconciliationRow.content_hash == content_hash)
        )
        return list(result.scalars().all())


class TestRunPollReconciliation:
    @pytest.mark.asyncio
    async def test_match_persisted_and_never_quarantined(
        self,
        gate_sessionmaker: SessionmakerFixture,
        reeval_sessionmaker: SessionmakerFixture,
    ) -> None:
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex  # 64 hex chars, unique per run
        await _seed_verdict(gate_sessionmaker, content_hash=content_hash, verdict="PASS")
        marketplace = _FakeMarketplace([{"content_hash": content_hash, "skill_id": "skill-match"}])

        async with gate_sessionmaker() as gate_session, reeval_sessionmaker() as reeval_session:
            async with reeval_session.begin():
                outcomes = await run_poll_reconciliation(
                    gate_session=gate_session,
                    reeval_session=reeval_session,
                    marketplace=marketplace,
                )

        assert outcomes[0].result is ReconciliationResult.MATCH
        assert marketplace.quarantine_calls == []
        rows = await _reconciliation_rows_for(reeval_sessionmaker, content_hash=content_hash)
        assert len(rows) == 1
        assert rows[0].result == "MATCH"
        assert rows[0].source == "poll"

    @pytest.mark.asyncio
    async def test_orphan_persisted_and_auto_quarantined_by_default(
        self,
        gate_sessionmaker: SessionmakerFixture,
        reeval_sessionmaker: SessionmakerFixture,
    ) -> None:
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex  # never seeded -> ORPHAN
        marketplace = _FakeMarketplace([{"content_hash": content_hash, "skill_id": "skill-orphan"}])

        async with gate_sessionmaker() as gate_session, reeval_sessionmaker() as reeval_session:
            async with reeval_session.begin():
                outcomes = await run_poll_reconciliation(
                    gate_session=gate_session,
                    reeval_session=reeval_session,
                    marketplace=marketplace,
                )

        assert outcomes[0].result is ReconciliationResult.ORPHAN
        # SECURITY: poll-sourced ORPHAN auto-quarantines by default (SAD §4.3).
        assert len(marketplace.quarantine_calls) == 1
        called_skill_id, called_reason = marketplace.quarantine_calls[0]
        assert called_skill_id == "skill-orphan"
        assert "poll-sourced" in called_reason and "ORPHAN" in called_reason
        rows = await _reconciliation_rows_for(reeval_sessionmaker, content_hash=content_hash)
        assert rows[0].result == "ORPHAN"

    @pytest.mark.asyncio
    async def test_one_failed_quarantine_call_does_not_block_the_others(
        self,
        gate_sessionmaker: SessionmakerFixture,
        reeval_sessionmaker: SessionmakerFixture,
    ) -> None:
        hash_a = uuid.uuid4().hex + uuid.uuid4().hex
        hash_b = uuid.uuid4().hex + uuid.uuid4().hex
        marketplace = _FakeMarketplace(
            [
                {"content_hash": hash_a, "skill_id": "skill-a-fails"},
                {"content_hash": hash_b, "skill_id": "skill-b-succeeds"},
            ],
            quarantine_fails_for=frozenset({"skill-a-fails"}),
        )

        async with gate_sessionmaker() as gate_session, reeval_sessionmaker() as reeval_session:
            async with reeval_session.begin():
                outcomes = await run_poll_reconciliation(
                    gate_session=gate_session,
                    reeval_session=reeval_session,
                    marketplace=marketplace,
                )

        assert len(outcomes) == 2
        # skill-a-fails' quarantine call raised but must not have prevented
        # skill-b-succeeds' from being attempted, and both rows still persisted.
        assert any(call[0] == "skill-b-succeeds" for call in marketplace.quarantine_calls)
        assert not any(call[0] == "skill-a-fails" for call in marketplace.quarantine_calls)
        rows_a = await _reconciliation_rows_for(reeval_sessionmaker, content_hash=hash_a)
        rows_b = await _reconciliation_rows_for(reeval_sessionmaker, content_hash=hash_b)
        assert len(rows_a) == 1
        assert len(rows_b) == 1


class TestApplyPushEvent:
    @pytest.mark.asyncio
    async def test_push_sourced_orphan_alerts_but_does_not_auto_quarantine(
        self,
        gate_sessionmaker: SessionmakerFixture,
        reeval_sessionmaker: SessionmakerFixture,
    ) -> None:
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex
        marketplace = _FakeMarketplace([])  # list_published() not used by apply_push_event
        entry = MarketplacePublishedEntry(content_hash=content_hash, skill_id="skill-push")

        async with gate_sessionmaker() as gate_session, reeval_sessionmaker() as reeval_session:
            async with reeval_session.begin():
                outcome = await apply_push_event(
                    entry,
                    gate_session=gate_session,
                    reeval_session=reeval_session,
                    marketplace=marketplace,
                )

        assert outcome.result is ReconciliationResult.ORPHAN
        assert outcome.source.value == "push"
        # SECURITY (TB14): push-sourced never auto-quarantines by default.
        assert marketplace.quarantine_calls == []
        rows = await _reconciliation_rows_for(reeval_sessionmaker, content_hash=content_hash)
        assert rows[0].source == "push"

    @pytest.mark.asyncio
    async def test_push_sourced_quarantines_when_explicitly_opted_in(
        self,
        gate_sessionmaker: SessionmakerFixture,
        reeval_sessionmaker: SessionmakerFixture,
    ) -> None:
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex
        marketplace = _FakeMarketplace([])
        entry = MarketplacePublishedEntry(content_hash=content_hash, skill_id="skill-push-optin")

        async with gate_sessionmaker() as gate_session, reeval_sessionmaker() as reeval_session:
            async with reeval_session.begin():
                await apply_push_event(
                    entry,
                    gate_session=gate_session,
                    reeval_session=reeval_session,
                    marketplace=marketplace,
                    push_auto_quarantine_enabled=True,
                )

        assert len(marketplace.quarantine_calls) == 1
        called_skill_id, called_reason = marketplace.quarantine_calls[0]
        assert called_skill_id == "skill-push-optin"
        assert "push-sourced" in called_reason
