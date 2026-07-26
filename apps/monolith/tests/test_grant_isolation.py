"""GRANT isolation tests (coding spec §7.2, M3 acceptance bar: 'GRANT 越权
(A 写 B 表) → DB 拒') against the real local MySQL instance.

SECURITY: this is deliberately NOT mocked - the whole point of per-module
least-privilege MySQL users (policies/grants/manifest.yaml) is that a bug in
one module's code that somehow tried to touch another module's private table
is rejected by the DATABASE itself, not merely by application-layer
convention/code review. A test using a fake/mocked connection could never
prove this property.
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError

from monolith.modules.audit.models import AuditIntent
from monolith.modules.gate.models import VerdictRow
from monolith.modules.orchestration.models import ScanJob
from monolith.tests.conftest import SessionmakerFixture


class TestCrossModuleWritesRejected:
    @pytest.mark.asyncio
    async def test_orchestration_cannot_write_gate_verdict_table(
        self, orchestration_sessionmaker: SessionmakerFixture
    ) -> None:
        """svc_orchestration has no GRANT at all on `verdict` (gate's private
        table) - attempting to write it must fail at the DB layer."""
        async with orchestration_sessionmaker() as session, session.begin():
            session.add(
                VerdictRow(
                    scan_id="11111111-1111-1111-1111-111111111111",
                    content_hash="a" * 64,
                    verdict="PASS",
                    score=87,
                    policy_version="v1",
                    jti="22222222-2222-2222-2222-222222222222",
                    jws_signature="x",
                    effective_severity=0,
                    reasons=[],
                    issued_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )
            with pytest.raises(DBAPIError, match=r"(?i)command denied"):
                await session.flush()

    @pytest.mark.asyncio
    async def test_gate_cannot_write_orchestration_scan_job_table(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        """svc_gate has no GRANT at all on `scan_job` (orchestration's private
        table) - attempting to write it must fail at the DB layer."""
        async with gate_sessionmaker() as session, session.begin():
            session.add(
                ScanJob(
                    scan_id="33333333-3333-3333-3333-333333333333",
                    content_hash="b" * 64,
                    toolchain_digest="c" * 64,
                    cache_key="d" * 64,
                    state="queued",
                    submitter="attacker",
                    created_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )
            with pytest.raises(DBAPIError, match=r"(?i)command denied"):
                await session.flush()

    @pytest.mark.asyncio
    async def test_gate_can_insert_but_not_select_audit_intent(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        """SECURITY: gate's cross-module contract seam onto audit_intent is
        deliberately asymmetric - INSERT-only (policies/grants/manifest.yaml).
        gate may append an intent (proven by M3's own decide_and_record path)
        but must never be able to read the chain back."""
        async with gate_sessionmaker() as session:
            with pytest.raises(DBAPIError, match=r"(?i)command denied"):
                await session.execute(select(AuditIntent).limit(1))


class TestSameModuleWritesSucceed:
    @pytest.mark.asyncio
    async def test_orchestration_can_write_its_own_scan_job_table(
        self, orchestration_sessionmaker: SessionmakerFixture
    ) -> None:
        """Positive control: the isolation above is a real GRANT boundary, not
        an accidental blanket failure - the SAME user writing its OWN table
        must succeed. scan_id/cache_key are freshly randomized each run since
        this commits a durable row (unlike the negative tests above, which
        always roll back on the expected DBAPIError) - see
        [[feedback-mysql-tail-append-locking]] on this shared, accumulating
        local dev DB.
        """
        unique = uuid.uuid4().hex
        async with orchestration_sessionmaker() as session, session.begin():
            session.add(
                ScanJob(
                    scan_id=str(uuid.uuid4()),
                    content_hash="e" * 64,
                    toolchain_digest="f" * 64,
                    cache_key=(unique + unique)[:64],
                    state="queued",
                    submitter="tester",
                    created_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )
            await session.flush()  # must not raise
