"""Tests for `GET /v1/audit` (coding spec §9) - real local MySQL/Redis via a
real ScanRuntime; auth faked via FastAPI dependency override.
"""

from __future__ import annotations

import datetime
import json
import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from common.blobstore import LocalFilesystemBlobStore
from fastapi import FastAPI
from skillscan_core import GatePolicy, StaticKeywordEngine, TrustTier, Verdict
from sqlalchemy import select

from monolith.main import create_app
from monolith.modules.audit.models import AuditEntry
from monolith.modules.audit.service import drain_pending_intents
from monolith.modules.gate.models import AuditIntentInsertOnly
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.auth.dependencies import get_session_context
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.tests._audit_admin import admin_exec, reset_chain_to_genesis
from monolith.tests.conftest import SessionmakerFixture

_ENGINE = StaticKeywordEngine()


def _session(subject: str, roles: frozenset[str]) -> SessionContext:
    return SessionContext(
        subject=subject,
        roles=roles,
        scopes=frozenset(),
        tier=TrustTier.INTERNAL,
        token_exp=9999999999.0,
        is_machine=False,  # a console/reviewer session is a person
    )


@pytest.fixture
def app(
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    audit_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
) -> FastAPI:
    scan_runtime = ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=orchestration_sessionmaker,
        gate_session_factory=gate_sessionmaker,
        policy=GatePolicy(
            version=f"test-audit-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
        audit_session_factory=audit_sessionmaker,
    )
    return create_app(scan_runtime=scan_runtime)


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


def _as(app_instance: FastAPI, subject: str, roles: frozenset[str]) -> None:
    app_instance.dependency_overrides[get_session_context] = lambda: _session(subject, roles)


class TestGetAuditLog:
    @pytest.mark.asyncio
    async def test_auditor_can_read_and_gets_a_valid_chain(
        self, app: FastAPI, client: httpx.AsyncClient, audit_sessionmaker: SessionmakerFixture
    ) -> None:
        marker = f"op-{uuid.uuid4().hex[:12]}"
        async with audit_sessionmaker() as session, session.begin():
            session.add(
                AuditEntry(
                    prev_hash="0" * 64,
                    entry_hash=f"dummy-{uuid.uuid4().hex}",
                    operator=marker,
                    action="test_action",
                    payload={"note": "seeded"},
                    chained_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )
        _as(app, "auditor-alice", frozenset({"auditor"}))
        response = await client.get("/v1/audit")
        assert response.status_code == 200
        body = response.json()
        assert "chain_valid" in body
        matching = [e for e in body["entries"] if e["operator"] == marker]
        assert len(matching) == 1
        assert matching[0]["action"] == "test_action"

    @pytest.mark.asyncio
    async def test_non_auditor_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "carol", frozenset({"approver"}))
        response = await client.get("/v1/audit")
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_limit_is_bounded(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "auditor-alice", frozenset({"auditor"}))
        response = await client.get("/v1/audit", params={"limit": 999999})
        assert response.status_code == 200
        assert len(response.json()["entries"]) <= 500


class TestPagedChainVerificationIsStillWholeLedger:
    """SECURITY (milestone F Task 17): `since_seq` pages the READ; it must never
    narrow the VERIFICATION.

    The router used to forward the page cursor into `verify_chain(since_seq=...)`,
    which anchored on the entry at the cursor and never read anything older. A
    request for a page near the tail therefore answered `chain_valid: true` while
    an older entry had been rewritten - the console rendered a green "chain intact"
    badge for a ledger that was not intact. Measured against the old code: True.
    """

    @pytest.mark.asyncio
    async def test_paging_past_a_rewritten_entry_still_reports_tampered(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        audit_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        # A genesis-rooted claim needs a ledger this test owns: other test files
        # seed non-chaining dummy audit_entry rows into this shared table.
        await reset_chain_to_genesis()
        action = f"test_router_pre_cursor_{uuid.uuid4().hex[:12]}"
        async with gate_sessionmaker() as session, session.begin():
            for i in range(6):
                session.add(
                    AuditIntentInsertOnly(operator="tester", action=action, payload={"i": i})
                )
        await drain_pending_intents(audit_sessionmaker, batch_size=100)

        async with audit_sessionmaker() as session:
            seqs = list(
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
            assert len(seqs) == 6
            victim_seq, cursor_seq = seqs[0], seqs[-1]
            original_payload = (
                await session.execute(
                    select(AuditEntry.payload).where(AuditEntry.seq == victim_seq)
                )
            ).scalar_one()

        _as(app, "auditor-alice", frozenset({"auditor"}))
        # Positive control on the exact request under test: intact right now, so
        # the False below can only come from the tamper.
        before = await client.get("/v1/audit", params={"since_seq": cursor_seq})
        assert before.status_code == 200
        assert before.json()["chain_valid"] is True

        try:
            # SECURITY (threat model): an out-of-band admin write, NOT an app user -
            # svc_audit has no UPDATE on audit_entry by design. Do not widen that
            # grant to make this easier; db/setup_grants.py has no REVOKE, so the
            # grant would survive into every dev DB and could make this pass wrongly.
            await admin_exec(
                "UPDATE audit_entry SET payload = :p WHERE seq = :s",
                {
                    "p": json.dumps({**(original_payload or {}), "tampered": True}),
                    "s": victim_seq,
                },
            )
            response = await client.get("/v1/audit", params={"since_seq": cursor_seq})
            assert response.status_code == 200
            body = response.json()
            # The rewritten entry is NOT on the page that was served - detection
            # therefore cannot have come from the rows the client can see, only
            # from re-anchoring the verification on genesis.
            assert victim_seq not in [e["seq"] for e in body["entries"]]
            assert body["chain_valid"] is False
        finally:
            await admin_exec(
                "UPDATE audit_entry SET payload = :p WHERE seq = :s",
                {"p": json.dumps(original_payload), "s": victim_seq},
            )
