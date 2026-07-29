"""Tests for `GET/POST /v1/reeval*`, `GET /v1/reconciliation` (coding spec
§9/§11.7) - real local MySQL/Redis via a real ScanRuntime; auth faked via
FastAPI dependency override.
"""

from __future__ import annotations

import datetime
import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from common.blobstore import LocalFilesystemBlobStore
from fastapi import FastAPI
from skillscan_core import GatePolicy, StaticKeywordEngine, TrustTier, Verdict
from sqlalchemy import select, update

from monolith.main import create_app
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.auth.dependencies import get_session_context
from monolith.modules.gateway.auth.middleware import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.inventory.models import SkillVersionRow
from monolith.modules.inventory.service import register_skill_version, transition_skill
from monolith.modules.orchestration.models import ScanJob
from monolith.modules.reeval.models import ReconciliationRow
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
    reeval_sessionmaker: SessionmakerFixture,
    inventory_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
) -> FastAPI:
    scan_runtime = ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=orchestration_sessionmaker,
        gate_session_factory=gate_sessionmaker,
        policy=GatePolicy(
            version=f"test-reeval-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
        reeval_session_factory=reeval_sessionmaker,
    )
    return create_app(scan_runtime=scan_runtime)


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


def _as(app_instance: FastAPI, subject: str, roles: frozenset[str]) -> None:
    app_instance.dependency_overrides[get_session_context] = lambda: _session(subject, roles)


async def _seed_published_skill(
    inventory_sessionmaker: SessionmakerFixture, *, skill_id: str, toolchain_digest: str
) -> None:
    async with inventory_sessionmaker() as session, session.begin():
        await register_skill_version(
            session,
            skill_id=skill_id,
            source="test-suite",
            trust_tier="public",
            content_hash=uuid.uuid4().hex + uuid.uuid4().hex,
            toolchain_digest=toolchain_digest,
            declared_perms=None,
            operator="tester",
            actor_is_admin=False,
        )


class TestListReevalStatus:
    @pytest.mark.asyncio
    async def test_reports_stale_when_toolchain_digest_differs(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_published_skill(
            inventory_sessionmaker, skill_id=skill_id, toolchain_digest="stale-digest-xyz"
        )
        _as(app, "carol", frozenset({"approver"}))
        response = await client.get("/v1/reeval")
        assert response.status_code == 200
        body = response.json()
        matching = [s for s in body["skills"] if s["skill_id"] == skill_id]
        assert len(matching) == 1
        assert matching[0]["stale"] is True
        assert matching[0]["recorded_toolchain_digest"] == "stale-digest-xyz"

    @pytest.mark.asyncio
    async def test_submitter_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "dave", frozenset({"submitter"}))
        response = await client.get("/v1/reeval")
        assert response.status_code == 403


class TestTriggerReeval:
    @pytest.mark.asyncio
    async def test_admin_can_force_trigger_even_when_not_stale(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_published_skill(
            inventory_sessionmaker, skill_id=skill_id, toolchain_digest="placeholder"
        )
        _as(app, "carol", frozenset({"approver"}))
        status_response = await client.get("/v1/reeval")
        current_digest = status_response.json()["current_toolchain_digest"]

        # rewrite the seeded entry's toolchain_digest to match "current" so it
        # is NOT stale, then confirm the admin trigger still queues a rescan
        # (manual trigger deliberately bypasses the staleness filter).
        async with inventory_sessionmaker() as session, session.begin():
            await session.execute(
                update(SkillVersionRow)
                .where(SkillVersionRow.skill_id == skill_id)
                .values(toolchain_digest=current_digest)
            )

        _as(app, "admin-alice", frozenset({"admin"}))
        response = await client.post(f"/v1/reeval/{skill_id}")
        assert response.status_code == 200
        assert response.json()["versions_queued"] == 1

    # SECURITY regression: trigger_reeval opened its session with no
    # .begin() at all, so the scan_job INSERTs trigger_rescans performed were
    # silently rolled back when the session closed - the endpoint still
    # returned HTTP 200 with a correct-looking versions_queued count even
    # though nothing was actually committed. A response-only assertion (as in
    # test_admin_can_force_trigger_even_when_not_stale above) cannot catch
    # this; this test additionally re-queries the database, through
    # ORCHESTRATION's own credentials (svc_reeval is INSERT-only on scan_job
    # and cannot read it back - see test_reeval_controller.py's
    # test_queues_a_real_scan_job_visible_to_orchestration for the same
    # pattern), in a fresh session opened AFTER the HTTP call has returned -
    # proving the row is genuinely durable, not just visible within the
    # request's own (uncommitted) transaction. Filters by this test's own
    # freshly-generated content_hash (not e.g. submitter="admin-alice",
    # which other tests in this class/file also use and would make the
    # row count flaky against shared, un-truncated test DB state).
    @pytest.mark.asyncio
    async def test_queued_rescan_is_actually_committed(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="public",
                content_hash=content_hash,
                toolchain_digest="placeholder",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )

        _as(app, "admin-alice", frozenset({"admin"}))
        response = await client.post(f"/v1/reeval/{skill_id}")
        assert response.status_code == 200
        assert response.json()["versions_queued"] == 1

        async with orchestration_sessionmaker() as session:
            rows = (
                (await session.execute(select(ScanJob).where(ScanJob.content_hash == content_hash)))
                .scalars()
                .all()
            )
        assert len(rows) == 1
        assert rows[0].state == "queued"
        assert rows[0].submitter == "admin-alice"

    @pytest.mark.asyncio
    async def test_only_the_current_version_is_queued_for_a_multi_version_skill(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        """I4 (2026-07-29, milestone F Task 11 follow-up): this route queued a
        rescan for EVERY version a skill had ever had. Harmless while no skill
        could have a second version (`"submitted"` appeared 0 times as a target
        in `lifecycle.VALID_TRANSITIONS`); a real fan-out the moment Task 11
        made a v2 possible. Reeval re-applies CURRENT detection to what is
        live - resurrecting superseded packages costs real scan capacity and
        puts verdicts on record for content nobody ships.
        """
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        v1_hash = uuid.uuid4().hex + uuid.uuid4().hex
        v2_hash = uuid.uuid4().hex + uuid.uuid4().hex
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="public",
                content_hash=v1_hash,
                toolchain_digest="placeholder",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )
        # A real v2 needs a real lifecycle: v1 has to settle before the skill
        # may re-enter at `submitted`. Driven through the production service
        # functions, never by writing rows by hand.
        for to_state in ("scanning", "published"):
            async with inventory_sessionmaker() as session, session.begin():
                await transition_skill(
                    session,
                    skill_id=skill_id,
                    to_state=to_state,
                    reason="test",
                    actor="system",
                    content_hash=v1_hash,
                )
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="public",
                content_hash=v2_hash,
                toolchain_digest="placeholder",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )

        _as(app, "admin-alice", frozenset({"admin"}))
        response = await client.post(f"/v1/reeval/{skill_id}")
        assert response.status_code == 200
        assert response.json()["versions_queued"] == 1

        async with orchestration_sessionmaker() as session:
            queued_hashes = set(
                (
                    await session.execute(
                        select(ScanJob.content_hash).where(
                            ScanJob.content_hash.in_([v1_hash, v2_hash])
                        )
                    )
                )
                .scalars()
                .all()
            )
        # The superseded v1 must not be rescanned at all - not merely counted
        # once. Asserting only the count would pass if the WRONG version were
        # the one queued.
        assert queued_hashes == {v2_hash}

    @pytest.mark.asyncio
    async def test_unknown_skill_is_404(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        response = await client.post(f"/v1/reeval/nonexistent-{uuid.uuid4().hex}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_approver_cannot_trigger(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_published_skill(inventory_sessionmaker, skill_id=skill_id, toolchain_digest="x")
        _as(app, "carol", frozenset({"approver"}))
        response = await client.post(f"/v1/reeval/{skill_id}")
        assert response.status_code == 403

    # SECURITY regression (2026-07-06 spec-compliance audit): this route was the
    # one state-changing endpoint in the whole API missing require_csrf - same
    # bug class as the break-glass CSRF gap fixed earlier, just a different
    # route. A real cookie (not the dependency-override auth the other tests in
    # this class use) is required here specifically to exercise require_csrf's
    # actual cookie-presence check, matching test_admin_router.py/
    # test_allowlist_router.py's established pattern for proving CSRF wiring.
    @pytest.mark.asyncio
    async def test_missing_csrf_token_is_403(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_published_skill(inventory_sessionmaker, skill_id=skill_id, toolchain_digest="x")
        _as(app, "admin-alice", frozenset({"admin"}))
        client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
        client.cookies.set(CSRF_COOKIE_NAME, "test-csrf-token")
        response = await client.post(f"/v1/reeval/{skill_id}")  # no x-csrf-token header
        assert response.status_code == 403


class TestGetReconciliationStatus:
    @pytest.mark.asyncio
    async def test_admin_can_read_recent_outcomes(
        self, app: FastAPI, client: httpx.AsyncClient, reeval_sessionmaker: SessionmakerFixture
    ) -> None:
        marker = f"skill-{uuid.uuid4().hex[:12]}"
        async with reeval_sessionmaker() as session, session.begin():
            session.add(
                ReconciliationRow(
                    content_hash="a" * 64,
                    skill_id=marker,
                    result="ORPHAN",
                    source="poll",
                    detected_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                )
            )
        _as(app, "admin-alice", frozenset({"admin"}))
        response = await client.get("/v1/reconciliation")
        assert response.status_code == 200
        matching = [o for o in response.json()["outcomes"] if o["skill_id"] == marker]
        assert len(matching) == 1
        assert matching[0]["result"] == "ORPHAN"

    @pytest.mark.asyncio
    async def test_approver_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "carol", frozenset({"approver"}))
        response = await client.get("/v1/reconciliation")
        assert response.status_code == 403
