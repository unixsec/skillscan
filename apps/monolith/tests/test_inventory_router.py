"""Tests for `GET/POST /v1/inventory*` (coding spec §9/§16.2) - real local
MySQL/Redis via a real ScanRuntime; auth faked via FastAPI dependency
override, matching test_admin_router.py's established pattern.
"""

from __future__ import annotations

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
from monolith.modules.audit.models import AuditIntent
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.auth.dependencies import get_session_context
from monolith.modules.gateway.auth.middleware import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
)
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.inventory.models import SkillLifecycleEventRow, SkillRow
from monolith.modules.inventory.ownership import SkillOwnershipError, authorize_skill_write
from monolith.modules.inventory.service import (
    get_registered_skill,
    register_skill_version,
    set_baseline,
    transition_skill,
)
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
            version=f"test-inv-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
        inventory_session_factory=inventory_sessionmaker,
    )
    return create_app(scan_runtime=scan_runtime)


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


def _as(app_instance: FastAPI, subject: str, roles: frozenset[str]) -> None:
    app_instance.dependency_overrides[get_session_context] = lambda: _session(subject, roles)


def _csrf_headers_and_cookies(client_instance: httpx.AsyncClient) -> dict[str, str]:
    client_instance.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
    client_instance.cookies.set(CSRF_COOKIE_NAME, "test-csrf-token")
    return {CSRF_HEADER_NAME: "test-csrf-token"}


async def _seed_skill(inventory_sessionmaker: SessionmakerFixture, *, skill_id: str) -> None:
    # NOTE: content_hash is skill_version's PRIMARY KEY - must be unique per
    # call, not a shared constant, or a second seeded skill in the same test
    # run collides on it (a real IntegrityError caught by actually running
    # this against MySQL, not assumed correct from reading the code).
    async with inventory_sessionmaker() as session, session.begin():
        await register_skill_version(
            session,
            skill_id=skill_id,
            source="test-suite",
            trust_tier="public",
            content_hash=uuid.uuid4().hex + uuid.uuid4().hex,
            toolchain_digest="digest-v1",
            declared_perms=None,
            operator="tester",
            actor_is_admin=False,
        )


class TestListInventory:
    @pytest.mark.asyncio
    async def test_approver_can_list(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "carol", frozenset({"approver"}))
        response = await client.get("/v1/inventory")
        assert response.status_code == 200
        matching = [s for s in response.json()["skills"] if s["skill_id"] == skill_id]
        assert len(matching) == 1
        assert matching[0]["state"] == "submitted"

    @pytest.mark.asyncio
    async def test_submitter_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "dave", frozenset({"submitter"}))
        response = await client.get("/v1/inventory")
        assert response.status_code == 403


class TestGetInventoryItem:
    @pytest.mark.asyncio
    async def test_returns_versions_and_state(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "carol", frozenset({"auditor"}))
        response = await client.get(f"/v1/inventory/{skill_id}")
        assert response.status_code == 200
        body = response.json()
        assert body["state"] == "submitted"
        assert len(body["versions"]) == 1
        assert body["baseline"] is None

    @pytest.mark.asyncio
    async def test_unknown_skill_is_404(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "carol", frozenset({"auditor"}))
        response = await client.get(f"/v1/inventory/nonexistent-{uuid.uuid4().hex}")
        assert response.status_code == 404


class TestQuarantineSkill:
    @pytest.mark.asyncio
    async def test_admin_can_quarantine_a_published_skill(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        # submitted -> scanning -> published (valid transition path)
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="scan started",
                actor="system",
            )
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="published",
                reason="passed gate",
                actor="system",
            )

        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/quarantine",
            json={"reason": "drift detected"},
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["state"] == "quarantined"

    @pytest.mark.asyncio
    async def test_invalid_transition_is_409(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)  # state: submitted
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        # submitted -> quarantined is not a valid transition
        response = await client.post(
            f"/v1/inventory/{skill_id}/quarantine", json={"reason": "x"}, headers=headers
        )
        assert response.status_code == 409

    @pytest.mark.asyncio
    async def test_non_admin_denied(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/quarantine", json={"reason": "x"}, headers=headers
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_unknown_skill_is_404(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/nonexistent-{uuid.uuid4().hex}/quarantine",
            json={"reason": "x"},
            headers=headers,
        )
        assert response.status_code == 404


class TestRestoreSkill:
    """SECURITY (milestone F Task 11 follow-up C2): `quarantined -> published`
    was legal in `VALID_TRANSITIONS` and produced by no caller anywhere, so a
    quarantined skill could only ever be retired. `VALID_TRANSITIONS` also
    refuses `quarantined -> submitted` and justifies that refusal by naming
    this route - which made the justification circular until the route
    existed."""

    @staticmethod
    async def _quarantine(inventory_sessionmaker: SessionmakerFixture, *, skill_id: str) -> None:
        for to_state, reason in (
            ("scanning", "scan started"),
            ("published", "passed gate"),
            ("quarantined", "drift detected"),
        ):
            async with inventory_sessionmaker() as session, session.begin():
                await transition_skill(
                    session,
                    skill_id=skill_id,
                    to_state=to_state,
                    reason=reason,
                    actor="system",
                )

    @pytest.mark.asyncio
    async def test_admin_can_restore_a_quarantined_skill_and_it_becomes_usable_again(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        """Walks past the restore itself to the thing the restore is FOR: a
        skill that can take a new version again. Asserting only "the POST
        returned 200" would be the same mistake Task 11 made - declaring
        victory at the edge that was just made reachable while the path beyond
        it stayed blocked."""
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        await self._quarantine(inventory_sessionmaker, skill_id=skill_id)

        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/restore",
            json={"reason": "investigated, false alarm"},
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["state"] == "published"

        detail = await client.get(f"/v1/inventory/{skill_id}")
        assert detail.status_code == 200
        assert detail.json()["state"] == "published"

        # The point of the restore: `published -> submitted` re-entry works
        # again, so a v2 can ship. `tester` is the recorded owner (_seed_skill
        # registered it), so C1's ownership gate is satisfied, not bypassed.
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="public",
                content_hash=uuid.uuid4().hex + uuid.uuid4().hex,
                toolchain_digest="digest-v2",
                declared_perms=None,
                operator="tester",
                actor_is_admin=False,
            )
        after = await client.get(f"/v1/inventory/{skill_id}")
        assert after.json()["state"] == "submitted"
        assert len(after.json()["versions"]) == 2

    @pytest.mark.asyncio
    async def test_the_transition_is_audited(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        """A state change of this weight must leave the same same-transaction
        `audit_intent` trail its quarantine/retire siblings do (INV-12)."""
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        await self._quarantine(inventory_sessionmaker, skill_id=skill_id)

        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/restore",
            json={"reason": "investigated, false alarm"},
            headers=headers,
        )
        assert response.status_code == 200

        async with inventory_sessionmaker() as session:
            events = (
                (
                    await session.execute(
                        select(SkillLifecycleEventRow)
                        .where(SkillLifecycleEventRow.skill_id == skill_id)
                        .order_by(SkillLifecycleEventRow.id)
                    )
                )
                .scalars()
                .all()
            )
        assert [e.to_state for e in events] == [
            "submitted",
            "scanning",
            "published",
            "quarantined",
            "published",
        ]
        restore_event = events[-1]
        assert restore_event.from_state == "quarantined"
        assert restore_event.actor == "admin-alice"
        assert restore_event.reason == "investigated, false alarm"

    @pytest.mark.asyncio
    async def test_restore_does_not_move_the_drift_baseline(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        """SECURITY: a restore approves nothing - it is a decision about
        content that already passed the gate. Re-baselining here would let an
        admin launder swapped content into the approved baseline with one
        click and no scan."""
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        await self._quarantine(inventory_sessionmaker, skill_id=skill_id)
        pinned = uuid.uuid4().hex + uuid.uuid4().hex
        async with inventory_sessionmaker() as session, session.begin():
            await set_baseline(session, skill_id=skill_id, content_hash=pinned, actor="admin:alice")

        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/restore", json={"reason": "cleared"}, headers=headers
        )
        assert response.status_code == 200

        detail = await client.get(f"/v1/inventory/{skill_id}")
        assert detail.json()["baseline"]["content_hash"] == pinned

    @pytest.mark.asyncio
    async def test_restoring_a_skill_that_is_not_quarantined_is_409(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        """SECURITY: `published` is also a legal target from `scanning` and
        `review_pending`, so an unguarded restore would double as a way to
        publish a skill whose scan is still in flight, or to clear a
        `review_pending` skill without the human review that state exists to
        force - in both cases with no verdict behind the release."""
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="scan started",
                actor="system",
            )
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/restore", json={"reason": "x"}, headers=headers
        )
        assert response.status_code == 409

        # And it really did not publish - a 409 that still wrote would be the
        # worst of both.
        detail = await client.get(f"/v1/inventory/{skill_id}")
        assert detail.json()["state"] == "scanning"

    @pytest.mark.asyncio
    async def test_non_admin_denied(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        await self._quarantine(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/restore", json={"reason": "x"}, headers=headers
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_missing_csrf_is_403(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        await self._quarantine(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "admin-alice", frozenset({"admin"}))
        # SECURITY: deliberately no _csrf_headers_and_cookies() call - this is
        # a state-changing endpoint (coding spec §16.1 INV-16) and must be
        # CSRF-gated like every sibling write endpoint in this router.
        client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
        response = await client.post(f"/v1/inventory/{skill_id}/restore", json={"reason": "x"})
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_unknown_skill_is_404(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/nonexistent-{uuid.uuid4().hex}/restore",
            json={"reason": "x"},
            headers=headers,
        )
        assert response.status_code == 404


class TestRetireSkill:
    @pytest.mark.asyncio
    async def test_admin_can_retire(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        async with inventory_sessionmaker() as session, session.begin():
            await transition_skill(
                session,
                skill_id=skill_id,
                to_state="scanning",
                reason="scan started",
                actor="system",
            )
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/retire", json={"reason": "obsolete"}, headers=headers
        )
        assert response.status_code == 200
        assert response.json()["state"] == "retired"


class TestSetBaseline:
    # SECURITY (regression, was BUG): `inventory.service.set_baseline` had NO
    # HTTP-reachable caller anywhere - none of the mounted routers called it -
    # so a drift-detection baseline could never be established in any real
    # deployment, and worker.py's rug-pull auto-quarantine logic (SUPPLY-06)
    # could never fire. `POST /v1/inventory/{skill_id}/baseline` is the fix.

    @pytest.mark.asyncio
    async def test_admin_can_set_baseline_and_it_is_persisted(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)

        response = await client.post(
            f"/v1/inventory/{skill_id}/baseline",
            json={"content_hash": content_hash},
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json() == {"skill_id": skill_id, "content_hash": content_hash}

        # Confirms the baseline was actually persisted (not just a 200 with
        # no real write) - readable back via the existing GET, the same
        # place `TestGetInventoryItem` already asserts `baseline` shape.
        get_response = await client.get(f"/v1/inventory/{skill_id}")
        assert get_response.status_code == 200
        baseline = get_response.json()["baseline"]
        assert baseline is not None
        assert baseline["content_hash"] == content_hash

    @pytest.mark.asyncio
    async def test_set_baseline_replaces_existing_baseline(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        first_hash = uuid.uuid4().hex + uuid.uuid4().hex
        second_hash = uuid.uuid4().hex + uuid.uuid4().hex
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)

        await client.post(
            f"/v1/inventory/{skill_id}/baseline",
            json={"content_hash": first_hash},
            headers=headers,
        )
        response = await client.post(
            f"/v1/inventory/{skill_id}/baseline",
            json={"content_hash": second_hash},
            headers=headers,
        )
        assert response.status_code == 200

        get_response = await client.get(f"/v1/inventory/{skill_id}")
        assert get_response.json()["baseline"]["content_hash"] == second_hash

    @pytest.mark.asyncio
    async def test_non_admin_denied(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/baseline",
            json={"content_hash": uuid.uuid4().hex + uuid.uuid4().hex},
            headers=headers,
        )
        assert response.status_code == 403

        # Confirms the denial was real, not just a misleading status code -
        # no baseline row actually got written.
        _as(app, "admin-alice", frozenset({"admin"}))
        get_response = await client.get(f"/v1/inventory/{skill_id}")
        assert get_response.json()["baseline"] is None

    @pytest.mark.asyncio
    async def test_unknown_skill_is_404(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/nonexistent-{uuid.uuid4().hex}/baseline",
            json={"content_hash": uuid.uuid4().hex + uuid.uuid4().hex},
            headers=headers,
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_missing_csrf_is_403(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "admin-alice", frozenset({"admin"}))
        # SECURITY: deliberately no _csrf_headers_and_cookies() call - this is
        # a state-changing endpoint (coding spec §16.1 INV-16) and must be
        # CSRF-gated like every sibling write endpoint in this router.
        client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
        response = await client.post(
            f"/v1/inventory/{skill_id}/baseline",
            json={"content_hash": uuid.uuid4().hex + uuid.uuid4().hex},
        )
        assert response.status_code == 403


async def _make_unowned(inventory_sessionmaker: SessionmakerFixture, *, skill_id: str) -> None:
    """Turns a seeded skill into a PRE-`skill.owner` row - `owner` cleared,
    genesis lifecycle event intact. That is exactly the shape of the ~481
    bulk-imported skills on the deployed VM, and the reason this whole surface
    exists."""
    async with inventory_sessionmaker() as session, session.begin():
        skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        skill.owner = None


class TestUnownedWorklistEndpoint:
    """`GET /v1/inventory/ownership/unowned` (milestone F Task 15)."""

    @pytest.mark.asyncio
    async def test_admin_sees_the_unowned_skill_and_its_genesis_actor(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        await _make_unowned(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "admin-alice", frozenset({"admin"}))
        response = await client.get("/v1/inventory/ownership/unowned?limit=200")
        assert response.status_code == 200
        body = response.json()
        row = next(s for s in body["skills"] if s["skill_id"] == skill_id)
        # `_seed_skill` registers as "tester", so that is the genesis actor -
        # ADVISORY evidence only. Nothing here or in the console writes it to
        # `skill.owner`; an admin reads it and decides.
        assert row["genesis_actor"] == "tester"
        assert body["total"] >= 1

    @pytest.mark.asyncio
    async def test_an_owned_skill_is_absent(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "admin-alice", frozenset({"admin"}))
        response = await client.get("/v1/inventory/ownership/unowned?limit=200")
        assert response.status_code == 200
        assert skill_id not in {s["skill_id"] for s in response.json()["skills"]}

    @pytest.mark.asyncio
    async def test_the_path_is_not_shadowed_by_the_skill_detail_route(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # `/ownership/unowned` is two segments precisely so `GET /{skill_id}`
        # cannot swallow it (and so a skill literally named "unowned" cannot
        # collide with it). If route registration ever changed such that this
        # resolved to the detail handler, it would answer 404 "skill not
        # found" for a route that exists.
        _as(app, "admin-alice", frozenset({"admin"}))
        response = await client.get("/v1/inventory/ownership/unowned")
        assert response.status_code == 200
        assert "skills" in response.json()

    @pytest.mark.asyncio
    async def test_a_reader_role_is_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        # ADMIN-ONLY, unlike its sibling read routes: this is the input side of
        # an authorization decision, and it dumps genesis actors in bulk. The
        # roles that may read one skill's record do not need a directory of who
        # first submitted what.
        for role in ("approver", "auditor", "submitter"):
            _as(app, "carol", frozenset({role}))
            response = await client.get("/v1/inventory/ownership/unowned")
            assert response.status_code == 403, role

    @pytest.mark.asyncio
    async def test_the_limit_is_clamped_rather_than_honoured(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        response = await client.get("/v1/inventory/ownership/unowned?limit=100000")
        assert response.status_code == 422


class TestSetSkillOwner:
    """`POST /v1/inventory/{skill_id}/owner` - the assignment/transfer
    primitive, and the only path in the system that changes `skill.owner`
    after genesis."""

    @pytest.mark.asyncio
    async def test_admin_assigns_an_owner_to_an_unowned_skill(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        await _make_unowned(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/owner",
            json={"owner": "tester", "reason": "matches the genesis actor"},
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json() == {
            "skill_id": skill_id,
            "owner": "tester",
            "previous_owner": None,
        }

    @pytest.mark.asyncio
    async def test_the_assigned_owner_can_then_submit_a_new_version_over_http(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # THE WHOLE POINT, end to end: C1 made an unowned skill admin-only, so
        # every pre-existing skill was unversionable by the person who actually
        # maintains it. After an admin assigns, `authorize_skill_write` lets
        # that identity through like any other owner.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        await _make_unowned(inventory_sessionmaker, skill_id=skill_id)

        async with inventory_sessionmaker() as session:
            registered = await get_registered_skill(session, skill_id=skill_id)
        assert registered is not None
        assert registered.owner is None
        with pytest.raises(SkillOwnershipError):
            authorize_skill_write(
                skill_id=skill_id,
                recorded_owner=registered.owner,
                actor="tester",
                actor_is_admin=False,
            )

        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/owner",
            json={"owner": "tester", "reason": "legacy row"},
            headers=headers,
        )
        assert response.status_code == 200

        async with inventory_sessionmaker() as session:
            registered = await get_registered_skill(session, skill_id=skill_id)
        assert registered is not None
        authorize_skill_write(
            skill_id=skill_id,
            recorded_owner=registered.owner,
            actor="tester",
            actor_is_admin=False,
        )

    @pytest.mark.asyncio
    async def test_assigning_over_an_existing_owner_is_409_not_a_silent_takeover(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/owner",
            json={"owner": "mallory", "reason": "stale worklist"},
            headers=headers,
        )
        assert response.status_code == 409

        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        assert skill.owner == "tester"

    @pytest.mark.asyncio
    async def test_an_explicit_transfer_is_accepted_and_reports_the_previous_owner(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # The departing-owner path. Refusing it strands every skill in a
        # leaver's name; allowing it by DEFAULT would make every assignment a
        # potential takeover. It has to be asked for.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/owner",
            json={"owner": "bob", "reason": "tester left", "expect_unowned": False},
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["previous_owner"] == "tester"

    @pytest.mark.asyncio
    async def test_a_blank_owner_is_400_not_a_stored_empty_string(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        await _make_unowned(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/owner",
            json={"owner": "   ", "reason": "oops"},
            headers=headers,
        )
        assert response.status_code == 400

        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        assert skill.owner is None

    @pytest.mark.asyncio
    async def test_an_unknown_skill_is_404_and_creates_nothing(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"never-registered-{uuid.uuid4().hex[:12]}"
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/inventory/{skill_id}/owner",
            json={"owner": "alice", "reason": "typo"},
            headers=headers,
        )
        assert response.status_code == 404

        async with inventory_sessionmaker() as session:
            assert await session.get(SkillRow, skill_id) is None

    @pytest.mark.asyncio
    async def test_a_non_admin_may_not_claim_an_unowned_skill(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # STEP 3, DECIDED NO, pinned as a test rather than left as prose. A
        # self-service claim of an unowned asset is first-come-first-served as
        # an authorization model - the same class of hole C1 closed. The system
        # holds no evidence separating the rightful owner of an unowned skill
        # from anyone who can read its skill_id off the console.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        await _make_unowned(inventory_sessionmaker, skill_id=skill_id)
        headers = _csrf_headers_and_cookies(client)
        for role in ("submitter", "approver", "auditor"):
            _as(app, "carol", frozenset({role}))
            response = await client.post(
                f"/v1/inventory/{skill_id}/owner",
                json={"owner": "carol", "reason": "it is mine"},
                headers=headers,
            )
            assert response.status_code == 403, role

        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        assert skill.owner is None

    @pytest.mark.asyncio
    async def test_csrf_is_required(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        await _make_unowned(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "admin-alice", frozenset({"admin"}))
        client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
        client.cookies.set(CSRF_COOKIE_NAME, "test-csrf-token")
        response = await client.post(
            f"/v1/inventory/{skill_id}/owner",
            json={"owner": "tester", "reason": "no csrf header"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_the_owner_is_reported_on_the_detail_route(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # Without this the console cannot answer "why can nobody submit a new
        # version of this skill" at all - the fail-closed NULL would be
        # invisible.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "carol", frozenset({"auditor"}))
        response = await client.get(f"/v1/inventory/{skill_id}")
        assert response.status_code == 200
        assert response.json()["owner"] == "tester"

        await _make_unowned(inventory_sessionmaker, skill_id=skill_id)
        response = await client.get(f"/v1/inventory/{skill_id}")
        assert response.json()["owner"] is None


class TestBulkAssignOwner:
    """`POST /v1/inventory/ownership/assign` - how an admin gets through ~481
    stranded rows without a one-at-a-time form."""

    @pytest.mark.asyncio
    async def test_assigns_every_named_unowned_skill(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        skill_ids = [f"skill-{uuid.uuid4().hex[:12]}" for _ in range(3)]
        for skill_id in skill_ids:
            await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
            await _make_unowned(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/inventory/ownership/assign",
            json={"owner": "tester", "reason": "batch 1", "skill_ids": skill_ids},
            headers=headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert sorted(body["assigned"]) == sorted(skill_ids)
        assert body["failed"] == []

        async with inventory_sessionmaker() as session:
            for skill_id in skill_ids:
                skill = await session.get(SkillRow, skill_id)
                assert skill is not None
                assert skill.owner == "tester"

    @pytest.mark.asyncio
    async def test_one_conflicting_row_does_not_block_the_rest(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # PARTIAL SUCCESS IS REPORTED, NOT ROLLED BACK. An all-or-nothing batch
        # would let one row that got claimed since the worklist was rendered
        # block the other 480, and the admin would re-run into the same wall.
        unowned = f"skill-{uuid.uuid4().hex[:12]}"
        already_owned = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=unowned)
        await _make_unowned(inventory_sessionmaker, skill_id=unowned)
        await _seed_skill(inventory_sessionmaker, skill_id=already_owned)
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/inventory/ownership/assign",
            json={
                "owner": "bob",
                "reason": "batch",
                "skill_ids": [unowned, already_owned],
            },
            headers=headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert body["assigned"] == [unowned]
        assert [f["skill_id"] for f in body["failed"]] == [already_owned]

        async with inventory_sessionmaker() as session:
            # The conflicting row keeps its original owner - a bulk assign is
            # never allowed to take a skill away from anyone.
            skill = await session.get(SkillRow, already_owned)
            assert skill is not None
            assert skill.owner == "tester"

    @pytest.mark.asyncio
    async def test_bulk_cannot_transfer_even_if_asked(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # There is no `expect_unowned` on this route: it is hardcoded True, so
        # a mass revocation of other people's authority is not expressible
        # here at all. An extra field is ignored rather than honoured.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/inventory/ownership/assign",
            json={
                "owner": "mallory",
                "reason": "take everything",
                "skill_ids": [skill_id],
                "expect_unowned": False,
            },
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["assigned"] == []

        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        assert skill.owner == "tester"

    @pytest.mark.asyncio
    async def test_a_duplicated_skill_id_is_assigned_once(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # Otherwise the second copy writes a second audit row for one decision
        # - and 409s against the change the first one just made.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        await _make_unowned(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/inventory/ownership/assign",
            json={"owner": "tester", "reason": "dupes", "skill_ids": [skill_id, skill_id]},
            headers=headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert body["assigned"] == [skill_id]
        assert body["failed"] == []

    @pytest.mark.asyncio
    async def test_a_blank_owner_fails_the_whole_request_before_any_write(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        # A malformed owner is a property of the REQUEST, not of any skill in
        # it - so it is one 400, not N identical per-skill failures, and
        # nothing is committed on the way to finding out.
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
        await _make_unowned(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/inventory/ownership/assign",
            json={"owner": "  ", "reason": "oops", "skill_ids": [skill_id]},
            headers=headers,
        )
        assert response.status_code == 400

        async with inventory_sessionmaker() as session:
            skill = await session.get(SkillRow, skill_id)
        assert skill is not None
        assert skill.owner is None

    @pytest.mark.asyncio
    async def test_an_empty_or_oversized_batch_is_rejected(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        empty = await client.post(
            "/v1/inventory/ownership/assign",
            json={"owner": "alice", "reason": "r", "skill_ids": []},
            headers=headers,
        )
        assert empty.status_code == 422
        oversized = await client.post(
            "/v1/inventory/ownership/assign",
            json={"owner": "alice", "reason": "r", "skill_ids": [f"s-{i}" for i in range(201)]},
            headers=headers,
        )
        assert oversized.status_code == 422

    @pytest.mark.asyncio
    async def test_a_non_admin_is_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        headers = _csrf_headers_and_cookies(client)
        for role in ("submitter", "approver", "auditor"):
            _as(app, "carol", frozenset({role}))
            response = await client.post(
                "/v1/inventory/ownership/assign",
                json={"owner": "carol", "reason": "r", "skill_ids": ["anything"]},
                headers=headers,
            )
            assert response.status_code == 403, role

    @pytest.mark.asyncio
    async def test_every_assignment_gets_its_own_audit_row(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        inventory_sessionmaker: SessionmakerFixture,
        audit_sessionmaker: SessionmakerFixture,
    ) -> None:
        # "Who granted alice authority over skill X" has to be answerable from
        # X. A single opaque batch record would make it answerable only from a
        # batch nobody knows the id of.
        skill_ids = [f"skill-{uuid.uuid4().hex[:12]}" for _ in range(2)]
        for skill_id in skill_ids:
            await _seed_skill(inventory_sessionmaker, skill_id=skill_id)
            await _make_unowned(inventory_sessionmaker, skill_id=skill_id)
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/inventory/ownership/assign",
            json={"owner": "tester", "reason": "batch 1", "skill_ids": skill_ids},
            headers=headers,
        )
        assert response.status_code == 200

        async with audit_sessionmaker() as session:
            rows = (
                (
                    await session.execute(
                        select(AuditIntent).where(AuditIntent.action == "skill_owner_assigned")
                    )
                )
                .scalars()
                .all()
            )
        by_skill = {
            r.payload["skill_id"]: r for r in rows if r.payload.get("skill_id") in set(skill_ids)
        }
        assert set(by_skill) == set(skill_ids)
        for entry in by_skill.values():
            assert entry.operator == "admin-alice"
            assert entry.payload["previous_owner"] is None
            assert entry.payload["new_owner"] == "tester"
