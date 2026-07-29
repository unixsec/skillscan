"""Tests for `GET/POST /v1/reviews*` (coding spec §9) - real local MySQL/
Redis via a real ScanRuntime; auth faked via FastAPI dependency override.
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
from schemas.findings import serialize_finding
from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    Finding,
    GatePolicy,
    Severity,
    StaticKeywordEngine,
    TrustTier,
    Verdict,
)

from monolith.main import create_app
from monolith.modules.gate import reviews_router
from monolith.modules.gate.models import VerdictRow
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway import router as gateway_router
from monolith.modules.gateway.auth.dependencies import get_session_context
from monolith.modules.gateway.auth.middleware import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
)
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.inventory.service import register_skill_version, transition_skill
from monolith.modules.orchestration.models import ScanJob, ScanResultRow, ScanSubmitterRow
from monolith.modules.orchestration.service import submitter_attribution
from monolith.tests.conftest import SessionmakerFixture

_ENGINE = StaticKeywordEngine()

# The three keys `orchestration.service.submitter_attribution` produces per
# scan_id - same tuple as test_gateway_scan_detail.py's `_ATTRIBUTION_KEYS`,
# duplicated rather than imported across test files by convention here.
_ATTRIBUTION_KEYS = ("submitters", "submitter_sources", "source")


def _session(subject: str, roles: frozenset[str]) -> SessionContext:
    return SessionContext(
        subject=subject,
        roles=roles,
        scopes=frozenset(),
        tier=TrustTier.INTERNAL,
        token_exp=9999999999.0,
        is_machine=False,  # a console/reviewer session is a person
    )


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


@pytest.fixture
def app(
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
) -> FastAPI:
    scan_runtime = ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=orchestration_sessionmaker,
        gate_session_factory=gate_sessionmaker,
        policy=GatePolicy(
            version=f"test-reviews-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
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


async def _seed_review_scan(
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    *,
    scan_id: str,
    submitter: str,
    content_hash: str | None = None,
) -> str:
    """Returns the content_hash the seeded scan/verdict were written under, so
    an I3 test can register that SAME content as a skill version and drive its
    lifecycle - supersession is decided on content_hash, not scan_id."""
    content_hash = content_hash or (uuid.uuid4().hex + uuid.uuid4().hex)
    # One MEDIUM/0.8-confidence finding, so submit_review_decision's new
    # score-recompute has something real to work with. With the default
    # CategoryWeights (all 1.0): penalty = 8.0 * 0.8 * 1.0 = 6.4, so an
    # approve->PASS decision (band[75,100]) scores round(100-6.4)=94.
    finding = Finding(
        rule_id="review.test.finding",
        test_item_id="review.test.finding",
        category=DetectionCategory.CODE,
        title="test finding for review-decision scoring",
        severity=Severity.MEDIUM,
        confidence=0.8,
        source_engine="test-engine",
        source_capability=EngineCapability.STATIC,
    )
    async with orchestration_sessionmaker() as session, session.begin():
        session.add(
            ScanJob(
                scan_id=scan_id,
                content_hash=content_hash,
                toolchain_digest="digest-v1",
                cache_key=f"cache-{uuid.uuid4().hex}",
                state="scored",
                submitter=submitter,
                created_at=_naive_utcnow(),
            )
        )
        session.add(
            ScanResultRow(
                scan_id=scan_id,
                content_hash=content_hash,
                severity=int(Severity.MEDIUM),
                confidence_at_max=0.8,
                trifecta_present=False,
                findings_capped=False,
                required_ok=True,
                findings=[serialize_finding(finding)],
                provenance=[],
                hard_gate_hits=[],
            )
        )
    async with gate_sessionmaker() as session, session.begin():
        session.add(
            VerdictRow(
                scan_id=scan_id,
                content_hash=content_hash,
                verdict="REVIEW",
                score=57,
                policy_version="v1",
                jti=str(uuid.uuid4()),
                jws_signature="original-sig",
                effective_severity=2,
                reasons=["automated: ambiguous"],
                issued_at=_naive_utcnow(),
            )
        )
    return content_hash


class TestListReviews:
    @pytest.mark.asyncio
    async def test_approver_can_list_pending_reviews(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )
        _as(app, "approver-carol", frozenset({"approver"}))
        response = await client.get("/v1/reviews")
        assert response.status_code == 200
        assert any(s["scan_id"] == scan_id for s in response.json()["scans"])

    @pytest.mark.asyncio
    async def test_submitter_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "bob", frozenset({"submitter"}))
        response = await client.get("/v1/reviews")
        assert response.status_code == 403

    # 里程碑 F Task 16: the queue used to carry only the scalar
    # `ScanJob.submitter`, the FIRST submitter. Full attribution existed on the
    # scan DETAIL response and nowhere else, so an approver working this queue on
    # a deduplicated scan saw one name out of several.
    @pytest.mark.asyncio
    async def test_queue_names_every_submitter_of_a_deduplicated_scan(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )
        # Two association rows, as `submit_scan` writes when byte-identical
        # content from a second caller collapses onto one scan_job. `_seed_...`
        # writes the `scan_job` directly and no association rows at all, so they
        # are added here rather than assumed.
        async with orchestration_sessionmaker() as session, session.begin():
            session.add(
                ScanSubmitterRow(
                    scan_id=scan_id,
                    submitter="dev-dave",
                    source="console",
                    requested_trust_tier="internal",
                )
            )
            session.add(
                ScanSubmitterRow(
                    scan_id=scan_id,
                    submitter="dev-erin",
                    source="marketplace",
                    requested_trust_tier="public",
                )
            )

        _as(app, "approver-carol", frozenset({"approver"}))
        entry = next(
            s for s in (await client.get("/v1/reviews")).json()["scans"] if s["scan_id"] == scan_id
        )
        # The scalar stays the FIRST submitter - additive, not a redefinition.
        assert entry["submitter"] == "dev-dave"
        assert entry["submitters"] == ["dev-dave", "dev-erin"]
        # Byte-for-byte the shape `GET /v1/scans/{scan_id}` and `GET /v1/scans`
        # return. One concept, one shape, one producer
        # (`orchestration.service.submitter_attribution`).
        assert entry["submitter_sources"] == [
            {"submitter": "dev-dave", "source": "console", "requested_trust_tier": "internal"},
            {"submitter": "dev-erin", "source": "marketplace", "requested_trust_tier": "public"},
        ]
        assert entry["source"] == ["console", "marketplace"]

        # SECURITY regression (whole-branch review, 2026-07-29): the assertions
        # above only check `/v1/reviews` against hand-written expectations -
        # they would not notice this endpoint drifting from the other two that
        # `submitter_attribution`'s own docstring names as serving "the IDENTICAL
        # shape" (`GET /v1/scans/{scan_id}`, `GET /v1/scans`).
        # `TestListCarriesTheSameAttributionAsDetail` in
        # test_gateway_scan_detail.py already cross-checks those first two
        # against each other; this closes the third leg, same approver session
        # (a member of `_REVIEWER_ROLES`, so both endpoints are readable without
        # a submitter-scoped identity).
        detail = (await client.get(f"/v1/scans/{scan_id}")).json()
        listing_item = next(
            i for i in (await client.get("/v1/scans")).json()["items"] if i["scan_id"] == scan_id
        )
        for key in _ATTRIBUTION_KEYS:
            assert entry[key] == detail[key], f"{key!r} differs between /v1/reviews and detail"
            assert entry[key] == listing_item[key], f"{key!r} differs between /v1/reviews and list"

    @pytest.mark.asyncio
    async def test_an_entry_with_no_association_rows_lists_empty_not_the_first_submitter(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        # Empty lists, never the scalar promoted into a one-element list: that
        # would assert the first submitter is the ONLY authorized reader, which
        # is the claim `scan_submitter` exists to stop making.
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )
        _as(app, "approver-carol", frozenset({"approver"}))
        entry = next(
            s for s in (await client.get("/v1/reviews")).json()["scans"] if s["scan_id"] == scan_id
        )
        assert entry["submitter"] == "dev-dave"
        assert entry["submitters"] == []
        assert entry["submitter_sources"] == []
        assert entry["source"] == []


class TestEmptyAttributionTracksTheProducer:
    """`gateway.router._EMPTY_ATTRIBUTION` and `reviews_router._EMPTY_ATTRIBUTION`
    are each a hand-written dict spelling out `submitter_attribution`'s three
    keys - what a scan/entry with no `scan_submitter` rows renders as.

    This is the OPPOSITE role from test_marketplace_router.py's
    `_SPEC_TOP_LEVEL_FIELDS`: that literal must NOT reference the
    implementation, because its job is catching the implementation drifting
    from an independent spec. These two literals ARE implementation - a
    fallback for the same producer's own attributed shape - so their job is
    the reverse: tracking `submitter_attribution`, not standing apart from it.
    If it ever adds, removes or renames a key, an attributed scan and an
    unattributed one would report DIFFERENT response shapes, which
    `submitter_attribution`'s own docstring forbids ("a response whose shape
    changes with the data is what consumers silently mis-parse") - and nothing
    previously asserted the two literals still match a REAL attributed result.
    """

    @pytest.mark.asyncio
    async def test_empty_attribution_keys_match_a_real_attributed_result(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )
        async with orchestration_sessionmaker() as session, session.begin():
            session.add(
                ScanSubmitterRow(
                    scan_id=scan_id,
                    submitter="dev-dave",
                    source="console",
                    requested_trust_tier="internal",
                )
            )

        async with orchestration_sessionmaker() as session:
            attribution = await submitter_attribution(session, scan_ids=[scan_id])
        producer_keys = set(attribution[scan_id])

        assert set(gateway_router._EMPTY_ATTRIBUTION) == producer_keys
        assert set(reviews_router._EMPTY_ATTRIBUTION) == producer_keys


class TestDecideReview:
    @pytest.mark.asyncio
    async def test_approver_can_approve(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )
        _as(app, "approver-carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/reviews/{scan_id}",
            json={"decision": "approve", "reason": "looks fine"},
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["verdict"] == "PASS"

        async with gate_sessionmaker() as session:
            row = await session.get(VerdictRow, scan_id)
        assert row is not None
        assert row.score == 94

    @pytest.mark.asyncio
    async def test_reviewer_same_as_submitter_is_403(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )
        _as(app, "dev-dave", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/reviews/{scan_id}", json={"decision": "approve"}, headers=headers
        )
        assert response.status_code == 403

    # SECURITY (milestone F Task 18): the same 403 for a CO-submitter. Held at
    # the HTTP layer as well as in `test_gate_reviews.py`, because this is the
    # surface an attacker actually reaches and a router that dropped or
    # reordered the check would leave that file's unit case still green.
    @pytest.mark.asyncio
    async def test_a_co_submitter_of_a_deduplicated_scan_is_403(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )
        # What `submit_scan` writes when dev-erin submits bytes dev-dave had
        # already submitted: one scan_job, still naming dev-dave, and two
        # association rows. dev-erin is a rightful submitter - she can read this
        # scan and it appears in her own scan list - so approving it is her own
        # sign-off on her own submission.
        async with orchestration_sessionmaker() as session, session.begin():
            session.add(
                ScanSubmitterRow(
                    scan_id=scan_id,
                    submitter="dev-dave",
                    source="console",
                    requested_trust_tier="internal",
                )
            )
            session.add(
                ScanSubmitterRow(
                    scan_id=scan_id,
                    submitter="dev-erin",
                    source="console",
                    requested_trust_tier="internal",
                )
            )

        _as(app, "dev-erin", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/reviews/{scan_id}", json={"decision": "approve"}, headers=headers
        )
        assert response.status_code == 403

        async with gate_sessionmaker() as session:
            row = await session.get(VerdictRow, scan_id)
        assert row is not None
        assert row.verdict == "REVIEW"

    @pytest.mark.asyncio
    async def test_unknown_scan_is_404(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "approver-carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/reviews/{uuid.uuid4()}", json={"decision": "approve"}, headers=headers
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_invalid_decision_is_400(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )
        _as(app, "approver-carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/reviews/{scan_id}", json={"decision": "maybe"}, headers=headers
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_missing_csrf_is_403(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )
        _as(app, "approver-carol", frozenset({"approver"}))
        client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
        response = await client.post(f"/v1/reviews/{scan_id}", json={"decision": "approve"})
        assert response.status_code == 403


class TestSupersededReviews:
    """I3 (2026-07-29, milestone F Task 11 follow-up): Task 11 made
    `review_pending -> submitted` legal so a skill awaiting review can ship a
    corrected version - and left the EARLIER REVIEW verdict sitting in the
    queue, because `gate.service.list_pending_reviews` filters purely on
    `verdict == "REVIEW"` and knows nothing about lifecycle.

    An approver picking that entry up is deciding a content hash the skill has
    already moved off. `worker.sync_lifecycle_tick` then discards the answer
    (it transitions only skills whose latest state is `scanning` or
    `review_pending`), so the sign-off is thrown away with no feedback and the
    audit trail records a `review_decided` intent that moved nothing.

    Needs an app with inventory WIRED - the module-level `app` fixture above
    deliberately has no `inventory_session_factory`, which is the honest
    "deployment without an inventory module" case where every REVIEW stays
    decidable.
    """

    @pytest.fixture
    def app(
        self,
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
            inventory_session_factory=inventory_sessionmaker,
            policy=GatePolicy(
                version=f"test-reviews-{uuid.uuid4().hex[:8]}",
                required_engines=frozenset({_ENGINE.metadata.name}),
                hard_gate_rules=frozenset(),
                fail_closed_verdict=Verdict.BLOCK,
            ),
            engine_metadatas=(_ENGINE.metadata,),
            allowlist=(),
            signer=LocalDevSigner(),
        )
        return create_app(scan_runtime=scan_runtime)

    @staticmethod
    async def _seed_skill_awaiting_review(
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        inventory_sessionmaker: SessionmakerFixture,
        *,
        scan_id: str,
    ) -> tuple[str, str]:
        """Drives a real skill to `review_pending` at a real content_hash, with
        a matching REVIEW verdict in the queue. Returns (skill_id, hash).

        Lifecycle is driven through the production service functions, never by
        inserting `skill_lifecycle_event` rows directly - a test that hand-wrote
        rows could set up a state the machine forbids.
        """
        skill_id = f"skill-{uuid.uuid4().hex[:12]}"
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=content_hash,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="dev-dave",
                actor_is_admin=False,
            )
        for to_state in ("scanning", "review_pending"):
            async with inventory_sessionmaker() as session, session.begin():
                await transition_skill(
                    session,
                    skill_id=skill_id,
                    to_state=to_state,
                    reason="test",
                    actor="system",
                    content_hash=content_hash,
                )
        await _seed_review_scan(
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            submitter="dev-dave",
            content_hash=content_hash,
        )
        return skill_id, content_hash

    @staticmethod
    async def _submit_a_newer_version(
        inventory_sessionmaker: SessionmakerFixture, *, skill_id: str
    ) -> None:
        async with inventory_sessionmaker() as session, session.begin():
            await register_skill_version(
                session,
                skill_id=skill_id,
                source="test-suite",
                trust_tier="internal",
                content_hash=uuid.uuid4().hex + uuid.uuid4().hex,
                toolchain_digest="digest-v1",
                declared_perms=None,
                operator="dev-dave",
                actor_is_admin=False,
            )

    @pytest.mark.asyncio
    async def test_a_live_review_is_not_flagged_superseded(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        # The control case. Flagging a still-actionable review would be a far
        # worse bug than the one being fixed - it would make the queue
        # undecidable.
        scan_id = str(uuid.uuid4())
        await self._seed_skill_awaiting_review(
            orchestration_sessionmaker,
            gate_sessionmaker,
            inventory_sessionmaker,
            scan_id=scan_id,
        )
        _as(app, "approver-carol", frozenset({"approver"}))
        response = await client.get("/v1/reviews")
        assert response.status_code == 200
        entry = next(s for s in response.json()["scans"] if s["scan_id"] == scan_id)
        assert entry["superseded"] is False

    @pytest.mark.asyncio
    async def test_a_newer_version_flags_the_old_entry_as_superseded(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        skill_id, _ = await self._seed_skill_awaiting_review(
            orchestration_sessionmaker,
            gate_sessionmaker,
            inventory_sessionmaker,
            scan_id=scan_id,
        )
        await self._submit_a_newer_version(inventory_sessionmaker, skill_id=skill_id)

        _as(app, "approver-carol", frozenset({"approver"}))
        response = await client.get("/v1/reviews")
        assert response.status_code == 200
        entry = next(s for s in response.json()["scans"] if s["scan_id"] == scan_id)
        # STILL LISTED, and labelled. Silently dropping it would leave the
        # approver wondering where the item went; the honest answer is "this
        # one is stale, the new version has its own review coming".
        assert entry["superseded"] is True

    @pytest.mark.asyncio
    async def test_deciding_a_superseded_entry_is_409_and_writes_nothing(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        inventory_sessionmaker: SessionmakerFixture,
    ) -> None:
        # The core of I3: the decision used to be accepted, the verdict row
        # rewritten and re-signed, an outbox event and a `review_decided` audit
        # intent emitted - and then the lifecycle threw all of it away.
        scan_id = str(uuid.uuid4())
        skill_id, _ = await self._seed_skill_awaiting_review(
            orchestration_sessionmaker,
            gate_sessionmaker,
            inventory_sessionmaker,
            scan_id=scan_id,
        )
        await self._submit_a_newer_version(inventory_sessionmaker, skill_id=skill_id)

        _as(app, "approver-carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/reviews/{scan_id}",
            json={"decision": "approve", "reason": "looks fine"},
            headers=headers,
        )
        assert response.status_code == 409

        async with gate_sessionmaker() as session:
            row = await session.get(VerdictRow, scan_id)
        assert row is not None
        # Untouched: the refusal happens BEFORE anything is signed or written.
        assert row.verdict == "REVIEW"
        assert row.jws_signature == "original-sig"
        assert row.reasons == ["automated: ambiguous"]

    @pytest.mark.asyncio
    async def test_an_unregistered_content_hash_stays_decidable(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        # An anonymous submission (no skill_id) has no lifecycle at all, so
        # nothing can supersede it. Asserted over the wire with inventory
        # WIRED, because "no rows found" and "not configured" must not be
        # allowed to collapse into the same refusal.
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )
        _as(app, "approver-carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            f"/v1/reviews/{scan_id}",
            json={"decision": "approve", "reason": "looks fine"},
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["verdict"] == "PASS"
