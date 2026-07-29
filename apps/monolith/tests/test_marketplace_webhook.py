"""Tests for `POST /v1/marketplace/webhook` (coding spec §11.6/SAD §4.3 push
reconciliation) - real local MySQL via `gate_sessionmaker`/`reeval_sessionmaker`,
a fake `MarketplacePort` (no real marketplace in this environment), real HMAC
signing exercised over real HTTP requests (`httpx.AsyncClient` + ASGITransport,
same pattern as test_router.py).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from common.blobstore import LocalFilesystemBlobStore
from fastapi import FastAPI
from skillscan_core import GatePolicy, StaticKeywordEngine, Verdict

from monolith.main import create_app
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.tests.conftest import SessionmakerFixture

_ENGINE = StaticKeywordEngine()
_HMAC_SECRET = "test-push-hmac-secret"  # noqa: S105 - test-only literal


class _FakeMarketplace:
    def __init__(self) -> None:
        self.quarantine_calls: list[tuple[str, str]] = []

    async def write_verdict(self, jws: str, content_hash: str) -> None:
        raise NotImplementedError

    async def list_published(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def quarantine(self, skill_id: str, reason: str) -> None:
        self.quarantine_calls.append((skill_id, reason))


def _sign(body: bytes, *, timestamp: int, secret: str = _HMAC_SECRET) -> str:
    return hmac.new(
        secret.encode("utf-8"), f"{timestamp}.".encode("ascii") + body, hashlib.sha256
    ).hexdigest()


def _signed_headers(
    body: bytes, *, timestamp: int | None = None, secret: str = _HMAC_SECRET
) -> dict[str, str]:
    ts = timestamp if timestamp is not None else int(time.time())
    return {
        "X-Marketplace-Signature": _sign(body, timestamp=ts, secret=secret),
        "X-Marketplace-Timestamp": str(ts),
    }


@pytest.fixture
def marketplace() -> _FakeMarketplace:
    return _FakeMarketplace()


@pytest.fixture
def app(
    gate_sessionmaker: SessionmakerFixture,
    reeval_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
    marketplace: _FakeMarketplace,
) -> FastAPI:
    scan_runtime = ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=gate_sessionmaker,  # unused by this endpoint
        gate_session_factory=gate_sessionmaker,
        policy=GatePolicy(
            version=f"test-webhook-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
        reeval_session_factory=reeval_sessionmaker,
        marketplace=marketplace,
        push_hmac_secret=_HMAC_SECRET,
        push_replay_window_s=300,
        push_auto_quarantine_enabled=False,
    )
    return create_app(scan_runtime=scan_runtime)


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


async def _scrape_orphan_total(client_instance: httpx.AsyncClient) -> float:
    """Task 13: read the counter off a REAL `/metrics` scrape of this app, not
    off the collector object - only the exposition path proves the value a
    Prometheus scraper would actually see."""
    response = await client_instance.get("/metrics")
    assert response.status_code == 200
    for line in response.text.splitlines():
        if line.startswith("skillscan_reconciliation_orphan_total "):
            return float(line.rsplit(" ", 1)[1])
    raise AssertionError("reconciliation_orphan_total missing from /metrics output")


class TestMarketplaceWebhook:
    @pytest.mark.asyncio
    async def test_valid_signed_orphan_event_processed_but_not_auto_quarantined(
        self, client: httpx.AsyncClient, marketplace: _FakeMarketplace
    ) -> None:
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex  # never seeded -> ORPHAN
        body = json.dumps({"content_hash": content_hash, "skill_id": "skill-webhook"}).encode()
        response = await client.post(
            "/v1/marketplace/webhook", content=body, headers=_signed_headers(body)
        )
        assert response.status_code == 202
        assert response.json() == {"status": "processed", "result": "ORPHAN"}
        # SECURITY (TB14): push-sourced never auto-quarantines by default,
        # even though the signature itself was valid.
        assert marketplace.quarantine_calls == []

    @pytest.mark.asyncio
    async def test_an_orphan_moves_the_reconciliation_orphan_metric(
        self, client: httpx.AsyncClient
    ) -> None:
        """Task 13 (2026-07-29): `reconciliation_orphan_total` (coding spec
        §11.7) had no production writer.

        FINDING recorded here rather than only in the report: this is the ONLY
        production path in the repo that can move this counter.
        `reeval.service.run_poll_reconciliation` - which SAD §4.3 names as the
        control that can actually detect an ORPHAN, because only it enumerates
        the marketplace's full published set independently - has no caller
        anywhere outside tests. No scheduler, no worker step, no route. So the
        counter can only ever rise on an event the marketplace chooses to send
        us, which is precisely the case a bypassing marketplace would not send.
        """
        before = await _scrape_orphan_total(client)

        content_hash = uuid.uuid4().hex + uuid.uuid4().hex  # never seeded -> ORPHAN
        body = json.dumps(
            {"content_hash": content_hash, "skill_id": "skill-orphan-metric"}
        ).encode()
        response = await client.post(
            "/v1/marketplace/webhook", content=body, headers=_signed_headers(body)
        )
        assert response.json()["result"] == "ORPHAN"

        assert await _scrape_orphan_total(client) == before + 1.0

    @pytest.mark.asyncio
    async def test_a_non_orphan_outcome_does_NOT_move_it(self, client: httpx.AsyncClient) -> None:
        # An event whose signature verifies but whose reconciliation says
        # anything other than ORPHAN must leave the counter alone - otherwise
        # it degenerates into "how many webhooks did we receive", which is not
        # a security signal at all. A malformed body is rejected before
        # reconciliation runs, so it can never reach the increment either.
        before = await _scrape_orphan_total(client)

        body = b"{not json at all"
        response = await client.post(
            "/v1/marketplace/webhook", content=body, headers=_signed_headers(body)
        )
        assert response.status_code == 400

        assert await _scrape_orphan_total(client) == before

    @pytest.mark.asyncio
    async def test_missing_signature_header_rejected(self, client: httpx.AsyncClient) -> None:
        body = json.dumps({"content_hash": "a" * 64, "skill_id": "s"}).encode()
        response = await client.post(
            "/v1/marketplace/webhook",
            content=body,
            headers={"X-Marketplace-Timestamp": str(int(time.time()))},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_signature_rejected(self, client: httpx.AsyncClient) -> None:
        body = json.dumps({"content_hash": "a" * 64, "skill_id": "s"}).encode()
        headers = _signed_headers(body, secret="wrong-secret")
        response = await client.post("/v1/marketplace/webhook", content=body, headers=headers)
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_replayed_old_timestamp_rejected(self, client: httpx.AsyncClient) -> None:
        body = json.dumps({"content_hash": "a" * 64, "skill_id": "s"}).encode()
        old_timestamp = int(time.time()) - 10_000  # well outside the 300s window
        headers = _signed_headers(body, timestamp=old_timestamp)
        response = await client.post("/v1/marketplace/webhook", content=body, headers=headers)
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_tampered_body_rejected(self, client: httpx.AsyncClient) -> None:
        original_body = json.dumps({"content_hash": "a" * 64, "skill_id": "s"}).encode()
        headers = _signed_headers(original_body)
        tampered_body = json.dumps({"content_hash": "b" * 64, "skill_id": "s"}).encode()
        response = await client.post(
            "/v1/marketplace/webhook", content=tampered_body, headers=headers
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_signature_but_malformed_body_is_400(
        self, client: httpx.AsyncClient
    ) -> None:
        body = b"not even json"
        response = await client.post(
            "/v1/marketplace/webhook", content=body, headers=_signed_headers(body)
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_valid_signature_but_missing_required_field_is_400(
        self, client: httpx.AsyncClient
    ) -> None:
        body = json.dumps({"content_hash": "a" * 64}).encode()  # missing skill_id
        response = await client.post(
            "/v1/marketplace/webhook", content=body, headers=_signed_headers(body)
        )
        assert response.status_code == 400


class TestMarketplaceWebhookDisabled:
    @pytest.fixture
    def app(
        self,
        gate_sessionmaker: SessionmakerFixture,
        reeval_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
        marketplace: _FakeMarketplace,
    ) -> FastAPI:
        scan_runtime = ScanRuntime(
            redis=redis_client,
            blobstore=blobstore,
            orchestration_session_factory=gate_sessionmaker,
            gate_session_factory=gate_sessionmaker,
            policy=GatePolicy(
                version=f"test-webhook-disabled-{uuid.uuid4().hex[:8]}",
                required_engines=frozenset({_ENGINE.metadata.name}),
                hard_gate_rules=frozenset(),
                fail_closed_verdict=Verdict.BLOCK,
            ),
            engine_metadatas=(_ENGINE.metadata,),
            allowlist=(),
            signer=LocalDevSigner(),
            reeval_session_factory=reeval_sessionmaker,
            marketplace=marketplace,
            push_hmac_secret=None,  # push disabled entirely
        )
        return create_app(scan_runtime=scan_runtime)

    @pytest.mark.asyncio
    async def test_push_disabled_yields_404_regardless_of_signature(
        self, client: httpx.AsyncClient
    ) -> None:
        body = json.dumps({"content_hash": "a" * 64, "skill_id": "s"}).encode()
        response = await client.post(
            "/v1/marketplace/webhook", content=body, headers=_signed_headers(body)
        )
        assert response.status_code == 404


class TestMarketplaceWebhookNotConfigured:
    @pytest.fixture
    def app(
        self,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> FastAPI:
        scan_runtime = ScanRuntime(
            redis=redis_client,
            blobstore=blobstore,
            orchestration_session_factory=gate_sessionmaker,
            gate_session_factory=gate_sessionmaker,
            policy=GatePolicy(
                version=f"test-webhook-noconfig-{uuid.uuid4().hex[:8]}",
                required_engines=frozenset({_ENGINE.metadata.name}),
                hard_gate_rules=frozenset(),
                fail_closed_verdict=Verdict.BLOCK,
            ),
            engine_metadatas=(_ENGINE.metadata,),
            allowlist=(),
            signer=LocalDevSigner(),
            # reeval_session_factory/marketplace deliberately left unset (None)
            push_hmac_secret=_HMAC_SECRET,
        )
        return create_app(scan_runtime=scan_runtime)

    @pytest.mark.asyncio
    async def test_valid_signature_but_no_marketplace_wiring_is_accepted_but_not_processed(
        self, client: httpx.AsyncClient
    ) -> None:
        body = json.dumps({"content_hash": "a" * 64, "skill_id": "s"}).encode()
        response = await client.post(
            "/v1/marketplace/webhook", content=body, headers=_signed_headers(body)
        )
        assert response.status_code == 202
        assert response.json() == {"status": "accepted_but_not_configured"}
