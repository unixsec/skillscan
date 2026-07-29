"""Tests for `GET /.well-known/jwks.json`, `/healthz`, `/readyz`, `/metrics`
(coding spec §9/§11.7) - deliberately public/unauthenticated, real
ScanRuntime. Needs real MySQL/Redis (orchestration_sessionmaker/
gate_sessionmaker/redis_client/blobstore fixtures) - per this repo's
CLAUDE.md, written here but run only on the dev VM, never on this machine.
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
from skillscan_core import GatePolicy, StaticKeywordEngine, Verdict

from monolith.main import create_app
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.tests.conftest import SessionmakerFixture
from monolith.tests.test_observability import EXPECTED_HELP

_ENGINE = StaticKeywordEngine()


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
            version=f"test-infra-{uuid.uuid4().hex[:8]}",
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


class TestJwks:
    @pytest.mark.asyncio
    async def test_returns_public_key_with_no_auth(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        response = await client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        keys = response.json()["keys"]
        assert len(keys) == 1
        assert keys[0]["kty"] == "RSA"
        assert keys[0]["alg"] == "RS256"


class TestHealthz:
    @pytest.mark.asyncio
    async def test_always_ok(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestReadyz:
    @pytest.mark.asyncio
    async def test_ready_when_dependencies_healthy(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        response = await client.get("/readyz")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["checks"]["redis"] is True
        assert body["checks"]["orchestration_db"] is True

    @pytest.mark.asyncio
    async def test_not_ready_when_redis_unreachable(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # SECURITY: fail-closed - point at a port nothing is listening on
        # rather than mocking, so this is a REAL connection failure.
        broken_redis: aioredis.Redis = aioredis.Redis.from_url("redis://localhost:1")
        app.state.scan.redis = broken_redis
        try:
            response = await client.get("/readyz")
            assert response.status_code == 503
            assert response.json()["checks"]["redis"] is False
        finally:
            await broken_redis.aclose()


class TestMetrics:
    """Task 12 (2026-07-29): `GET /metrics` exposes `ScanRuntime.
    security_metrics.registry` in real Prometheus text-exposition format -
    every collector `SecurityMetrics` currently defines must appear, at
    whatever value it actually holds (not asserted-away as "probably 0").
    """

    # All nine collectors `SecurityMetrics.__init__` defines as of this test
    # (libs/common/observability.py) - named explicitly, not derived
    # from the class under test, so a collector silently added or removed
    # there without a matching change here fails this test rather than
    # passing by construction. The task-12 brief said "seven"; the registry
    # actually holds nine - `introspection_failures_total` and
    # `allowlist_entries_total` are the two it undercounted, and neither had
    # any test in test_observability.py either (see task-12-report.md).
    _EXPECTED_METRIC_NAMES = frozenset(
        {
            "skillscan_worker_failures_total",
            "skillscan_cross_scope_access_attempts_total",
            "skillscan_introspection_failures_total",
            "skillscan_allowlist_entries_total",
            "skillscan_audit_intent_unchained",
            "skillscan_reconciliation_inactive",
            "skillscan_reconciliation_orphan_total",
            "skillscan_sandbox_egress_denied_total",
            "skillscan_external_egress_attempts_total",
        }
    )

    @pytest.mark.asyncio
    async def test_no_auth_required(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        # SECURITY: deliberately unauthenticated (Prometheus scraping
        # convention carries no credential) - protection is the
        # NetworkPolicy in deploy/networkpolicy/monolith-metrics-ingress.yaml,
        # not a check here. Confirm no session/CSRF is demanded.
        response = await client.get("/metrics")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_every_named_collector_is_present(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        response = await client.get("/metrics")
        assert response.status_code == 200
        body = response.text
        missing = {name for name in self._EXPECTED_METRIC_NAMES if name not in body}
        assert not missing, f"collectors missing from /metrics output: {sorted(missing)}"

    @pytest.mark.asyncio
    async def test_every_collector_carries_its_documented_help_text(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        """2026-07-29 honesty review: the sibling assertion to the one above,
        and the one that was missing. This class asserted metric NAMES, which
        cannot disagree with a description - so `worker_failures_total` was
        served for a whole milestone as "Engine-runner worker task failures"
        while counting only the monolith's tick loop.

        The table lives in `test_observability.py` (its docstring says why it is
        hand-written); this asserts it survives the trip through
        `generate_latest` into the response body a Prometheus scraper actually
        parses, since HELP is the only description that reaches a dashboard.
        """
        body = (await client.get("/metrics")).text
        for name, documentation in EXPECTED_HELP.items():
            assert f"# HELP {name} {documentation}\n" in body, (
                f"the scrape does not carry {name}'s documented HELP text"
            )

    @pytest.mark.asyncio
    async def test_reflects_the_live_registry_not_a_fresh_one(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # Proves the endpoint reads the SAME instance the rest of the app
        # would write to, not a throwaway registry that always reads 0 - the
        # exact failure mode that would make a real deployment's scrape look
        # identical to a correctly-wired one while reporting nothing real.
        runtime: ScanRuntime = app.state.scan
        runtime.security_metrics.cross_scope_access_attempts_total.inc()
        runtime.security_metrics.audit_intent_unchained.set(3)

        response = await client.get("/metrics")
        body = response.text
        assert "skillscan_cross_scope_access_attempts_total 1.0" in body
        assert "skillscan_audit_intent_unchained 3.0" in body


class TestReconciliationInactiveIsActuallyWritten:
    """Task 13 (2026-07-29). This is the defect Task 12 caught in the act:
    `create_app` logged "reconciliation_inactive metric should be raised" at
    startup while a scrape of that same process reported the gauge at 0.0,
    because nothing had ever instantiated `SecurityMetrics`. The app named its
    own defect and the scrape demonstrated it in the same breath.

    Asserted through a real `/metrics` scrape of a real `create_app`, not by
    calling `observe_reconciliation_mode` directly - the failure mode was
    never that the setter is wrong, it was that nothing called it.
    """

    @staticmethod
    def _gauge(body: str) -> float:
        for line in body.splitlines():
            if line.startswith("skillscan_reconciliation_inactive "):
                return float(line.rsplit(" ", 1)[1])
        raise AssertionError("reconciliation_inactive missing from /metrics output")

    @pytest.mark.asyncio
    async def test_the_gauge_is_raised_when_poll_is_disabled(
        self, app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # `SKILLSCAN_RECONCILIATION_POLL_ENABLED` defaults to False
        # (common.config.ReconciliationSettings), which is the degraded
        # posture the startup warning is about - so a default-configured
        # deployment, exactly like the VM one Task 12 scraped, must read 1.0.
        monkeypatch.delenv("SKILLSCAN_RECONCILIATION_POLL_ENABLED", raising=False)
        rebuilt = create_app(scan_runtime=app.state.scan)
        transport = httpx.ASGITransport(app=rebuilt)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
            body = (await c.get("/metrics")).text
        assert self._gauge(body) == 1.0

    @pytest.mark.asyncio
    async def test_the_gauge_reads_zero_when_poll_is_enabled(
        self, app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The healthy case must be an EXPLICIT 0, written by the same call -
        # a gauge only ever set on the bad path is indistinguishable from an
        # unwired one, which is the whole defect being fixed here.
        monkeypatch.setenv("SKILLSCAN_RECONCILIATION_POLL_ENABLED", "true")
        rebuilt = create_app(scan_runtime=app.state.scan)
        transport = httpx.ASGITransport(app=rebuilt)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
            body = (await c.get("/metrics")).text
        assert self._gauge(body) == 0.0
