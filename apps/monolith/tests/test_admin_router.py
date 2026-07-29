"""Tests for `POST/GET /v1/admin/*` (coding spec §9/§16.1) - real local
MySQL/Redis via a real ScanRuntime; only auth is faked via FastAPI dependency
override, matching test_router.py's established pattern.
"""

from __future__ import annotations

import asyncio
import datetime
import uuid
from collections.abc import AsyncIterator

import httpx
import pyotp
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from common.blobstore import LocalFilesystemBlobStore
from common.engine_toggle import DISABLED_ENGINES_KEY
from engine_runner.sandbox_engines import SANDBOX_ENGINE_NAMES
from fastapi import FastAPI
from skillscan_core import GatePolicy, StaticKeywordEngine, TrustTier, Verdict
from sqlalchemy import delete, select

from monolith.main import create_app
from monolith.modules.admin.breakglass import deactivate_breakglass
from monolith.modules.audit.models import AuditIntent
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.auth.dependencies import get_session_context
from monolith.modules.gateway.auth.middleware import (
    BREAKGLASS_SESSION_COOKIE_NAME,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
)
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.intel.matcher import INTEL_ENGINE_NAME
from monolith.modules.orchestration.models import ScanEngineHealthRow
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
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
) -> FastAPI:
    scan_runtime = ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=orchestration_sessionmaker,
        gate_session_factory=gate_sessionmaker,
        policy=GatePolicy(
            version=f"test-admin-{uuid.uuid4().hex[:8]}",
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


class _FakeBreakGlassCredentials:
    """Test double for `BreakGlassCredentialPort` - no live Vault is authorized
    for this automated suite (same policy as `test_gate_signer.py`'s fake
    hvac Transit client); this stands in for `VaultBreakGlassCredentialPort`,
    which has its own dedicated tests against a fake hvac KV v2 client in
    `test_breakglass_vault.py`."""

    def __init__(self, *, credential: str, totp_secret: str) -> None:
        self._credential = credential
        self._totp_secret = totp_secret

    async def fetch_credential(self) -> str:
        return self._credential

    async def fetch_totp_secret(self) -> str:
        return self._totp_secret


_BREAKGLASS_CREDENTIAL = "breakglass-test-credential"
_BREAKGLASS_TOTP_SECRET = pyotp.random_base32()


@pytest.fixture
def breakglass_app(
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
            version=f"test-admin-bg-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
        breakglass_enabled=True,
        breakglass_credentials=_FakeBreakGlassCredentials(
            credential=_BREAKGLASS_CREDENTIAL, totp_secret=_BREAKGLASS_TOTP_SECRET
        ),
    )
    return create_app(scan_runtime=scan_runtime)


@pytest_asyncio.fixture
async def breakglass_client(breakglass_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=breakglass_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


def _as_admin(app: FastAPI) -> None:
    app.dependency_overrides[get_session_context] = lambda: _session(
        "admin-alice", frozenset({"admin"})
    )


def _as_submitter(app: FastAPI) -> None:
    app.dependency_overrides[get_session_context] = lambda: _session(
        "bob", frozenset({"submitter"})
    )


def _csrf_headers_and_cookies(client: httpx.AsyncClient) -> dict[str, str]:
    # NOTE: also sets the SESSION cookie (any value - get_session_context is
    # dependency-overridden in these tests, so its validity is never checked)
    # so require_csrf actually treats this as a cookie-authenticated request
    # needing CSRF, matching a real BFF/browser request's shape - otherwise
    # every "success" test below would silently take the CSRF-exempt bearer
    # path and never really exercise CSRF validation at all.
    client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
    client.cookies.set(CSRF_COOKIE_NAME, "test-csrf-token")
    return {CSRF_HEADER_NAME: "test-csrf-token"}


class TestListEngines:
    @pytest.mark.asyncio
    async def test_admin_can_list_engines(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as_admin(app)
        response = await client.get("/v1/admin/engines")
        assert response.status_code == 200
        engines = response.json()["engines"]
        assert any(e["name"] == _ENGINE.metadata.name and e["required"] for e in engines)

    @pytest.mark.asyncio
    async def test_non_admin_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as_submitter(app)
        response = await client.get("/v1/admin/engines")
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_lists_all_three_engine_tiers_including_the_intel_matcher(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        """THE LIVE DEFECT (milestone C Task 2, 2026-07-29): this listing
        enumerated only two tiers - `runtime.engine_metadatas` (which main.py
        fills from `floor_engines()` alone) and `SANDBOX_ENGINE_NAMES`. The
        intel matcher is a third tier, declared only inside
        `worker._floor_engines_with_intel`, so it ran on every scan while being
        invisible here and un-toggleable (see the 404 test below)."""
        _as_admin(app)
        response = await client.get("/v1/admin/engines")
        assert response.status_code == 200
        by_name = {e["name"]: e for e in response.json()["engines"]}
        assert INTEL_ENGINE_NAME in by_name
        assert by_name[INTEL_ENGINE_NAME]["enabled"] is True
        # Advisory tier: never `required_engines` (an intel-DB hiccup degrades
        # to floor-only findings rather than fail-closed BLOCKing every scan).
        assert by_name[INTEL_ENGINE_NAME]["required"] is False
        assert set(SANDBOX_ENGINE_NAMES) <= set(by_name)

    @pytest.mark.asyncio
    async def test_every_listed_engine_is_addressable_by_the_toggle(
        self, app: FastAPI, client: httpx.AsyncClient, redis_client: aioredis.Redis
    ) -> None:
        """The listing and the toggle's `known_names` guard used to be built by
        two independent expressions; both missed the intel tier. They are now
        one derivation, and this asserts the property end-to-end rather than
        trusting that."""
        _as_admin(app)
        listed = [e["name"] for e in (await client.get("/v1/admin/engines")).json()["engines"]]
        headers = _csrf_headers_and_cookies(client)
        for name in listed:
            response = await client.patch(
                f"/v1/admin/engines/{name}", json={"enabled": True}, headers=headers
            )
            # 200 (toggled) or 409 (required floor engine, INV-1) - never 404,
            # which would mean the console renders a row nothing can act on.
            assert response.status_code in (200, 409), f"{name} listed but not addressable"


class TestEngineHealthEndpoint:
    """`GET /v1/admin/engines/health` against a REAL `scan_engine_health` table
    (milestone C Task 10).

    VM ONLY - these need real MySQL. The rules they exercise (window folding,
    the three duration states, the counts) are proved without a database in
    `test_engine_health_read.py`; what only a real server can prove is the part
    those cannot touch: that the two-statement read actually returns rows under
    `svc_orchestration`'s grant, that `LIMIT` on a grouped/ordered subquery
    behaves as expected, and that a `not_reported` row survives the round trip
    with `engine_status` genuinely NULL rather than coerced to a string.
    """

    @pytest_asyncio.fixture(autouse=True)
    async def _empty_health_table(
        self, orchestration_sessionmaker: SessionmakerFixture
    ) -> AsyncIterator[None]:
        """Every other test in this repo isolates itself with a unique id, and
        that is enough because it then reads back by that id.
        `GET /v1/admin/engines/health` cannot: it folds a window over the WHOLE
        table, so a sibling test's rows land inside the window and are counted.
        `recorded_at` is a plain `DATETIME` (second granularity) and the whole
        class runs inside one second, so "the newest scan" is not even
        deterministic between them.

        Measured on the VM 2026-07-29: without this, three of the eight fail
        (`assert {'aig-mcp-scan', 'bandit'} >= {'bandit', 'yara'}` and
        `assert 'currently_disabled' is None`) while each passes alone against
        an empty table. The endpoint is behaving correctly in both cases - a
        window holding a `not_reported` row for `yara` SHOULD attribute it -
        so the fix belongs here, not in the read path.
        """
        async with orchestration_sessionmaker() as session, session.begin():
            await session.execute(delete(ScanEngineHealthRow))
        yield

    @staticmethod
    async def _insert_health(
        sessionmaker: SessionmakerFixture,
        rows: list[tuple[str, str, str, str | None, int | None, int | None, str | None]],
        *,
        recorded_at: datetime.datetime,
    ) -> None:
        async with sessionmaker() as session, session.begin():
            for scan_id, engine, state, status, duration, findings, error in rows:
                session.add(
                    ScanEngineHealthRow(
                        scan_id=scan_id,
                        engine_name=engine,
                        report_state=state,
                        engine_status=status,
                        analyze_duration_ms=duration,
                        finding_count=findings,
                        error=error,
                        recorded_at=recorded_at,
                    )
                )

    @pytest.mark.asyncio
    async def test_returned_error_and_never_reported_arrive_as_different_values(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        """ACCEPTANCE CRITERION 8, end to end over HTTP. Before this milestone
        the storage layer could not express the difference at all: a missing
        blob became a fabricated `EngineStatus.ERROR` so the gate would fail
        closed, and the telemetry inherited the fabrication."""
        _as_admin(app)
        scan_id = f"health-{uuid.uuid4().hex[:12]}"
        await self._insert_health(
            orchestration_sessionmaker,
            [
                (scan_id, "bandit", "reported", "error", 90, 0, "adapter exited 1"),
                (scan_id, "aig-mcp-scan", "not_reported", None, None, None, "no findings reported"),
            ],
            recorded_at=datetime.datetime.now(),
        )
        body = (await client.get("/v1/admin/engines/health")).json()
        by_name = {e["name"]: e for e in body["engines"]}

        bandit = by_name["bandit"]
        assert (bandit["last_report_state"], bandit["last_engine_status"]) == ("reported", "error")
        assert (
            by_name["aig-mcp-scan"]["last_report_state"],
            by_name["aig-mcp-scan"]["last_engine_status"],
        ) == ("not_reported", None), (
            "a never-reported engine came back with a non-null engine_status - the column "
            "split is what makes 'returned ERROR' and 'never reported' different facts, and "
            "a driver coercing NULL to '' would silently undo it"
        )
        assert by_name["bandit"]["counts"]["error"] >= 1
        assert by_name["aig-mcp-scan"]["counts"]["not_reported"] >= 1

    @pytest.mark.asyncio
    async def test_the_three_duration_states_survive_the_round_trip(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        """A `0` that comes back as NULL (or a NULL that comes back as 0) would
        be invisible in every pure test, because both live entirely inside the
        driver + column type."""
        _as_admin(app)
        scan_id = f"health-{uuid.uuid4().hex[:12]}"
        await self._insert_health(
            orchestration_sessionmaker,
            [
                (scan_id, "static-keyword", "reported", "ok", 0, 0, None),
                (scan_id, "yara", "reported", "ok", None, 0, None),
                (scan_id, "bandit", "reported", "ok", 42, 1, None),
            ],
            recorded_at=datetime.datetime.now(),
        )
        by_name = {
            e["name"]: e for e in (await client.get("/v1/admin/engines/health")).json()["engines"]
        }
        assert by_name["static-keyword"]["last_analyze_duration_ms"] == 0
        assert by_name["yara"]["last_analyze_duration_ms"] is None
        assert by_name["bandit"]["last_analyze_duration_ms"] == 42
        assert by_name["static-keyword"]["measured_duration_count"] == 1
        assert by_name["yara"]["measured_duration_count"] == 0

    @pytest.mark.asyncio
    async def test_the_window_is_counted_in_scans_and_reports_what_it_covered(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        """`?scans=1` must return ONE scan's worth of history, not one ROW's.
        This is the assertion that would catch a `LIMIT` applied to the wrong
        statement - the ungrouped rows rather than the grouped scan ids."""
        _as_admin(app)
        base = datetime.datetime.now()
        older, newer = f"h-{uuid.uuid4().hex[:12]}", f"h-{uuid.uuid4().hex[:12]}"
        await self._insert_health(
            orchestration_sessionmaker,
            [
                (older, "bandit", "reported", "error", 10, 0, "old failure"),
                (older, "yara", "reported", "ok", 10, 0, None),
            ],
            recorded_at=base - datetime.timedelta(hours=1),
        )
        await self._insert_health(
            orchestration_sessionmaker,
            [
                (newer, "bandit", "reported", "ok", 11, 0, None),
                (newer, "yara", "reported", "ok", 11, 0, None),
            ],
            recorded_at=base,
        )
        body = (await client.get("/v1/admin/engines/health?scans=1")).json()
        assert body["window"]["requested_scans"] == 1
        assert body["window"]["observed_scans"] == 1
        by_name = {e["name"]: e for e in body["engines"]}
        # Both engines of the newest scan are in the window; neither row of the
        # older scan is, so the old failure must not be counted.
        assert set(by_name) >= {"bandit", "yara"}
        assert by_name["bandit"]["counts"]["error"] == 0
        assert by_name["bandit"]["last_scan_id"] == newer

    @pytest.mark.asyncio
    async def test_an_out_of_range_window_is_rejected_rather_than_read_whole(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        assert (await client.get("/v1/admin/engines/health?scans=100000")).status_code == 422
        assert (await client.get("/v1/admin/engines/health?scans=0")).status_code == 422

    @pytest.mark.asyncio
    async def test_a_disabled_engine_that_never_reported_is_attributed_to_the_toggle(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        redis_client: aioredis.Redis,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        """The Redis disabled set is one of only two authoritative sources for
        WHY an engine did not report. The join has to be real: this test writes
        the toggle through the same endpoint an operator would use, so a
        change to the key name or the set semantics breaks it."""
        _as_admin(app)
        scan_id = f"health-{uuid.uuid4().hex[:12]}"
        await self._insert_health(
            orchestration_sessionmaker,
            [(scan_id, "yara", "not_reported", None, None, None, "no findings reported")],
            recorded_at=datetime.datetime.now(),
        )
        headers = _csrf_headers_and_cookies(client)
        await client.patch("/v1/admin/engines/yara", json={"enabled": False}, headers=headers)
        try:
            by_name = {
                e["name"]: e
                for e in (await client.get("/v1/admin/engines/health")).json()["engines"]
            }
            assert by_name["yara"]["not_reported_attribution"] == "currently_disabled"
            # 2026-07-29: the qualifier has to be ON THE WIRE, not only in the
            # console's translated hint - a second consumer reading a bare
            # `currently_disabled` inherits it as a fact about THIS scan.
            assert by_name["yara"]["not_reported_attribution_basis"] == "current_config"
        finally:
            await redis_client.srem(DISABLED_ENGINES_KEY, "yara")  # type: ignore[misc]

    @pytest.mark.asyncio
    async def test_a_reporting_engine_gets_no_attribution_even_while_disabled(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        redis_client: aioredis.Redis,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        """Attribution answers "why did it not report". Attaching it to an
        engine that DID report would put a config note next to a healthy row
        and make the toggle look like a failure cause."""
        _as_admin(app)
        scan_id = f"health-{uuid.uuid4().hex[:12]}"
        await self._insert_health(
            orchestration_sessionmaker,
            [(scan_id, "yara", "reported", "ok", 7, 0, None)],
            recorded_at=datetime.datetime.now(),
        )
        await redis_client.sadd(DISABLED_ENGINES_KEY, "yara")  # type: ignore[misc]
        try:
            by_name = {
                e["name"]: e
                for e in (await client.get("/v1/admin/engines/health")).json()["engines"]
            }
            assert by_name["yara"]["not_reported_attribution"] is None
            # No token to qualify, so no basis: a basis on a null attribution
            # would be a claim in its own right.
            assert by_name["yara"]["not_reported_attribution_basis"] is None
        finally:
            await redis_client.srem(DISABLED_ENGINES_KEY, "yara")  # type: ignore[misc]

    @pytest.mark.asyncio
    async def test_the_console_will_not_call_an_engine_unbuilt_that_it_has_heard_from(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        """THE VM's 2026-07-29 split brain, reproduced over HTTP.

        `SKILLSCAN_VLLM_BASE_URL` was set on the engine-runner Deployment and
        not on the monolith, so the engine-runner built `aig-mcp-scan` and ran
        it on every scan while the monolith - which derives its LLM-gated set
        from its OWN copy of that variable - believed the engine did not exist.
        The page rendered "this deployment does not build this engine" beside
        `failed 2` for that engine, in one row.

        This fixture's ScanRuntime leaves `sandbox_llm_configured` at its
        default False, which IS the monolith's half of that disagreement; the
        `reported` row below is the engine-runner's half. The endpoint must
        return `None`, not the false cause - and must not invent a replacement
        one either.
        """
        _as_admin(app)
        now = datetime.datetime.now()
        older = f"health-{uuid.uuid4().hex[:12]}"
        newer = f"health-{uuid.uuid4().hex[:12]}"
        # The engine-runner delivered a result. It failed, which is still proof
        # the engine was constructed - the VM's rows were errors too.
        await self._insert_health(
            orchestration_sessionmaker,
            [(older, "aig-mcp-scan", "reported", "error", 805, 0, "python3 exited 1")],
            recorded_at=now - datetime.timedelta(minutes=5),
        )
        # ... and a later scan the monolith decided without waiting for it,
        # which is what makes an attribution get computed at all.
        await self._insert_health(
            orchestration_sessionmaker,
            [(newer, "aig-mcp-scan", "not_reported", None, None, None, "no findings reported")],
            recorded_at=now,
        )

        by_name = {
            e["name"]: e for e in (await client.get("/v1/admin/engines/health")).json()["engines"]
        }
        aig = by_name["aig-mcp-scan"]
        assert aig["last_report_state"] == "not_reported"
        # The contradiction the console showed, asserted as data: a nonzero
        # failure count and "not built here" cannot both be on this row.
        assert aig["counts"]["error"] == 1
        assert aig["not_reported_attribution"] is None
        assert aig["not_reported_attribution_basis"] is None

    @pytest.mark.asyncio
    async def test_the_llm_cause_states_this_services_config_and_says_so_on_the_wire(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        """The other half of the same split brain, and the half no evidence can
        reach (2026-07-29 honesty review).

        Above, the engine-runner's endpoint was DOWN, so `aig-mcp-scan` exited
        in under a second and left `reported` rows the overrule could use. With
        that endpoint UP the engine takes ~240 s, this monolith never waits for
        it, and every row is `not_reported` - identical to a deployment that
        genuinely does not build it. The token must therefore be true in both,
        which is why it names THIS service's configuration rather than the
        other pod's behaviour, and why the basis travels beside it.
        """
        _as_admin(app)
        scan_id = f"health-{uuid.uuid4().hex[:12]}"
        await self._insert_health(
            orchestration_sessionmaker,
            [(scan_id, "aig-mcp-scan", "not_reported", None, None, None, "no findings reported")],
            recorded_at=datetime.datetime.now(),
        )
        by_name = {
            e["name"]: e for e in (await client.get("/v1/admin/engines/health")).json()["engines"]
        }
        aig = by_name["aig-mcp-scan"]
        # The precondition that makes this the unfalsifiable shape: zero
        # delivered results, so the evidence overrule has nothing to fire on.
        assert (aig["counts"]["ok"], aig["counts"]["partial"], aig["counts"]["error"]) == (0, 0, 0)
        assert aig["not_reported_attribution"] == "llm_endpoint_unconfigured"
        assert aig["not_reported_attribution_basis"] == "current_config"

    @pytest.mark.asyncio
    async def test_a_health_row_under_an_unknown_name_is_surfaced_not_dropped(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        """`osv_scanner` is the LOCK-FILE key; the runtime name is
        `osv-scanner`. A row written under the wrong namespace joins against
        nothing in the console and would simply vanish - which is exactly how
        `build_engine_coverage`'s disabled flag stayed wrong for years."""
        _as_admin(app)
        scan_id = f"health-{uuid.uuid4().hex[:12]}"
        await self._insert_health(
            orchestration_sessionmaker,
            [(scan_id, "osv_scanner", "reported", "ok", 5, 0, None)],
            recorded_at=datetime.datetime.now(),
        )
        body = (await client.get("/v1/admin/engines/health")).json()
        assert "osv_scanner" in body["unregistered_engines"]

    @pytest.mark.asyncio
    async def test_non_admin_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as_submitter(app)
        assert (await client.get("/v1/admin/engines/health")).status_code == 403


class TestSetEngineEnabled:
    @pytest.mark.asyncio
    async def test_disabling_required_floor_engine_is_409(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        response = await client.patch(
            f"/v1/admin/engines/{_ENGINE.metadata.name}",
            json={"enabled": False},
            headers=headers,
        )
        assert response.status_code == 409

    @pytest.mark.asyncio
    async def test_disabling_non_required_engine_succeeds(
        self, app: FastAPI, client: httpx.AsyncClient, redis_client: aioredis.Redis
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        # A real, known sandbox engine name (services/engine_runner/
        # sandbox_engines.py's SANDBOX_ENGINE_NAMES) - the endpoint now
        # rejects unknown names with 404 (test_disabling_unknown_engine_name_
        # is_404 below), so a made-up name can no longer stand in here.
        name = "bandit"
        try:
            response = await client.patch(
                f"/v1/admin/engines/{name}", json={"enabled": False}, headers=headers
            )
            assert response.status_code == 200
            assert response.json()["enabled"] is False
        finally:
            await redis_client.srem("skillscan:admin:disabled_engines", name)  # type: ignore[misc]

    @pytest.mark.asyncio
    async def test_toggling_the_intel_matcher_is_not_404(
        self, app: FastAPI, client: httpx.AsyncClient, redis_client: aioredis.Redis
    ) -> None:
        """THE LIVE DEFECT (milestone C Task 2, 2026-07-29): `known_names` was
        floor names | SANDBOX_ENGINE_NAMES, so PATCHing `inhouse-intel-matcher`
        404'd - an engine that runs on every scan could not be switched off at
        all. `worker.worker_tick` now honours the toggle for it too, so this is
        a real control rather than a write-only Redis entry."""
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        try:
            response = await client.patch(
                f"/v1/admin/engines/{INTEL_ENGINE_NAME}", json={"enabled": False}, headers=headers
            )
            assert response.status_code == 200
            assert response.json()["enabled"] is False
            body = (await client.get("/v1/admin/engines")).json()
            listed = {e["name"]: e for e in body["engines"]}
            assert listed[INTEL_ENGINE_NAME]["enabled"] is False
        finally:
            await redis_client.srem(DISABLED_ENGINES_KEY, INTEL_ENGINE_NAME)  # type: ignore[misc]

    @pytest.mark.asyncio
    async def test_disabling_unknown_engine_name_is_404(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        name = f"not-a-real-engine-{uuid.uuid4().hex[:8]}"
        response = await client.patch(
            f"/v1/admin/engines/{name}", json={"enabled": False}, headers=headers
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_disabling_engine_writes_audit_intent(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        audit_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
    ) -> None:
        # SECURITY (coding spec §16.1: "admin 高危操作...经审计"): admin has no
        # DB user of its own (policies/grants/manifest.yaml) - verifying the
        # row actually landed requires svc_audit's own (SELECT-capable)
        # session, same pattern as test_policy_workflow.py's equivalent test.
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        name = "bandit"
        try:
            # audit_intent is append-only (no delete grant, by design - see
            # feedback_setup_grants_additive_masks_violations) and this exact
            # engine name is also used by a sibling test in this class, so a
            # full-suite run can carry a pre-existing row for the same
            # action/name. Snapshot ids beforehand and only assert on rows
            # this PATCH call actually created, instead of an unscoped count.
            async with audit_sessionmaker() as session:
                result = await session.execute(
                    select(AuditIntent).where(AuditIntent.action == "engine_enabled_changed")
                )
                pre_existing_ids = {
                    row.id for row in result.scalars().all() if row.payload.get("name") == name
                }

            response = await client.patch(
                f"/v1/admin/engines/{name}", json={"enabled": False}, headers=headers
            )
            assert response.status_code == 200

            async with audit_sessionmaker() as session:
                result = await session.execute(
                    select(AuditIntent).where(AuditIntent.action == "engine_enabled_changed")
                )
                intents = [
                    row
                    for row in result.scalars().all()
                    if row.payload.get("name") == name and row.id not in pre_existing_ids
                ]
            assert len(intents) == 1
            assert intents[0].operator == "admin-alice"
            assert intents[0].payload["enabled"] is False
        finally:
            await redis_client.srem("skillscan:admin:disabled_engines", name)  # type: ignore[misc]

    @pytest.mark.asyncio
    async def test_missing_csrf_token_is_403(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as_admin(app)
        # NOTE: `require_csrf` decides cookie- vs bearer-authenticated purely
        # from the SESSION cookie's presence on the raw request - independent
        # of `get_session_context`'s dependency override above, which only
        # fakes the RESULT of auth, not the request shape. A real BFF/browser
        # request always carries this cookie, so set one here too (any value -
        # its validity is what the override bypasses, not its presence).
        client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
        response = await client.patch(
            f"/v1/admin/engines/bandit-{uuid.uuid4().hex[:8]}", json={"enabled": False}
        )
        assert response.status_code == 403


class TestPolicyEndpoints:
    @pytest.mark.asyncio
    async def test_get_policy_returns_active_policy_and_empty_pending(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        response = await client.get("/v1/admin/policy")
        assert response.status_code == 200
        body = response.json()
        assert "active_policy" in body
        assert body["active_policy"]["required_engines"] == [_ENGINE.metadata.name]

    @pytest.mark.asyncio
    async def test_propose_non_hard_gate_change_is_auto_approved(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/admin/policy",
            json={"policy_yaml": f'version: "v-{uuid.uuid4().hex[:8]}"\nrequired_engines: []\n'},
            headers=headers,
        )
        assert response.status_code == 201
        assert response.json()["status"] == "approved"

    @pytest.mark.asyncio
    async def test_propose_hard_gate_change_then_appears_in_pending(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        yaml_body = (
            f'version: "v-{uuid.uuid4().hex[:8]}"\n'
            "required_engines: []\n"
            "hard_gate_rules:\n  - pii.credit_card\n"
        )
        propose_response = await client.post(
            "/v1/admin/policy", json={"policy_yaml": yaml_body}, headers=headers
        )
        assert propose_response.status_code == 201
        assert propose_response.json()["status"] == "pending"

        get_response = await client.get("/v1/admin/policy")
        pending_ids = [p["id"] for p in get_response.json()["pending_proposals"]]
        assert propose_response.json()["id"] in pending_ids

    @pytest.mark.asyncio
    async def test_invalid_policy_yaml_is_400(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/admin/policy", json={"policy_yaml": "not valid: [policy"}, headers=headers
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_self_approval_of_own_proposal_is_403(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        yaml_body = (
            f'version: "v-{uuid.uuid4().hex[:8]}"\n'
            "required_engines: []\n"
            "hard_gate_rules:\n  - pii.credit_card\n"
        )
        propose_response = await client.post(
            "/v1/admin/policy", json={"policy_yaml": yaml_body}, headers=headers
        )
        proposal_id = propose_response.json()["id"]

        # same admin ("admin-alice") tries to approve their own proposal
        approve_response = await client.post(
            f"/v1/admin/policy/{proposal_id}/approve", headers=headers
        )
        assert approve_response.status_code == 403

    @pytest.mark.asyncio
    async def test_different_admin_can_approve(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        yaml_body = (
            f'version: "v-{uuid.uuid4().hex[:8]}"\n'
            "required_engines: []\n"
            "hard_gate_rules:\n  - pii.credit_card\n"
        )
        propose_response = await client.post(
            "/v1/admin/policy", json={"policy_yaml": yaml_body}, headers=headers
        )
        proposal_id = propose_response.json()["id"]

        app.dependency_overrides[get_session_context] = lambda: _session(
            "admin-carol", frozenset({"admin"})
        )
        approve_response = await client.post(
            f"/v1/admin/policy/{proposal_id}/approve", headers=headers
        )
        assert approve_response.status_code == 200
        assert approve_response.json()["status"] == "approved"
        assert approve_response.json()["approved_by"] == "admin-carol"

    @pytest.mark.asyncio
    async def test_approving_nonexistent_proposal_is_404(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        response = await client.post("/v1/admin/policy/999999999/approve", headers=headers)
        assert response.status_code == 404


class TestListUsers:
    @pytest.mark.asyncio
    async def test_admin_can_view_group_role_map(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as_admin(app)
        response = await client.get("/v1/admin/users")
        assert response.status_code == 200
        assert "group_role_map" in response.json()

    @pytest.mark.asyncio
    async def test_non_admin_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as_submitter(app)
        response = await client.get("/v1/admin/users")
        assert response.status_code == 403


class TestBreakGlassDisabledByDefault:
    """The plain `app` fixture builds a `ScanRuntime` with no break-glass
    kwargs, so `breakglass_enabled` is False by default (coding spec §16.3:
    disabled-by-default is the mandatory posture) - every break-glass route
    must fail closed to 404, never expose whether it's merely unconfigured
    vs. something more specific."""

    @pytest.mark.asyncio
    async def test_status_reports_disabled(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as_admin(app)
        response = await client.get("/v1/admin/breakglass")
        assert response.status_code == 200
        assert response.json() == {"enabled": False, "armed": False}

    @pytest.mark.asyncio
    async def test_activate_is_404(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as_admin(app)
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "admin-bob", "totp_code": "000000"},
            headers=headers,
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_login_is_404(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        response = await client.post(
            "/v1/admin/breakglass/login", json={"credential": "x", "totp_code": "000000"}
        )
        assert response.status_code == 404


class TestBreakGlassEnabled:
    @pytest_asyncio.fixture(autouse=True)
    async def _reset_armed_state(self, redis_client: aioredis.Redis) -> AsyncIterator[None]:
        # SECURITY-adjacent test hygiene: the armed/used state lives in
        # module-level Redis keys shared across every test in this class (and
        # test_breakglass.py) - reset to "not armed" before each test so an
        # earlier test's leftover activation can never make a later
        # "not-yet-activated" assertion pass (or fail) for the wrong reason.
        await deactivate_breakglass(redis_client)
        yield

    @pytest.mark.asyncio
    async def test_status_reports_enabled_and_not_armed(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        _as_admin(breakglass_app)
        response = await breakglass_client.get("/v1/admin/breakglass")
        assert response.status_code == 200
        assert response.json() == {"enabled": True, "armed": False}

    @pytest.mark.asyncio
    async def test_activate_requires_two_different_people(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        _as_admin(breakglass_app)  # session.subject == "admin-alice"
        headers = _csrf_headers_and_cookies(breakglass_client)
        code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "admin-alice", "totp_code": code},
            headers=headers,
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_activate_with_wrong_totp_is_403(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        _as_admin(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "admin-bob", "totp_code": "000000"},
            headers=headers,
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_activate_requires_csrf(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        _as_admin(breakglass_app)
        # NOTE (see TestSetEngineEnabled.test_missing_csrf_token_is_403): require_csrf
        # decides cookie- vs. bearer-authenticated purely from the SESSION cookie's
        # presence on the raw request, independent of the get_session_context
        # override above - set it here too so this reads as a BFF/browser request
        # that genuinely needs CSRF, not one silently exempted as bearer-like.
        breakglass_client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
        code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "admin-bob", "totp_code": code},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_activate_requires_admin_role(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        _as_submitter(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "admin-bob", "totp_code": code},
            headers=headers,
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_activate_succeeds_and_status_then_reports_armed(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        _as_admin(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        # SECURITY (BUG 2 fix): `second_activator` must now be a real, known
        # admin identity - this app builds its AuthRuntime from the REAL
        # policies/rbac/group_role_map.yaml (no auth_runtime override passed
        # to create_app in this fixture), so "skillscan-admins" (that file's
        # actual admin-mapped group name) is what the router's
        # known_admin_subjects allowlist actually contains - an arbitrary
        # name like the old "admin-bob" no longer passes.
        activate_response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "skillscan-admins", "totp_code": code},
            headers=headers,
        )
        assert activate_response.status_code == 200
        assert activate_response.json()["activated_by"] == ["admin-alice", "skillscan-admins"]

        status_response = await breakglass_client.get("/v1/admin/breakglass")
        assert status_response.json() == {"enabled": True, "armed": True}

    @pytest.mark.asyncio
    async def test_login_without_activation_fails(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        login_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        response = await breakglass_client.post(
            "/v1/admin/breakglass/login",
            json={"credential": _BREAKGLASS_CREDENTIAL, "totp_code": login_code},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_login_succeeds_after_activation_and_sets_cookies(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        _as_admin(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        activate_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "skillscan-admins", "totp_code": activate_code},
            headers=headers,
        )

        # SECURITY: login is deliberately NOT gated by get_session_context/
        # require_csrf - it authenticates purely via credential+TOTP, so no
        # `_as_admin`/session override is needed (or meaningful) here.
        login_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        login_response = await breakglass_client.post(
            "/v1/admin/breakglass/login",
            json={"credential": _BREAKGLASS_CREDENTIAL, "totp_code": login_code},
        )
        assert login_response.status_code == 200
        assert BREAKGLASS_SESSION_COOKIE_NAME in login_response.cookies
        assert CSRF_COOKIE_NAME in login_response.cookies

    @pytest.mark.asyncio
    async def test_authenticated_write_request_without_csrf_token_is_403(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        # SECURITY/BUG (caught by real browser testing, not by any test that
        # fakes the session via a dependency override - see require_csrf's
        # own module docstring for the full story): a REAL break-glass
        # session (established here via an actual login, not an override)
        # must still require CSRF on a subsequent state-changing request -
        # proves the fix holds through the full stack, not just at the
        # require_csrf unit level (test_dependencies.py covers that half).
        _as_admin(breakglass_app)
        activate_headers = _csrf_headers_and_cookies(breakglass_client)
        activate_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "skillscan-admins", "totp_code": activate_code},
            headers=activate_headers,
        )
        login_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        login_response = await breakglass_client.post(
            "/v1/admin/breakglass/login",
            json={"credential": _BREAKGLASS_CREDENTIAL, "totp_code": login_code},
        )
        assert login_response.status_code == 200

        # NOTE: no _as_admin override here and no CSRF header - this is now a
        # REAL break-glass session (cookies persisted on breakglass_client by
        # httpx across requests), not a faked one, and it deliberately omits
        # the CSRF header despite having a valid session + CSRF cookie.
        del breakglass_app.dependency_overrides[get_session_context]
        response = await breakglass_client.patch(
            f"/v1/admin/engines/bandit-{uuid.uuid4().hex[:8]}", json={"enabled": False}
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_login_with_wrong_credential_fails(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        _as_admin(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        activate_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "skillscan-admins", "totp_code": activate_code},
            headers=headers,
        )
        login_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        response = await breakglass_client.post(
            "/v1/admin/breakglass/login",
            json={"credential": "wrong-credential", "totp_code": login_code},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_second_login_after_use_fails(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        # SECURITY (INV-17 "用后即禁"): the arming is single-use - a second
        # login attempt must fail even though it's well within the TTL and
        # supplies fully correct credential+TOTP.
        _as_admin(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        activate_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "skillscan-admins", "totp_code": activate_code},
            headers=headers,
        )
        first_login_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        first = await breakglass_client.post(
            "/v1/admin/breakglass/login",
            json={"credential": _BREAKGLASS_CREDENTIAL, "totp_code": first_login_code},
        )
        assert first.status_code == 200

        second_login_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        second = await breakglass_client.post(
            "/v1/admin/breakglass/login",
            json={"credential": _BREAKGLASS_CREDENTIAL, "totp_code": second_login_code},
        )
        assert second.status_code == 401

    @pytest.mark.asyncio
    async def test_concurrent_logins_against_same_activation_only_one_succeeds(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        # SECURITY (BUG 1 regression, full HTTP stack): the same TOCTOU race
        # test_breakglass.py exercises at the pure-function level, proven
        # through the REAL router/HTTP layer this time - two concurrent login
        # POSTs against the same armed activation, both with fully correct
        # credential+TOTP, must not both return 200.
        _as_admin(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        activate_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "skillscan-admins", "totp_code": activate_code},
            headers=headers,
        )
        login_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()

        async def _attempt() -> httpx.Response:
            return await breakglass_client.post(
                "/v1/admin/breakglass/login",
                json={"credential": _BREAKGLASS_CREDENTIAL, "totp_code": login_code},
            )

        responses = await asyncio.gather(_attempt(), _attempt())
        status_codes = sorted(r.status_code for r in responses)
        assert status_codes == [200, 401]

    @pytest.mark.asyncio
    async def test_activate_rejects_unknown_second_activator(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        # SECURITY (BUG 2 regression, full HTTP stack): an arbitrary string
        # that is NOT a real, known admin identity must be rejected - the
        # core "four-eyes was not real" fix.
        _as_admin(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "totally-made-up-name", "totp_code": code},
            headers=headers,
        )
        assert response.status_code == 403
        assert "real, known admin" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_activate_rejects_second_activator_equal_to_caller(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        # SECURITY (BUG 2 regression, full HTTP stack): `second_activator`
        # naming the CALLER's own identity must be rejected even though
        # `session.subject` ("admin-alice") textually differs from the
        # existing "same string twice" check's field name - this is the
        # router-level explicit guard, independent of the pure function's
        # own activator_a == activator_b check.
        _as_admin(breakglass_app)  # session.subject == "admin-alice"
        headers = _csrf_headers_and_cookies(breakglass_client)
        code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "admin-alice", "totp_code": code},
            headers=headers,
        )
        assert response.status_code == 403
        assert "other than the caller" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_activate_while_already_armed_is_rejected_not_clobbered(
        self, breakglass_app: FastAPI, breakglass_client: httpx.AsyncClient
    ) -> None:
        # SECURITY (BUG 3 regression, full HTTP stack): re-activating on top
        # of an existing armed-and-unused activation must fail (403), not
        # silently succeed and clobber the pending one.
        _as_admin(breakglass_app)
        headers = _csrf_headers_and_cookies(breakglass_client)
        first_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        first_response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "skillscan-admins", "totp_code": first_code},
            headers=headers,
        )
        assert first_response.status_code == 200

        second_code = pyotp.TOTP(_BREAKGLASS_TOTP_SECRET).now()
        second_response = await breakglass_client.post(
            "/v1/admin/breakglass/activate",
            json={"second_activator": "skillscan-admins", "totp_code": second_code},
            headers=headers,
        )
        assert second_response.status_code == 403
        assert "already armed" in second_response.json()["detail"]

        status_response = await breakglass_client.get("/v1/admin/breakglass")
        assert status_response.json() == {"enabled": True, "armed": True}
