"""Marketplace pull-API router tests (里程碑 B' spec §4/§6/§7).

Real local MySQL/Redis via a real `ScanRuntime`; only authentication is faked
(FastAPI dependency override), matching test_router.py's established pattern -
there is no real IdP in this environment, but everything downstream of the
session context is the production code path.

What is worth testing HERE rather than in test_marketplace_views.py: the
projection itself is a pure function already covered without infrastructure.
This file covers what only the wired-up router can be wrong about - the
authorization matrix, the 404-not-403 shape, the tier actually persisted onto
the scan, the audit row, the rate limit, and the guarantee that what crosses
the HTTP boundary is the projection and nothing else.
"""

from __future__ import annotations

import datetime
import io
import json
import logging
import tarfile
import uuid
from collections.abc import AsyncIterator
from typing import cast

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from common.blobstore import LocalFilesystemBlobStore
from fastapi import FastAPI
from skillscan_core import GatePolicy, Severity, StaticKeywordEngine, TrustTier, Verdict
from sqlalchemy import select, update
from sqlalchemy.exc import OperationalError

from monolith.main import create_app
from monolith.modules.gate.models import VerdictRow
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.auth.dependencies import get_session_context
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.inventory.models import SkillRow
from monolith.modules.marketplace_api import views
from monolith.modules.marketplace_api.models import MarketplaceFetchLogRow
from monolith.modules.orchestration.models import ScanEngineHealthRow, ScanJob, ScanResultRow
from monolith.tests.conftest import SessionmakerFixture

_ENGINE = StaticKeywordEngine()

_READ_ONLY = frozenset({"scan:read"})
_SUBMIT_ONLY = frozenset({"scan:submit"})
_BOTH = frozenset({"scan:submit", "scan:read"})


def _account(prefix: str) -> str:
    """A fresh service-account name per test.

    The rate-limit counter is keyed on the service account with a 60-second
    window in a SHARED Redis - a fixed name would leak one test's consumed
    budget into the next one's.
    """
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _market_session(
    subject: str, scopes: frozenset[str], *, tier: TrustTier = TrustTier.PUBLIC
) -> SessionContext:
    """An M2M session as `m2m.authenticate_client_credentials` would build it:
    the `submitter` role, per-service-account scopes, per-service-account tier,
    and `is_machine=True` - which is not decoration here. `SessionContext` has
    no default for it precisely so this fixture cannot quietly fake a HUMAN
    session while claiming to test the machine path (see spec §6.1 / C1)."""
    return SessionContext(
        subject=subject,
        roles=frozenset({"submitter"}),
        scopes=scopes,
        tier=tier,
        token_exp=9999999999.0,
        is_machine=True,
    )


def _make_tar_bytes(content: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name="skill.py")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _unique_package() -> bytes:
    """Unique content per submission, for TEST ISOLATION only.

    submit_scan is single-flight on content+toolchain, so shared bytes would
    collapse unrelated tests onto one scan_job (and one another's seeded
    results/verdicts). It is no longer a workaround for a broken authorization
    model: sharing the scan_job used to mean the second submitter was refused
    it - see TestDeduplicatedSubmissionsStayReadableByEverySubmitter, which
    deliberately submits the SAME bytes twice to exercise exactly that path.
    """
    return _make_tar_bytes(f"print({uuid.uuid4().hex!r})\n".encode())


@pytest_asyncio.fixture(autouse=True)
async def _clean_marketplace_rate_redis_state() -> AsyncIterator[None]:
    """Same rationale as test_marketplace_ratelimit.py's identical fixture -
    the rate-limit keys live in the shared Redis DB with no flush between
    tests."""
    client: aioredis.Redis = aioredis.Redis.from_url("redis://localhost:6379/0")
    try:

        async def _clear() -> None:
            keys = [k async for k in client.scan_iter(match="skillscan:mkt:rate:*")]
            if keys:
                await client.delete(*keys)

        await _clear()
        yield
        await _clear()
    finally:
        await client.aclose()


def _build_app(
    *,
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    inventory_sessionmaker: SessionmakerFixture,
    marketplace_sessionmaker: SessionmakerFixture | None,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
    rate_limit_per_min: int,
    reporting_sessionmaker: SessionmakerFixture | None = None,
) -> FastAPI:
    scan_runtime = ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=orchestration_sessionmaker,
        gate_session_factory=gate_sessionmaker,
        # REQUIRED as of 2026-07-30: both marketplace endpoints touch inventory
        # now (submit registers the skill and its version; the poll resolves
        # skill_id -> latest version and reads `skill.owner` to authorize). An
        # unwired factory makes them 503, which would mask every assertion here.
        inventory_session_factory=inventory_sessionmaker,
        policy=GatePolicy(
            version=f"test-market-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
        marketplace_session_factory=marketplace_sessionmaker,
        marketplace_rate_limit_per_min=rate_limit_per_min,
        # Wired so `GET /v1/scans/{id}/sarif` is a real endpoint here rather
        # than the explicit 500 an unconfigured reporting module fails closed
        # with - the C1/C2 tests assert authorization on that route, and a 500
        # would mask both the 403 and the 200 they are actually checking.
        reporting_session_factory=reporting_sessionmaker,
    )
    return create_app(scan_runtime=scan_runtime)


@pytest.fixture
def app(
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    inventory_sessionmaker: SessionmakerFixture,
    marketplace_sessionmaker: SessionmakerFixture,
    reporting_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
) -> FastAPI:
    return _build_app(
        orchestration_sessionmaker=orchestration_sessionmaker,
        gate_sessionmaker=gate_sessionmaker,
        inventory_sessionmaker=inventory_sessionmaker,
        marketplace_sessionmaker=marketplace_sessionmaker,
        reporting_sessionmaker=reporting_sessionmaker,
        redis_client=redis_client,
        blobstore=blobstore,
        rate_limit_per_min=120,
    )


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


def _skill_id(prefix: str) -> str:
    """A fresh skill_id per submission. Registration is genesis-owned, so a reused
    id would be owned by the FIRST test that used it and 403 every later one."""
    return f"{prefix}/{uuid.uuid4().hex[:10]}"


async def _submit(
    client_instance: httpx.AsyncClient,
    *,
    skill_id: str | None = None,
    package: bytes | None = None,
) -> tuple[str, str]:
    """Submit through the marketplace surface. Returns `(skill_id, scan_id)`.

    `skill_id` is REQUIRED by the endpoint as of 2026-07-30 - the poll is keyed on
    it, so a submission without one would be unpollable. The scan_id still comes
    back in the 202 and is still what the seeding helpers below need, but it is no
    longer part of any response the marketplace reads.
    """
    resolved = skill_id or _skill_id("mkt-skill")
    response = await client_instance.post(
        "/v1/market/scans",
        files={"package": ("skill.tar", package or _unique_package(), "application/x-tar")},
        data={"skill_id": resolved},
    )
    assert response.status_code == 202, response.text
    scan_id: str = response.json()["scan_id"]
    return resolved, scan_id


async def _poll(client_instance: httpx.AsyncClient, skill_id: str) -> httpx.Response:
    return await client_instance.get(f"/v1/market/skills/{skill_id}")


async def _scrape_cross_scope(client_instance: httpx.AsyncClient) -> float:
    """Task 13: read `cross_scope_access_attempts_total` off a REAL `/metrics`
    scrape of this same app, never off the counter object. The defect class
    being guarded against is an increment on a line that does not execute, and
    only the exposition path proves the value a scraper would actually see."""
    response = await client_instance.get("/metrics")
    assert response.status_code == 200
    for line in response.text.splitlines():
        if line.startswith("skillscan_cross_scope_access_attempts_total "):
            return float(line.rsplit(" ", 1)[1])
    raise AssertionError("cross_scope_access_attempts_total missing from /metrics output")


async def _force_state(
    orchestration_sessionmaker: SessionmakerFixture, scan_id: str, state: str
) -> None:
    """Drive the job to a terminal state without running a worker - this file
    tests the router, not the pipeline (test_orchestration_pipeline.py owns
    that)."""
    async with orchestration_sessionmaker() as session, session.begin():
        await session.execute(update(ScanJob).where(ScanJob.scan_id == scan_id).values(state=state))


def _finding_with_snippet_hash() -> dict[str, object]:
    return {
        "rule_id": "static.eval_call",
        "test_item_id": "CODE-02",
        "category": "code",
        "title": "eval() call detected",
        "severity": 3,
        "confidence": 0.5,
        "source_engine": "static-keyword",
        "source_capability": "static",
        "trifecta_signals": [],
        "file_path": "scripts/helper.py",
        "start_line": 25,
        "evidence_redacted": "eval() call (redacted)",
        # SECURITY: present internally, must never reach the response (INV-9).
        "snippet_hash": "a" * 64,
    }


async def _seed_result(
    orchestration_sessionmaker: SessionmakerFixture, scan_id: str, *, findings_total: int = 1
) -> None:
    async with orchestration_sessionmaker() as session, session.begin():
        session.add(
            ScanResultRow(
                scan_id=scan_id,
                content_hash="c" * 64,
                severity=3,
                confidence_at_max=0.5,
                trifecta_present=False,
                findings_capped=False,
                findings_total=findings_total,
                required_ok=True,
                findings=[_finding_with_snippet_hash()],
                provenance=[["static-keyword", "static"]],
                hard_gate_hits=[],
            )
        )


def _poll_body_without_findings(body: dict[str, object]) -> str:
    """The response as text, minus `findings` - whose `source_engine` field is a
    whitelisted engine name and would make any "no engine name leaked" assertion
    trivially false for the wrong reason."""
    return json.dumps({k: v for k, v in body.items() if k != "findings"}, default=str)


async def _seed_engine_health(
    orchestration_sessionmaker: SessionmakerFixture,
    scan_id: str,
    rows: list[tuple[str, str, str | None]],
) -> None:
    """Real `scan_engine_health` rows - the table the coverage read joins.

    Rows are `(engine_name, report_state, engine_status)`. Written through the
    ORM rather than a fixture-level shortcut because the model enforces the
    acceptance-criterion-8 invariant with a DB CHECK
    (`engine_status IS NOT NULL` iff `report_state = 'reported'`): a test that
    seeded a state pair the schema forbids would be exercising a shape
    production can never produce.
    """
    async with orchestration_sessionmaker() as session, session.begin():
        for engine_name, report_state, engine_status in rows:
            session.add(
                ScanEngineHealthRow(
                    scan_id=scan_id,
                    engine_name=engine_name,
                    report_state=report_state,
                    engine_status=engine_status,
                    analyze_duration_ms=0 if report_state == "reported" else None,
                    finding_count=0 if report_state == "reported" else None,
                    error=None,
                    recorded_at=datetime.datetime(2026, 7, 30, 12, 0, 0),
                )
            )


# A fixed, microsecond-free decision time. Fixed so a test can assert the
# EXACT value that crosses the HTTP boundary rather than "not null"; whole
# seconds because `verdict.issued_at` is a MySQL DATETIME with no fractional
# part, which would round a `now()` timestamp out from under such an assertion.
_SEEDED_ISSUED_AT = datetime.datetime(2026, 1, 2, 3, 4, 5)
_SEEDED_POLICY_VERSION = "test-v1"


async def _seed_verdict(
    gate_sessionmaker: SessionmakerFixture,
    scan_id: str,
    *,
    verdict: str = "REVIEW",
    issued_at: datetime.datetime = _SEEDED_ISSUED_AT,
    policy_version: str = _SEEDED_POLICY_VERSION,
    fail_closed: bool = False,
) -> None:
    async with gate_sessionmaker() as session, session.begin():
        session.add(
            VerdictRow(
                scan_id=scan_id,
                content_hash="c" * 64,
                verdict=verdict,
                policy_version=policy_version,
                jti=str(uuid.uuid4()),
                jws_signature="eyJhbGciOiJSUzI1NiJ9.stub.sig",
                effective_severity=3,
                score=62,
                reasons=[],
                # 2026-07-30: passed EXPLICITLY, never left to the ORM default.
                # A seed that always wrote False could not tell the difference
                # between the old structural inference and the new column.
                fail_closed=fail_closed,
                issued_at=issued_at,
            )
        )


class TestAuthorizationMatrix:
    """spec §6.1/§6.2 - scope AND ownership, and the deliberate choice of which
    status code each failure gets.

    2026-07-30: "ownership" is `skill.owner` now, not `scan_submitter` membership.
    The status codes are unchanged, deliberately - see this file's counterpart
    reasoning in `marketplace_api.router`'s rule 3.
    """

    @pytest.mark.asyncio
    async def test_own_skill_with_read_scope_is_200(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        subject = _account("mkt-own-read")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, _scan_id = await _submit(client)

        response = await _poll(client, skill_id)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["skill_id"] == skill_id
        # The submission registered `skill.owner = subject`, which is the ONLY
        # reason this read is allowed - assert the answer names the version too,
        # so a 200 built from nothing cannot pass.
        assert body["content_hash"]

    @pytest.mark.asyncio
    async def test_another_accounts_skill_is_404_not_403(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # SECURITY (spec §6.2): a 403 would confirm the skill_id exists, which is
        # all an enumerator needs. Indistinguishable from "no such skill".
        owner = _account("mkt-owner")
        app.dependency_overrides[get_session_context] = lambda: _market_session(owner, _BOTH)
        skill_id, _scan_id = await _submit(client)

        intruder = _account("mkt-intruder")
        app.dependency_overrides[get_session_context] = lambda: _market_session(intruder, _BOTH)
        response = await _poll(client, skill_id)
        assert response.status_code == 404

        unknown = await _poll(client, _skill_id("mkt-nonexistent"))
        assert unknown.status_code == 404
        # The two cases must not be distinguishable by body either.
        assert response.json() == unknown.json()

    @pytest.mark.asyncio
    async def test_an_unowned_skill_is_404_for_everyone(
        self, app: FastAPI, client: httpx.AsyncClient, inventory_sessionmaker: SessionmakerFixture
    ) -> None:
        """SECURITY: `skill.owner IS NULL` fails closed on the READ side too.

        This is not hypothetical scale. The deployed database holds hundreds of
        bulk-imported skills registered before the owner column existed, all NULL,
        and a permissive read default would hand every one of them to any service
        account that can guess a name. The write side already fails closed here
        (`authorize_skill_write`); this asserts the read side does not diverge.

        The NULL is written out-of-band rather than produced by a submission,
        because no submission path can produce it any more - which is exactly why
        it has to be constructed to be tested at all.
        """
        subject = _account("mkt-unowned")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, _scan_id = await _submit(client)
        assert (await _poll(client, skill_id)).status_code == 200

        async with inventory_sessionmaker() as session, session.begin():
            await session.execute(
                update(SkillRow).where(SkillRow.skill_id == skill_id).values(owner=None)
            )

        # Same identity, same skill, same content - only the owner record changed.
        assert (await _poll(client, skill_id)).status_code == 404

    @pytest.mark.asyncio
    async def test_a_cross_account_read_moves_the_cross_scope_metric(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # Task 13 (2026-07-29): `cross_scope_access_attempts_total`, preserved
        # verbatim through the 2026-07-30 re-key. This branch is the strongest form
        # of the signal in the codebase - there is no reviewer escape hatch on this
        # surface, so reaching it always means one service account named another's
        # object. Scraped through the real `/metrics` endpoint, because an `.inc()`
        # on a line that never runs reads identically to a working one.
        owner = _account("mkt-metric-owner")
        app.dependency_overrides[get_session_context] = lambda: _market_session(owner, _BOTH)
        skill_id, _scan_id = await _submit(client)
        before = await _scrape_cross_scope(client)

        intruder = _account("mkt-metric-intruder")
        app.dependency_overrides[get_session_context] = lambda: _market_session(intruder, _BOTH)
        assert (await _poll(client, skill_id)).status_code == 404

        assert await _scrape_cross_scope(client) == before + 1.0

    @pytest.mark.asyncio
    async def test_an_unknown_skill_id_does_NOT_move_the_cross_scope_metric(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # §6.2 makes these two 404s deliberately indistinguishable to the
        # caller; that is exactly why the distinction has to survive here.
        subject = _account("mkt-metric-unknown")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        before = await _scrape_cross_scope(client)

        assert (await _poll(client, _skill_id("mkt-never-registered"))).status_code == 404

        assert await _scrape_cross_scope(client) == before

    @pytest.mark.asyncio
    async def test_a_cross_account_SUBMIT_also_moves_the_cross_scope_metric(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # The write side of the same counter, new on this surface as of 2026-07-30:
        # before skill_id existed here there was no cross-scope write to attempt.
        # 403 rather than the read path's 404 - the console already accepts that a
        # write refusal names the skill_id as taken.
        owner = _account("mkt-write-owner")
        app.dependency_overrides[get_session_context] = lambda: _market_session(owner, _BOTH)
        skill_id, _scan_id = await _submit(client)
        before = await _scrape_cross_scope(client)

        intruder = _account("mkt-write-intruder")
        app.dependency_overrides[get_session_context] = lambda: _market_session(intruder, _BOTH)
        response = await client.post(
            "/v1/market/scans",
            files={"package": ("skill.tar", _unique_package(), "application/x-tar")},
            data={"skill_id": skill_id},
        )
        assert response.status_code == 403, response.text
        # SECURITY: the refusal must not name the owner - that would turn every
        # submission attempt into an identity-harvesting probe.
        assert owner not in response.text

        assert await _scrape_cross_scope(client) == before + 1.0

    @pytest.mark.asyncio
    async def test_a_missing_scope_403_does_NOT_move_the_cross_scope_metric(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # A missing `scan:read` grant is a misconfigured client, and it is
        # checked BEFORE ownership - the ownership branch is never reached, so
        # nothing about which object was named was ever established.
        owner = _account("mkt-metric-owner3")
        app.dependency_overrides[get_session_context] = lambda: _market_session(owner, _BOTH)
        skill_id, _scan_id = await _submit(client)
        before = await _scrape_cross_scope(client)

        stranger = _account("mkt-metric-stranger")
        app.dependency_overrides[get_session_context] = lambda: _market_session(
            stranger, _SUBMIT_ONLY
        )
        assert (await _poll(client, skill_id)).status_code == 403

        assert await _scrape_cross_scope(client) == before

    @pytest.mark.asyncio
    async def test_own_skill_without_read_scope_is_403(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # The compatibility guarantee of spec §6.1: an existing M2M identity
        # keeps the default `scan:submit`-only grant and gains NO read access
        # from this milestone - not even to its own skills.
        subject = _account("mkt-submit-only")
        app.dependency_overrides[get_session_context] = lambda: _market_session(
            subject, _SUBMIT_ONLY
        )
        skill_id, _scan_id = await _submit(client)

        assert (await _poll(client, skill_id)).status_code == 403

    @pytest.mark.asyncio
    async def test_another_accounts_skill_without_read_scope_is_403(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # Scope is checked before ownership, so the 403 here reveals only the
        # caller's own configuration - still nothing about the skill.
        owner = _account("mkt-owner2")
        app.dependency_overrides[get_session_context] = lambda: _market_session(owner, _BOTH)
        skill_id, _scan_id = await _submit(client)

        stranger = _account("mkt-stranger")
        app.dependency_overrides[get_session_context] = lambda: _market_session(
            stranger, _SUBMIT_ONLY
        )
        # Someone else's real skill and a skill_id that does not exist both stop
        # at the scope check - the ownership lookup is never even reached.
        assert (await _poll(client, skill_id)).status_code == 403
        assert (await _poll(client, _skill_id("mkt-absent"))).status_code == 403

    @pytest.mark.asyncio
    async def test_submit_without_submit_scope_is_403(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        subject = _account("mkt-read-only")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _READ_ONLY)
        response = await client.post(
            "/v1/market/scans",
            files={"package": ("skill.tar", _unique_package(), "application/x-tar")},
            data={"skill_id": _skill_id("mkt-noscope")},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_submit_without_a_skill_id_is_422(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # REQUIRED, and refused by FastAPI's own validation before the handler
        # runs. A submission with no skill_id could never be polled on the only
        # surface this contract offers, so accepting it would be a 202 whose
        # result can never be read.
        subject = _account("mkt-no-skill-id")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        response = await client.post(
            "/v1/market/scans",
            files={"package": ("skill.tar", _unique_package(), "application/x-tar")},
        )
        assert response.status_code == 422, response.text

    @pytest.mark.asyncio
    async def test_submit_with_a_blank_skill_id_is_400(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # Present-but-empty reaches the handler, so it gets the handler's own 400
        # rather than being registered as a skill literally named "".
        subject = _account("mkt-blank-skill-id")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        response = await client.post(
            "/v1/market/scans",
            files={"package": ("skill.tar", _unique_package(), "application/x-tar")},
            data={"skill_id": "   "},
        )
        assert response.status_code == 400, response.text
        assert "skill_id" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_unauthenticated_request_is_401(self, client: httpx.AsyncClient) -> None:
        # No dependency override - the real get_session_context fail-closes.
        response = await _poll(client, _skill_id("mkt-unauth"))
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_a_slash_bearing_skill_id_is_pollable(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # Skill ids in this ecosystem are commonly `@handle/slug` (the skillhub and
        # clawhub canonical form, and the only form that disambiguates ~97k skills).
        # A plain `{skill_id}` path parameter would 404 on the slash and make a
        # whole class of skill silently unpollable, which is why the route declares
        # `{skill_id:path}`. `_skill_id` already produces a slash, so this asserts
        # the shape explicitly rather than relying on that.
        #
        # The literal is UNIQUE-SUFFIXED for the reason `_skill_id`'s own
        # docstring gives: registration is genesis-owned, so a fixed id belongs
        # to the first run that used it and 403s every later one. This test held
        # a bare "@acme/data-helper" and therefore passed exactly ONCE per
        # database - green on a fresh CI container, red on the second run
        # against the VM's persistent test database (measured 2026-07-30).
        subject = _account("mkt-slashy")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, _scan_id = await _submit(
            client, skill_id=f"@acme/data-helper-{uuid.uuid4().hex[:10]}"
        )
        assert skill_id.count("/") == 1, "the canonical @handle/slug shape this test is about"

        response = await _poll(client, skill_id)
        assert response.status_code == 200, response.text
        assert response.json()["skill_id"] == skill_id


class TestTheProjectionIsTheOnlyDoor:
    """SECURITY (milestone B' C1): the anti-corruption boundary must not be
    walkable-around with the marketplace's own credentials.

    The console's `/v1/scans/{scan_id}` returns `result_row.findings` verbatim -
    `serialize_finding`'s raw blob, `snippet_hash` included - plus `provenance`,
    `required_ok` and `hard_gate_hits`: precisely the four things spec §5.3
    withholds. `require_role()` with no arguments accepted any authenticated
    session, and an M2M identity holds `roles={"submitter"}` and IS the
    submitter of the scans it submitted, so it passed the role check and the
    ownership check alike. Zero extra permissions, same bearer token.

    Every test here asserts BOTH halves in one place. Asserting only the 403
    would be satisfied by a marketplace identity that simply cannot reach its
    own data at all - the claim being locked down is narrower and stronger:
    the projection is the route it MUST take, not data it may not have.
    """

    @pytest.mark.asyncio
    async def test_the_console_scan_endpoint_is_403_for_its_own_scan(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        subject = _account("mkt-console-probe")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, scan_id = await _submit(client)

        console = await client.get(f"/v1/scans/{scan_id}")
        assert console.status_code == 403, console.text
        market = await _poll(client, skill_id)
        assert market.status_code == 200, market.text
        assert market.json()["skill_id"] == skill_id

    @pytest.mark.asyncio
    async def test_no_internal_field_reaches_a_machine_through_the_console(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        # The seeded result genuinely carries every withheld field (asserted
        # against the database below), so this proves they are unreachable
        # rather than merely absent from the fixture.
        subject = _account("mkt-console-leak")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, scan_id = await _submit(client)
        await _seed_result(orchestration_sessionmaker, scan_id)
        await _seed_verdict(gate_sessionmaker, scan_id)
        await _force_state(orchestration_sessionmaker, scan_id, "decided")

        async with orchestration_sessionmaker() as session:
            stored = (
                await session.execute(select(ScanResultRow).where(ScanResultRow.scan_id == scan_id))
            ).scalar_one()
        assert stored.findings[0]["snippet_hash"]
        assert stored.provenance and stored.required_ok is True

        console = await client.get(f"/v1/scans/{scan_id}")
        assert console.status_code == 403
        # `hard_gate_hits` left this list on 2026-07-30 - it is now a deliberate
        # part of the binary contract (an "unsafe" answer has to be able to say
        # that an UNWAIVABLE rule fired), so it is no longer a withheld field and
        # asserting its absence would now be asserting the wrong thing.
        # `snippet_hash`, `provenance` and `required_ok` were re-examined at the
        # same time and stay withheld.
        for withheld in ("snippet_hash", "provenance", "required_ok"):
            assert withheld not in console.text

        market = await _poll(client, skill_id)
        assert market.status_code == 200
        assert set(market.json()) == views.EXTERNAL_TOP_LEVEL_FIELDS

    @pytest.mark.asyncio
    async def test_the_sarif_export_is_closed_to_machines_too(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # `GET /v1/scans/{id}/sarif` carries the same internal finding shape and
        # had the same `require_role()` gate - a fix that closed only the JSON
        # endpoint would leave the identical hole one path segment away.
        subject = _account("mkt-console-sarif")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, scan_id = await _submit(client)

        assert (await client.get(f"/v1/scans/{scan_id}/sarif")).status_code == 403
        assert (await _poll(client, skill_id)).status_code == 200

    @pytest.mark.asyncio
    async def test_the_console_scan_list_is_closed_to_machines(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # Enumeration, not just per-scan reads: `GET /v1/scans` filters to the
        # caller's own submissions, which for a marketplace identity is exactly
        # the set it must read through the projection instead.
        subject = _account("mkt-console-list")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        await _submit(client)

        assert (await client.get("/v1/scans")).status_code == 403
        assert (await client.get("/v1/me")).status_code == 403

    @pytest.mark.asyncio
    async def test_a_human_console_session_is_unaffected(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # The control: the console endpoints still work, so the tests above are
        # measuring the identity check and not a broken route.
        app.dependency_overrides[get_session_context] = lambda: SessionContext(
            subject=_account("console-human"),
            roles=frozenset({"submitter"}),
            scopes=frozenset(),
            tier=TrustTier.INTERNAL,
            token_exp=9999999999.0,
            is_machine=False,
        )
        response = await client.get("/v1/me")
        assert response.status_code == 200


class TestTrustTierIsServerDecided:
    """spec §4.1 - the caller may not choose the strictness it is judged by."""

    @pytest.mark.asyncio
    async def test_a_caller_supplied_trust_tier_is_400_not_ignored(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        subject = _account("mkt-tier-form")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        response = await client.post(
            "/v1/market/scans",
            files={"package": ("skill.tar", _unique_package(), "application/x-tar")},
            data={"skill_id": _skill_id("mkt-tier-form"), "trust_tier": "internal"},
        )
        # SECURITY: 400, never a silent drop - a caller whose setting is
        # discarded without a word believes it took effect.
        assert response.status_code == 400
        assert "trust_tier" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_a_trust_tier_query_parameter_is_also_400(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        subject = _account("mkt-tier-query")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        response = await client.post(
            "/v1/market/scans?trust_tier=internal",
            files={"package": ("skill.tar", _unique_package(), "application/x-tar")},
            data={"skill_id": _skill_id("mkt-tier-query")},
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_the_persisted_tier_comes_from_the_session_grant(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        # PARTNER is deliberately neither the process default
        # (`runtime.default_trust_tier` = INTERNAL) nor the default M2M grant
        # (PUBLIC), so this can only pass by actually reading `session.tier`.
        subject = _account("mkt-tier-grant")
        app.dependency_overrides[get_session_context] = lambda: _market_session(
            subject, _BOTH, tier=TrustTier.PARTNER
        )
        _skill, scan_id = await _submit(client)

        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        assert job.trust_tier == TrustTier.PARTNER.value


def _console_session(subject: str) -> SessionContext:
    """A human console session - `is_machine=False`, so `require_human_role`
    lets it through (C1) and it can drive `POST /v1/scans`."""
    return SessionContext(
        subject=subject,
        roles=frozenset({"submitter"}),
        scopes=frozenset(),
        tier=TrustTier.INTERNAL,
        token_exp=9999999999.0,
        is_machine=False,
    )


async def _submit_console(client_instance: httpx.AsyncClient, package: bytes) -> str:
    response = await client_instance.post(
        "/v1/scans", files={"package": ("skill.tar", package, "application/x-tar")}
    )
    assert response.status_code == 202, response.text
    scan_id: str = response.json()["scan_id"]
    return scan_id


async def _submit_market(
    client_instance: httpx.AsyncClient, package: bytes, *, skill_id: str | None = None
) -> tuple[str, str]:
    """Marketplace submit with explicit bytes. Returns `(skill_id, scan_id)`."""
    return await _submit(client_instance, skill_id=skill_id, package=package)


class TestDeduplicatedSubmissionsStayReadableByEverySubmitter:
    """SECURITY (milestone B' review, C2): single-flight dedup must not hand a
    caller an answer it can never read.

    `submit_scan` keys on `content_hash + toolchain_digest`, so byte-identical
    content submitted twice collapses onto ONE scan_job - which keeps the FIRST
    submitter in `scan_job.submitter`. "The console and the marketplace scan the
    same skills" is this product's normal case.

    2026-07-30: the marketplace side of this is now structurally immune rather
    than fixed-by-association-table. Its poll asks about a SKILL it owns, and
    ownership is unaffected by which submission created the underlying scan_job -
    so the C2 failure mode (a 404 on a scan_id we had just issued to this very
    caller) cannot arise on that surface at all. The console side still depends on
    `scan_submitter` membership and is still tested here: a change that only
    reasoned about the marketplace would produce the mirror-image bug there.
    """

    @pytest.mark.asyncio
    async def test_console_first_then_marketplace_can_still_poll(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        package = _unique_package()

        # Anonymous console submission (no skill_id), which is what leaves these
        # bytes free for the marketplace to register under its own skill.
        app.dependency_overrides[get_session_context] = lambda: _console_session("alice")
        console_scan_id = await _submit_console(client, package)

        market_account = _account("mkt-dedup-second")
        app.dependency_overrides[get_session_context] = lambda: _market_session(
            market_account, _BOTH
        )
        skill_id, market_scan_id = await _submit_market(client, package)

        # The premise: dedup really did collapse the two submissions.
        assert market_scan_id == console_scan_id

        response = await _poll(client, skill_id)
        assert response.status_code == 200, response.text
        assert response.json()["skill_id"] == skill_id

    @pytest.mark.asyncio
    async def test_marketplace_first_then_the_console_submitter_can_still_read_it(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # The mirror direction, and the half that still rests on `scan_submitter`:
        # the console user who submitted the very same bytes must still be able to
        # open, list and export that scan.
        package = _unique_package()

        market_account = _account("mkt-dedup-first")
        app.dependency_overrides[get_session_context] = lambda: _market_session(
            market_account, _BOTH
        )
        _skill_id_unused, market_scan_id = await _submit_market(client, package)

        app.dependency_overrides[get_session_context] = lambda: _console_session("bob")
        console_scan_id = await _submit_console(client, package)
        assert console_scan_id == market_scan_id

        detail = await client.get(f"/v1/scans/{console_scan_id}")
        assert detail.status_code == 200, detail.text
        assert detail.json()["scan_id"] == console_scan_id

        # ...and it must be REACHABLE, not merely openable by an id the user
        # would have no way to find.
        listed = await client.get("/v1/scans")
        assert listed.status_code == 200
        assert console_scan_id in {item["scan_id"] for item in listed.json()["items"]}

        sarif = await client.get(f"/v1/scans/{console_scan_id}/sarif")
        assert sarif.status_code == 200

    @pytest.mark.asyncio
    async def test_a_console_registered_skill_refuses_a_marketplace_re_registration(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        """The new interaction the 2026-07-30 re-key creates, asserted rather than
        discovered in production.

        Now that the marketplace registers skills, the console and the marketplace
        can both claim the same BYTES under different skill_ids - and
        `skill_version.content_hash` is a primary key, so exactly one of them may.
        The refusal is a 409 naming the owning skill (not a 403: nothing here is
        about identity, and it would be true whoever asked), and it must land
        BEFORE the scan is committed rather than after.
        """
        package = _unique_package()
        console_skill = _skill_id("console-owned")

        app.dependency_overrides[get_session_context] = lambda: _console_session("heidi")
        console = await client.post(
            "/v1/scans",
            files={"package": ("skill.tar", package, "application/x-tar")},
            data={"skill_id": console_skill},
        )
        assert console.status_code == 202, console.text

        market_account = _account("mkt-dedup-crossclaim")
        app.dependency_overrides[get_session_context] = lambda: _market_session(
            market_account, _BOTH
        )
        response = await client.post(
            "/v1/market/scans",
            files={"package": ("skill.tar", package, "application/x-tar")},
            data={"skill_id": _skill_id("mkt-wants-same-bytes")},
        )
        assert response.status_code == 409, response.text
        assert console_skill in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_a_subject_that_does_not_own_the_skill_is_still_404(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # Access follows ownership and nothing else - reading is never what grants
        # it, and neither is having submitted the same bytes.
        package = _unique_package()
        owner = _account("mkt-dedup-owner")
        app.dependency_overrides[get_session_context] = lambda: _market_session(owner, _BOTH)
        skill_id, _scan_id = await _submit_market(client, package)

        # A second account that submits the IDENTICAL bytes (and so becomes a
        # `scan_submitter` of the very same scan_job via dedup) still may not read
        # the first account's skill. That association is exactly what used to grant
        # access, so this is the assertion that the key really moved.
        stranger = _account("mkt-dedup-stranger")
        app.dependency_overrides[get_session_context] = lambda: _market_session(stranger, _BOTH)
        assert (await _poll(client, skill_id)).status_code == 404

        app.dependency_overrides[get_session_context] = lambda: _console_session("dave")
        listed = await client.get("/v1/scans")
        assert listed.status_code == 200

    @pytest.mark.asyncio
    async def test_judged_at_tier_reports_the_first_submitters_tier_not_the_pollers(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # SECURITY (C2): the verdict was adjudicated once, at the tier of the
        # submission that created the scan_job. It is NOT re-decided for a later
        # submitter, so it must not be re-described as if it had been. The
        # console's default here is INTERNAL (BLOCK at CRITICAL); the polling
        # marketplace account is PUBLIC (BLOCK at HIGH) - a real difference in
        # threshold that the caller would otherwise assume in its own favour.
        package = _unique_package()
        app.dependency_overrides[get_session_context] = lambda: _console_session("erin")
        scan_id = await _submit_console(client, package)

        market_account = _account("mkt-dedup-tier")
        app.dependency_overrides[get_session_context] = lambda: _market_session(
            market_account, _BOTH, tier=TrustTier.PUBLIC
        )
        skill_id, market_scan_id = await _submit_market(client, package)
        assert market_scan_id == scan_id

        body = (await _poll(client, skill_id)).json()
        assert body["judged_at_tier"] == TrustTier.INTERNAL.value
        assert body["judged_at_tier"] != TrustTier.PUBLIC.value


@pytest.fixture
def tiered_app(
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    inventory_sessionmaker: SessionmakerFixture,
    marketplace_sessionmaker: SessionmakerFixture,
    reporting_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
) -> FastAPI:
    """The `app` fixture above ships a policy with NO `tier_block_overrides`,
    so every tier resolves to the same CRITICAL threshold and `tier_direction`
    could only ever answer "equivalent" - a test written against it would pass
    no matter what the implementation did. This one mirrors the REAL
    `policies/gate/v1.yaml`: `public` blocks at HIGH, everything else at
    CRITICAL. (Same trap, same fix, as test_trust_tier_plumbing.py's `_policy`.)
    """
    scan_runtime = ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=orchestration_sessionmaker,
        gate_session_factory=gate_sessionmaker,
        inventory_session_factory=inventory_sessionmaker,
        policy=GatePolicy(
            version=f"test-market-tiered-{uuid.uuid4().hex[:8]}",
            required_engines=frozenset({_ENGINE.metadata.name}),
            hard_gate_rules=frozenset(),
            tier_block_overrides=((TrustTier.PUBLIC, Severity.HIGH),),
            fail_closed_verdict=Verdict.BLOCK,
        ),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
        marketplace_session_factory=marketplace_sessionmaker,
        marketplace_rate_limit_per_min=120,
        reporting_session_factory=reporting_sessionmaker,
    )
    return create_app(scan_runtime=scan_runtime)


@pytest_asyncio.fixture
async def tiered_client(tiered_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=tiered_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


class TestTheMarketplaceLearnsItsVerdictWasJudgedAtAnotherTier:
    """SECURITY (里程碑 F Task 18): `judged_at_tier` alone reported a tier and
    left the caller to assume it was the one they asked for.

    On THIS surface it usually is not. A marketplace service account defaults to
    PUBLIC, the STRICTEST tier (`policies/gate/v1.yaml` blocks it at HIGH; every
    other tier only at CRITICAL), while the console commonly submits at
    `internal`. Single-flight dedup then hands a marketplace poll a verdict
    adjudicated under a MORE PERMISSIVE ruleset than it asked for - a HIGH
    finding that should have blocked for it reads REVIEW/PASS instead. That is
    the commonest instance of the dangerous direction, and until Task 18 nothing
    in the response said so.

    Task 14 added exactly this disclosure to the CONSOLE detail response and
    stopped there.
    """

    @pytest.mark.asyncio
    async def test_a_public_caller_handed_an_internal_verdict_is_told_it_is_looser(
        self,
        tiered_app: FastAPI,
        tiered_client: httpx.AsyncClient,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        package = _unique_package()

        tiered_app.dependency_overrides[get_session_context] = lambda: _console_session("frank")
        console_scan_id = await _submit_console(tiered_client, package)

        market_account = _account("mkt-tier-direction")
        tiered_app.dependency_overrides[get_session_context] = lambda: _market_session(
            market_account, _BOTH, tier=TrustTier.PUBLIC
        )
        skill_id, market_scan_id = await _submit_market(tiered_client, package)
        assert market_scan_id == console_scan_id

        # THE ADJUDICATION HAS TO EXIST for the basis to be able to name it.
        # Submitting only queues a scan; nothing in this fixture runs a tick, so
        # without this the verdict row is absent, `signed_policy_version` is
        # None and `tier_divergence` correctly answers "current_policy" - which
        # is what the VM run of 2026-07-29 measured
        # (`assert 'current_policy' == 'signing_policy'`). The console-side
        # sibling of this test (test_gateway_scan_detail.py) always seeded one;
        # this copy was written without that step.
        runtime: ScanRuntime = tiered_app.state.scan
        await _seed_verdict(
            gate_sessionmaker, console_scan_id, policy_version=runtime.policy.version
        )

        body = (await _poll(tiered_client, skill_id)).json()
        assert body["judged_at_tier"] == TrustTier.INTERNAL.value
        # This caller's OWN recorded request, off its OWN scan_submitter row -
        # not the scan's tier under a second label.
        assert body["requested_tier"] == TrustTier.PUBLIC.value
        assert body["tier_direction"] == "looser"
        # 2026-07-29 residual triage: the label is qualified by the policy it
        # was computed under. This scan was just decided by the live runtime, so
        # its verdict carries the loaded policy's own version - the one case
        # where the direction really does describe the adjudication that
        # happened rather than today's thresholds.
        assert body["tier_direction_basis"] == "signing_policy"

    @pytest.mark.asyncio
    async def test_no_divergence_is_reported_when_the_caller_created_the_scan(
        self, tiered_app: FastAPI, tiered_client: httpx.AsyncClient
    ) -> None:
        # The ordinary case must stay quiet: an alarm that fires on every poll
        # is one nobody reads when it matters.
        package = _unique_package()
        market_account = _account("mkt-tier-agree")
        tiered_app.dependency_overrides[get_session_context] = lambda: _market_session(
            market_account, _BOTH, tier=TrustTier.PUBLIC
        )
        skill_id, _scan_id = await _submit_market(tiered_client, package)

        body = (await _poll(tiered_client, skill_id)).json()
        assert body["judged_at_tier"] == TrustTier.PUBLIC.value
        assert body["requested_tier"] == TrustTier.PUBLIC.value
        assert body["tier_direction"] is None
        # Nothing was compared, so there is nothing to qualify - a basis here
        # would be claiming a comparison that never happened.
        assert body["tier_direction_basis"] is None

    @pytest.mark.asyncio
    async def test_the_disclosure_does_not_widen_the_whitelist(
        self, tiered_app: FastAPI, tiered_client: httpx.AsyncClient
    ) -> None:
        """SECURITY: reading the divergence costs one `submitter_attribution`
        call, which returns EVERY submitter of the scan - and §6.2 gives a
        machine identity no business knowing which console user also submitted
        the same bytes. Only this caller's own entry is used; the projection
        whitelist is what makes that structural. Asserted on a real response
        body, with the attribution keys named by hand: a test that only compared
        against `views.EXTERNAL_TOP_LEVEL_FIELDS` would agree with an
        implementation that had added them to the whitelist too.
        """
        package = _unique_package()
        tiered_app.dependency_overrides[get_session_context] = lambda: _console_session("grace")
        scan_id = await _submit_console(tiered_client, package)

        market_account = _account("mkt-tier-whitelist")
        tiered_app.dependency_overrides[get_session_context] = lambda: _market_session(
            market_account, _BOTH, tier=TrustTier.PUBLIC
        )
        skill_id, market_scan_id = await _submit_market(tiered_client, package)
        assert market_scan_id == scan_id

        body = (await _poll(tiered_client, skill_id)).json()
        assert set(body) == views.EXTERNAL_TOP_LEVEL_FIELDS
        for leaked in ("submitters", "submitter_sources", "source", "submitter"):
            assert leaked not in body, f"{leaked!r} crossed the marketplace boundary"


# The contract, written out literally. NOT `views.EXTERNAL_TOP_LEVEL_FIELDS` -
# asserting the implementation against the constant the implementation itself
# reads is a tautology: delete a field and both sides shrink together, still
# equal. That hole was real and shipped (2026-07-28, test_marketplace_views.py
# closed it there with an identical literal); this file still only compared
# against `views.EXTERNAL_TOP_LEVEL_FIELDS` below, so the router-level, real-
# HTTP-response guard never got the same treatment. Duplicated here by hand
# (not imported from test_marketplace_views.py) and must be edited deliberately
# when the contract genuinely changes. Source of truth: design spec 5.3.
#
# 2026-07-30 - EDITED BY HAND for the skill-keyed binary contract, in this file AND
# in test_marketplace_views.py, which keeps its own independent copy on purpose.
# Removed: `scan_id` (the key was replaced outright), `verdict` (three-valued),
# `fail_closed` (now `unsafe_reason == "scan_incomplete"`), `requires_review` (now
# `unsafe_reason == "pending_review"`). Added: `skill_id`, `content_hash`,
# `is_safe`, `unsafe_reason`, `hard_gate_hits` (the last one reverses a deliberate
# exclusion - a binary "unsafe" that cannot say an UNWAIVABLE rule fired is not
# actionable). Two copies means two edits; that is the cost of the guard working.
_SPEC_TOP_LEVEL_FIELDS = frozenset(
    {
        "skill_id",
        "content_hash",
        "status",
        "poll_after_ms",
        "is_safe",
        "unsafe_reason",
        "hard_gate_hits",
        "score",
        "policy_version",
        "decided_at",
        "verdict_jws",
        "judged_at_tier",
        "requested_tier",
        "tier_direction",
        "tier_direction_basis",
        # 2026-07-30 per-scan engine coverage - added by hand HERE and in
        # test_marketplace_views.py, which keeps its own independent copy on
        # purpose. Two copies means two edits; that is the cost of the guard
        # working. Why the contract gained them: every non-required engine fails
        # OPEN, so a timed-out advisory engine silently shrinks the ruleset the
        # verdict was computed under, and on a real 290-scan run that doubled the
        # PASS rate.
        "engines_expected",
        "engines_reported",
        "engines_not_applicable",
        "evidence_complete",
        "engine_coverage_basis",
        "summary",
        "findings",
    }
)


class TestProjectionIsWhatCrossesTheBoundary:
    """spec §3.1 rule 2 / §5.3 - the response is
    `views.project_skill_verdict`'s output, field for field."""

    @pytest.mark.asyncio
    async def test_a_decided_scan_returns_exactly_the_whitelisted_fields(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        subject = _account("mkt-projection")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, scan_id = await _submit(client)
        await _seed_result(orchestration_sessionmaker, scan_id)
        await _seed_verdict(gate_sessionmaker, scan_id)
        await _force_state(orchestration_sessionmaker, scan_id, "decided")

        body = (await _poll(client, skill_id)).json()

        # The guard: not "contains what we expect" but "is exactly the
        # whitelist". An internal field that started leaking, or a contract
        # field that vanished, both fail here.
        assert set(body) == views.EXTERNAL_TOP_LEVEL_FIELDS
        assert set(body["findings"][0]) == views.EXTERNAL_FINDING_FIELDS
        assert body["status"] == "COMPLETED"
        # The seeded verdict is REVIEW: unsafe, and specifically "a human has to
        # look at this" rather than "we could not scan it".
        assert body["is_safe"] is False
        assert body["unsafe_reason"] == "pending_review"
        assert body["hard_gate_hits"] == []
        assert body["poll_after_ms"] == 0
        assert body["score"] == 62
        # The answer names the version it is about (owner decision 1). Asserted
        # against the REAL content hash of the submitted bytes, end to end, so a
        # projection that echoed some other row's hash would fail.
        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        assert body["content_hash"] == job.content_hash
        assert body["verdict_jws"] == "eyJhbGciOiJSUzI1NiJ9.stub.sig"
        # spec §7 non-repudiation - WHICH policy decided this, and WHEN. Both
        # were unasserted anywhere until 2026-07-28: hardcoding them to None in
        # views.project_scan passed this suite. `decided_at` in particular is a
        # cross-layer rename (gate.service.get_verdict_view emits `issued_at`,
        # views republishes it as `decided_at`), so it is asserted here against
        # the exact value seeded into the gate's own table, end to end.
        assert body["policy_version"] == _SEEDED_POLICY_VERSION
        assert body["decided_at"] == _SEEDED_ISSUED_AT.isoformat()

    @pytest.mark.asyncio
    async def test_top_level_contract_matches_the_spec_literally(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        """Catches a field being REMOVED from the contract - the direction
        `test_a_decided_scan_returns_exactly_the_whitelisted_fields` above
        cannot catch, since it asserts against `views.EXTERNAL_TOP_LEVEL_FIELDS`
        itself: delete a field there and that test's two sides shrink together,
        still equal. Only a literal written independently of the implementation
        can see a field vanish (or a new internal one leak in) on a REAL HTTP
        response, not just the pure-function projection test_marketplace_views.py
        already covers this way.
        """
        subject = _account("mkt-spec-contract")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, scan_id = await _submit(client)
        await _seed_result(orchestration_sessionmaker, scan_id)
        await _seed_verdict(gate_sessionmaker, scan_id)
        await _force_state(orchestration_sessionmaker, scan_id, "decided")

        body = (await _poll(client, skill_id)).json()
        assert set(body) == _SPEC_TOP_LEVEL_FIELDS

    @pytest.mark.asyncio
    async def test_engine_coverage_crosses_the_boundary_from_real_health_rows(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        """2026-07-30, end to end through real rows and real HTTP.

        The pure tests in test_marketplace_views.py prove the classification; this
        proves the WIRING - that the router reads `scan_engine_health` at all, on
        the right session, keyed by the right scan. A projection that quietly
        received `coverage=None` on every request would pass every pure test in
        the suite and publish `evidence_complete: null` forever.
        """
        subject = _account("mkt-coverage")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, scan_id = await _submit(client)
        await _seed_result(orchestration_sessionmaker, scan_id)
        await _seed_verdict(gate_sessionmaker, scan_id)
        await _force_state(orchestration_sessionmaker, scan_id, "decided")
        # The corpus' own shape: one engine delivered, one wrote a valid blob
        # saying it timed out (the case `report_state` alone cannot see), one
        # never reported.
        await _seed_engine_health(
            orchestration_sessionmaker,
            scan_id,
            [
                ("static-keyword", "reported", "ok"),
                ("skillspector", "reported", "timeout"),
                ("bandit", "not_reported", None),
            ],
        )

        body = (await _poll(client, skill_id)).json()
        assert body["engines_expected"] == 3
        assert body["engines_reported"] == 1
        assert body["evidence_complete"] is False
        assert body["engine_coverage_basis"] == "current_config"
        # No engine NAME crosses this boundary - counts only. The console gets
        # the names; a machine consumer branches on the numbers.
        assert "skillspector" not in _poll_body_without_findings(body)

    @pytest.mark.asyncio
    async def test_a_scan_with_no_health_rows_reports_null_never_complete(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        """A dead-lettered scan, one past the retention window, or one scored
        before the health table existed. `null`, never `true`: "0 of 0 engines
        missing, therefore complete" is the same fabricated-field mistake
        `fail_closed` shipped as a structural inference hours before this."""
        subject = _account("mkt-coverage-none")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, scan_id = await _submit(client)
        await _seed_result(orchestration_sessionmaker, scan_id)
        await _seed_verdict(gate_sessionmaker, scan_id)
        await _force_state(orchestration_sessionmaker, scan_id, "decided")

        body = (await _poll(client, skill_id)).json()
        assert body["evidence_complete"] is None
        assert body["engine_coverage_basis"] is None
        assert (body["engines_expected"], body["engines_reported"]) == (0, 0)

    @pytest.mark.asyncio
    async def test_snippet_hash_never_crosses_the_boundary(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        # SECURITY (INV-9, spec §5.3): the seeded finding DOES carry a
        # snippet_hash in the database - asserted below - so this proves the
        # projection strips it, not that the fixture happened to omit it.
        subject = _account("mkt-snippet")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, scan_id = await _submit(client)
        await _seed_result(orchestration_sessionmaker, scan_id)
        await _seed_verdict(gate_sessionmaker, scan_id)
        await _force_state(orchestration_sessionmaker, scan_id, "decided")

        async with orchestration_sessionmaker() as session:
            stored = (
                await session.execute(select(ScanResultRow).where(ScanResultRow.scan_id == scan_id))
            ).scalar_one()
        assert stored.findings[0]["snippet_hash"] == "a" * 64

        response = await _poll(client, skill_id)
        assert "snippet_hash" not in response.json()["findings"][0]
        assert "snippet_hash" not in response.text

    @pytest.mark.asyncio
    async def test_a_queued_scan_is_pending_with_a_polling_hint(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        subject = _account("mkt-pending")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, _scan_id = await _submit(client)

        body = (await _poll(client, skill_id)).json()
        assert body["status"] == "PENDING"
        # Owner decision 3, read strictly: an unfinished scan is NOT safe. This is
        # the assertion that stops "no verdict yet" from being published as clean.
        assert body["is_safe"] is False
        assert body["unsafe_reason"] == "not_yet_scanned"
        assert body["findings"] == []
        assert body["poll_after_ms"] == views.POLL_AFTER_MS["PENDING"]

    @pytest.mark.asyncio
    async def test_a_failed_scan_reads_as_completed_block_fail_closed(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        # spec §5.1 / acceptance #3: fail-closed is a real signed BLOCK with no
        # result row. Reporting "FAILED" would invite a retry that bypasses it.
        subject = _account("mkt-failclosed")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, scan_id = await _submit(client)
        await _seed_verdict(gate_sessionmaker, scan_id, verdict="BLOCK", fail_closed=True)
        await _force_state(orchestration_sessionmaker, scan_id, "failed")

        body = (await _poll(client, skill_id)).json()
        assert body["status"] == "COMPLETED"
        assert body["is_safe"] is False
        assert body["unsafe_reason"] == "scan_incomplete"
        assert body["findings"] == []

    @pytest.mark.asyncio
    async def test_a_fail_closed_block_WITH_a_result_row_still_reads_scan_incomplete(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        """The 2026-07-30 bug, asserted end to end over real HTTP.

        `fail_closed` used to be inferred as "a verdict exists and no
        ScanResultRow does". Only the DEAD-LETTER path omits that row; the ordinary
        result-collector path writes one (with `required_ok=False`) and its
        fail-closed BLOCKs therefore reported `fail_closed: false`. On a real
        226-package run that was 17 of the 18 BLOCKs - engine timeouts with zero
        findings, each one presented as an ordinary content BLOCK.

        The scan below is `decided`, not `failed`, and DOES have a result row, so
        the old inference would answer `content_findings` here. That is the whole
        point: under a binary contract this is the difference between "we could not
        scan this" and "this is dangerous".
        """
        subject = _account("mkt-failclosed-with-row")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, scan_id = await _submit(client)
        async with orchestration_sessionmaker() as session, session.begin():
            session.add(
                ScanResultRow(
                    scan_id=scan_id,
                    content_hash="c" * 64,
                    severity=4,
                    confidence_at_max=1.0,
                    trifecta_present=False,
                    findings_capped=False,
                    findings_total=0,
                    # What the collector really writes on this path.
                    required_ok=False,
                    findings=[],
                    provenance=[],
                    hard_gate_hits=[],
                )
            )
        await _seed_verdict(gate_sessionmaker, scan_id, verdict="BLOCK", fail_closed=True)
        await _force_state(orchestration_sessionmaker, scan_id, "decided")

        body = (await _poll(client, skill_id)).json()
        assert body["is_safe"] is False
        assert body["unsafe_reason"] == "scan_incomplete"
        assert body["findings"] == []

    @pytest.mark.asyncio
    async def test_a_hard_gate_block_names_the_rule_that_fired(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        # `hard_gate_hits` was deliberately withheld under the three-valued
        # contract. Under a binary one the marketplace needs to know WHY it is
        # unsafe, and "an unwaivable rule fired" (INV-3) is not the same problem as
        # "findings accumulated" - no allowlist can move the first one.
        subject = _account("mkt-hardgate")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, scan_id = await _submit(client)
        async with orchestration_sessionmaker() as session, session.begin():
            session.add(
                ScanResultRow(
                    scan_id=scan_id,
                    content_hash="c" * 64,
                    severity=4,
                    confidence_at_max=1.0,
                    trifecta_present=True,
                    findings_capped=False,
                    findings_total=1,
                    required_ok=True,
                    findings=[_finding_with_snippet_hash()],
                    provenance=[["static-keyword", "static"]],
                    hard_gate_hits=["net.exfil_to_pastebin"],
                )
            )
        await _seed_verdict(gate_sessionmaker, scan_id, verdict="BLOCK")
        await _force_state(orchestration_sessionmaker, scan_id, "decided")

        body = (await _poll(client, skill_id)).json()
        assert body["is_safe"] is False
        assert body["unsafe_reason"] == "hard_gate"
        assert body["hard_gate_hits"] == ["net.exfil_to_pastebin"]

    @pytest.mark.asyncio
    async def test_a_pass_verdict_is_the_only_safe_answer(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        # The positive control. Without it every assertion above would be satisfied
        # by an endpoint that answers "unsafe" unconditionally.
        subject = _account("mkt-pass")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, scan_id = await _submit(client)
        async with orchestration_sessionmaker() as session, session.begin():
            session.add(
                ScanResultRow(
                    scan_id=scan_id,
                    content_hash="c" * 64,
                    severity=0,
                    confidence_at_max=0.0,
                    trifecta_present=False,
                    findings_capped=False,
                    findings_total=0,
                    required_ok=True,
                    findings=[],
                    provenance=[["static-keyword", "static"]],
                    hard_gate_hits=[],
                )
            )
        await _seed_verdict(gate_sessionmaker, scan_id, verdict="PASS")
        await _force_state(orchestration_sessionmaker, scan_id, "decided")

        body = (await _poll(client, skill_id)).json()
        assert body["is_safe"] is True
        assert body["unsafe_reason"] is None
        assert body["poll_after_ms"] == 0


class _RefusedAuditTransaction:
    """`db_session.begin()`'s context manager, raising at COMMIT.

    That is where the real failure surfaces: SQLAlchemy starts the transaction
    lazily, so the INSERT is emitted when the block exits - which is where MySQL
    answers `1142 INSERT command denied` for a `svc_marketplace` user that was
    never granted it.
    """

    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *exc_info: object) -> bool:
        raise OperationalError(
            "INSERT INTO marketplace_fetch_log (scan_id, service_account, ...) VALUES (...)",
            {},
            Exception(
                "(1142, \"INSERT command denied to user 'svc_marketplace'@'localhost' "
                "for table 'marketplace_fetch_log'\")"
            ),
        )


class _AuditSinkThatRefusesWrites:
    """A configured-but-unwritable marketplace session factory (and session).

    Records what was attempted, so a test can prove the audit path was actually
    entered rather than skipped.
    """

    def __init__(self) -> None:
        self.sessions_opened = 0
        self.rows_attempted: list[MarketplaceFetchLogRow] = []

    def __call__(self) -> _AuditSinkThatRefusesWrites:
        return self

    async def __aenter__(self) -> _AuditSinkThatRefusesWrites:
        self.sessions_opened += 1
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False  # never swallow: the router's own except is what must catch

    def begin(self) -> _RefusedAuditTransaction:
        return _RefusedAuditTransaction()

    def add(self, row: MarketplaceFetchLogRow) -> None:
        self.rows_attempted.append(row)


class _RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class TestFetchAudit:
    """spec §7 - what we told whom, when."""

    @pytest.mark.asyncio
    async def test_a_successful_poll_writes_one_audit_row(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        marketplace_sessionmaker: SessionmakerFixture,
    ) -> None:
        subject = _account("mkt-audit")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, scan_id = await _submit(client)
        await _seed_result(orchestration_sessionmaker, scan_id)
        await _seed_verdict(gate_sessionmaker, scan_id, verdict="BLOCK")
        await _force_state(orchestration_sessionmaker, scan_id, "decided")

        assert (await _poll(client, skill_id)).status_code == 200

        async with marketplace_sessionmaker() as session:
            rows = (
                (
                    await session.execute(
                        select(MarketplaceFetchLogRow).where(
                            MarketplaceFetchLogRow.skill_id == skill_id
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert len(rows) == 1
        assert rows[0].service_account == subject
        # The audit must record what was ACTUALLY shown, not what is currently
        # in the verdict table - that is the whole non-repudiation claim.
        assert rows[0].status_shown == "COMPLETED"
        assert rows[0].is_safe_shown is False
        assert rows[0].unsafe_reason_shown == "content_findings"
        # Keyed on the skill the caller asked about, while still naming the scan
        # that answered and the version the answer was about - "we told them X was
        # safe" is worth little without the bytes it was true of.
        assert rows[0].skill_id == skill_id
        assert rows[0].scan_id == scan_id
        assert rows[0].content_hash_shown
        # The internal verdict the binary answer was derived from. The response no
        # longer carries it, so this column is now derivation evidence rather than a
        # copy of a returned field - see MarketplaceFetchLogRow's docstring.
        assert rows[0].verdict_shown == "BLOCK"

    @pytest.mark.asyncio
    async def test_polling_an_undecided_scan_records_a_null_verdict(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        marketplace_sessionmaker: SessionmakerFixture,
    ) -> None:
        subject = _account("mkt-audit-null")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        skill_id, scan_id = await _submit(client)

        assert (await _poll(client, skill_id)).status_code == 200

        async with marketplace_sessionmaker() as session:
            row = (
                await session.execute(
                    select(MarketplaceFetchLogRow).where(
                        MarketplaceFetchLogRow.skill_id == skill_id
                    )
                )
            ).scalar_one()
        assert row.status_shown == "PENDING"
        assert row.verdict_shown is None
        # An undecided scan is still an ANSWER, and the record must say what that
        # answer was: unsafe, because nothing has been judged yet.
        assert row.is_safe_shown is False
        assert row.unsafe_reason_shown == "not_yet_scanned"
        assert row.scan_id == scan_id

    @pytest.mark.asyncio
    async def test_an_audit_write_that_raises_does_not_fail_the_poll(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        inventory_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        """The audit failure spec §7's own operational trap describes.

        The test below it (`..._unwritable_audit_sink_...`) models an
        UNCONFIGURED sink, which takes `_record_fetch`'s early return and never
        enters the `try`. The failure that actually happens in production is the
        other one: `svc_marketplace` exists in the runtime config but was never
        granted INSERT (deploy without re-running `db/setup_grants.py`), so the
        process starts fine - engines connect lazily - and the write raises
        INSIDE the `async with`. Nothing exercised that path, so narrowing the
        `except Exception` to `SQLAlchemyError`, or any exception surfacing from
        `db_session.begin().__aexit__`, would 500 every poll with a green suite.
        """
        sink = _AuditSinkThatRefusesWrites()
        app = _build_app(
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            inventory_sessionmaker=inventory_sessionmaker,
            # A real sessionmaker with a real revoked GRANT would need a MySQL
            # user this suite must not create or alter; this fake fails at the
            # same place with the same exception type.
            marketplace_sessionmaker=cast(SessionmakerFixture, sink),
            redis_client=redis_client,
            blobstore=blobstore,
            rate_limit_per_min=120,
        )
        subject = _account("mkt-audit-refused")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)

        # NOT caplog: `common.log.get_logger` sets `propagate = False`, so these
        # records never reach the root handler pytest captures on.
        audit_logger = logging.getLogger("skillscan.marketplace_api.router")
        handler = _RecordingHandler()
        audit_logger.addHandler(handler)
        transport = httpx.ASGITransport(app=app)
        try:
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
                skill_id, scan_id = await _submit(c)
                await _seed_result(orchestration_sessionmaker, scan_id)
                await _seed_verdict(gate_sessionmaker, scan_id, verdict="BLOCK")
                await _force_state(orchestration_sessionmaker, scan_id, "decided")
                response = await _poll(c, skill_id)
        finally:
            audit_logger.removeHandler(handler)

        # 200 AND the right body: the decided, signed verdict is delivered in
        # full, not a degraded or partial one.
        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == views.EXTERNAL_TOP_LEVEL_FIELDS
        assert body["skill_id"] == skill_id
        assert body["status"] == "COMPLETED"
        assert body["is_safe"] is False
        assert body["unsafe_reason"] == "content_findings"
        assert body["verdict_jws"] == "eyJhbGciOiJSUzI1NiJ9.stub.sig"
        # The write was really ATTEMPTED and really failed - without this the
        # test would pass just as happily against a sink that is never reached,
        # which is exactly how the early-return test came to stand in for this
        # one.
        assert sink.sessions_opened == 1
        assert len(sink.rows_attempted) == 1
        # MAINTENANCE_GUIDE §1 tells operators that a healthy system with an
        # empty `marketplace_fetch_log` is diagnosed by grepping for this exact
        # metric - so the fail-soft path owes them that log line.
        assert any(
            getattr(record, "context", {}).get("metric") == "marketplace_fetch_audit_write_failed"
            for record in handler.records
        )

    @pytest.mark.asyncio
    async def test_an_unwritable_audit_sink_does_not_fail_the_poll(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        inventory_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        # SECURITY (spec §7, same posture as integration_relay.siem): the
        # verdict is already decided and signed - an audit-sink problem must
        # degrade to a log line, never withhold the result. Modelled here as an
        # unconfigured sink, the one audit failure a test can produce
        # deterministically without breaking the shared database.
        app = _build_app(
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            inventory_sessionmaker=inventory_sessionmaker,
            marketplace_sessionmaker=None,
            redis_client=redis_client,
            blobstore=blobstore,
            rate_limit_per_min=120,
        )
        subject = _account("mkt-no-audit")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
            skill_id, _scan_id = await _submit(c)
            response = await _poll(c, skill_id)
        assert response.status_code == 200
        assert response.json()["skill_id"] == skill_id


class TestRateLimit:
    """spec §6.3 - the penalty half of the polling-cadence design."""

    @pytest.fixture
    def throttled_app(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        inventory_sessionmaker: SessionmakerFixture,
        marketplace_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> FastAPI:
        return _build_app(
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
            inventory_sessionmaker=inventory_sessionmaker,
            marketplace_sessionmaker=marketplace_sessionmaker,
            redis_client=redis_client,
            blobstore=blobstore,
            rate_limit_per_min=3,
        )

    @pytest_asyncio.fixture
    async def throttled_client(self, throttled_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
        transport = httpx.ASGITransport(app=throttled_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
            yield c

    @pytest.mark.asyncio
    async def test_exceeding_the_budget_is_429_with_retry_after(
        self, throttled_app: FastAPI, throttled_client: httpx.AsyncClient
    ) -> None:
        subject = _account("mkt-throttled")
        throttled_app.dependency_overrides[get_session_context] = lambda: _market_session(
            subject, _BOTH
        )
        skill_id, _scan_id = await _submit(throttled_client)  # request 1 of 3

        assert (await _poll(throttled_client, skill_id)).status_code == 200
        assert (await _poll(throttled_client, skill_id)).status_code == 200

        over = await _poll(throttled_client, skill_id)
        assert over.status_code == 429
        assert int(over.headers["Retry-After"]) > 0

    @pytest.mark.asyncio
    async def test_one_accounts_exhausted_budget_does_not_affect_another(
        self, throttled_app: FastAPI, throttled_client: httpx.AsyncClient
    ) -> None:
        # spec §6.3: the window is per service account precisely so one
        # marketplace cannot deny service to another.
        noisy = _account("mkt-noisy")
        throttled_app.dependency_overrides[get_session_context] = lambda: _market_session(
            noisy, _BOTH
        )
        skill_id, _scan_id = await _submit(throttled_client)
        for _ in range(2):
            await _poll(throttled_client, skill_id)
        assert (await _poll(throttled_client, skill_id)).status_code == 429

        quiet = _account("mkt-quiet")
        throttled_app.dependency_overrides[get_session_context] = lambda: _market_session(
            quiet, _BOTH
        )
        # Not this account's skill, so 404 - but a 404 proves the request was
        # PROCESSED rather than throttled, which is what this asserts.
        response = await _poll(throttled_client, skill_id)
        assert response.status_code == 404
