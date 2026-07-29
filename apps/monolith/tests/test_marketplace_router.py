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
from monolith.modules.marketplace_api import views
from monolith.modules.marketplace_api.models import MarketplaceFetchLogRow
from monolith.modules.orchestration.models import ScanJob, ScanResultRow
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
    marketplace_sessionmaker: SessionmakerFixture,
    reporting_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
) -> FastAPI:
    return _build_app(
        orchestration_sessionmaker=orchestration_sessionmaker,
        gate_sessionmaker=gate_sessionmaker,
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


async def _submit(client_instance: httpx.AsyncClient) -> str:
    response = await client_instance.post(
        "/v1/market/scans",
        files={"package": ("skill.tar", _unique_package(), "application/x-tar")},
    )
    assert response.status_code == 202, response.text
    scan_id: str = response.json()["scan_id"]
    return scan_id


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
) -> None:
    async with gate_sessionmaker() as session, session.begin():
        session.add(
            VerdictRow(
                scan_id=scan_id,
                content_hash="c" * 64,
                verdict=verdict,
                policy_version=_SEEDED_POLICY_VERSION,
                jti=str(uuid.uuid4()),
                jws_signature="eyJhbGciOiJSUzI1NiJ9.stub.sig",
                effective_severity=3,
                score=62,
                reasons=[],
                issued_at=issued_at,
            )
        )


class TestAuthorizationMatrix:
    """spec §6.1/§6.2 - scope AND ownership, and the deliberate choice of which
    status code each failure gets."""

    @pytest.mark.asyncio
    async def test_own_scan_with_read_scope_is_200(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        subject = _account("mkt-own-read")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        scan_id = await _submit(client)

        response = await client.get(f"/v1/market/scans/{scan_id}")
        assert response.status_code == 200
        assert response.json()["scan_id"] == scan_id

    @pytest.mark.asyncio
    async def test_another_accounts_scan_is_404_not_403(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # SECURITY (spec §6.2): a 403 would confirm the scan_id exists, which is
        # all an enumerator needs. Indistinguishable from "no such scan".
        owner = _account("mkt-owner")
        app.dependency_overrides[get_session_context] = lambda: _market_session(owner, _BOTH)
        scan_id = await _submit(client)

        intruder = _account("mkt-intruder")
        app.dependency_overrides[get_session_context] = lambda: _market_session(intruder, _BOTH)
        response = await client.get(f"/v1/market/scans/{scan_id}")
        assert response.status_code == 404

        unknown = await client.get(f"/v1/market/scans/{uuid.uuid4()}")
        assert unknown.status_code == 404
        # The two cases must not be distinguishable by body either.
        assert response.json() == unknown.json()

    @pytest.mark.asyncio
    async def test_own_scan_without_read_scope_is_403(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # The compatibility guarantee of spec §6.1: an existing M2M identity
        # keeps the default `scan:submit`-only grant and gains NO read access
        # from this milestone - not even to its own scans.
        subject = _account("mkt-submit-only")
        app.dependency_overrides[get_session_context] = lambda: _market_session(
            subject, _SUBMIT_ONLY
        )
        scan_id = await _submit(client)

        response = await client.get(f"/v1/market/scans/{scan_id}")
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_another_accounts_scan_without_read_scope_is_403(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # Scope is checked before ownership, so the 403 here reveals only the
        # caller's own configuration - still nothing about the scan.
        owner = _account("mkt-owner2")
        app.dependency_overrides[get_session_context] = lambda: _market_session(owner, _BOTH)
        scan_id = await _submit(client)

        stranger = _account("mkt-stranger")
        app.dependency_overrides[get_session_context] = lambda: _market_session(
            stranger, _SUBMIT_ONLY
        )
        # Someone else's real scan and a scan_id that does not exist both stop
        # at the scope check - the ownership lookup is never even reached.
        assert (await client.get(f"/v1/market/scans/{scan_id}")).status_code == 403
        assert (await client.get(f"/v1/market/scans/{uuid.uuid4()}")).status_code == 403

    @pytest.mark.asyncio
    async def test_submit_without_submit_scope_is_403(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        subject = _account("mkt-read-only")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _READ_ONLY)
        response = await client.post(
            "/v1/market/scans",
            files={"package": ("skill.tar", _unique_package(), "application/x-tar")},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_unauthenticated_request_is_401(self, client: httpx.AsyncClient) -> None:
        # No dependency override - the real get_session_context fail-closes.
        response = await client.get(f"/v1/market/scans/{uuid.uuid4()}")
        assert response.status_code == 401


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
        scan_id = await _submit(client)

        console = await client.get(f"/v1/scans/{scan_id}")
        assert console.status_code == 403, console.text
        market = await client.get(f"/v1/market/scans/{scan_id}")
        assert market.status_code == 200, market.text
        assert market.json()["scan_id"] == scan_id

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
        scan_id = await _submit(client)
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
        for withheld in ("snippet_hash", "provenance", "required_ok", "hard_gate_hits"):
            assert withheld not in console.text

        market = await client.get(f"/v1/market/scans/{scan_id}")
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
        scan_id = await _submit(client)

        assert (await client.get(f"/v1/scans/{scan_id}/sarif")).status_code == 403
        assert (await client.get(f"/v1/market/scans/{scan_id}")).status_code == 200

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
            data={"trust_tier": "internal"},
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
        scan_id = await _submit(client)

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


async def _submit_market(client_instance: httpx.AsyncClient, package: bytes) -> str:
    response = await client_instance.post(
        "/v1/market/scans", files={"package": ("skill.tar", package, "application/x-tar")}
    )
    assert response.status_code == 202, response.text
    scan_id: str = response.json()["scan_id"]
    return scan_id


class TestDeduplicatedSubmissionsStayReadableByEverySubmitter:
    """SECURITY (milestone B' review, C2): single-flight dedup must not hand a
    caller a scan_id it can never read.

    `submit_scan` keys on `content_hash + toolchain_digest`, so byte-identical
    content submitted twice collapses onto ONE scan_job - which keeps the FIRST
    submitter in `scan_job.submitter`. Authorization used to compare that single
    column against the requester, so the second submitter got 404 for the
    scan_id it had just been handed, permanently (re-submitting returns the same
    id), and spec §6.2 makes that 404 indistinguishable from "no such scan" -
    the marketplace could not even diagnose it.

    "The console and the marketplace scan the same skills" is this product's
    normal case. Note the tests run both orderings: a fix applied to only the
    marketplace side produces the mirror-image bug on the console side.
    """

    @pytest.mark.asyncio
    async def test_console_first_then_marketplace_can_still_poll(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        package = _unique_package()

        app.dependency_overrides[get_session_context] = lambda: _console_session("alice")
        console_scan_id = await _submit_console(client, package)

        market_account = _account("mkt-dedup-second")
        app.dependency_overrides[get_session_context] = lambda: _market_session(
            market_account, _BOTH
        )
        market_scan_id = await _submit_market(client, package)

        # The premise: dedup really did collapse the two submissions.
        assert market_scan_id == console_scan_id

        response = await client.get(f"/v1/market/scans/{market_scan_id}")
        assert response.status_code == 200, response.text
        assert response.json()["scan_id"] == market_scan_id

    @pytest.mark.asyncio
    async def test_marketplace_first_then_the_console_submitter_can_still_read_it(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # The mirror direction. Fixing only the marketplace's check would leave
        # this failing: the marketplace can read the scan, and the console user
        # who submitted the very same bytes cannot.
        package = _unique_package()

        market_account = _account("mkt-dedup-first")
        app.dependency_overrides[get_session_context] = lambda: _market_session(
            market_account, _BOTH
        )
        market_scan_id = await _submit_market(client, package)

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
    async def test_a_subject_that_never_submitted_is_still_404(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        # The fix widens access to actual submitters and to nobody else - the
        # association is appended on submission, never on a read.
        package = _unique_package()
        app.dependency_overrides[get_session_context] = lambda: _console_session("carol")
        scan_id = await _submit_console(client, package)

        stranger = _account("mkt-dedup-stranger")
        app.dependency_overrides[get_session_context] = lambda: _market_session(stranger, _BOTH)
        assert (await client.get(f"/v1/market/scans/{scan_id}")).status_code == 404

        app.dependency_overrides[get_session_context] = lambda: _console_session("dave")
        assert (await client.get(f"/v1/scans/{scan_id}")).status_code == 404
        listed = await client.get("/v1/scans")
        assert scan_id not in {item["scan_id"] for item in listed.json()["items"]}

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
        assert await _submit_market(client, package) == scan_id

        body = (await client.get(f"/v1/market/scans/{scan_id}")).json()
        assert body["judged_at_tier"] == TrustTier.INTERNAL.value
        assert body["judged_at_tier"] != TrustTier.PUBLIC.value


@pytest.fixture
def tiered_app(
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
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
        self, tiered_app: FastAPI, tiered_client: httpx.AsyncClient
    ) -> None:
        package = _unique_package()

        tiered_app.dependency_overrides[get_session_context] = lambda: _console_session("frank")
        console_scan_id = await _submit_console(tiered_client, package)

        market_account = _account("mkt-tier-direction")
        tiered_app.dependency_overrides[get_session_context] = lambda: _market_session(
            market_account, _BOTH, tier=TrustTier.PUBLIC
        )
        assert await _submit_market(tiered_client, package) == console_scan_id

        body = (await tiered_client.get(f"/v1/market/scans/{console_scan_id}")).json()
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
        scan_id = await _submit_market(tiered_client, package)

        body = (await tiered_client.get(f"/v1/market/scans/{scan_id}")).json()
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
        assert await _submit_market(tiered_client, package) == scan_id

        body = (await tiered_client.get(f"/v1/market/scans/{scan_id}")).json()
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
_SPEC_TOP_LEVEL_FIELDS = frozenset(
    {
        "scan_id",
        "status",
        "verdict",
        "score",
        "policy_version",
        "decided_at",
        "verdict_jws",
        "fail_closed",
        "requires_review",
        "poll_after_ms",
        "judged_at_tier",
        "requested_tier",
        "tier_direction",
        "tier_direction_basis",
        "summary",
        "findings",
    }
)


class TestProjectionIsWhatCrossesTheBoundary:
    """spec §3.1 rule 2 / §5.3 - the response is `views.project_scan`'s output,
    field for field."""

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
        scan_id = await _submit(client)
        await _seed_result(orchestration_sessionmaker, scan_id)
        await _seed_verdict(gate_sessionmaker, scan_id)
        await _force_state(orchestration_sessionmaker, scan_id, "decided")

        body = (await client.get(f"/v1/market/scans/{scan_id}")).json()

        # The guard: not "contains what we expect" but "is exactly the
        # whitelist". An internal field that started leaking, or a contract
        # field that vanished, both fail here.
        assert set(body) == views.EXTERNAL_TOP_LEVEL_FIELDS
        assert set(body["findings"][0]) == views.EXTERNAL_FINDING_FIELDS
        assert body["status"] == "COMPLETED"
        assert body["verdict"] == "REVIEW"
        assert body["requires_review"] is True
        assert body["fail_closed"] is False
        assert body["poll_after_ms"] == 0
        assert body["score"] == 62
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
        scan_id = await _submit(client)
        await _seed_result(orchestration_sessionmaker, scan_id)
        await _seed_verdict(gate_sessionmaker, scan_id)
        await _force_state(orchestration_sessionmaker, scan_id, "decided")

        body = (await client.get(f"/v1/market/scans/{scan_id}")).json()
        assert set(body) == _SPEC_TOP_LEVEL_FIELDS

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
        scan_id = await _submit(client)
        await _seed_result(orchestration_sessionmaker, scan_id)
        await _seed_verdict(gate_sessionmaker, scan_id)
        await _force_state(orchestration_sessionmaker, scan_id, "decided")

        async with orchestration_sessionmaker() as session:
            stored = (
                await session.execute(select(ScanResultRow).where(ScanResultRow.scan_id == scan_id))
            ).scalar_one()
        assert stored.findings[0]["snippet_hash"] == "a" * 64

        response = await client.get(f"/v1/market/scans/{scan_id}")
        assert "snippet_hash" not in response.json()["findings"][0]
        assert "snippet_hash" not in response.text

    @pytest.mark.asyncio
    async def test_a_queued_scan_is_pending_with_a_polling_hint(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        subject = _account("mkt-pending")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        scan_id = await _submit(client)

        body = (await client.get(f"/v1/market/scans/{scan_id}")).json()
        assert body["status"] == "PENDING"
        assert body["verdict"] is None
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
        scan_id = await _submit(client)
        await _seed_verdict(gate_sessionmaker, scan_id, verdict="BLOCK")
        await _force_state(orchestration_sessionmaker, scan_id, "failed")

        body = (await client.get(f"/v1/market/scans/{scan_id}")).json()
        assert body["status"] == "COMPLETED"
        assert body["verdict"] == "BLOCK"
        assert body["fail_closed"] is True
        assert body["findings"] == []


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
        scan_id = await _submit(client)
        await _seed_result(orchestration_sessionmaker, scan_id)
        await _seed_verdict(gate_sessionmaker, scan_id, verdict="BLOCK")
        await _force_state(orchestration_sessionmaker, scan_id, "decided")

        assert (await client.get(f"/v1/market/scans/{scan_id}")).status_code == 200

        async with marketplace_sessionmaker() as session:
            rows = (
                (
                    await session.execute(
                        select(MarketplaceFetchLogRow).where(
                            MarketplaceFetchLogRow.scan_id == scan_id
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
        scan_id = await _submit(client)

        assert (await client.get(f"/v1/market/scans/{scan_id}")).status_code == 200

        async with marketplace_sessionmaker() as session:
            row = (
                await session.execute(
                    select(MarketplaceFetchLogRow).where(MarketplaceFetchLogRow.scan_id == scan_id)
                )
            ).scalar_one()
        assert row.status_shown == "PENDING"
        assert row.verdict_shown is None

    @pytest.mark.asyncio
    async def test_an_audit_write_that_raises_does_not_fail_the_poll(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
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
                scan_id = await _submit(c)
                await _seed_result(orchestration_sessionmaker, scan_id)
                await _seed_verdict(gate_sessionmaker, scan_id, verdict="BLOCK")
                await _force_state(orchestration_sessionmaker, scan_id, "decided")
                response = await c.get(f"/v1/market/scans/{scan_id}")
        finally:
            audit_logger.removeHandler(handler)

        # 200 AND the right body: the decided, signed verdict is delivered in
        # full, not a degraded or partial one.
        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == views.EXTERNAL_TOP_LEVEL_FIELDS
        assert body["scan_id"] == scan_id
        assert body["status"] == "COMPLETED"
        assert body["verdict"] == "BLOCK"
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
            marketplace_sessionmaker=None,
            redis_client=redis_client,
            blobstore=blobstore,
            rate_limit_per_min=120,
        )
        subject = _account("mkt-no-audit")
        app.dependency_overrides[get_session_context] = lambda: _market_session(subject, _BOTH)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
            scan_id = await _submit(c)
            response = await c.get(f"/v1/market/scans/{scan_id}")
        assert response.status_code == 200
        assert response.json()["scan_id"] == scan_id


class TestRateLimit:
    """spec §6.3 - the penalty half of the polling-cadence design."""

    @pytest.fixture
    def throttled_app(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        marketplace_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> FastAPI:
        return _build_app(
            orchestration_sessionmaker=orchestration_sessionmaker,
            gate_sessionmaker=gate_sessionmaker,
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
        scan_id = await _submit(throttled_client)  # request 1 of 3

        assert (await throttled_client.get(f"/v1/market/scans/{scan_id}")).status_code == 200
        assert (await throttled_client.get(f"/v1/market/scans/{scan_id}")).status_code == 200

        over = await throttled_client.get(f"/v1/market/scans/{scan_id}")
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
        scan_id = await _submit(throttled_client)
        for _ in range(2):
            await throttled_client.get(f"/v1/market/scans/{scan_id}")
        assert (await throttled_client.get(f"/v1/market/scans/{scan_id}")).status_code == 429

        quiet = _account("mkt-quiet")
        throttled_app.dependency_overrides[get_session_context] = lambda: _market_session(
            quiet, _BOTH
        )
        # Not this account's scan, so 404 - but a 404 proves the request was
        # PROCESSED rather than throttled, which is what this asserts.
        response = await throttled_client.get(f"/v1/market/scans/{scan_id}")
        assert response.status_code == 404
