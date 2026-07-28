"""Tests for `GET/POST /v1/reports*` (coding spec §9/§16.2) - real local
MySQL/Redis via a real ScanRuntime; only auth is faked via FastAPI dependency
override, matching test_admin_router.py's established pattern.
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
from monolith.modules.audit.models import AuditEntry
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.gateway.auth.dependencies import get_session_context
from monolith.modules.gateway.auth.middleware import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
)
from monolith.modules.gateway.auth.session import SessionContext
from monolith.modules.gateway.runtime import ScanRuntime
from monolith.modules.orchestration.models import ScanResultRow
from monolith.tests.conftest import SessionmakerFixture


async def _seed_audit_entry(
    session_factory: SessionmakerFixture,
    *,
    action: str,
    payload: dict[str, object],
    operator: str = "tester",
    chained_at: datetime.datetime | None = None,
) -> None:
    async with session_factory() as session, session.begin():
        session.add(
            AuditEntry(
                prev_hash="0" * 64,
                entry_hash=f"dummy-{uuid.uuid4().hex}",
                operator=operator,
                action=action,
                payload=payload,
                chained_at=chained_at or datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
            )
        )


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


def _base_policy(version_prefix: str) -> GatePolicy:
    return GatePolicy(
        version=f"{version_prefix}-{uuid.uuid4().hex[:8]}",
        required_engines=frozenset({_ENGINE.metadata.name}),
        hard_gate_rules=frozenset(),
        fail_closed_verdict=Verdict.BLOCK,
    )


@pytest.fixture
def app_without_reporting(
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
        policy=_base_policy("test-reports-noreporting"),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
    )
    return create_app(scan_runtime=scan_runtime)


@pytest.fixture
def app(
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    reporting_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
) -> FastAPI:
    scan_runtime = ScanRuntime(
        redis=redis_client,
        blobstore=blobstore,
        orchestration_session_factory=orchestration_sessionmaker,
        gate_session_factory=gate_sessionmaker,
        policy=_base_policy("test-reports"),
        engine_metadatas=(_ENGINE.metadata,),
        allowlist=(),
        signer=LocalDevSigner(),
        reporting_session_factory=reporting_sessionmaker,
    )
    return create_app(scan_runtime=scan_runtime)


async def _client_for(app_instance: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app_instance)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async for c in _client_for(app):
        yield c


@pytest_asyncio.fixture
async def client_without_reporting(
    app_without_reporting: FastAPI,
) -> AsyncIterator[httpx.AsyncClient]:
    async for c in _client_for(app_without_reporting):
        yield c


def _as(app_instance: FastAPI, subject: str, roles: frozenset[str]) -> None:
    app_instance.dependency_overrides[get_session_context] = lambda: _session(subject, roles)


def _csrf_headers_and_cookies(client_instance: httpx.AsyncClient) -> dict[str, str]:
    client_instance.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
    client_instance.cookies.set(CSRF_COOKIE_NAME, "test-csrf-token")
    return {CSRF_HEADER_NAME: "test-csrf-token"}


class TestGetReport:
    @pytest.mark.asyncio
    async def test_approver_can_read_engine_coverage(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as(app, "carol", frozenset({"approver"}))
        response = await client.get("/v1/reports", params={"template": "engine_coverage"})
        assert response.status_code == 200
        body = response.json()
        assert body["template"] == "engine_coverage"
        assert "summary" in body and "rows" in body

    @pytest.mark.asyncio
    async def test_submitter_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "dave", frozenset({"submitter"}))
        response = await client.get("/v1/reports", params={"template": "engine_coverage"})
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_unknown_template_is_400(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "carol", frozenset({"admin"}))
        response = await client.get("/v1/reports", params={"template": "bogus"})
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_csv_export(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "carol", frozenset({"auditor"}))
        response = await client.get(
            "/v1/reports", params={"template": "engine_coverage", "export": "csv"}
        )
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")
        assert "attachment" in response.headers["content-disposition"]

    @pytest.mark.asyncio
    async def test_pdf_export(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "carol", frozenset({"auditor"}))
        response = await client.get(
            "/v1/reports", params={"template": "engine_coverage", "export": "pdf"}
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert response.content.startswith(b"%PDF-")

    @pytest.mark.asyncio
    async def test_unknown_export_format_is_400(
        self, app: FastAPI, client: httpx.AsyncClient
    ) -> None:
        _as(app, "carol", frozenset({"admin"}))
        response = await client.get(
            "/v1/reports", params={"template": "engine_coverage", "export": "xml"}
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_bare_date_until_includes_the_whole_day(
        self, app: FastAPI, client: httpx.AsyncClient, audit_sessionmaker: SessionmakerFixture
    ) -> None:
        # BUG (reported 2026-07-23): a `<input type="date">` sends a bare
        # "YYYY-MM-DD" for `until`, which pydantic parses as midnight - an
        # entry from LATER the same day then fell outside `chained_at <=
        # until` and the UI looked like "filtering finds nothing" whenever
        # since/until were set to the same day. An entry timestamped in the
        # afternoon must still be included when `until` is that same bare date.
        day = datetime.date(2026, 3, 10)
        marker = f"scan-{uuid.uuid4().hex[:12]}"
        await _seed_audit_entry(
            audit_sessionmaker,
            action="verdict_issued",
            payload={"scan_id": marker, "verdict": "BLOCK", "policy_version": "v1"},
            chained_at=datetime.datetime.combine(day, datetime.time(18, 30)),
        )
        _as(app, "carol", frozenset({"admin"}))
        response = await client.get(
            "/v1/reports",
            params={
                "template": "compliance_status",
                "since": day.isoformat(),
                "until": day.isoformat(),
            },
        )
        assert response.status_code == 200
        assert response.json()["summary"]["verdict_counts"].get("BLOCK", 0) >= 1

    @pytest.mark.asyncio
    async def test_reporting_not_configured_is_500(
        self, app_without_reporting: FastAPI, client_without_reporting: httpx.AsyncClient
    ) -> None:
        _as(app_without_reporting, "carol", frozenset({"admin"}))
        response = await client_without_reporting.get(
            "/v1/reports", params={"template": "engine_coverage"}
        )
        assert response.status_code == 500


def _finding(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        test_item_id="T-001",
        category=DetectionCategory.DATA_CREDENTIAL,
        title="Hardcoded secret detected",
        severity=Severity.HIGH,
        confidence=0.9,
        source_engine="bandit",
        source_capability=EngineCapability.STATIC,
        evidence_redacted="secret=<redacted>",
    )


class TestGetReportSarif:
    @pytest.mark.asyncio
    async def test_bundles_findings_for_requested_scans(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        orchestration_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        async with orchestration_sessionmaker() as session, session.begin():
            session.add(
                ScanResultRow(
                    scan_id=scan_id,
                    content_hash="a" * 64,
                    severity=int(Severity.HIGH),
                    confidence_at_max=0.9,
                    trifecta_present=False,
                    findings_capped=False,
                    required_ok=True,
                    findings=[serialize_finding(_finding("static.secret"))],
                    provenance=[],
                    hard_gate_hits=[],
                )
            )
        _as(app, "carol", frozenset({"auditor"}))
        response = await client.get("/v1/reports/sarif", params={"scan_ids": scan_id})
        assert response.status_code == 200
        assert response.json()["runs"][0]["results"][0]["ruleId"] == "static.secret"

    @pytest.mark.asyncio
    async def test_empty_scan_ids_is_400(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "carol", frozenset({"auditor"}))
        response = await client.get("/v1/reports/sarif", params={"scan_ids": ""})
        assert response.status_code == 400


class TestReportSchedule:
    @pytest.mark.asyncio
    async def test_admin_can_create_schedule(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/reports/schedule",
            json={
                "template": "executive_summary",
                "cron": "0 6 * * *",
                "targets": ["siem.internal:514"],
            },
            headers=headers,
        )
        assert response.status_code == 201
        assert response.json()["created_by"] == "admin-alice"

    @pytest.mark.asyncio
    async def test_non_admin_denied(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "carol", frozenset({"approver"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/reports/schedule",
            json={
                "template": "executive_summary",
                "cron": "0 6 * * *",
                "targets": ["siem.internal:514"],
            },
            headers=headers,
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_missing_csrf_is_403(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        client.cookies.set(SESSION_COOKIE_NAME, "fake-session-cookie-for-csrf-test")
        response = await client.post(
            "/v1/reports/schedule",
            json={
                "template": "executive_summary",
                "cron": "0 6 * * *",
                "targets": ["siem.internal:514"],
            },
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_unknown_template_is_400(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        response = await client.post(
            "/v1/reports/schedule",
            json={"template": "bogus", "cron": "0 6 * * *", "targets": ["siem.internal:514"]},
            headers=headers,
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_list_schedules(self, app: FastAPI, client: httpx.AsyncClient) -> None:
        _as(app, "admin-alice", frozenset({"admin"}))
        headers = _csrf_headers_and_cookies(client)
        marker = f"target-{uuid.uuid4().hex[:8]}.internal"
        await client.post(
            "/v1/reports/schedule",
            json={"template": "risk_trend", "cron": "0 6 * * *", "targets": [marker]},
            headers=headers,
        )
        response = await client.get("/v1/reports/schedule")
        matching = [s for s in response.json()["schedules"] if marker in s["targets"]]
        assert len(matching) == 1
