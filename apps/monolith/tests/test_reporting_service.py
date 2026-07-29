"""Tests for `reporting.service` (coding spec §16.2 FR-REP) against real
local MySQL/Redis. Audit rows are seeded directly via `audit_sessionmaker`
(svc_audit has INSERT+SELECT on audit_entry) to simulate history other
modules' real code paths would produce - `chained_at`/`prev_hash`/`entry_hash`
are dummy values here (this test never exercises the hash-chain itself, only
reporting's aggregation over whatever rows exist), same shortcut used
throughout this suite when seeding data owned by a different module.
"""

from __future__ import annotations

import datetime
import uuid
from pathlib import Path

import pytest
import redis.asyncio as aioredis
import yaml
from common.engine_toggle import DISABLED_ENGINES_KEY
from schemas.findings import serialize_finding
from skillscan_core import DetectionCategory, EngineCapability, Finding, Severity
from sqlalchemy.exc import DBAPIError

from monolith.modules.audit.models import AuditEntry
from monolith.modules.orchestration.floor import floor_engine_names
from monolith.modules.orchestration.models import ScanResultRow
from monolith.modules.reporting.service import (
    InvalidCronError,
    ReportingError,
    UnknownReportTemplateError,
    build_compliance_status,
    build_engine_coverage,
    build_exception_audit,
    build_executive_summary,
    build_risk_trend,
    export_csv,
    export_pdf,
    export_sarif_for_scans,
    generate_report,
    list_schedules,
    schedule_report,
    validate_cron,
)
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


class TestValidateCron:
    def test_valid_five_field_expression_passes(self) -> None:
        validate_cron("0 3 * * *")

    def test_wrong_field_count_raises(self) -> None:
        with pytest.raises(InvalidCronError, match="5 whitespace-separated fields"):
            validate_cron("0 3 * *")

    def test_invalid_field_character_raises(self) -> None:
        with pytest.raises(InvalidCronError, match="invalid cron field"):
            validate_cron("0 3 * * MON")


class TestScheduleReport:
    @pytest.mark.asyncio
    async def test_valid_schedule_persists(
        self, reporting_sessionmaker: SessionmakerFixture
    ) -> None:
        async with reporting_sessionmaker() as session, session.begin():
            row = await schedule_report(
                session,
                template="executive_summary",
                cron="0 6 * * *",
                targets=["siem.internal:514"],
                created_by="admin-alice",
            )
        assert row.id is not None
        assert row.template == "executive_summary"

    @pytest.mark.asyncio
    async def test_unknown_template_rejected(
        self, reporting_sessionmaker: SessionmakerFixture
    ) -> None:
        with pytest.raises(UnknownReportTemplateError):
            async with reporting_sessionmaker() as session, session.begin():
                await schedule_report(
                    session,
                    template="not_a_real_template",
                    cron="0 6 * * *",
                    targets=["siem.internal:514"],
                    created_by="admin-alice",
                )

    @pytest.mark.asyncio
    async def test_invalid_cron_rejected(self, reporting_sessionmaker: SessionmakerFixture) -> None:
        with pytest.raises(InvalidCronError):
            async with reporting_sessionmaker() as session, session.begin():
                await schedule_report(
                    session,
                    template="executive_summary",
                    cron="not a cron",
                    targets=["siem.internal:514"],
                    created_by="admin-alice",
                )

    @pytest.mark.asyncio
    async def test_empty_targets_rejected(
        self, reporting_sessionmaker: SessionmakerFixture
    ) -> None:
        with pytest.raises(ReportingError, match="delivery target"):
            async with reporting_sessionmaker() as session, session.begin():
                await schedule_report(
                    session,
                    template="executive_summary",
                    cron="0 6 * * *",
                    targets=[],
                    created_by="admin-alice",
                )


class TestListSchedules:
    @pytest.mark.asyncio
    async def test_lists_persisted_schedules(
        self, reporting_sessionmaker: SessionmakerFixture
    ) -> None:
        marker = f"target-{uuid.uuid4().hex[:8]}.internal"
        async with reporting_sessionmaker() as session, session.begin():
            await schedule_report(
                session,
                template="risk_trend",
                cron="0 6 * * *",
                targets=[marker],
                created_by="admin-bob",
            )
        async with reporting_sessionmaker() as session:
            schedules = await list_schedules(session)
        matching = [s for s in schedules if marker in s.targets]
        assert len(matching) == 1
        assert matching[0].created_by == "admin-bob"


class TestBuildExecutiveSummary:
    @pytest.mark.asyncio
    async def test_aggregates_verdicts_transitions_and_activations(
        self, reporting_sessionmaker: SessionmakerFixture, audit_sessionmaker: SessionmakerFixture
    ) -> None:
        marker = f"scan-{uuid.uuid4().hex[:12]}"
        since = datetime.datetime.now(datetime.UTC).replace(tzinfo=None) - datetime.timedelta(
            seconds=1
        )
        await _seed_audit_entry(
            audit_sessionmaker,
            action="verdict_issued",
            payload={"scan_id": marker, "verdict": "BLOCK", "policy_version": "v1"},
        )
        await _seed_audit_entry(
            audit_sessionmaker,
            action="verdict_issued",
            payload={"scan_id": f"{marker}-2", "verdict": "PASS", "policy_version": "v1"},
        )
        await _seed_audit_entry(
            audit_sessionmaker,
            action="skill_lifecycle_transition",
            payload={"skill_id": marker, "to_state": "quarantined"},
        )
        await _seed_audit_entry(
            audit_sessionmaker,
            action="breakglass_activated",
            payload={"activated_by": ["alice", "bob"]},
        )

        async with reporting_sessionmaker() as session:
            report = await build_executive_summary(session, since=since)

        own_rows = [r for r in report.rows if str(r["scan_id"]).startswith(marker)]
        assert len(own_rows) == 2
        assert report.summary["lifecycle_transitions"] >= 1
        assert report.summary["breakglass_activations"] >= 1
        assert {r["verdict"] for r in own_rows} == {"BLOCK", "PASS"}


class TestBuildComplianceStatus:
    @pytest.mark.asyncio
    async def test_aggregates_policy_decisions(
        self, reporting_sessionmaker: SessionmakerFixture, audit_sessionmaker: SessionmakerFixture
    ) -> None:
        marker_id = 900000 + uuid.uuid4().int % 90000
        since = datetime.datetime.now(datetime.UTC).replace(tzinfo=None) - datetime.timedelta(
            seconds=1
        )
        await _seed_audit_entry(
            audit_sessionmaker,
            action="policy_proposed",
            payload={
                "proposal_id": marker_id,
                "changes_hard_gate_rules": True,
                "status": "pending",
            },
        )
        await _seed_audit_entry(
            audit_sessionmaker,
            action="policy_approved",
            payload={"proposal_id": marker_id, "proposed_by": "alice"},
            operator="bob",
        )

        async with reporting_sessionmaker() as session:
            report = await build_compliance_status(session, since=since)

        own_rows = [r for r in report.rows if r["proposal_id"] == marker_id]
        assert {r["action"] for r in own_rows} == {"proposed", "approved"}
        assert report.summary["policy_proposals"]["approved"] >= 1


class TestBuildRiskTrend:
    @pytest.mark.asyncio
    async def test_buckets_verdicts_by_day(
        self, reporting_sessionmaker: SessionmakerFixture, audit_sessionmaker: SessionmakerFixture
    ) -> None:
        # NOTE: audit_entry is shared MySQL with no per-test rollback - a fixed
        # calendar date would accumulate more rows every time this test reruns
        # (the risk_trend query has no scan_id filter to scope by), so this
        # picks an effectively-unique day per run instead.
        marker = f"scan-{uuid.uuid4().hex[:12]}"
        day = datetime.datetime(2026, 1, 1) + datetime.timedelta(days=uuid.uuid4().int % 3650)
        since = day - datetime.timedelta(hours=1)
        until = day + datetime.timedelta(hours=1)
        await _seed_audit_entry(
            audit_sessionmaker,
            action="verdict_issued",
            payload={"scan_id": marker, "verdict": "BLOCK"},
            chained_at=day,
        )
        await _seed_audit_entry(
            audit_sessionmaker,
            action="verdict_issued",
            payload={"scan_id": f"{marker}-2", "verdict": "BLOCK"},
            chained_at=day,
        )

        async with reporting_sessionmaker() as session:
            report = await build_risk_trend(session, since=since, until=until)

        assert report.rows == [{"date": day.date().isoformat(), "verdict": "BLOCK", "count": 2}]

    @pytest.mark.asyncio
    async def test_since_until_excludes_out_of_range_entries(
        self, reporting_sessionmaker: SessionmakerFixture, audit_sessionmaker: SessionmakerFixture
    ) -> None:
        marker = f"scan-{uuid.uuid4().hex[:12]}"
        far_past = datetime.datetime(2020, 1, 1, 0, 0, 0)
        await _seed_audit_entry(
            audit_sessionmaker,
            action="verdict_issued",
            payload={"scan_id": marker, "verdict": "REVIEW"},
            chained_at=far_past,
        )
        since = datetime.datetime(2026, 1, 1, 0, 0, 0)
        async with reporting_sessionmaker() as session:
            report = await build_risk_trend(session, since=since)
        assert all(r["date"] != "2020-01-01" for r in report.rows)


class TestBuildEngineCoverage:
    @pytest.mark.asyncio
    async def test_reports_role_status_required_and_disabled(
        self, redis_client: aioredis.Redis, tmp_path: Path
    ) -> None:
        # Real LOCK KEYS (`osv_scanner`, not `osv-scanner`) - the previous
        # version of this test used runtime names as lock keys, which is
        # precisely the assumption the namespace defect was hiding behind: with
        # key == runtime name the broken join looks correct.
        lock_path = tmp_path / "engines.lock.yaml"
        lock_path.write_text(
            yaml.safe_dump(
                {
                    "engines": {
                        "osv_scanner": {"role": "mandatory", "adapter_status": "built"},
                        "aig": {"role": "mandatory"},
                    }
                }
            )
        )
        report = await build_engine_coverage(redis_client, engines_lock_path=lock_path)
        by_key = {r["lock_key"]: r for r in report.rows}
        assert by_key["osv_scanner"]["adapter_status"] == "built"
        assert by_key["aig"]["adapter_status"] == "not_built"
        assert report.summary["total_engines"] == 2
        # Rows are identified by the RUNTIME name, the same identifier the admin
        # console, every finding's source_engine and the frontend's
        # `engine.<name>` labels use.
        assert by_key["osv_scanner"]["name"] == "osv-scanner"
        assert by_key["aig"]["name"] == "aig-mcp-scan"
        assert by_key["osv_scanner"]["required"] == ("osv-scanner" in floor_engine_names())
        assert report.summary["unmapped_lock_keys"] == []

    @pytest.mark.asyncio
    async def test_disabling_an_engine_shows_on_the_row_whose_lock_key_differs(
        self, redis_client: aioredis.Redis, tmp_path: Path
    ) -> None:
        """THE LIVE DEFECT (milestone C Task 2, 2026-07-29): the `disabled` flag
        was `<lock key> in <set of disabled RUNTIME names>`. `osv_scanner` and
        `aig` are not runtime names, so an admin disabling `osv-scanner` never
        showed up on this panel for 2 of the 5 vendored engines - the flag was
        permanently False for them no matter what was toggled.

        Exercises the REAL Redis set the admin endpoint writes, not a stand-in:
        the whole bug lives in the join between that set and the lock file."""
        lock_path = tmp_path / "engines.lock.yaml"
        lock_path.write_text(
            yaml.safe_dump(
                {"engines": {"osv_scanner": {"role": "mandatory"}, "bandit": {"role": "mandatory"}}}
            )
        )
        await redis_client.sadd(DISABLED_ENGINES_KEY, "osv-scanner")  # type: ignore[misc]
        try:
            report = await build_engine_coverage(redis_client, engines_lock_path=lock_path)
            by_key = {r["lock_key"]: r for r in report.rows}
            assert by_key["osv_scanner"]["disabled"] is True
            assert by_key["bandit"]["disabled"] is False
        finally:
            await redis_client.srem(DISABLED_ENGINES_KEY, "osv-scanner")  # type: ignore[misc]

    @pytest.mark.asyncio
    async def test_an_unmapped_lock_key_is_unknown_not_silently_fine(
        self, redis_client: aioredis.Redis, tmp_path: Path
    ) -> None:
        """A newly vendored engine nobody added to `common.engine_names` must
        NOT render as "not required, not disabled" (indistinguishable from a
        healthy row - the exact failure mode being fixed). It renders as
        unknown, and the report summary names it."""
        lock_path = tmp_path / "engines.lock.yaml"
        lock_path.write_text(
            yaml.safe_dump({"engines": {"a_brand_new_engine": {"role": "fill_in"}}})
        )
        report = await build_engine_coverage(redis_client, engines_lock_path=lock_path)
        assert report.rows[0]["required"] is None
        assert report.rows[0]["disabled"] is None
        assert report.summary["unmapped_lock_keys"] == ["a_brand_new_engine"]

    @pytest.mark.asyncio
    async def test_missing_lock_file_fails_soft_not_500(
        self, redis_client: aioredis.Redis, tmp_path: Path
    ) -> None:
        # Regression (found live on the VM/k8s deploy): the runtime image does
        # not ship vendor/engines.lock.yaml, so a missing lock file must degrade
        # to an empty engine-coverage report, never raise (which surfaced as a
        # 500 that broke the dashboard's engine-coverage panel).
        report = await build_engine_coverage(
            redis_client, engines_lock_path=tmp_path / "does-not-exist.yaml"
        )
        assert report.template == "engine_coverage"
        assert report.rows == []
        assert report.summary["total_engines"] == 0


class TestBuildExceptionAudit:
    @pytest.mark.asyncio
    async def test_aggregates_grant_and_revoke_events(
        self, reporting_sessionmaker: SessionmakerFixture, audit_sessionmaker: SessionmakerFixture
    ) -> None:
        # SCOPE NOTE: allowlist grant/revoke isn't wired to an HTTP endpoint or
        # audited yet (task #30) - these seeded rows simulate what that future
        # code path will emit, proving THIS aggregation logic is correct now.
        rule_id = f"rule-{uuid.uuid4().hex[:12]}"
        since = datetime.datetime.now(datetime.UTC).replace(tzinfo=None) - datetime.timedelta(
            seconds=1
        )
        await _seed_audit_entry(
            audit_sessionmaker,
            action="allowlist_granted",
            payload={"rule_id": rule_id, "scope_value": "skill-123"},
        )
        await _seed_audit_entry(
            audit_sessionmaker,
            action="allowlist_revoked",
            payload={"rule_id": rule_id, "scope_value": "skill-123"},
        )

        async with reporting_sessionmaker() as session:
            report = await build_exception_audit(session, since=since)

        own_rows = [r for r in report.rows if r["rule_id"] == rule_id]
        assert {r["action"] for r in own_rows} == {"granted", "revoked"}

    @pytest.mark.asyncio
    async def test_no_matching_events_returns_empty_rows(
        self, reporting_sessionmaker: SessionmakerFixture
    ) -> None:
        far_future = datetime.datetime(2099, 1, 1)
        async with reporting_sessionmaker() as session:
            report = await build_exception_audit(session, since=far_future)
        assert report.rows == []
        assert report.summary == {"total_granted": 0, "total_revoked": 0}


class TestGenerateReport:
    @pytest.mark.asyncio
    async def test_dispatches_to_the_right_builder(
        self, reporting_sessionmaker: SessionmakerFixture, redis_client: aioredis.Redis
    ) -> None:
        async with reporting_sessionmaker() as session:
            report = await generate_report("engine_coverage", session=session, redis=redis_client)
        assert report.template == "engine_coverage"

    @pytest.mark.asyncio
    async def test_unknown_template_raises(
        self, reporting_sessionmaker: SessionmakerFixture, redis_client: aioredis.Redis
    ) -> None:
        with pytest.raises(UnknownReportTemplateError):
            async with reporting_sessionmaker() as session:
                await generate_report("bogus", session=session, redis=redis_client)


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
        file_path="skill/main.py",
        start_line=1,
        snippet_hash="a" * 64,
        evidence_redacted="secret=<redacted>",
    )


class TestExportSarifForScans:
    @pytest.mark.asyncio
    async def test_bundles_findings_across_requested_scans(
        self,
        reporting_sessionmaker: SessionmakerFixture,
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

        async with reporting_sessionmaker() as session:
            sarif = await export_sarif_for_scans(session, [scan_id])

        assert len(sarif["runs"][0]["results"]) == 1
        assert sarif["runs"][0]["results"][0]["ruleId"] == "static.secret"

    @pytest.mark.asyncio
    async def test_reporting_session_cannot_write_scan_result(
        self, reporting_sessionmaker: SessionmakerFixture
    ) -> None:
        # SECURITY: proves the SELECT-only grant on scan_result is real at the
        # DB layer, same isolation-proving pattern as test_grant_isolation.py.
        with pytest.raises(DBAPIError):
            async with reporting_sessionmaker() as session, session.begin():
                session.add(
                    ScanResultRow(
                        scan_id=str(uuid.uuid4()),
                        content_hash="b" * 64,
                        severity=1,
                        confidence_at_max=0.1,
                        trifecta_present=False,
                        findings_capped=False,
                        required_ok=True,
                        findings=[],
                        provenance=[],
                        hard_gate_hits=[],
                    )
                )
                await session.flush()


class TestReportingSessionCannotWriteAuditEntry:
    @pytest.mark.asyncio
    async def test_insert_is_rejected(self, reporting_sessionmaker: SessionmakerFixture) -> None:
        # SECURITY: proves svc_reporting's audit_entry grant is genuinely
        # SELECT-only, not just an application-layer convention.
        with pytest.raises(DBAPIError):
            async with reporting_sessionmaker() as session, session.begin():
                session.add(
                    AuditEntry(
                        prev_hash="0" * 64,
                        entry_hash="x" * 64,
                        operator="attacker",
                        action="forged",
                        payload={},
                        chained_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                    )
                )
                await session.flush()


class TestExportCsv:
    @pytest.mark.asyncio
    async def test_csv_with_rows_has_header_and_data(
        self, reporting_sessionmaker: SessionmakerFixture, redis_client: aioredis.Redis
    ) -> None:
        async with reporting_sessionmaker() as session:
            report = await generate_report("engine_coverage", session=session, redis=redis_client)
        csv_text = export_csv(report)
        lines = csv_text.strip().splitlines()
        assert "name" in lines[0]
        assert len(lines) == len(report.rows) + 1

    def test_csv_with_no_rows_falls_back_to_summary(self) -> None:
        from monolith.modules.reporting.service import Report

        report = Report(template="x", since=None, until=None, summary={"a": 1}, rows=[])
        csv_text = export_csv(report)
        assert "key,value" in csv_text
        assert "a,1" in csv_text


class TestExportPdf:
    @pytest.mark.asyncio
    async def test_produces_structurally_valid_pdf_bytes(
        self, reporting_sessionmaker: SessionmakerFixture, redis_client: aioredis.Redis
    ) -> None:
        async with reporting_sessionmaker() as session:
            report = await generate_report("engine_coverage", session=session, redis=redis_client)
        pdf_bytes = export_pdf(report)
        assert pdf_bytes.startswith(b"%PDF-")
        assert b"%%EOF" in pdf_bytes[-64:]

    def test_handles_empty_rows(self) -> None:
        from monolith.modules.reporting.service import Report

        report = Report(template="x", since=None, until=None, summary={"a": 1}, rows=[])
        pdf_bytes = export_pdf(report)
        assert pdf_bytes.startswith(b"%PDF-")
