"""Tests for `gate.service` (coding spec §11.3/§11.6, INV-12/INV-13) against
the real local MySQL instance - `decide_and_record`'s outbox payload and
`list_issued_verdicts`' cross-module read boundary, plus a real DB-level
proof that a replayed `jti` is rejected (the `uq_jti` UNIQUE constraint,
coding spec §7.1) rather than merely assumed from `sign_verdict` always
generating a fresh one.
"""

from __future__ import annotations

import datetime
import time
import uuid

import jwt as pyjwt
import pytest
from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    Finding,
    GatePolicy,
    ScanResult,
    Severity,
    TrustTier,
    Verdict,
)
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from monolith.modules.audit.models import AuditIntent
from monolith.modules.gate.models import AllowlistRow, GateOutboxRow, VerdictRow
from monolith.modules.gate.service import (
    AllowlistError,
    decide_and_record,
    grant_allowlist_entry,
    list_active_allowlist_entries,
    list_issued_verdicts,
    revoke_allowlist_entry,
)
from monolith.modules.gate.signer import LocalDevSigner
from monolith.tests.conftest import SessionmakerFixture


def _scan_result(*, content_hash: str, findings: tuple[Finding, ...] = ()) -> ScanResult:
    # SECURITY: decide() derives its verdict from `findings`' own severities
    # (skillscan_core.gate.evaluate_findings), NOT from a top-level severity
    # field - ScanResult carries no such field to (mis)set here.
    return ScanResult(
        content_hash=content_hash,
        severity=max((f.severity for f in findings), default=Severity.NONE),
        confidence_at_max=max((f.confidence for f in findings), default=0.0),
        trifecta_present=False,
        hard_gate_hits=(),
        findings=findings,
        engine_provenance=(),
        findings_capped=False,
        required_ok=True,
        missing_or_failed_required=(),
    )


def _critical_finding() -> Finding:
    return Finding(
        rule_id="test.critical_finding",
        test_item_id="TEST-01",
        category=DetectionCategory.CODE,
        title="critical test finding",
        severity=Severity.CRITICAL,
        confidence=0.95,
        source_engine="test-engine",
        source_capability=EngineCapability.STATIC,
    )


def _policy(*, version: str) -> GatePolicy:
    return GatePolicy(
        version=version,
        required_engines=frozenset(),
        hard_gate_rules=frozenset(),
        fail_closed_verdict=Verdict.BLOCK,
    )


class TestDecideAndRecord:
    @pytest.mark.asyncio
    async def test_outbox_payload_carries_the_jws_itself(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        # SECURITY: svc_relay has no GRANT on `verdict` - the outbox payload
        # MUST carry the actual JWS, since relay has no other way to fetch it
        # for MarketplacePort.write_verdict (see gate/service.py's own comment).
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex
        scan_id = str(uuid.uuid4())
        signer = LocalDevSigner()

        async with gate_sessionmaker() as session, session.begin():
            await decide_and_record(
                session,
                scan_id=scan_id,
                scan_result=_scan_result(content_hash=content_hash),
                policy=_policy(version=f"test-{uuid.uuid4().hex[:8]}"),
                trust_tier=TrustTier.INTERNAL,
                allowlist=(),
                signer=signer,
                operator="tester",
                now=time.time(),
            )

        async with gate_sessionmaker() as session:
            row = (
                await session.execute(
                    select(GateOutboxRow).where(GateOutboxRow.aggregate_id == scan_id)
                )
            ).scalar_one()
        assert "jws" in row.payload
        assert isinstance(row.payload["jws"], str)
        assert len(row.payload["jws"]) > 0

    @pytest.mark.asyncio
    async def test_policy_version_recorded_on_the_verdict(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex
        scan_id = str(uuid.uuid4())
        policy_version = f"policy-version-{uuid.uuid4().hex[:8]}"

        async with gate_sessionmaker() as session, session.begin():
            result = await decide_and_record(
                session,
                scan_id=scan_id,
                scan_result=_scan_result(content_hash=content_hash),
                policy=_policy(version=policy_version),
                trust_tier=TrustTier.INTERNAL,
                allowlist=(),
                signer=LocalDevSigner(),
                operator="tester",
                now=time.time(),
            )
        assert result.policy_version == policy_version

        async with gate_sessionmaker() as session:
            row = (
                await session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
            ).scalar_one()
        assert row.policy_version == policy_version

    @pytest.mark.asyncio
    async def test_score_is_recorded_on_the_verdict_row(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex
        scan_id = str(uuid.uuid4())

        async with gate_sessionmaker() as session, session.begin():
            result = await decide_and_record(
                session,
                scan_id=scan_id,
                scan_result=_scan_result(content_hash=content_hash),
                policy=_policy(version=f"test-{uuid.uuid4().hex[:8]}"),
                trust_tier=TrustTier.INTERNAL,
                allowlist=(),
                signer=LocalDevSigner(),
                operator="tester",
                now=time.time(),
            )
        assert result.score == 100  # PASS, no findings

        async with gate_sessionmaker() as session:
            row = (
                await session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
            ).scalar_one()
        assert row.score == 100

    @pytest.mark.asyncio
    async def test_score_is_signed_into_the_jws(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex
        scan_id = str(uuid.uuid4())

        async with gate_sessionmaker() as session, session.begin():
            await decide_and_record(
                session,
                scan_id=scan_id,
                scan_result=_scan_result(
                    content_hash=content_hash, findings=(_critical_finding(),)
                ),
                policy=_policy(version=f"test-{uuid.uuid4().hex[:8]}"),
                trust_tier=TrustTier.INTERNAL,
                allowlist=(),
                signer=LocalDevSigner(),
                operator="tester",
                now=time.time(),
            )

        async with gate_sessionmaker() as session:
            row = (
                await session.execute(select(VerdictRow).where(VerdictRow.scan_id == scan_id))
            ).scalar_one()
        claims = pyjwt.decode(row.jws_signature, options={"verify_signature": False})
        assert claims["score"] == row.score


class TestListIssuedVerdicts:
    @pytest.mark.asyncio
    async def test_returns_content_hash_and_verdict_for_recorded_rows(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        content_hash = uuid.uuid4().hex + uuid.uuid4().hex
        async with gate_sessionmaker() as session, session.begin():
            await decide_and_record(
                session,
                scan_id=str(uuid.uuid4()),
                scan_result=_scan_result(
                    content_hash=content_hash, findings=(_critical_finding(),)
                ),
                policy=_policy(version=f"test-{uuid.uuid4().hex[:8]}"),
                trust_tier=TrustTier.INTERNAL,
                allowlist=(),
                signer=LocalDevSigner(),
                operator="tester",
                now=time.time(),
            )

        async with gate_sessionmaker() as session:
            issued = await list_issued_verdicts(session)
        matching = [v for v in issued if v.content_hash == content_hash]
        assert len(matching) == 1
        assert matching[0].verdict == "BLOCK"  # CRITICAL severity -> BLOCK by default policy


class TestJtiReplayRejectedAtDbLayer:
    @pytest.mark.asyncio
    async def test_duplicate_jti_insert_rejected_by_unique_constraint(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        # SECURITY (INV-13 anti-replay): the `uq_jti` UNIQUE constraint (coding
        # spec §7.1) is what actually enforces "a jti can never be recorded
        # twice" - proven here directly against the real schema, not merely
        # inferred from sign_verdict always generating a fresh uuid4.
        shared_jti = str(uuid.uuid4())
        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)

        async with gate_sessionmaker() as session, session.begin():
            session.add(
                VerdictRow(
                    scan_id=str(uuid.uuid4()),
                    content_hash=uuid.uuid4().hex + uuid.uuid4().hex,
                    verdict="PASS",
                    score=87,
                    policy_version="v1",
                    jti=shared_jti,
                    jws_signature="sig-1",
                    effective_severity=0,
                    reasons=[],
                    issued_at=now,
                )
            )

        with pytest.raises(IntegrityError):
            async with gate_sessionmaker() as session, session.begin():
                session.add(
                    VerdictRow(
                        scan_id=str(uuid.uuid4()),
                        content_hash=uuid.uuid4().hex + uuid.uuid4().hex,
                        verdict="PASS",
                        score=87,
                        policy_version="v1",
                        jti=shared_jti,  # SECURITY: same jti - must be rejected
                        jws_signature="sig-2",
                        effective_severity=0,
                        reasons=[],
                        issued_at=now,
                    )
                )


class TestGrantAllowlistEntry:
    @pytest.mark.asyncio
    async def test_valid_grant_persists_and_is_audited(
        self, gate_sessionmaker: SessionmakerFixture, audit_sessionmaker: SessionmakerFixture
    ) -> None:
        rule_id = f"rule-{uuid.uuid4().hex[:12]}"
        async with gate_sessionmaker() as session, session.begin():
            row = await grant_allowlist_entry(
                session,
                scope_type="skill_id",
                scope_value="skill-123",
                rule_id=rule_id,
                expires_at=time.time() + 3600,
                approved_by="admin-bob",
                requested_by="admin-alice",
            )
        assert row.id is not None

        async with audit_sessionmaker() as session:
            result = await session.execute(
                select(AuditIntent).where(AuditIntent.action == "allowlist_granted")
            )
            intents = [r for r in result.scalars().all() if r.payload.get("allowlist_id") == row.id]
        assert len(intents) == 1
        assert intents[0].payload["rule_id"] == rule_id

    @pytest.mark.asyncio
    async def test_self_approval_rejected_four_eyes(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        with pytest.raises(AllowlistError, match="four-eyes"):
            async with gate_sessionmaker() as session, session.begin():
                await grant_allowlist_entry(
                    session,
                    scope_type="skill_id",
                    scope_value="skill-123",
                    rule_id="rule-x",
                    expires_at=time.time() + 3600,
                    approved_by="admin-alice",
                    requested_by="admin-alice",
                )

    @pytest.mark.asyncio
    async def test_already_expired_grant_rejected(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        with pytest.raises(AllowlistError):
            async with gate_sessionmaker() as session, session.begin():
                await grant_allowlist_entry(
                    session,
                    scope_type="skill_id",
                    scope_value="skill-123",
                    rule_id="rule-x",
                    expires_at=-1.0,
                    approved_by="admin-bob",
                    requested_by="admin-alice",
                )

    @pytest.mark.asyncio
    async def test_invalid_scope_type_rejected(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        with pytest.raises(AllowlistError):
            async with gate_sessionmaker() as session, session.begin():
                await grant_allowlist_entry(
                    session,
                    scope_type="not_a_real_scope",
                    scope_value="skill-123",
                    rule_id="rule-x",
                    expires_at=time.time() + 3600,
                    approved_by="admin-bob",
                    requested_by="admin-alice",
                )


class TestListActiveAllowlistEntries:
    @pytest.mark.asyncio
    async def test_excludes_expired_entries(self, gate_sessionmaker: SessionmakerFixture) -> None:
        rule_id = f"rule-{uuid.uuid4().hex[:12]}"
        now = time.time()
        async with gate_sessionmaker() as session, session.begin():
            await grant_allowlist_entry(
                session,
                scope_type="skill_id",
                scope_value="skill-active",
                rule_id=rule_id,
                expires_at=now + 3600,
                approved_by="admin-bob",
                requested_by="admin-alice",
            )
        # a manually-inserted, already-expired row (grant_allowlist_entry
        # itself refuses to create one) to prove the query excludes it
        expired_rule_id = f"rule-{uuid.uuid4().hex[:12]}"
        async with gate_sessionmaker() as session, session.begin():
            session.add(
                AllowlistRow(
                    id=str(uuid.uuid4()),
                    scope_type="skill_id",
                    scope_value="skill-expired",
                    rule_id=expired_rule_id,
                    expires_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
                    - datetime.timedelta(hours=1),
                    approved_by="admin-bob",
                    requested_by="admin-alice",
                )
            )

        async with gate_sessionmaker() as session:
            active = await list_active_allowlist_entries(session, now=now)
        rule_ids = {e.rule_id for e in active}
        assert rule_id in rule_ids
        assert expired_rule_id not in rule_ids


class TestRevokeAllowlistEntry:
    @pytest.mark.asyncio
    async def test_revoke_deletes_row_and_audits(
        self, gate_sessionmaker: SessionmakerFixture, audit_sessionmaker: SessionmakerFixture
    ) -> None:
        async with gate_sessionmaker() as session, session.begin():
            row = await grant_allowlist_entry(
                session,
                scope_type="skill_id",
                scope_value="skill-123",
                rule_id=f"rule-{uuid.uuid4().hex[:12]}",
                expires_at=time.time() + 3600,
                approved_by="admin-bob",
                requested_by="admin-alice",
            )
        allowlist_id = row.id

        async with gate_sessionmaker() as session, session.begin():
            await revoke_allowlist_entry(session, allowlist_id=allowlist_id, actor="admin-carol")

        async with gate_sessionmaker() as session:
            assert await session.get(AllowlistRow, allowlist_id) is None

        async with audit_sessionmaker() as session:
            result = await session.execute(
                select(AuditIntent).where(AuditIntent.action == "allowlist_revoked")
            )
            intents = [
                r for r in result.scalars().all() if r.payload.get("allowlist_id") == allowlist_id
            ]
        assert len(intents) == 1
        assert intents[0].operator == "admin-carol"

    @pytest.mark.asyncio
    async def test_revoking_unknown_id_raises(self, gate_sessionmaker: SessionmakerFixture) -> None:
        with pytest.raises(AllowlistError, match="not found"):
            async with gate_sessionmaker() as session, session.begin():
                await revoke_allowlist_entry(
                    session, allowlist_id=str(uuid.uuid4()), actor="admin-carol"
                )
