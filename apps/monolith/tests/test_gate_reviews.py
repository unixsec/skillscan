"""Tests for `gate.reviews` (coding spec §9 `POST /v1/reviews/{scan_id}`,
SoD) against the real local MySQL instance - holds both an orchestration-
credentialed and a gate-credentialed session at once, same pattern as
reeval.service's reconciliation functions.
"""

from __future__ import annotations

import datetime
import uuid

import jwt as pyjwt
import pytest
from schemas.findings import serialize_finding
from skillscan_core import DetectionCategory, EngineCapability, Finding, Severity

from monolith.modules.gate.models import VerdictRow
from monolith.modules.gate.reviews import (
    InvalidDecisionError,
    NotPendingReviewError,
    ReviewNotFoundError,
    SodViolationError,
    submit_review_decision,
)
from monolith.modules.gate.service import list_pending_reviews
from monolith.modules.gate.signer import LocalDevSigner
from monolith.modules.orchestration.models import ScanJob, ScanResultRow
from monolith.tests.conftest import SessionmakerFixture


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


async def _seed_review_scan(
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    *,
    scan_id: str,
    submitter: str,
    verdict: str = "REVIEW",
) -> None:
    content_hash = uuid.uuid4().hex + uuid.uuid4().hex
    # One MEDIUM/0.8-confidence finding, so submit_review_decision's new
    # score-recompute has something real to work with. With the default
    # CategoryWeights (all 1.0): penalty = 8.0 * 0.8 * 1.0 = 6.4, so
    # approve->PASS band[75,100] scores round(100-6.4)=94, and
    # reject->BLOCK band[0,39] scores round(39-6.4)=33 - both asserted below.
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
                verdict=verdict,
                score={"PASS": 87, "REVIEW": 57, "BLOCK": 20}[verdict],
                policy_version="v1",
                jti=str(uuid.uuid4()),
                jws_signature="original-sig",
                effective_severity=2,
                reasons=["automated: ambiguous"],
                issued_at=_naive_utcnow(),
            )
        )


class TestSubmitReviewDecision:
    @pytest.mark.asyncio
    async def test_approve_sets_verdict_to_pass(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )

        async with (
            orchestration_sessionmaker() as orch_session,
            gate_sessionmaker() as gate_session,
            gate_session.begin(),
        ):
            result = await submit_review_decision(
                orchestration_session=orch_session,
                gate_session=gate_session,
                scan_id=scan_id,
                decision="approve",
                reviewer="approver-carol",
                reason="reviewed, looks fine",
                signer=LocalDevSigner(),
            )
        assert result.verdict == "PASS"
        assert result.score == 94
        assert "manual review by approver-carol" in result.reasons[-1]

    @pytest.mark.asyncio
    async def test_reject_sets_verdict_to_block(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )

        async with (
            orchestration_sessionmaker() as orch_session,
            gate_sessionmaker() as gate_session,
            gate_session.begin(),
        ):
            result = await submit_review_decision(
                orchestration_session=orch_session,
                gate_session=gate_session,
                scan_id=scan_id,
                decision="reject",
                reviewer="approver-carol",
                reason="confirmed malicious",
                signer=LocalDevSigner(),
            )
        assert result.verdict == "BLOCK"
        assert result.score == 33

    @pytest.mark.asyncio
    async def test_approve_signs_score_into_the_jws(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )

        async with (
            orchestration_sessionmaker() as orch_session,
            gate_sessionmaker() as gate_session,
            gate_session.begin(),
        ):
            result = await submit_review_decision(
                orchestration_session=orch_session,
                gate_session=gate_session,
                scan_id=scan_id,
                decision="approve",
                reviewer="approver-carol",
                reason="reviewed, looks fine",
                signer=LocalDevSigner(),
            )

        claims = pyjwt.decode(result.jws_signature, options={"verify_signature": False})
        assert claims["score"] == result.score == 94

    @pytest.mark.asyncio
    async def test_same_person_as_submitter_is_sod_violation(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )

        with pytest.raises(SodViolationError):
            async with (
                orchestration_sessionmaker() as orch_session,
                gate_sessionmaker() as gate_session,
                gate_session.begin(),
            ):
                await submit_review_decision(
                    orchestration_session=orch_session,
                    gate_session=gate_session,
                    scan_id=scan_id,
                    decision="approve",
                    reviewer="dev-dave",
                    reason="x",
                    signer=LocalDevSigner(),
                )

    @pytest.mark.asyncio
    async def test_invalid_decision_value_rejected(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker, gate_sessionmaker, scan_id=scan_id, submitter="dev-dave"
        )

        with pytest.raises(InvalidDecisionError):
            async with (
                orchestration_sessionmaker() as orch_session,
                gate_sessionmaker() as gate_session,
                gate_session.begin(),
            ):
                await submit_review_decision(
                    orchestration_session=orch_session,
                    gate_session=gate_session,
                    scan_id=scan_id,
                    decision="maybe",
                    reviewer="approver-carol",
                    reason="x",
                    signer=LocalDevSigner(),
                )

    @pytest.mark.asyncio
    async def test_unknown_scan_id_raises_not_found(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        with pytest.raises(ReviewNotFoundError):
            async with (
                orchestration_sessionmaker() as orch_session,
                gate_sessionmaker() as gate_session,
                gate_session.begin(),
            ):
                await submit_review_decision(
                    orchestration_session=orch_session,
                    gate_session=gate_session,
                    scan_id=str(uuid.uuid4()),
                    decision="approve",
                    reviewer="approver-carol",
                    reason="x",
                    signer=LocalDevSigner(),
                )

    @pytest.mark.asyncio
    async def test_already_decided_scan_raises_conflict(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            submitter="dev-dave",
            verdict="PASS",  # not pending review
        )

        with pytest.raises(NotPendingReviewError):
            async with (
                orchestration_sessionmaker() as orch_session,
                gate_sessionmaker() as gate_session,
                gate_session.begin(),
            ):
                await submit_review_decision(
                    orchestration_session=orch_session,
                    gate_session=gate_session,
                    scan_id=scan_id,
                    decision="approve",
                    reviewer="approver-carol",
                    reason="x",
                    signer=LocalDevSigner(),
                )


class TestListPendingReviews:
    @pytest.mark.asyncio
    async def test_lists_only_review_verdicts(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
    ) -> None:
        review_scan_id = str(uuid.uuid4())
        pass_scan_id = str(uuid.uuid4())
        await _seed_review_scan(
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=review_scan_id,
            submitter="dev-dave",
            verdict="REVIEW",
        )
        await _seed_review_scan(
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=pass_scan_id,
            submitter="dev-dave",
            verdict="PASS",
        )

        async with gate_sessionmaker() as session:
            pending = await list_pending_reviews(session)
        pending_ids = {v.scan_id for v in pending}
        assert review_scan_id in pending_ids
        assert pass_scan_id not in pending_ids
