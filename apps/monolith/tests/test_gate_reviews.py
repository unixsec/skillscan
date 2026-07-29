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
import redis.asyncio as aioredis
from common.blobstore import LocalFilesystemBlobStore
from schemas.findings import serialize_finding
from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    Finding,
    GatePolicy,
    Severity,
    StaticKeywordEngine,
    TrustTier,
)
from sqlalchemy import select

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
from monolith.modules.orchestration.models import ScanJob, ScanResultRow, ScanSubmitterRow
from monolith.modules.orchestration.service import SubmissionChannel, submit_scan
from monolith.tests.conftest import SessionmakerFixture


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


async def _seed_result_and_verdict(
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    *,
    scan_id: str,
    content_hash: str,
    verdict: str = "REVIEW",
) -> None:
    """The REVIEW-pending state for an ALREADY-EXISTING scan_job.

    Split out of `_seed_review_scan` (Task 18) so the SoD cases below can seed
    it onto a scan_job produced by the REAL `submit_scan` dedup path rather
    than by a hand-written `ScanJob` insert - the whole point there is that the
    scan_job and its `scan_submitter` rows were written by production code.
    """
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


async def _seed_review_scan(
    orchestration_sessionmaker: SessionmakerFixture,
    gate_sessionmaker: SessionmakerFixture,
    *,
    scan_id: str,
    submitter: str,
    verdict: str = "REVIEW",
) -> None:
    content_hash = uuid.uuid4().hex + uuid.uuid4().hex
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
    # NOTE: writes NO `scan_submitter` rows, deliberately - this helper is the
    # "scalar submitter only, association table empty" shape that
    # `reeval.controller.build_rescan_job` also produces, and
    # `test_same_person_as_submitter_is_sod_violation` below is what keeps SoD
    # armed for it.
    await _seed_result_and_verdict(
        orchestration_sessionmaker,
        gate_sessionmaker,
        scan_id=scan_id,
        content_hash=content_hash,
        verdict=verdict,
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
                # These cases seed a content_hash that inventory has never
                # registered, so there is no lifecycle for I3's supersession
                # check to consult - `None` says that explicitly rather than
                # opening a session that would only ever return None.
                inventory_session=None,
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
                # These cases seed a content_hash that inventory has never
                # registered, so there is no lifecycle for I3's supersession
                # check to consult - `None` says that explicitly rather than
                # opening a session that would only ever return None.
                inventory_session=None,
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
                # These cases seed a content_hash that inventory has never
                # registered, so there is no lifecycle for I3's supersession
                # check to consult - `None` says that explicitly rather than
                # opening a session that would only ever return None.
                inventory_session=None,
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
                    inventory_session=None,  # no registered skill - see above
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
                    inventory_session=None,  # no registered skill - see above
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
                    inventory_session=None,  # no registered skill - see above
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
                    inventory_session=None,  # no registered skill - see above
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


_DEDUP_ENGINE = StaticKeywordEngine()


def _dedup_policy() -> GatePolicy:
    return GatePolicy(
        version="sod-dedup-v1",
        required_engines=frozenset({_DEDUP_ENGINE.metadata.name}),
    )


async def _two_submitters_onto_one_scan(
    orchestration_sessionmaker: SessionmakerFixture,
    redis_client: aioredis.Redis,
    blobstore: LocalFilesystemBlobStore,
) -> str:
    """Alice submits, then Bob submits the SAME bytes - through the real
    `submit_scan`, so the dedup and the `scan_submitter` rows are production's
    doing and not the test's.

    Returns the single scan_id both were handed.
    """
    files = [("skill.py", 0o644, f"# {uuid.uuid4().hex}\n".encode())]
    policy = _dedup_policy()
    scan_ids: list[str] = []
    for submitter in ("dev-alice", "dev-bob"):
        async with orchestration_sessionmaker() as session, session.begin():
            scan_ids.append(
                await submit_scan(
                    session,
                    redis_client,
                    blobstore,
                    files=files,
                    submitter=submitter,
                    engine_metadatas=(_DEDUP_ENGINE.metadata,),
                    policy=policy,
                    trust_tier=TrustTier.INTERNAL,
                    source=SubmissionChannel.CONSOLE,
                    requested_trust_tier=TrustTier.INTERNAL,
                )
            )
    assert scan_ids[0] == scan_ids[1], (
        "single-flight dedup did not collapse two identical submissions - the "
        "premise of every case below"
    )
    return scan_ids[0]


class TestSodReadsTheAssociationTableNotTheFirstSubmitter:
    """SECURITY (milestone F Task 18): SoD keyed on `ScanJob.submitter` alone -
    the FIRST submitter - let a CO-submitter approve their own submission.

    Bob submits bytes Alice already submitted; single-flight dedup hands Bob
    Alice's scan_job, `submit_scan` records Bob in `scan_submitter` (he is a
    rightful submitter: he can read the scan, and it appears in his own scan
    list), but `scan_job.submitter` still says "dev-alice". `reviewer ==
    job.submitter` therefore compared Bob against Alice, found them different,
    and approved. Every other object-level check in this system had already
    been moved onto the association table by milestone B' review C2; the review
    path had not.
    """

    @pytest.mark.asyncio
    async def test_a_co_submitter_of_a_deduplicated_scan_cannot_approve_it(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        scan_id = await _two_submitters_onto_one_scan(
            orchestration_sessionmaker, redis_client, blobstore
        )

        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
            associated = set(
                (
                    await session.execute(
                        select(ScanSubmitterRow.submitter).where(
                            ScanSubmitterRow.scan_id == scan_id
                        )
                    )
                )
                .scalars()
                .all()
            )
        # The exact shape of the bypass, asserted rather than assumed: the
        # scalar column names ONLY Alice, so the old `reviewer ==
        # job.submitter` test could not see Bob at all - while the association
        # table, the authorization source everywhere else, names them both.
        assert job.submitter == "dev-alice"
        assert associated == {"dev-alice", "dev-bob"}

        await _seed_result_and_verdict(
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            content_hash=job.content_hash,
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
                    inventory_session=None,  # no registered skill - see above
                    scan_id=scan_id,
                    decision="approve",
                    reviewer="dev-bob",
                    reason="approving my own submission",
                    signer=LocalDevSigner(),
                )

        # Nothing was written. A SoD refusal that still rewrote and re-signed
        # the verdict would be the same failure wearing an exception.
        async with gate_sessionmaker() as session:
            row = await session.get(VerdictRow, scan_id)
        assert row is not None
        assert row.verdict == "REVIEW"
        assert row.jws_signature == "original-sig"

    @pytest.mark.asyncio
    async def test_the_first_submitter_of_a_deduplicated_scan_still_cannot_approve_it(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        # The case that always worked, kept so the widened check cannot regress
        # into "only co-submitters are refused".
        scan_id = await _two_submitters_onto_one_scan(
            orchestration_sessionmaker, redis_client, blobstore
        )
        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        await _seed_result_and_verdict(
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            content_hash=job.content_hash,
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
                    inventory_session=None,  # no registered skill - see above
                    scan_id=scan_id,
                    decision="approve",
                    reviewer="dev-alice",
                    reason="approving my own submission",
                    signer=LocalDevSigner(),
                )

    @pytest.mark.asyncio
    async def test_an_unrelated_approver_can_still_decide_a_deduplicated_scan(
        self,
        orchestration_sessionmaker: SessionmakerFixture,
        gate_sessionmaker: SessionmakerFixture,
        redis_client: aioredis.Redis,
        blobstore: LocalFilesystemBlobStore,
    ) -> None:
        # The other half of the fix: widening a DENY rule must not start
        # refusing people it has no business refusing. Carol submitted nothing,
        # so she is in neither the scalar column nor the association table.
        scan_id = await _two_submitters_onto_one_scan(
            orchestration_sessionmaker, redis_client, blobstore
        )
        async with orchestration_sessionmaker() as session:
            job = (
                await session.execute(select(ScanJob).where(ScanJob.scan_id == scan_id))
            ).scalar_one()
        await _seed_result_and_verdict(
            orchestration_sessionmaker,
            gate_sessionmaker,
            scan_id=scan_id,
            content_hash=job.content_hash,
        )

        async with (
            orchestration_sessionmaker() as orch_session,
            gate_sessionmaker() as gate_session,
            gate_session.begin(),
        ):
            result = await submit_review_decision(
                orchestration_session=orch_session,
                gate_session=gate_session,
                inventory_session=None,  # no registered skill - see above
                scan_id=scan_id,
                decision="approve",
                reviewer="approver-carol",
                reason="reviewed, looks fine",
                signer=LocalDevSigner(),
            )
        assert result.verdict == "PASS"
