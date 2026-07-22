"""Tests for `gate.policy_workflow` (coding spec §9/§16.1: two-person
hard-gate policy approval) against the real local MySQL instance.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from monolith.modules.audit.models import AuditIntent
from monolith.modules.gate.policy_workflow import (
    PolicyProposalError,
    approve_policy_proposal,
    propose_policy_change,
    reject_policy_proposal,
)
from monolith.tests.conftest import SessionmakerFixture

_BASE_POLICY_YAML = """
version: "v2"
required_engines:
  - static-keyword
"""


class TestProposePolicyChange:
    @pytest.mark.asyncio
    async def test_non_hard_gate_change_is_auto_approved(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        async with gate_sessionmaker() as session, session.begin():
            proposal = await propose_policy_change(
                session,
                proposed_by="alice",
                current_hard_gate_rules=frozenset(),
                proposed_policy_yaml=_BASE_POLICY_YAML,
            )
        assert proposal.changes_hard_gate_rules is False
        assert proposal.status == "approved"
        assert proposal.approved_by == "alice"

    @pytest.mark.asyncio
    async def test_hard_gate_change_requires_approval(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        new_yaml = _BASE_POLICY_YAML + "hard_gate_rules:\n  - pii.credit_card\n"
        async with gate_sessionmaker() as session, session.begin():
            proposal = await propose_policy_change(
                session,
                proposed_by="alice",
                current_hard_gate_rules=frozenset(),
                proposed_policy_yaml=new_yaml,
            )
        assert proposal.changes_hard_gate_rules is True
        assert proposal.status == "pending"
        assert proposal.approved_by is None

    @pytest.mark.asyncio
    async def test_hard_gate_rules_unchanged_is_not_flagged(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        new_yaml = _BASE_POLICY_YAML + "hard_gate_rules:\n  - pii.credit_card\n"
        async with gate_sessionmaker() as session, session.begin():
            proposal = await propose_policy_change(
                session,
                proposed_by="alice",
                current_hard_gate_rules=frozenset({"pii.credit_card"}),
                proposed_policy_yaml=new_yaml,
            )
        assert proposal.changes_hard_gate_rules is False
        assert proposal.status == "approved"

    @pytest.mark.asyncio
    async def test_invalid_policy_yaml_rejected_before_recording(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        with pytest.raises(PolicyProposalError, match="invalid"):
            async with gate_sessionmaker() as session, session.begin():
                await propose_policy_change(
                    session,
                    proposed_by="alice",
                    current_hard_gate_rules=frozenset(),
                    proposed_policy_yaml="not: valid: policy: [",
                )

    @pytest.mark.asyncio
    async def test_policy_missing_required_fields_rejected(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        with pytest.raises(PolicyProposalError, match="invalid"):
            async with gate_sessionmaker() as session, session.begin():
                await propose_policy_change(
                    session,
                    proposed_by="alice",
                    current_hard_gate_rules=frozenset(),
                    proposed_policy_yaml="version: v2\n",  # missing required_engines
                )


class TestApprovePolicyProposal:
    @pytest.mark.asyncio
    async def test_different_admin_can_approve(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        new_yaml = _BASE_POLICY_YAML + "hard_gate_rules:\n  - pii.credit_card\n"
        async with gate_sessionmaker() as session, session.begin():
            proposal = await propose_policy_change(
                session,
                proposed_by="alice",
                current_hard_gate_rules=frozenset(),
                proposed_policy_yaml=new_yaml,
            )
        async with gate_sessionmaker() as session, session.begin():
            session.add(proposal)
            await approve_policy_proposal(session, proposal, approved_by="bob")
        assert proposal.status == "approved"
        assert proposal.approved_by == "bob"

    @pytest.mark.asyncio
    async def test_same_person_cannot_approve_their_own_proposal(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        # SECURITY (four-eyes): the whole point of this workflow.
        new_yaml = _BASE_POLICY_YAML + "hard_gate_rules:\n  - pii.credit_card\n"
        async with gate_sessionmaker() as session, session.begin():
            proposal = await propose_policy_change(
                session,
                proposed_by="alice",
                current_hard_gate_rules=frozenset(),
                proposed_policy_yaml=new_yaml,
            )
        with pytest.raises(PolicyProposalError, match="four-eyes"):
            async with gate_sessionmaker() as session, session.begin():
                session.add(proposal)
                await approve_policy_proposal(session, proposal, approved_by="alice")

    @pytest.mark.asyncio
    async def test_cannot_approve_an_already_approved_proposal(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        async with gate_sessionmaker() as session, session.begin():
            proposal = await propose_policy_change(
                session,
                proposed_by="alice",
                current_hard_gate_rules=frozenset(),
                proposed_policy_yaml=_BASE_POLICY_YAML,  # no hard-gate change -> auto-approved
            )
        with pytest.raises(PolicyProposalError, match="not pending"):
            async with gate_sessionmaker() as session, session.begin():
                session.add(proposal)
                await approve_policy_proposal(session, proposal, approved_by="bob")


class TestRejectPolicyProposal:
    @pytest.mark.asyncio
    async def test_reject_records_reason_and_rejecter(
        self, gate_sessionmaker: SessionmakerFixture
    ) -> None:
        new_yaml = _BASE_POLICY_YAML + "hard_gate_rules:\n  - pii.credit_card\n"
        async with gate_sessionmaker() as session, session.begin():
            proposal = await propose_policy_change(
                session,
                proposed_by="alice",
                current_hard_gate_rules=frozenset(),
                proposed_policy_yaml=new_yaml,
            )
        async with gate_sessionmaker() as session, session.begin():
            session.add(proposal)
            await reject_policy_proposal(session, proposal, rejected_by="bob", reason="too broad")
        assert proposal.status == "rejected"
        assert proposal.approved_by == "bob"
        assert proposal.reason == "too broad"


class TestPolicyWorkflowAuditTrail:
    """SECURITY (coding spec §16.1: "admin 高危操作...经审计"): every propose/
    approve/reject call must land a real, queryable audit_intent row in the
    SAME transaction as the proposal write - verified via audit_sessionmaker
    (svc_gate itself cannot SELECT audit_intent back, INSERT-only), same
    isolation-proving pattern as test_inventory_service.py's equivalent test.
    """

    @pytest.mark.asyncio
    async def test_propose_writes_audit_intent(
        self, gate_sessionmaker: SessionmakerFixture, audit_sessionmaker: SessionmakerFixture
    ) -> None:
        new_yaml = _BASE_POLICY_YAML + "hard_gate_rules:\n  - pii.credit_card\n"
        async with gate_sessionmaker() as session, session.begin():
            proposal = await propose_policy_change(
                session,
                proposed_by="alice",
                current_hard_gate_rules=frozenset(),
                proposed_policy_yaml=new_yaml,
            )

        async with audit_sessionmaker() as session:
            result = await session.execute(
                select(AuditIntent).where(AuditIntent.action == "policy_proposed")
            )
            intents = [
                row
                for row in result.scalars().all()
                if row.payload.get("proposal_id") == proposal.id
            ]
        assert len(intents) == 1
        assert intents[0].operator == "alice"
        assert intents[0].payload["changes_hard_gate_rules"] is True
        assert intents[0].payload["status"] == "pending"

    @pytest.mark.asyncio
    async def test_approve_writes_audit_intent(
        self, gate_sessionmaker: SessionmakerFixture, audit_sessionmaker: SessionmakerFixture
    ) -> None:
        new_yaml = _BASE_POLICY_YAML + "hard_gate_rules:\n  - pii.credit_card\n"
        async with gate_sessionmaker() as session, session.begin():
            proposal = await propose_policy_change(
                session,
                proposed_by="alice",
                current_hard_gate_rules=frozenset(),
                proposed_policy_yaml=new_yaml,
            )
        async with gate_sessionmaker() as session, session.begin():
            session.add(proposal)
            await approve_policy_proposal(session, proposal, approved_by="bob")

        async with audit_sessionmaker() as session:
            result = await session.execute(
                select(AuditIntent).where(AuditIntent.action == "policy_approved")
            )
            intents = [
                row
                for row in result.scalars().all()
                if row.payload.get("proposal_id") == proposal.id
            ]
        assert len(intents) == 1
        assert intents[0].operator == "bob"
        assert intents[0].payload["proposed_by"] == "alice"

    @pytest.mark.asyncio
    async def test_reject_writes_audit_intent(
        self, gate_sessionmaker: SessionmakerFixture, audit_sessionmaker: SessionmakerFixture
    ) -> None:
        new_yaml = _BASE_POLICY_YAML + "hard_gate_rules:\n  - pii.credit_card\n"
        async with gate_sessionmaker() as session, session.begin():
            proposal = await propose_policy_change(
                session,
                proposed_by="alice",
                current_hard_gate_rules=frozenset(),
                proposed_policy_yaml=new_yaml,
            )
        async with gate_sessionmaker() as session, session.begin():
            session.add(proposal)
            await reject_policy_proposal(session, proposal, rejected_by="bob", reason="too broad")

        async with audit_sessionmaker() as session:
            result = await session.execute(
                select(AuditIntent).where(AuditIntent.action == "policy_rejected")
            )
            intents = [
                row
                for row in result.scalars().all()
                if row.payload.get("proposal_id") == proposal.id
            ]
        assert len(intents) == 1
        assert intents[0].operator == "bob"
        assert intents[0].payload["reason"] == "too broad"
