"""Policy change proposal + two-person approval workflow (coding spec §9
admin·policy, §16.1: "gate 策略(版本化查看/提议;硬门禁项变更需二人 + 审计)").

SECURITY: this does NOT mutate the live policy - `policies/gate/*.yaml` on
disk remains the actual config-as-code source of truth, applied via a
PR-reviewed deployment (coding spec §11.6). This workflow is a PRECONDITION
gate: a proposal that changes `hard_gate_rules` needs a SECOND, DIFFERENT
admin's sign-off (four-eyes, mirroring skillscan_core.AllowlistEntry's own
`approved_by != requested_by` invariant) before anyone should go open that
PR; a proposal that leaves `hard_gate_rules` untouched is auto-approved
(recorded, not silently skipped) since a single admin's own judgment is
sufficient for non-hard-gate tuning (review_confidence, severity thresholds,
etc.) per the coding spec's own scoping of the two-person requirement to
hard-gate items specifically.
"""

from __future__ import annotations

import datetime

import yaml
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditIntentInsertOnly, PolicyProposalRow
from .policy import GatePolicyLoadError, parse_gate_policy


class PolicyProposalError(ValueError):
    pass


def _naive_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


async def propose_policy_change(
    session: AsyncSession,
    *,
    proposed_by: str,
    current_hard_gate_rules: frozenset[str],
    proposed_policy_yaml: str,
) -> PolicyProposalRow:
    """SECURITY: the proposed YAML is validated the SAME way a real policy
    file would be (parse_gate_policy - fail-closed on anything malformed)
    before being recorded at all; an invalid proposal never enters the
    approval queue. Caller must run this inside `async with session.begin():`.
    """
    try:
        raw = yaml.safe_load(proposed_policy_yaml)
        if not isinstance(raw, dict):
            raise GatePolicyLoadError("proposed policy must be a YAML mapping at the top level")
        proposed_policy = parse_gate_policy(raw)
    except (yaml.YAMLError, GatePolicyLoadError) as exc:
        raise PolicyProposalError(f"proposed policy is invalid: {exc}") from exc

    changes_hard_gate_rules = proposed_policy.hard_gate_rules != current_hard_gate_rules
    now = _naive_utcnow()
    proposal = PolicyProposalRow(
        proposed_policy_yaml=proposed_policy_yaml,
        changes_hard_gate_rules=changes_hard_gate_rules,
        # SECURITY: only a hard-gate-rule change requires the second sign-off -
        # everything else is auto-approved (recorded, not silently skipped).
        status="pending" if changes_hard_gate_rules else "approved",
        proposed_by=proposed_by,
        approved_by=None if changes_hard_gate_rules else proposed_by,
        created_at=now,
        decided_at=None if changes_hard_gate_rules else now,
    )
    session.add(proposal)
    await session.flush()  # populates proposal.id (autoincrement) for the audit payload below
    # SECURITY (coding spec §16.1: "admin 高危操作...经审计"): recorded in the
    # SAME transaction as the proposal itself (INV-12 same-transaction pattern,
    # already established by gate.service.decide_and_record) - a proposal can
    # never exist without a corresponding audit entry, not even under a crash
    # between two separate writes.
    session.add(
        AuditIntentInsertOnly(
            operator=proposed_by,
            action="policy_proposed",
            payload={
                "proposal_id": proposal.id,
                "changes_hard_gate_rules": changes_hard_gate_rules,
                "status": proposal.status,
            },
        )
    )
    await session.flush()
    return proposal


async def approve_policy_proposal(
    session: AsyncSession, proposal: PolicyProposalRow, *, approved_by: str
) -> None:
    """SECURITY (four-eyes): raises if `approved_by` is the same person who
    proposed it, or if the proposal isn't actually pending - never silently
    no-ops on a misuse attempt. Caller must run inside `async with
    session.begin():`."""
    if proposal.status != "pending":
        raise PolicyProposalError(
            f"proposal {proposal.id} is {proposal.status!r}, not pending - cannot approve"
        )
    if approved_by == proposal.proposed_by:
        raise PolicyProposalError(
            f"approver must differ from proposer (four-eyes) - {approved_by!r} proposed this change"
        )
    proposal.status = "approved"
    proposal.approved_by = approved_by
    proposal.decided_at = _naive_utcnow()
    session.add(
        AuditIntentInsertOnly(
            operator=approved_by,
            action="policy_approved",
            payload={"proposal_id": proposal.id, "proposed_by": proposal.proposed_by},
        )
    )
    await session.flush()


async def reject_policy_proposal(
    session: AsyncSession, proposal: PolicyProposalRow, *, rejected_by: str, reason: str
) -> None:
    if proposal.status != "pending":
        raise PolicyProposalError(
            f"proposal {proposal.id} is {proposal.status!r}, not pending - cannot reject"
        )
    proposal.status = "rejected"
    proposal.approved_by = rejected_by
    proposal.reason = reason
    proposal.decided_at = _naive_utcnow()
    session.add(
        AuditIntentInsertOnly(
            operator=rejected_by,
            action="policy_rejected",
            payload={
                "proposal_id": proposal.id,
                "proposed_by": proposal.proposed_by,
                "reason": reason,
            },
        )
    )
    await session.flush()
