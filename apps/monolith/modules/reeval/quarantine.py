"""Asymmetric auto-quarantine correction (coding spec §11.6, SAD §4.3, TB14).

SECURITY: poll-sourced ORPHAN/MISMATCH comes from OUR OWN authenticated,
independent read of the marketplace's full published set - high confidence,
cannot be forged by a third party. push-sourced comes from an inbound event
the marketplace (or an attacker impersonating it) sent us - even with strong
auth (mTLS/signed event + anti-replay), a compromised or spoofed pusher could
still trigger a false MISMATCH/ORPHAN. Auto-correcting on push by default
would turn the push webhook into a takedown-as-a-service DoS primitive
against published Skills - so push-sourced auto-correction defaults OFF,
opt-in only (coding spec: "push-sourced 恶意下架...强认证+默认仅告警缓解").
"""

from __future__ import annotations

from dataclasses import dataclass

from .reconciliation import ReconciliationOutcome, ReconciliationResult, ReconciliationSource

_ACTIONABLE_RESULTS = frozenset({ReconciliationResult.ORPHAN, ReconciliationResult.MISMATCH})


@dataclass(frozen=True, slots=True)
class QuarantineDecision:
    should_quarantine: bool
    should_alert: bool
    reason: str | None


def decide_quarantine_action(
    outcome: ReconciliationOutcome, *, push_auto_quarantine_enabled: bool = False
) -> QuarantineDecision:
    if outcome.result not in _ACTIONABLE_RESULTS:
        return QuarantineDecision(should_quarantine=False, should_alert=False, reason=None)

    reason = (
        f"{outcome.source.value}-sourced {outcome.result.value} for "
        f"skill_id={outcome.skill_id!r} content_hash={outcome.content_hash!r}"
    )
    if outcome.source is ReconciliationSource.POLL:
        # SECURITY: high-confidence, our own authenticated read -> act by default.
        return QuarantineDecision(should_quarantine=True, should_alert=True, reason=reason)

    # SECURITY: push-sourced - forgeable/replayable provenance - alert always,
    # act only if the operator has explicitly opted in (default False).
    return QuarantineDecision(
        should_quarantine=push_auto_quarantine_enabled, should_alert=True, reason=reason
    )
