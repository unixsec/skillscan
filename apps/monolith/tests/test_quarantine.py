"""Tests for `reeval.quarantine` (coding spec §11.6, SAD §4.3, TB14) - the
asymmetric auto-quarantine correction-side logic. Pure, no DB/network needed.
"""

from __future__ import annotations

import pytest

from monolith.modules.reeval.quarantine import decide_quarantine_action
from monolith.modules.reeval.reconciliation import (
    ReconciliationOutcome,
    ReconciliationResult,
    ReconciliationSource,
)


def _outcome(
    *, result: ReconciliationResult, source: ReconciliationSource
) -> ReconciliationOutcome:
    return ReconciliationOutcome(
        content_hash="a" * 64, skill_id="skill-1", result=result, source=source
    )


class TestMatchNeverActionable:
    @pytest.mark.parametrize("source", [ReconciliationSource.POLL, ReconciliationSource.PUSH])
    def test_match_never_quarantines_or_alerts(self, source: ReconciliationSource) -> None:
        decision = decide_quarantine_action(
            _outcome(result=ReconciliationResult.MATCH, source=source)
        )
        assert decision.should_quarantine is False
        assert decision.should_alert is False
        assert decision.reason is None


class TestPollSourcedDefaultsToActing:
    @pytest.mark.parametrize("result", [ReconciliationResult.ORPHAN, ReconciliationResult.MISMATCH])
    def test_poll_sourced_orphan_or_mismatch_auto_quarantines_by_default(
        self, result: ReconciliationResult
    ) -> None:
        # SECURITY: poll is OUR OWN authenticated, independent read - high
        # confidence, cannot be forged by a third party - acts by default.
        decision = decide_quarantine_action(
            _outcome(result=result, source=ReconciliationSource.POLL)
        )
        assert decision.should_quarantine is True
        assert decision.should_alert is True
        assert decision.reason is not None
        assert "poll-sourced" in decision.reason


class TestPushSourcedDefaultsToAlertOnly:
    @pytest.mark.parametrize("result", [ReconciliationResult.ORPHAN, ReconciliationResult.MISMATCH])
    def test_push_sourced_never_auto_quarantines_by_default(
        self, result: ReconciliationResult
    ) -> None:
        # SECURITY (TB14): push-sourced provenance is forgeable/replayable -
        # even with the endpoint's own HMAC/anti-replay verification already
        # passed, auto-correction must still default OFF so a compromised or
        # spoofed pusher can't weaponize this into a takedown-as-a-service
        # DoS against legitimately published Skills.
        decision = decide_quarantine_action(
            _outcome(result=result, source=ReconciliationSource.PUSH)
        )
        assert decision.should_quarantine is False
        assert decision.should_alert is True  # still surfaced to a human
        assert decision.reason is not None
        assert "push-sourced" in decision.reason

    @pytest.mark.parametrize("result", [ReconciliationResult.ORPHAN, ReconciliationResult.MISMATCH])
    def test_push_sourced_quarantines_only_when_explicitly_opted_in(
        self, result: ReconciliationResult
    ) -> None:
        decision = decide_quarantine_action(
            _outcome(result=result, source=ReconciliationSource.PUSH),
            push_auto_quarantine_enabled=True,
        )
        assert decision.should_quarantine is True
        assert decision.should_alert is True

    def test_poll_sourced_ignores_the_push_opt_in_flag(self) -> None:
        # The opt-in flag is push-specific - it must not accidentally gate
        # poll's already-on-by-default behavior.
        decision = decide_quarantine_action(
            _outcome(result=ReconciliationResult.ORPHAN, source=ReconciliationSource.POLL),
            push_auto_quarantine_enabled=False,
        )
        assert decision.should_quarantine is True
