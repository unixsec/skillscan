"""Tests for `reeval.reconciliation` (coding spec §11.6, SAD §4.3, INV-13).
Pure logic + HMAC verification - no DB/network needed.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module
import json

import pytest

from monolith.modules.gate.service import IssuedVerdict
from monolith.modules.reeval.reconciliation import (
    MarketplacePublishedEntry,
    PushEventVerificationError,
    ReconciliationResult,
    ReconciliationSource,
    reconcile,
    reconciliation_mode_warnings,
    verify_push_event_signature,
)


class TestReconcile:
    def test_published_with_matching_pass_verdict_is_match(self) -> None:
        published = [MarketplacePublishedEntry(content_hash="a" * 64, skill_id="skill-1")]
        issued = [IssuedVerdict(content_hash="a" * 64, verdict="PASS")]
        outcomes = reconcile(published, issued, source=ReconciliationSource.POLL)
        assert len(outcomes) == 1
        assert outcomes[0].result is ReconciliationResult.MATCH
        assert outcomes[0].skill_id == "skill-1"

    def test_published_with_no_verdict_at_all_is_orphan(self) -> None:
        # SECURITY: this is the case that matters most - a Skill published
        # with NO verdict on record at all means the gate was bypassed.
        published = [MarketplacePublishedEntry(content_hash="b" * 64, skill_id="skill-2")]
        outcomes = reconcile(published, [], source=ReconciliationSource.POLL)
        assert outcomes[0].result is ReconciliationResult.ORPHAN

    def test_published_with_non_pass_verdict_is_mismatch(self) -> None:
        published = [MarketplacePublishedEntry(content_hash="c" * 64, skill_id="skill-3")]
        issued = [IssuedVerdict(content_hash="c" * 64, verdict="BLOCK")]
        outcomes = reconcile(published, issued, source=ReconciliationSource.POLL)
        assert outcomes[0].result is ReconciliationResult.MISMATCH

    def test_review_verdict_is_also_mismatch_not_match(self) -> None:
        # SECURITY: only an explicit PASS counts as a match - REVIEW means
        # human sign-off never happened, so marketplace publication is still
        # unauthorized regardless of what the gate's overall verdict enum meant.
        published = [MarketplacePublishedEntry(content_hash="d" * 64, skill_id="skill-4")]
        issued = [IssuedVerdict(content_hash="d" * 64, verdict="REVIEW")]
        outcomes = reconcile(published, issued, source=ReconciliationSource.POLL)
        assert outcomes[0].result is ReconciliationResult.MISMATCH

    def test_unrelated_verdicts_do_not_affect_unrelated_published_entries(self) -> None:
        published = [MarketplacePublishedEntry(content_hash="e" * 64, skill_id="skill-5")]
        issued = [IssuedVerdict(content_hash="f" * 64, verdict="PASS")]  # different hash
        outcomes = reconcile(published, issued, source=ReconciliationSource.POLL)
        assert outcomes[0].result is ReconciliationResult.ORPHAN

    def test_multiple_published_entries_all_evaluated_independently(self) -> None:
        published = [
            MarketplacePublishedEntry(content_hash="1" * 64, skill_id="s1"),
            MarketplacePublishedEntry(content_hash="2" * 64, skill_id="s2"),
            MarketplacePublishedEntry(content_hash="3" * 64, skill_id="s3"),
        ]
        issued = [
            IssuedVerdict(content_hash="1" * 64, verdict="PASS"),
            IssuedVerdict(content_hash="2" * 64, verdict="BLOCK"),
        ]
        outcomes = reconcile(published, issued, source=ReconciliationSource.POLL)
        by_hash = {o.content_hash: o.result for o in outcomes}
        assert by_hash["1" * 64] is ReconciliationResult.MATCH
        assert by_hash["2" * 64] is ReconciliationResult.MISMATCH
        assert by_hash["3" * 64] is ReconciliationResult.ORPHAN

    def test_empty_published_set_yields_no_outcomes(self) -> None:
        outcomes = reconcile(
            [],
            [IssuedVerdict(content_hash="a" * 64, verdict="PASS")],
            source=ReconciliationSource.POLL,
        )
        assert outcomes == ()

    def test_source_is_recorded_on_every_outcome(self) -> None:
        published = [MarketplacePublishedEntry(content_hash="a" * 64, skill_id="skill-1")]
        outcomes = reconcile(published, [], source=ReconciliationSource.PUSH)
        assert outcomes[0].source is ReconciliationSource.PUSH


class TestReconciliationModeWarnings:
    def test_both_enabled_yields_no_warnings(self) -> None:
        assert reconciliation_mode_warnings(poll_enabled=True, push_enabled=True) == ()

    def test_poll_only_yields_no_warnings(self) -> None:
        # SAD §4.3: poll alone already provides real, complete coverage.
        assert reconciliation_mode_warnings(poll_enabled=True, push_enabled=False) == ()

    def test_both_disabled_warns_about_full_bypass_risk(self) -> None:
        warnings = reconciliation_mode_warnings(poll_enabled=False, push_enabled=False)
        assert len(warnings) == 1
        assert "fully disabled" in warnings[0]

    def test_push_only_warns_about_reduced_coverage(self) -> None:
        warnings = reconciliation_mode_warnings(poll_enabled=False, push_enabled=True)
        assert len(warnings) == 1
        assert "cannot detect" in warnings[0] or "reduced-coverage" in warnings[0]


def _sign(body: bytes, *, timestamp: int, secret: str) -> str:
    return hmac_module.new(
        secret.encode("utf-8"), f"{timestamp}.".encode("ascii") + body, hashlib.sha256
    ).hexdigest()


class TestVerifyPushEventSignature:
    def test_valid_signature_within_window_passes(self) -> None:
        body = json.dumps({"content_hash": "a" * 64, "skill_id": "s1"}).encode()
        now = 1_000_000.0
        timestamp = int(now)
        signature = _sign(body, timestamp=timestamp, secret="shh")
        verify_push_event_signature(
            body=body,
            signature_header=signature,
            timestamp=timestamp,
            hmac_secret="shh",
            replay_window_s=300,
            now=now,
        )  # must not raise

    def test_wrong_secret_rejected(self) -> None:
        body = b'{"content_hash": "a"}'
        timestamp = 1000
        signature = _sign(body, timestamp=timestamp, secret="correct-secret")
        with pytest.raises(PushEventVerificationError, match="signature verification failed"):
            verify_push_event_signature(
                body=body,
                signature_header=signature,
                timestamp=timestamp,
                hmac_secret="wrong-secret",
                replay_window_s=300,
                now=float(timestamp),
            )

    def test_tampered_body_rejected(self) -> None:
        original_body = b'{"content_hash": "a"}'
        timestamp = 1000
        signature = _sign(original_body, timestamp=timestamp, secret="shh")
        tampered_body = b'{"content_hash": "b"}'
        with pytest.raises(PushEventVerificationError, match="signature verification failed"):
            verify_push_event_signature(
                body=tampered_body,
                signature_header=signature,
                timestamp=timestamp,
                hmac_secret="shh",
                replay_window_s=300,
                now=float(timestamp),
            )

    def test_timestamp_outside_replay_window_rejected(self) -> None:
        body = b'{"content_hash": "a"}'
        timestamp = 1000
        signature = _sign(body, timestamp=timestamp, secret="shh")
        with pytest.raises(PushEventVerificationError, match="replay window"):
            verify_push_event_signature(
                body=body,
                signature_header=signature,
                timestamp=timestamp,
                hmac_secret="shh",
                replay_window_s=300,
                now=float(timestamp + 301),  # just past the window
            )

    def test_replayed_old_signature_with_forged_fresh_timestamp_rejected(self) -> None:
        # SECURITY: proves the timestamp is bound INTO the signed material -
        # an attacker can't take a valid (old_timestamp, signature, body) and
        # just claim a new timestamp to slide the replay window forward.
        body = b'{"content_hash": "a"}'
        old_timestamp = 1000
        old_signature = _sign(body, timestamp=old_timestamp, secret="shh")
        forged_fresh_timestamp = 1250  # attacker claims this instead
        with pytest.raises(PushEventVerificationError, match="signature verification failed"):
            verify_push_event_signature(
                body=body,
                signature_header=old_signature,
                timestamp=forged_fresh_timestamp,
                hmac_secret="shh",
                replay_window_s=300,
                now=float(forged_fresh_timestamp),
            )

    def test_timestamp_in_the_future_within_window_still_passes(self) -> None:
        # Clock skew tolerance - the window is symmetric (abs()), not just "in the past".
        body = b'{"content_hash": "a"}'
        now = 1000.0
        future_timestamp = 1100
        signature = _sign(body, timestamp=future_timestamp, secret="shh")
        verify_push_event_signature(
            body=body,
            signature_header=signature,
            timestamp=future_timestamp,
            hmac_secret="shh",
            replay_window_s=300,
            now=now,
        )
