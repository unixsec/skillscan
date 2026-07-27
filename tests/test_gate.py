"""Unit tests for skillscan_core.gate (coding spec M1, §5.4).

Covers INV-1, INV-2 (basic case; randomized property test lives in
test_invariants.py), INV-3, INV-5, INV-8 as exercised through decide().
"""

from __future__ import annotations

import unittest

from skillscan_core import (
    AllowlistEntry,
    DetectionCategory,
    EngineCapability,
    EngineStatus,
    Finding,
    ScanResult,
    Severity,
    TrustTier,
    Verdict,
)
from skillscan_core.gate import decide

from tests._helpers import default_policy, make_finding, scan_result_from_findings


class TestGateFailClosed(unittest.TestCase):
    def test_inv1_missing_required_engine_forces_fail_closed(self) -> None:
        policy = default_policy(required_engines=frozenset({"static-keyword", "missing-engine"}))
        scan_result = scan_result_from_findings([], policy)
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
        self.assertEqual(verdict_result.verdict, policy.fail_closed_verdict)
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)

    def test_inv1_failed_required_engine_forces_fail_closed(self) -> None:
        policy = default_policy()
        scan_result = scan_result_from_findings([], policy, engine_status=EngineStatus.TIMEOUT)
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)


class TestGateHardGate(unittest.TestCase):
    def test_inv3_hard_gate_hit_blocks_unconditionally(self) -> None:
        policy = default_policy(hard_gate_rules=frozenset({"gate.hit"}))
        finding = make_finding(rule_id="gate.hit", severity=Severity.LOW, confidence=1.0)
        scan_result = scan_result_from_findings([finding], policy)
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)

    def test_inv3_hard_gate_hit_not_waivable_by_active_allowlist(self) -> None:
        policy = default_policy(hard_gate_rules=frozenset({"gate.hit"}))
        finding = make_finding(rule_id="gate.hit", severity=Severity.LOW, confidence=1.0)
        scan_result = scan_result_from_findings([finding], policy)
        allowlist = [
            AllowlistEntry(
                scope_type="rule_global",
                scope_value="*",
                rule_id="gate.hit",
                expires_at=1e18,
                approved_by="approver",
                requested_by="requester",
            )
        ]
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, allowlist, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)


class TestGateAllowlist(unittest.TestCase):
    def test_inv8_active_allowlist_waives_non_hard_gate_finding(self) -> None:
        policy = default_policy(block_on_severity=Severity.HIGH, review_on_severity=Severity.MEDIUM)
        finding = make_finding(rule_id="noisy.rule", severity=Severity.HIGH, confidence=1.0)
        scan_result = scan_result_from_findings([finding], policy)
        allowlist = [
            AllowlistEntry(
                scope_type="content_hash",
                scope_value=scan_result.content_hash,
                rule_id="noisy.rule",
                expires_at=1e18,
                approved_by="approver",
                requested_by="requester",
            )
        ]
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, allowlist, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.PASS)

    def test_inv8_expired_allowlist_does_not_waive(self) -> None:
        policy = default_policy(block_on_severity=Severity.HIGH, review_on_severity=Severity.MEDIUM)
        finding = make_finding(rule_id="noisy.rule", severity=Severity.HIGH, confidence=1.0)
        scan_result = scan_result_from_findings([finding], policy)
        allowlist = [
            AllowlistEntry(
                scope_type="content_hash",
                scope_value=scan_result.content_hash,
                rule_id="noisy.rule",
                expires_at=10.0,
                approved_by="approver",
                requested_by="requester",
            )
        ]
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, allowlist, now=20.0)
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)

    def test_inv8_severity_above_ceiling_not_waivable(self) -> None:
        policy = default_policy(allowlistable_max_severity=Severity.MEDIUM)
        finding = make_finding(rule_id="severe.rule", severity=Severity.CRITICAL, confidence=1.0)
        scan_result = scan_result_from_findings([finding], policy)
        allowlist = [
            AllowlistEntry(
                scope_type="content_hash",
                scope_value=scan_result.content_hash,
                rule_id="severe.rule",
                expires_at=1e18,
                approved_by="approver",
                requested_by="requester",
            )
        ]
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, allowlist, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)


class TestGateFloodCap(unittest.TestCase):
    def test_inv5_findings_capped_forces_at_least_review(self) -> None:
        policy = default_policy(
            block_on_severity=Severity.CRITICAL, review_on_severity=Severity.CRITICAL
        )
        # All LOW severity, high confidence -> would classify PASS on their own.
        findings = [
            make_finding(rule_id=f"low-{i}", severity=Severity.LOW, confidence=1.0)
            for i in range(10)
        ]
        scan_result = scan_result_from_findings(findings, policy, max_findings=3)
        self.assertTrue(scan_result.findings_capped)
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
        self.assertNotEqual(verdict_result.verdict, Verdict.PASS)


class TestGateClassifyThresholds(unittest.TestCase):
    def test_low_severity_high_confidence_passes(self) -> None:
        policy = default_policy(review_on_severity=Severity.HIGH, review_confidence=0.5)
        finding = make_finding(rule_id="r", severity=Severity.LOW, confidence=0.9)
        scan_result = scan_result_from_findings([finding], policy)
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.PASS)

    def test_low_severity_low_confidence_reviews(self) -> None:
        policy = default_policy(review_on_severity=Severity.HIGH, review_confidence=0.5)
        finding = make_finding(rule_id="r", severity=Severity.LOW, confidence=0.1)
        scan_result = scan_result_from_findings([finding], policy)
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.REVIEW)

    def test_tier_override_lowers_block_threshold(self) -> None:
        policy = default_policy(
            block_on_severity=Severity.CRITICAL,
            review_on_severity=Severity.CRITICAL,
            tier_block_overrides=((TrustTier.PUBLIC, Severity.MEDIUM),),
        )
        finding = make_finding(rule_id="r", severity=Severity.MEDIUM, confidence=1.0)
        scan_result = scan_result_from_findings([finding], policy)
        internal_verdict = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
        public_verdict = decide(scan_result, policy, TrustTier.PUBLIC, now=0.0)
        self.assertEqual(public_verdict.verdict, Verdict.BLOCK)
        self.assertNotEqual(internal_verdict.verdict, Verdict.BLOCK)


class TestGateScore(unittest.TestCase):
    def test_pass_verdict_with_no_findings_scores_100(self) -> None:
        policy = default_policy()
        scan_result = scan_result_from_findings([], policy)
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.PASS)
        self.assertEqual(verdict_result.score, 100)

    def test_hard_gate_hit_scores_zero(self) -> None:
        policy = default_policy(hard_gate_rules=frozenset({"gate.hit"}))
        finding = make_finding(rule_id="gate.hit", severity=Severity.LOW, confidence=1.0)
        scan_result = scan_result_from_findings([finding], policy)
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)
        self.assertEqual(verdict_result.score, 0)

    def test_required_engine_missing_scores_within_block_band(self) -> None:
        # Pins to exactly 0, not merely "somewhere in [0, 39]": a fail-closed
        # verdict means the scan couldn't be completed at all, so we know LESS
        # about this package than about any package with real findings - it
        # must pin to the band floor, never float up toward the band's top.
        # (A loose 0<=score<=39 assertion here is exactly the kind of weak
        # assertion that let the old top-of-band-39 inversion go unnoticed.)
        policy = default_policy(required_engines=frozenset({"static-keyword", "missing-engine"}))
        scan_result = scan_result_from_findings([], policy)
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)
        self.assertEqual(verdict_result.score, 0)

    def test_review_verdict_scores_within_review_band(self) -> None:
        policy = default_policy(
            block_on_severity=Severity.CRITICAL, review_on_severity=Severity.HIGH
        )
        finding = make_finding(rule_id="r", severity=Severity.HIGH, confidence=0.9)
        scan_result = scan_result_from_findings([finding], policy)
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.REVIEW)
        self.assertGreaterEqual(verdict_result.score, 40)
        self.assertLessEqual(verdict_result.score, 74)

    def test_required_engine_missing_and_hard_gate_hit_scores_zero(self) -> None:
        # SECURITY (review 2026-07-25, Task 3): site 1 (required_ok fail-closed
        # branch) must independently check hard_gate_hits rather than assuming
        # a fail-closed scan never carries one - these are two unrelated
        # signals that can co-occur (a missing required engine AND an already-
        # collected hard-gate-matching finding from the engines that DID run).
        policy = default_policy(
            required_engines=frozenset({"static-keyword", "missing-engine"}),
            hard_gate_rules=frozenset({"gate.hit"}),
        )
        finding = make_finding(rule_id="gate.hit", severity=Severity.LOW, confidence=1.0)
        scan_result = scan_result_from_findings([finding], policy)
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)
        self.assertEqual(verdict_result.score, 0)

    def test_dedup_restored_block_with_fully_waived_effective_set_scores_zero(self) -> None:
        # Third band-floor path (2026-07-27 review finding): the dedup-signal-
        # restoration block above can push verdict to BLOCK/REVIEW purely from
        # scan_result.severity (pre-dedup, authoritative per INV-4/INV-5) while
        # `effective` - the post-waiver set actually passed to security_score -
        # ends up EMPTY, because the one surviving (non-collided) finding is
        # itself legitimately waived. Scoring an empty `effective` under the
        # ordinary formula lands at the band's TOP (39 for BLOCK) - the same
        # "empty findings score highest" inversion the fail-closed/hard-gate
        # branches were fixed for, reached through a third, previously-missed
        # path. Constructed via a direct ScanResult (not scan_result_from_findings)
        # because dedup_collision_rule_ids and the pre-dedup severity must be
        # set independently of `findings`, exactly like a real dedup collision
        # would leave them.
        survivor = Finding(
            rule_id="rule.x",
            test_item_id="T",
            category=DetectionCategory.CODE,
            title="t",
            severity=Severity.LOW,
            confidence=1.0,
            source_engine="e",
            source_capability=EngineCapability.STATIC,
            file_path="a.py",
            start_line=1,
            evidence_redacted="e",
        )
        scan_result = ScanResult(
            content_hash="h" * 64,
            severity=Severity.CRITICAL,
            confidence_at_max=1.0,
            trifecta_present=False,
            hard_gate_hits=(),
            findings=(survivor,),
            engine_provenance=(),
            findings_capped=False,
            required_ok=True,
            missing_or_failed_required=(),
            dedup_collision_rule_ids=frozenset({"rule.y"}),
        )
        policy = default_policy(allowlistable_max_severity=Severity.HIGH)
        allowlist = [
            AllowlistEntry(
                rule_id="rule.x",
                scope_type="rule_global",
                scope_value="",
                expires_at=10_000.0,
                requested_by="a",
                approved_by="b",
            )
        ]
        verdict_result = decide(
            scan_result, policy, TrustTier.INTERNAL, allowlist=allowlist, now=0.0
        )
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)
        self.assertEqual(verdict_result.score, 0)


if __name__ == "__main__":
    unittest.main()
