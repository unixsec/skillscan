"""Unit tests for skillscan_core.gate (coding spec M1, §5.4).

Covers INV-1, INV-2 (basic case; randomized property test lives in
test_invariants.py), INV-3, INV-5, INV-8 as exercised through decide().
"""

from __future__ import annotations

import unittest

from skillscan_core import AllowlistEntry, EngineStatus, Severity, TrustTier, Verdict
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


if __name__ == "__main__":
    unittest.main()
