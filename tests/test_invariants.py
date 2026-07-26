"""Direct, spec-traceable tests for the M1 invariant checklist (coding spec §14, INV-1..8).

Test method names match their invariant ID so this file can be checked
line-by-line against the coding spec's checklist. Broader edge-case coverage
lives in the per-module test_*.py files; this file is the audit trail.
"""

from __future__ import annotations

import random
import unittest

from skillscan_core import (
    AllowlistEntry,
    EngineCapability,
    EngineMetadata,
    EngineStatus,
    GatePolicy,
    Severity,
    TrifectaSignal,
    TrustTier,
    Verdict,
    cache_key,
    content_hash,
    toolchain_digest,
)
from skillscan_core.gate import decide

from tests._helpers import default_policy, make_finding, scan_result_from_findings


class TestInvariants(unittest.TestCase):
    # INV-1: required engine missing/ERROR/TIMEOUT -> never PASS; a policy with
    # fail_closed_verdict=PASS is rejected outright at construction.
    def test_inv1_fail_closed_on_missing_or_failed_required_engine(self) -> None:
        policy = default_policy(required_engines=frozenset({"static-keyword", "ghost"}))
        scan_result = scan_result_from_findings([], policy)
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)

        for status in (EngineStatus.ERROR, EngineStatus.TIMEOUT):
            with self.subTest(status=status):
                policy2 = default_policy()
                sr = scan_result_from_findings([], policy2, engine_status=status)
                vr = decide(sr, policy2, TrustTier.INTERNAL, now=0.0)
                self.assertEqual(vr.verdict, Verdict.BLOCK)

    def test_inv1_fail_closed_verdict_must_not_be_pass(self) -> None:
        with self.assertRaises(ValueError):
            GatePolicy(version="v1", required_engines=frozenset(), fail_closed_verdict=Verdict.PASS)

    # INV-2: LLM findings may only escalate a verdict, never de-escalate it.
    # Randomized property test with a fixed seed, as the spec explicitly requires.
    def test_inv2_llm_monotonicity_randomized_fixed_seed(self) -> None:
        rng = random.Random(20260704)
        policy = default_policy()
        severities = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

        for trial in range(200):
            det_findings = [
                make_finding(
                    rule_id=f"det-{trial}-{i}",
                    severity=rng.choice(severities),
                    confidence=rng.random(),
                    capability=EngineCapability.STATIC,
                )
                for i in range(rng.randint(0, 4))
            ]
            llm_findings = [
                make_finding(
                    rule_id=f"llm-{trial}-{i}",
                    severity=rng.choice(severities),
                    confidence=rng.random(),
                    capability=EngineCapability.SEMANTIC_LLM,
                )
                for i in range(rng.randint(0, 4))
            ]

            all_scan = scan_result_from_findings(det_findings + llm_findings, policy)
            all_verdict = decide(all_scan, policy, TrustTier.INTERNAL, now=0.0)

            non_llm_scan = scan_result_from_findings(det_findings, policy)
            non_llm_verdict = decide(non_llm_scan, policy, TrustTier.INTERNAL, now=0.0)

            with self.subTest(trial=trial):
                self.assertGreaterEqual(
                    int(all_verdict.verdict),
                    int(non_llm_verdict.verdict),
                    "LLM findings must never make the verdict less strict",
                )

    def test_inv2_llm_only_cannot_pass_when_static_alone_blocks(self) -> None:
        policy = default_policy(block_on_severity=Severity.HIGH)
        det = make_finding(
            rule_id="det.block",
            severity=Severity.HIGH,
            confidence=1.0,
            capability=EngineCapability.STATIC,
        )
        llm = make_finding(
            rule_id="llm.noise",
            severity=Severity.LOW,
            confidence=0.01,
            capability=EngineCapability.SEMANTIC_LLM,
        )
        scan_result = scan_result_from_findings([det, llm], policy)
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)

    # INV-3: hard-gate hit -> BLOCK, never waivable even with a matching active entry.
    def test_inv3_hard_gate_unwaivable(self) -> None:
        policy = default_policy(hard_gate_rules=frozenset({"gate.hit"}))
        finding = make_finding(rule_id="gate.hit", severity=Severity.LOW, confidence=1.0)
        scan_result = scan_result_from_findings([finding], policy)
        allowlist = [
            AllowlistEntry(
                scope_type="rule_global",
                scope_value="*",
                rule_id="gate.hit",
                expires_at=1e18,
                approved_by="a",
                requested_by="b",
            )
        ]
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, allowlist, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)

    # INV-4: fatal-trifecta co-occurrence forces severity >= CRITICAL; missing one
    # signal must not escalate.
    def test_inv4_trifecta_forces_critical(self) -> None:
        policy = default_policy()
        findings = [
            make_finding(
                rule_id="a",
                severity=Severity.LOW,
                trifecta_signals=frozenset({TrifectaSignal.PRIVATE_DATA_ACCESS}),
            ),
            make_finding(
                rule_id="b",
                severity=Severity.LOW,
                trifecta_signals=frozenset({TrifectaSignal.UNTRUSTED_INPUT}),
            ),
            make_finding(
                rule_id="c",
                severity=Severity.LOW,
                trifecta_signals=frozenset({TrifectaSignal.EXTERNAL_EGRESS}),
            ),
        ]
        scan_result = scan_result_from_findings(findings, policy)
        self.assertTrue(scan_result.trifecta_present)
        self.assertEqual(scan_result.severity, Severity.CRITICAL)

    def test_inv4_two_of_three_signals_does_not_escalate(self) -> None:
        policy = default_policy()
        findings = [
            make_finding(
                rule_id="a",
                severity=Severity.LOW,
                trifecta_signals=frozenset({TrifectaSignal.PRIVATE_DATA_ACCESS}),
            ),
            make_finding(
                rule_id="b",
                severity=Severity.LOW,
                trifecta_signals=frozenset({TrifectaSignal.UNTRUSTED_INPUT}),
            ),
        ]
        scan_result = scan_result_from_findings(findings, policy)
        self.assertFalse(scan_result.trifecta_present)
        self.assertEqual(scan_result.severity, Severity.LOW)

    # INV-1/INV-4 regression (2026-07-06 spec-compliance audit): decide() must not
    # silently lose a trifecta-completing signal that a _dedup() key collision drops
    # from scan_result.findings - reproduced live via a real constructed ScanResult
    # where a lower-(severity,confidence) finding carrying the last trifecta signal
    # loses a dedup collision against an unrelated, higher-severity finding sharing
    # the same (rule_id, file_path, start_line, category) key. No flood/cap is
    # involved, so INV-5's "capped can't PASS" backstop must not be what's doing the
    # work here - this is a distinct failure mode.
    def test_inv4_dedup_collision_does_not_silently_lose_trifecta(self) -> None:
        policy = default_policy(
            block_on_severity=Severity.CRITICAL,
            review_on_severity=Severity.HIGH,
            review_confidence=0.6,
        )
        # Shares a dedup_key with `masked_signal` below; wins the collision on
        # (severity, confidence) but carries no trifecta signal of its own.
        winner = make_finding(
            rule_id="shared.rule",
            severity=Severity.MEDIUM,
            confidence=1.0,
            file_path="skill/run.py",
            start_line=10,
        )
        # Carries the last trifecta signal but loses the dedup collision against
        # `winner` - this finding must disappear from scan_result.findings entirely.
        masked_signal = make_finding(
            rule_id="shared.rule",
            severity=Severity.LOW,
            confidence=0.3,
            file_path="skill/run.py",
            start_line=10,
            trifecta_signals=frozenset({TrifectaSignal.EXTERNAL_EGRESS}),
        )
        other_signal_a = make_finding(
            rule_id="a",
            severity=Severity.LOW,
            trifecta_signals=frozenset({TrifectaSignal.PRIVATE_DATA_ACCESS}),
        )
        other_signal_b = make_finding(
            rule_id="b",
            severity=Severity.LOW,
            trifecta_signals=frozenset({TrifectaSignal.UNTRUSTED_INPUT}),
        )
        scan_result = scan_result_from_findings(
            [winner, masked_signal, other_signal_a, other_signal_b], policy
        )
        # Sanity: aggregate() itself must still get this right (it always has -
        # this test is about decide(), not aggregate()).
        self.assertTrue(scan_result.trifecta_present)
        self.assertEqual(scan_result.severity, Severity.CRITICAL)
        self.assertFalse(scan_result.findings_capped)
        # The dedup collision really did drop the signal-carrying finding.
        self.assertNotIn(masked_signal, scan_result.findings)

        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
        self.assertEqual(
            verdict_result.verdict,
            Verdict.BLOCK,
            "a true CRITICAL+trifecta scan must BLOCK even when dedup drops the "
            "specific finding that carried the completing signal",
        )
        self.assertTrue(verdict_result.trifecta_present)
        self.assertEqual(verdict_result.effective_severity, Severity.CRITICAL)
        self.assertIn("dedup_collision_signal_restored_from_scan_result", verdict_result.reasons)

    # Companion test: legitimate four-eyes waiving of the SAME visible findings (no
    # dedup collision involved) must still be able to defeat trifecta, per spec §5.4
    # step 6 ("pre-cap trifecta 未被(经四眼加白)移除" - explicitly conditions the
    # uplift on the waiving not having happened). The INV-1/INV-4 fix above must not
    # make trifecta unwaivable outright - only dedup-collision loss is illegitimate.
    def test_inv4_legitimate_waiver_can_still_defeat_trifecta_without_dedup_collision(
        self,
    ) -> None:
        policy = default_policy(
            block_on_severity=Severity.CRITICAL,
            review_on_severity=Severity.HIGH,
            review_confidence=0.6,
            allowlistable_max_severity=Severity.HIGH,
        )
        signal_a = make_finding(
            rule_id="a",
            severity=Severity.LOW,
            trifecta_signals=frozenset({TrifectaSignal.PRIVATE_DATA_ACCESS}),
        )
        signal_b = make_finding(
            rule_id="b",
            severity=Severity.LOW,
            trifecta_signals=frozenset({TrifectaSignal.UNTRUSTED_INPUT}),
        )
        signal_c = make_finding(
            rule_id="c",
            severity=Severity.LOW,
            confidence=1.0,
            trifecta_signals=frozenset({TrifectaSignal.EXTERNAL_EGRESS}),
        )
        scan_result = scan_result_from_findings([signal_a, signal_b, signal_c], policy)
        self.assertTrue(scan_result.trifecta_present)
        # No dedup collision here - all three findings have distinct dedup keys and
        # all three are still present in scan_result.findings.
        self.assertEqual(len(scan_result.findings), 3)

        allowlist = [
            AllowlistEntry(
                scope_type="rule_global",
                scope_value="*",
                rule_id="c",
                expires_at=1e18,
                approved_by="approver",
                requested_by="requester",
            )
        ]
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, allowlist, now=0.0)
        self.assertFalse(
            verdict_result.trifecta_present,
            "waiving one of the three genuinely-present trifecta findings must "
            "still be able to defeat trifecta - only dedup-collision loss is "
            "illegitimate, not four-eyes waiving of a visible finding",
        )
        self.assertNotIn("dedup_collision_signal_restored_from_scan_result", verdict_result.reasons)

    # Regression (2026-07-10 full-project review, Finding #10): the dedup-collision
    # restoration above must not override an allowlist waiver that ALREADY covers
    # the rule_id(s) behind the collision. Same fixture shape as
    # test_inv4_dedup_collision_does_not_silently_lose_trifecta (winner/masked_signal
    # share a dedup key), but this time "shared.rule" - the rule_id both of them
    # share - is actively four-eyes-waived. Empirically verified before the fix: the
    # identical waiver correctly produced PASS when the two findings did NOT collide
    # (different file_path), but was silently defeated by BLOCK when they did -
    # purely because of the incidental dedup collision, unrelated to whether the
    # rule_id was waived.
    def test_inv8_waiver_covering_the_colliding_rule_id_still_applies_despite_dedup(
        self,
    ) -> None:
        policy = default_policy(
            block_on_severity=Severity.CRITICAL,
            review_on_severity=Severity.HIGH,
            review_confidence=0.6,
            allowlistable_max_severity=Severity.HIGH,
        )
        winner = make_finding(
            rule_id="shared.rule",
            severity=Severity.MEDIUM,
            confidence=1.0,
            file_path="skill/run.py",
            start_line=10,
        )
        masked_signal = make_finding(
            rule_id="shared.rule",
            severity=Severity.LOW,
            confidence=0.3,
            file_path="skill/run.py",
            start_line=10,
            trifecta_signals=frozenset({TrifectaSignal.EXTERNAL_EGRESS}),
        )
        other_signal_a = make_finding(
            rule_id="a",
            severity=Severity.LOW,
            trifecta_signals=frozenset({TrifectaSignal.PRIVATE_DATA_ACCESS}),
        )
        other_signal_b = make_finding(
            rule_id="b",
            severity=Severity.LOW,
            trifecta_signals=frozenset({TrifectaSignal.UNTRUSTED_INPUT}),
        )
        scan_result = scan_result_from_findings(
            [winner, masked_signal, other_signal_a, other_signal_b], policy
        )
        # Sanity: this is the exact same illegitimate-signal-loss shape as the
        # unwaived test above - aggregate() still restores at its own layer.
        self.assertTrue(scan_result.trifecta_present)
        self.assertEqual(scan_result.severity, Severity.CRITICAL)
        self.assertNotIn(masked_signal, scan_result.findings)
        self.assertEqual(scan_result.dedup_collision_rule_ids, frozenset({"shared.rule"}))

        allowlist = [
            AllowlistEntry(
                scope_type="rule_global",
                scope_value="*",
                rule_id="shared.rule",
                expires_at=1e18,
                approved_by="approver",
                requested_by="requester",
            )
        ]
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, allowlist, now=0.0)
        self.assertNotIn(
            "dedup_collision_signal_restored_from_scan_result",
            verdict_result.reasons,
            "an active waiver covering every rule_id involved in the dedup "
            "collision must suppress the restoration, not be silently overridden "
            "by it",
        )
        self.assertFalse(verdict_result.trifecta_present)
        self.assertEqual(
            verdict_result.verdict,
            Verdict.PASS,
            "with 'shared.rule' waived, only 2 of 3 trifecta signals remain "
            "(other_signal_a/b) and no CRITICAL-severity finding survives "
            "waiving - must reach the same PASS a non-colliding equivalent would",
        )

    # Companion: an UNRELATED rule_id being waived must NOT suppress the
    # restoration - only full coverage of the colliding rule_id(s) qualifies.
    def test_inv8_waiver_of_unrelated_rule_id_does_not_suppress_dedup_restoration(
        self,
    ) -> None:
        policy = default_policy(
            block_on_severity=Severity.CRITICAL,
            review_on_severity=Severity.HIGH,
            review_confidence=0.6,
            allowlistable_max_severity=Severity.HIGH,
        )
        winner = make_finding(
            rule_id="shared.rule",
            severity=Severity.MEDIUM,
            confidence=1.0,
            file_path="skill/run.py",
            start_line=10,
        )
        masked_signal = make_finding(
            rule_id="shared.rule",
            severity=Severity.LOW,
            confidence=0.3,
            file_path="skill/run.py",
            start_line=10,
            trifecta_signals=frozenset({TrifectaSignal.EXTERNAL_EGRESS}),
        )
        other_signal_a = make_finding(
            rule_id="a",
            severity=Severity.LOW,
            trifecta_signals=frozenset({TrifectaSignal.PRIVATE_DATA_ACCESS}),
        )
        other_signal_b = make_finding(
            rule_id="b",
            severity=Severity.LOW,
            trifecta_signals=frozenset({TrifectaSignal.UNTRUSTED_INPUT}),
        )
        scan_result = scan_result_from_findings(
            [winner, masked_signal, other_signal_a, other_signal_b], policy
        )
        # Waives "a", not "shared.rule" - must not touch the restoration at all.
        allowlist = [
            AllowlistEntry(
                scope_type="rule_global",
                scope_value="*",
                rule_id="a",
                expires_at=1e18,
                approved_by="approver",
                requested_by="requester",
            )
        ]
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, allowlist, now=0.0)
        self.assertIn("dedup_collision_signal_restored_from_scan_result", verdict_result.reasons)
        self.assertTrue(verdict_result.trifecta_present)
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)

    # INV-5: flood beyond max_findings -> findings_capped=True and can never resolve
    # to PASS; truncation keeps the worst findings; hard-gate/trifecta signals survive
    # even if the contributing findings get pushed past the cap.
    def test_inv5_flood_capped_cannot_pass(self) -> None:
        policy = default_policy(
            block_on_severity=Severity.CRITICAL, review_on_severity=Severity.CRITICAL
        )
        findings = [
            make_finding(rule_id=f"low-{i}", severity=Severity.LOW, confidence=1.0)
            for i in range(20)
        ]
        scan_result = scan_result_from_findings(findings, policy, max_findings=5)
        self.assertTrue(scan_result.findings_capped)
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
        self.assertNotEqual(verdict_result.verdict, Verdict.PASS)

    def test_inv5_cap_keeps_worst_and_preserves_hard_gate(self) -> None:
        policy = default_policy(hard_gate_rules=frozenset({"gate.hit"}))
        filler = [
            make_finding(rule_id=f"filler-{i}", severity=Severity.HIGH, confidence=1.0)
            for i in range(10)
        ]
        buried_hard_gate = make_finding(rule_id="gate.hit", severity=Severity.LOW, confidence=1.0)
        scan_result = scan_result_from_findings(filler + [buried_hard_gate], policy, max_findings=3)
        self.assertTrue(scan_result.findings_capped)
        self.assertIn("gate.hit", scan_result.hard_gate_hits)

    # INV-6: content-addressing - order-independence, mode/byte sensitivity, and
    # traversal/duplicate rejection. Full coverage in test_canonical.py; a
    # representative assertion is kept here for the audit trail.
    def test_inv6_content_hash_order_independent_and_mode_sensitive(self) -> None:
        a = content_hash([("a.py", 0o644, b"x"), ("b.py", 0o644, b"y")])
        b = content_hash([("b.py", 0o644, b"y"), ("a.py", 0o644, b"x")])
        self.assertEqual(a, b)
        c = content_hash([("a.py", 0o755, b"x"), ("b.py", 0o644, b"y")])
        self.assertNotEqual(a, c)

    # INV-7: any engine/policy/prompt version change -> toolchain_digest changes ->
    # cache_key changes (stale-PASS prevention).
    def test_inv7_toolchain_digest_change_invalidates_cache_key(self) -> None:
        ch = content_hash([("a.py", 0o644, b"x")])
        e_v1 = EngineMetadata(
            name="eng", version="1.0.0", ruleset_digest="d", capabilities=frozenset()
        )
        e_v2 = EngineMetadata(
            name="eng", version="1.0.1", ruleset_digest="d", capabilities=frozenset()
        )
        td1 = toolchain_digest([e_v1], "policy-v1")
        td2 = toolchain_digest([e_v2], "policy-v1")
        self.assertNotEqual(td1, td2)
        self.assertNotEqual(cache_key(ch, td1), cache_key(ch, td2))

    # INV-8: four-eyes allowlist, mandatory expiry, severity ceiling, scope matching.
    def test_inv8_allowlist_four_eyes_enforced_at_construction(self) -> None:
        with self.assertRaises(ValueError):
            AllowlistEntry(
                scope_type="rule_global",
                scope_value="*",
                rule_id="r",
                expires_at=1e18,
                approved_by="same",
                requested_by="same",
            )

    def test_inv8_allowlist_expiry_enforced(self) -> None:
        entry = AllowlistEntry(
            scope_type="rule_global",
            scope_value="*",
            rule_id="r",
            expires_at=100.0,
            approved_by="a",
            requested_by="b",
        )
        self.assertFalse(entry.is_active(100.0, "any"))  # now >= expires_at -> expired

    def test_inv8_severity_above_ceiling_not_waivable(self) -> None:
        policy = default_policy(allowlistable_max_severity=Severity.MEDIUM)
        finding = make_finding(rule_id="severe", severity=Severity.CRITICAL, confidence=1.0)
        scan_result = scan_result_from_findings([finding], policy)
        allowlist = [
            AllowlistEntry(
                scope_type="content_hash",
                scope_value=scan_result.content_hash,
                rule_id="severe",
                expires_at=1e18,
                approved_by="a",
                requested_by="b",
            )
        ]
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, allowlist, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)

    def test_inv8_scope_mismatch_not_waived(self) -> None:
        policy = default_policy(block_on_severity=Severity.HIGH, review_on_severity=Severity.MEDIUM)
        finding = make_finding(rule_id="r", severity=Severity.HIGH, confidence=1.0)
        scan_result = scan_result_from_findings([finding], policy)
        allowlist = [
            AllowlistEntry(
                scope_type="content_hash",
                scope_value="different-hash",
                rule_id="r",
                expires_at=1e18,
                approved_by="a",
                requested_by="b",
            )
        ]
        verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, allowlist, now=0.0)
        self.assertEqual(verdict_result.verdict, Verdict.BLOCK)


class TestScoreBandInvariant(unittest.TestCase):
    # New invariant from the 2026-07-25 scoring design doc (not yet a
    # numbered INV in the coding spec's own §14 checklist - flagged to the
    # user, not silently added there). Randomized property test with a fixed
    # seed, same style as INV-2's test_inv2_llm_monotonicity_randomized_fixed_seed
    # above: score must always fall inside the band its own verdict maps to.
    #
    # SECURITY (review 2026-07-25, Task 3): each trial randomly picks which of
    # decide()'s 3 score-returning branches to exercise (normal path /
    # required-engine-missing fail-closed / hard-gate hit) - a fixed
    # default_policy() shared across all 200 trials would only ever reach the
    # normal path (found live: the original version of this test structurally
    # never exercised the other two, despite 200 trials).
    def test_score_always_within_the_verdict_band_randomized_fixed_seed(self) -> None:
        band = {Verdict.BLOCK: (0, 39), Verdict.REVIEW: (40, 74), Verdict.PASS: (75, 100)}
        rng = random.Random(20260725)
        severities = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        modes = ["normal", "missing_engine", "hard_gate"]

        for trial in range(200):
            mode = rng.choice(modes)
            if mode == "missing_engine":
                policy = default_policy(
                    required_engines=frozenset({"static-keyword", "missing-engine"})
                )
            elif mode == "hard_gate":
                policy = default_policy(hard_gate_rules=frozenset({f"gate-{trial}"}))
            else:
                policy = default_policy()

            if mode == "hard_gate":
                # Guarantee at least one finding actually matches the
                # trial's hard-gate rule, so this mode reliably reaches
                # decide()'s hard-gate branch rather than only sometimes.
                findings = [
                    make_finding(
                        rule_id=f"gate-{trial}" if i == 0 else f"f-{trial}-{i}",
                        severity=rng.choice(severities),
                        confidence=rng.random(),
                    )
                    for i in range(rng.randint(1, 6))
                ]
            else:
                findings = [
                    make_finding(
                        rule_id=f"f-{trial}-{i}",
                        severity=rng.choice(severities),
                        confidence=rng.random(),
                    )
                    for i in range(rng.randint(0, 6))
                ]

            scan_result = scan_result_from_findings(findings, policy)
            verdict_result = decide(scan_result, policy, TrustTier.INTERNAL, now=0.0)
            band_min, band_max = band[verdict_result.verdict]
            with self.subTest(trial=trial, mode=mode):
                self.assertGreaterEqual(verdict_result.score, band_min)
                self.assertLessEqual(verdict_result.score, band_max)


if __name__ == "__main__":
    unittest.main()
