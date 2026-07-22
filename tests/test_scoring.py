"""Unit tests for skillscan_core.scoring (coding spec M1, §5.3 - INV-4/INV-5)."""

from __future__ import annotations

import unittest

from skillscan_core import EngineCapability, EngineStatus, Severity, TrifectaSignal
from skillscan_core.scoring import _dedup, evaluate_findings

from tests._helpers import default_policy, make_finding, scan_result_from_findings


class TestEvaluateFindings(unittest.TestCase):
    def test_max_severity_aggregation(self) -> None:
        findings = [
            make_finding(rule_id="a", severity=Severity.LOW, confidence=1.0),
            make_finding(rule_id="b", severity=Severity.HIGH, confidence=1.0),
            make_finding(rule_id="c", severity=Severity.MEDIUM, confidence=1.0),
        ]
        severity, _conf, _trif, _hgh = evaluate_findings(findings)
        self.assertEqual(severity, Severity.HIGH)

    def test_confidence_at_max_is_at_the_max_severity_level(self) -> None:
        findings = [
            make_finding(rule_id="a", severity=Severity.HIGH, confidence=0.3),
            make_finding(rule_id="b", severity=Severity.HIGH, confidence=0.9),
            make_finding(rule_id="c", severity=Severity.LOW, confidence=1.0),
        ]
        severity, conf, _trif, _hgh = evaluate_findings(findings)
        self.assertEqual(severity, Severity.HIGH)
        self.assertEqual(conf, 0.9)

    def test_min_confidence_filters_severity_computation(self) -> None:
        findings = [
            make_finding(rule_id="a", severity=Severity.CRITICAL, confidence=0.1),
            make_finding(rule_id="b", severity=Severity.LOW, confidence=1.0),
        ]
        severity, _conf, _trif, _hgh = evaluate_findings(findings, min_confidence=0.5)
        self.assertEqual(severity, Severity.LOW)

    def test_hard_gate_hits_ignore_min_confidence(self) -> None:
        findings = [make_finding(rule_id="gate.1", severity=Severity.LOW, confidence=0.01)]
        _severity, _conf, _trif, hgh = evaluate_findings(
            findings, min_confidence=0.99, hard_gate_rules=frozenset({"gate.1"})
        )
        self.assertIn("gate.1", hgh)

    def test_trifecta_forces_critical(self) -> None:
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
        severity, _conf, trif, _hgh = evaluate_findings(findings)
        self.assertTrue(trif)
        self.assertEqual(severity, Severity.CRITICAL)

    def test_missing_one_signal_does_not_escalate(self) -> None:
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
        severity, _conf, trif, _hgh = evaluate_findings(findings)
        self.assertFalse(trif)
        self.assertEqual(severity, Severity.LOW)

    def test_empty_findings_yields_none_severity(self) -> None:
        severity, conf, trif, _hgh = evaluate_findings([])
        self.assertEqual(severity, Severity.NONE)
        self.assertEqual(conf, 0.0)
        self.assertFalse(trif)


class TestDedup(unittest.TestCase):
    def test_same_key_non_llm_keeps_max(self) -> None:
        low = make_finding(
            rule_id="a", severity=Severity.LOW, confidence=0.2, file_path="f.py", start_line=1
        )
        high = make_finding(
            rule_id="a", severity=Severity.HIGH, confidence=0.9, file_path="f.py", start_line=1
        )
        result, collided_rule_ids = _dedup([low, high])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, Severity.HIGH)
        self.assertEqual(collided_rule_ids, frozenset({"a"}))

    def test_llm_and_non_llm_at_same_key_both_survive(self) -> None:
        det = make_finding(
            rule_id="a",
            severity=Severity.HIGH,
            confidence=0.9,
            capability=EngineCapability.STATIC,
            file_path="f.py",
            start_line=1,
        )
        llm = make_finding(
            rule_id="a",
            severity=Severity.LOW,
            confidence=0.1,
            capability=EngineCapability.SEMANTIC_LLM,
            file_path="f.py",
            start_line=1,
        )
        result, collided_rule_ids = _dedup([det, llm])
        self.assertEqual(len(result), 2)
        # SECURITY: partitioned by is_llm_sourced too, so this is NOT a collision -
        # both findings survive, and dedup dropped nothing for gate.py to restore.
        self.assertEqual(collided_rule_ids, frozenset())


class TestAggregate(unittest.TestCase):
    def test_required_engine_missing(self) -> None:
        policy = default_policy(required_engines=frozenset({"static-keyword", "other-engine"}))
        result = scan_result_from_findings([], policy)
        self.assertFalse(result.required_ok)
        self.assertIn("other-engine", result.missing_or_failed_required)

    def test_required_engine_error_status_not_usable(self) -> None:
        policy = default_policy()
        result = scan_result_from_findings([], policy, engine_status=EngineStatus.ERROR)
        self.assertFalse(result.required_ok)

    def test_findings_capped_and_pre_cap_hard_gate_preserved(self) -> None:
        policy = default_policy(hard_gate_rules=frozenset({"gate.hit"}))
        filler = [
            make_finding(rule_id=f"filler-{i}", severity=Severity.HIGH, confidence=1.0)
            for i in range(10)
        ]
        # Sorts to the very bottom (lowest severity) - would be truncated by a small cap.
        hard_gate_finding = make_finding(rule_id="gate.hit", severity=Severity.LOW, confidence=1.0)
        result = scan_result_from_findings(filler + [hard_gate_finding], policy, max_findings=3)
        self.assertTrue(result.findings_capped)
        self.assertIn("gate.hit", result.hard_gate_hits)

    def test_findings_capped_and_pre_cap_trifecta_preserved(self) -> None:
        policy = default_policy()
        filler = [
            make_finding(rule_id=f"filler-{i}", severity=Severity.HIGH, confidence=1.0)
            for i in range(10)
        ]
        trifecta_findings = [
            make_finding(
                rule_id="t1",
                severity=Severity.LOW,
                trifecta_signals=frozenset({TrifectaSignal.PRIVATE_DATA_ACCESS}),
            ),
            make_finding(
                rule_id="t2",
                severity=Severity.LOW,
                trifecta_signals=frozenset({TrifectaSignal.UNTRUSTED_INPUT}),
            ),
            make_finding(
                rule_id="t3",
                severity=Severity.LOW,
                trifecta_signals=frozenset({TrifectaSignal.EXTERNAL_EGRESS}),
            ),
        ]
        result = scan_result_from_findings(filler + trifecta_findings, policy, max_findings=3)
        self.assertTrue(result.findings_capped)
        self.assertTrue(result.trifecta_present)
        self.assertEqual(result.severity, Severity.CRITICAL)

    def test_worst_first_truncation_keeps_most_severe(self) -> None:
        policy = default_policy()
        findings = [
            make_finding(rule_id="low", severity=Severity.LOW, confidence=1.0),
            make_finding(rule_id="critical", severity=Severity.CRITICAL, confidence=1.0),
            make_finding(rule_id="medium", severity=Severity.MEDIUM, confidence=1.0),
        ]
        result = scan_result_from_findings(findings, policy, max_findings=1)
        self.assertTrue(result.findings_capped)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_id, "critical")


if __name__ == "__main__":
    unittest.main()
