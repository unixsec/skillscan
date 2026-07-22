"""Unit tests for skillscan_core.models (coding spec M1, §5.1)."""

from __future__ import annotations

import unittest

from skillscan_core import (
    AllowlistEntry,
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    EngineResult,
    EngineStatus,
    Finding,
    GatePolicy,
    ScanMode,
    Severity,
    TrifectaSignal,
    TrustTier,
    Verdict,
)


class TestSeverityAndVerdictOrdering(unittest.TestCase):
    def test_severity_max_picks_most_severe(self) -> None:
        self.assertEqual(max(Severity.LOW, Severity.CRITICAL), Severity.CRITICAL)

    def test_verdict_max_picks_stricter(self) -> None:
        self.assertEqual(max(Verdict.PASS, Verdict.BLOCK), Verdict.BLOCK)
        self.assertEqual(max(Verdict.REVIEW, Verdict.PASS), Verdict.REVIEW)


class TestFinding(unittest.TestCase):
    def _base_kwargs(self, **overrides: object) -> dict:
        kwargs: dict = dict(
            rule_id="rule.1",
            test_item_id="CODE-01",
            category=DetectionCategory.CODE,
            title="t",
            severity=Severity.MEDIUM,
            confidence=0.5,
            source_engine="eng",
            source_capability=EngineCapability.STATIC,
        )
        kwargs.update(overrides)
        return kwargs

    def test_valid_finding_constructs(self) -> None:
        f = Finding(**self._base_kwargs())
        self.assertEqual(f.trifecta_signals, frozenset())

    def test_rejects_empty_rule_id(self) -> None:
        with self.assertRaises(ValueError):
            Finding(**self._base_kwargs(rule_id=""))

    def test_rejects_confidence_out_of_range(self) -> None:
        with self.assertRaises(ValueError):
            Finding(**self._base_kwargs(confidence=1.5))
        with self.assertRaises(ValueError):
            Finding(**self._base_kwargs(confidence=-0.1))

    def test_rejects_none_severity(self) -> None:
        with self.assertRaises(ValueError):
            Finding(**self._base_kwargs(severity=Severity.NONE))

    def test_rejects_plaintext_snippet_hash(self) -> None:
        with self.assertRaises(ValueError):
            Finding(**self._base_kwargs(snippet_hash="os.environ['SECRET']"))

    def test_accepts_hex_snippet_hash(self) -> None:
        f = Finding(**self._base_kwargs(snippet_hash="deadbeef"))
        self.assertEqual(f.snippet_hash, "deadbeef")

    def test_trifecta_signals_normalized_to_frozenset(self) -> None:
        f = Finding(**self._base_kwargs(trifecta_signals=[TrifectaSignal.EXTERNAL_EGRESS]))
        self.assertIsInstance(f.trifecta_signals, frozenset)

    def test_is_llm_sourced(self) -> None:
        det = Finding(**self._base_kwargs(source_capability=EngineCapability.STATIC))
        llm = Finding(**self._base_kwargs(source_capability=EngineCapability.SEMANTIC_LLM))
        self.assertFalse(det.is_llm_sourced)
        self.assertTrue(llm.is_llm_sourced)

    def test_dedup_key(self) -> None:
        f = Finding(**self._base_kwargs(file_path="a.py", start_line=3))
        self.assertEqual(f.dedup_key, ("rule.1", "a.py", 3, DetectionCategory.CODE))


class TestEngineMetadata(unittest.TestCase):
    def test_rejects_empty_name_or_version(self) -> None:
        with self.assertRaises(ValueError):
            EngineMetadata(name="", version="1", ruleset_digest="d", capabilities=frozenset())
        with self.assertRaises(ValueError):
            EngineMetadata(name="n", version="", ruleset_digest="d", capabilities=frozenset())

    def test_rejects_requires_network(self) -> None:
        with self.assertRaises(ValueError):
            EngineMetadata(
                name="n",
                version="1",
                ruleset_digest="d",
                capabilities=frozenset(),
                requires_network=True,
            )


class TestEngineResult(unittest.TestCase):
    def _metadata(self) -> EngineMetadata:
        return EngineMetadata(name="n", version="1", ruleset_digest="d", capabilities=frozenset())

    def test_usable_statuses(self) -> None:
        for status, expected in (
            (EngineStatus.OK, True),
            (EngineStatus.PARTIAL, True),
            (EngineStatus.ERROR, False),
            (EngineStatus.TIMEOUT, False),
        ):
            with self.subTest(status=status):
                result = EngineResult(
                    engine=self._metadata(),
                    findings=(),
                    status=status,
                    scan_mode=ScanMode.STATIC,
                )
                self.assertEqual(result.usable, expected)


class TestGatePolicy(unittest.TestCase):
    def test_rejects_empty_version(self) -> None:
        with self.assertRaises(ValueError):
            GatePolicy(version="", required_engines=frozenset())

    def test_rejects_fail_closed_pass(self) -> None:
        with self.assertRaises(ValueError):
            GatePolicy(version="v1", required_engines=frozenset(), fail_closed_verdict=Verdict.PASS)

    def test_rejects_looser_tier_override(self) -> None:
        with self.assertRaises(ValueError):
            GatePolicy(
                version="v1",
                required_engines=frozenset(),
                block_on_severity=Severity.HIGH,
                tier_block_overrides=((TrustTier.PUBLIC, Severity.CRITICAL),),
            )

    def test_accepts_stricter_tier_override(self) -> None:
        policy = GatePolicy(
            version="v1",
            required_engines=frozenset(),
            block_on_severity=Severity.HIGH,
            tier_block_overrides=((TrustTier.PUBLIC, Severity.MEDIUM),),
        )
        self.assertEqual(policy.block_threshold(TrustTier.PUBLIC), Severity.MEDIUM)
        self.assertEqual(policy.block_threshold(TrustTier.INTERNAL), Severity.HIGH)

    def test_block_threshold_takes_strictest_of_multiple_overrides(self) -> None:
        policy = GatePolicy(
            version="v1",
            required_engines=frozenset(),
            block_on_severity=Severity.CRITICAL,
            tier_block_overrides=(
                (TrustTier.PUBLIC, Severity.HIGH),
                (TrustTier.PUBLIC, Severity.MEDIUM),
            ),
        )
        self.assertEqual(policy.block_threshold(TrustTier.PUBLIC), Severity.MEDIUM)


class TestAllowlistEntry(unittest.TestCase):
    def _base_kwargs(self, **overrides: object) -> dict:
        kwargs: dict = dict(
            scope_type="content_hash",
            scope_value="abc123",
            rule_id="rule.1",
            expires_at=1000.0,
            approved_by="approver",
            requested_by="requester",
        )
        kwargs.update(overrides)
        return kwargs

    def test_rejects_same_approver_and_requester(self) -> None:
        with self.assertRaises(ValueError):
            AllowlistEntry(**self._base_kwargs(approved_by="same", requested_by="same"))

    def test_rejects_empty_approver_or_requester(self) -> None:
        with self.assertRaises(ValueError):
            AllowlistEntry(**self._base_kwargs(approved_by=""))

    def test_rejects_non_positive_expiry(self) -> None:
        with self.assertRaises(ValueError):
            AllowlistEntry(**self._base_kwargs(expires_at=0.0))
        with self.assertRaises(ValueError):
            AllowlistEntry(**self._base_kwargs(expires_at=-5.0))

    def test_rejects_invalid_scope_type(self) -> None:
        with self.assertRaises(ValueError):
            AllowlistEntry(**self._base_kwargs(scope_type="bogus"))

    def test_rejects_empty_scope_value_for_non_global_scope(self) -> None:
        with self.assertRaises(ValueError):
            AllowlistEntry(**self._base_kwargs(scope_type="content_hash", scope_value=""))
        with self.assertRaises(ValueError):
            AllowlistEntry(**self._base_kwargs(scope_type="skill_id", scope_value=""))

    def test_allows_empty_scope_value_for_rule_global(self) -> None:
        # scope_value is meaningless for rule_global (is_active() never reads
        # it) - the web UI submits it empty for this scope type, so this must
        # succeed rather than raise (previously untested combination that
        # made every rule_global waiver a guaranteed 400 in the live UI).
        entry = AllowlistEntry(**self._base_kwargs(scope_type="rule_global", scope_value=""))
        self.assertTrue(entry.is_active(0.0, "anything"))

    def test_is_active_expiry(self) -> None:
        entry = AllowlistEntry(**self._base_kwargs(expires_at=100.0))
        self.assertTrue(entry.is_active(50.0, "abc123"))
        self.assertFalse(entry.is_active(100.0, "abc123"))  # strict: now>=expires_at -> expired
        self.assertFalse(entry.is_active(150.0, "abc123"))

    def test_is_active_scope_matching(self) -> None:
        by_hash = AllowlistEntry(**self._base_kwargs(scope_type="content_hash", scope_value="H1"))
        self.assertTrue(by_hash.is_active(0.0, "H1"))
        self.assertFalse(by_hash.is_active(0.0, "H2"))

        by_skill = AllowlistEntry(**self._base_kwargs(scope_type="skill_id", scope_value="S1"))
        self.assertTrue(by_skill.is_active(0.0, "H1", "S1"))
        self.assertFalse(by_skill.is_active(0.0, "H1", "S2"))
        self.assertFalse(by_skill.is_active(0.0, "H1", None))

        global_entry = AllowlistEntry(**self._base_kwargs(scope_type="rule_global"))
        self.assertTrue(global_entry.is_active(0.0, "anything"))

    def test_waives_matches_by_rule_id(self) -> None:
        entry = AllowlistEntry(**self._base_kwargs(rule_id="rule.1"))
        finding = Finding(
            rule_id="rule.1",
            test_item_id="x",
            category=DetectionCategory.CODE,
            title="t",
            severity=Severity.LOW,
            confidence=1.0,
            source_engine="e",
            source_capability=EngineCapability.STATIC,
        )
        other = Finding(
            rule_id="rule.2",
            test_item_id="x",
            category=DetectionCategory.CODE,
            title="t",
            severity=Severity.LOW,
            confidence=1.0,
            source_engine="e",
            source_capability=EngineCapability.STATIC,
        )
        self.assertTrue(entry.waives(finding))
        self.assertFalse(entry.waives(other))


if __name__ == "__main__":
    unittest.main()
