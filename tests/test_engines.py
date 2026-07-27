"""Unit tests for skillscan_core.engines (coding spec M1, §5.5 - INV-7)."""

from __future__ import annotations

import copy
import time
import unittest

from skillscan_core.engines import (
    _STATIC_KEYWORD_PATTERNS,
    _TEST_ITEM_IDS,
    StaticKeywordEngine,
    _static_keyword_ruleset_digest,
)
from skillscan_core.models import DetectionCategory, EngineStatus, Severity, TrifectaSignal


class TestStaticKeywordRulesetDigest(unittest.TestCase):
    # INV-7 regression (2026-07-06 spec-compliance audit): the digest must
    # change if a rule's severity/category/trifecta_signal changes, not just
    # its rule_id/pattern - otherwise toolchain_digest/cache_key stay the same
    # and a stale cached PASS survives a rule severity upgrade.
    def test_digest_changes_when_severity_changes_for_same_rule_id_and_pattern(self) -> None:
        original_digest = _static_keyword_ruleset_digest()

        import skillscan_core.engines as engines_module

        patched = list(copy.deepcopy(_STATIC_KEYWORD_PATTERNS))
        pattern, rule_id, category, severity, trifecta_signal, title, confidence = patched[0]
        self.assertNotEqual(severity, Severity.CRITICAL, "test needs a real severity change")
        patched[0] = (
            pattern,
            rule_id,
            category,
            Severity.CRITICAL,
            trifecta_signal,
            title,
            confidence,
        )

        original_patterns = engines_module._STATIC_KEYWORD_PATTERNS
        try:
            engines_module._STATIC_KEYWORD_PATTERNS = tuple(patched)
            changed_digest = engines_module._static_keyword_ruleset_digest()
        finally:
            engines_module._STATIC_KEYWORD_PATTERNS = original_patterns

        self.assertNotEqual(
            original_digest,
            changed_digest,
            "changing an existing rule's severity must change the ruleset digest",
        )

    def test_digest_changes_when_category_changes(self) -> None:
        import skillscan_core.engines as engines_module

        patched = list(copy.deepcopy(_STATIC_KEYWORD_PATTERNS))
        pattern, rule_id, category, severity, trifecta_signal, title, confidence = patched[0]
        new_category = (
            DetectionCategory.SUPPLY_CHAIN
            if category is not DetectionCategory.SUPPLY_CHAIN
            else DetectionCategory.PERMISSION
        )
        patched[0] = (
            pattern,
            rule_id,
            new_category,
            severity,
            trifecta_signal,
            title,
            confidence,
        )

        original_patterns = engines_module._STATIC_KEYWORD_PATTERNS
        try:
            original_digest = engines_module._static_keyword_ruleset_digest()
            engines_module._STATIC_KEYWORD_PATTERNS = tuple(patched)
            changed_digest = engines_module._static_keyword_ruleset_digest()
        finally:
            engines_module._STATIC_KEYWORD_PATTERNS = original_patterns

        self.assertNotEqual(original_digest, changed_digest)

    def test_digest_changes_when_trifecta_signal_changes(self) -> None:
        import skillscan_core.engines as engines_module

        patched = list(copy.deepcopy(_STATIC_KEYWORD_PATTERNS))
        pattern, rule_id, category, severity, trifecta_signal, title, confidence = patched[0]
        new_signal = None if trifecta_signal is not None else TrifectaSignal.EXTERNAL_EGRESS
        patched[0] = (pattern, rule_id, category, severity, new_signal, title, confidence)

        original_patterns = engines_module._STATIC_KEYWORD_PATTERNS
        try:
            original_digest = engines_module._static_keyword_ruleset_digest()
            engines_module._STATIC_KEYWORD_PATTERNS = tuple(patched)
            changed_digest = engines_module._static_keyword_ruleset_digest()
        finally:
            engines_module._STATIC_KEYWORD_PATTERNS = original_patterns

        self.assertNotEqual(original_digest, changed_digest)

    def test_digest_changes_when_confidence_changes(self) -> None:
        # D6 (2026-07-27): confidence is now per-rule and gates gate.py's
        # review_confidence branch, so a confidence-only edit must also bust
        # the digest/cache_key - same INV-7 property as severity/category/
        # trifecta above.
        import skillscan_core.engines as engines_module

        patched = list(copy.deepcopy(_STATIC_KEYWORD_PATTERNS))
        pattern, rule_id, category, severity, trifecta_signal, title, confidence = patched[0]
        new_confidence = 0.1 if confidence != 0.1 else 0.2
        patched[0] = (pattern, rule_id, category, severity, trifecta_signal, title, new_confidence)

        original_patterns = engines_module._STATIC_KEYWORD_PATTERNS
        try:
            original_digest = engines_module._static_keyword_ruleset_digest()
            engines_module._STATIC_KEYWORD_PATTERNS = tuple(patched)
            changed_digest = engines_module._static_keyword_ruleset_digest()
        finally:
            engines_module._STATIC_KEYWORD_PATTERNS = original_patterns

        self.assertNotEqual(
            original_digest,
            changed_digest,
            "changing an existing rule's confidence must change the ruleset digest",
        )

    def test_digest_changes_when_test_item_id_changes(self) -> None:
        # D9 (2026-07-27): test_item_id used to equal rule_id, so it was
        # implicitly covered by the rule_id hash. Now that _TEST_ITEM_IDS is
        # an independent mapping, a test_item_id-only correction (e.g. fixing
        # a wrong catalog mapping) must still bust the digest/cache_key -
        # otherwise the fix would be silently served from a stale cached
        # verdict (same INV-7 property as severity/category/trifecta/
        # confidence above).
        import skillscan_core.engines as engines_module

        rule_id = _STATIC_KEYWORD_PATTERNS[0][1]
        patched = dict(_TEST_ITEM_IDS)
        patched[rule_id] = patched[rule_id] + "-CHANGED"

        original_mapping = engines_module._TEST_ITEM_IDS
        try:
            original_digest = engines_module._static_keyword_ruleset_digest()
            engines_module._TEST_ITEM_IDS = patched
            changed_digest = engines_module._static_keyword_ruleset_digest()
        finally:
            engines_module._TEST_ITEM_IDS = original_mapping

        self.assertNotEqual(
            original_digest,
            changed_digest,
            "changing an existing rule's test_item_id must change the ruleset digest",
        )

    def test_digest_stable_when_nothing_changes(self) -> None:
        self.assertEqual(_static_keyword_ruleset_digest(), _static_keyword_ruleset_digest())

    def test_engine_metadata_exposes_current_digest(self) -> None:
        engine = StaticKeywordEngine()
        self.assertEqual(engine.metadata.ruleset_digest, _static_keyword_ruleset_digest())


class TestStaticKeywordTestItemId(unittest.TestCase):
    """D9 hardening (2026-07-27): StaticKeywordEngine was the one engine
    Task 7's test_item_id unification missed - it used to pass
    test_item_id=rule_id straight through, so these findings emitted their
    own engine-internal rule name instead of a real
    企业Skill安全评估测试维度清单.xlsx catalog id."""

    def test_eval_call_maps_to_code_02(self) -> None:
        findings = StaticKeywordEngine().analyze({"a.py": b"eval(x)\n"}).findings
        self.assertTrue(findings)
        for f in findings:
            if f.rule_id == "static.eval_call":
                self.assertEqual(f.test_item_id, "CODE-02")

    def test_curl_http_maps_to_net_05(self) -> None:
        findings = StaticKeywordEngine().analyze({"a.py": b"curl http://example.com\n"}).findings
        self.assertTrue(findings)
        for f in findings:
            if f.rule_id == "static.curl_http":
                self.assertEqual(f.test_item_id, "NET-05")

    def test_os_environ_maps_to_cred_03(self) -> None:
        findings = StaticKeywordEngine().analyze({"a.py": b"os.environ['HOME']\n"}).findings
        self.assertTrue(findings)
        for f in findings:
            if f.rule_id == "static.os_environ":
                self.assertEqual(f.test_item_id, "CRED-03")

    def test_input_call_maps_to_gen_01(self) -> None:
        findings = StaticKeywordEngine().analyze({"a.py": b"input('x')\n"}).findings
        self.assertTrue(findings)
        for f in findings:
            if f.rule_id == "static.input_call":
                self.assertEqual(f.test_item_id, "GEN-01")

    def test_test_item_id_never_falls_back_to_rule_id(self) -> None:
        """Regression guard for the exact defect: test_item_id must not equal
        rule_id for any static-keyword rule (a real catalog id never happens
        to match an engine-internal "static.*" rule name)."""
        files = {"a.py": (b"eval(x)\ncurl http://example.com\nos.environ['HOME']\ninput('x')\n")}
        findings = StaticKeywordEngine().analyze(files).findings
        self.assertEqual(len(findings), 4)
        for f in findings:
            self.assertNotEqual(f.test_item_id, f.rule_id)
            self.assertEqual(f.test_item_id, _TEST_ITEM_IDS[f.rule_id])


class TestStaticKeywordConfidence(unittest.TestCase):
    def test_substring_rules_are_not_full_confidence(self) -> None:
        """`"eval(" in line` matches comments, docstrings and string literals.
        Recording that as confidence 1.0 misrepresented a substring hit as
        certainty, and kept review_confidence (0.6) from ever firing."""
        findings = StaticKeywordEngine().analyze({"a.py": b"# eval(x) in a comment\n"}).findings
        self.assertTrue(findings)
        for f in findings:
            self.assertLess(f.confidence, 1.0)

    def test_confidence_is_per_rule_not_per_engine(self) -> None:
        # `eval(` and `os.environ` deliberately: a bare substring match that
        # commonly appears in comments and literals (0.5) versus a distinctive
        # attribute access (0.7). `input(` is NOT used here - it is also 0.5,
        # and correctly so, since it has the same weak-evidence shape as
        # `eval(`; a test proving "not one constant" needs two rules that
        # genuinely differ, not two that happen to agree for good reason.
        files = {"a.py": b"eval(x)\nos.environ['HOME']\n"}
        by_rule = {f.rule_id: f.confidence for f in StaticKeywordEngine().analyze(files).findings}
        self.assertGreater(len(set(by_rule.values())), 1, "all rules still share one constant")


class TestStaticKeywordEngineDeadline(unittest.TestCase):
    """SECURITY (2026-07-27): the deadline check compared time.monotonic()
    (an uptime counter, thousands of seconds) against a wall-clock epoch
    (~1.7e9), so it was never true and the timeout never fired. Same bug the
    sandbox adapters fixed in adapters/base.py:96-105."""

    def test_expired_deadline_reports_timeout(self) -> None:
        engine = StaticKeywordEngine()
        # A wall-clock epoch one hour in the PAST - every real caller threads
        # `airlock.now_epoch() + N`, i.e. time.time()-based.
        expired = time.time() - 3600
        result = engine.analyze({"a.py": b"eval(x)\n"}, deadline=expired)
        self.assertEqual(result.status, EngineStatus.TIMEOUT)
        self.assertFalse(result.usable)

    def test_generous_deadline_completes_normally(self) -> None:
        engine = StaticKeywordEngine()
        # scan_deadline_s defaults to 300s; floor engines are pure in-memory
        # regex, so a real budget must never trip the timeout.
        result = engine.analyze({"a.py": b"eval(x)\n"}, deadline=time.time() + 300)
        self.assertEqual(result.status, EngineStatus.OK)
        self.assertTrue(result.findings)


if __name__ == "__main__":
    unittest.main()
